// P25 decoder daemon for ka9q-radio
// Reads complex baseband (I/Q) RTP streams from radiod, runs one P25 Phase 1 receiver per SSRC
// and logs what it decodes, one timestamped line per event, on standard output.
// Follows trunked calls: on a voice channel grant it asks radiod for that channel, and it sends
// the clear voice it decodes as RTP audio streams, and the vocoder frames themselves as RTP streams
// Copyright 2026, Matthew Kaufman, KA6SQG

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <signal.h>
#include <poll.h>
#include <getopt.h>
#include <sysexits.h>
#include <sys/socket.h>

#include "misc.h"
#include "multicast.h"
#include "rtp.h"
#include "status.h"
#include "radio.h"
#include "import.h"
#include "timing.h"
#include "defaults.h"
#include "chanctl.h"
#include "p25p1.h"
#include "p25msg.h"
#include "p25p1msg.h"
#include "p25trunk.h"
#include "p25alias.h"
#include "p25audio.h"

#define MAX_MCAST 20   // Maximum number of input groups
#define RESEQ 32       // Resequencing queue, packets. radiod sends one to three packets per 20 ms block
#define MAX_TALKGROUPS 4096 // In the allow and deny lists together
#define MAX_RADIOS 8   // radiod instances whose channels p25d may ask for
#define MAX_EVENTS 128 // Trunking events waiting to be acted on, per site
#define MAX_WORK 256   // Log lines and channel requests waiting for a site's lock to be let go
#define MAX_REFUSED 64 // Frequencies radiod refused, per site, remembered so each is logged once

struct site;
struct work;

// One block of complex samples on its way from the input thread to a decode thread
// Also the resequencing queue entry for the packet it came from
struct block {
  struct block *next;
  uint32_t timestamp;      // RTP timestamp of the first sample
  bool marker;             // RTP marker: don't fill the gap before this packet
  double samprate;         // Hz; a change restarts the decoder
  double frequency;        // Hz, channel frequency from the status stream
  int64_t time;            // Sender's time of the first sample, ns since GPS epoch; 0 if not yet known
  int count;               // complex samples
  float complex samples[]; // I in the real part, Q in the imaginary, as radiod sends them
};

// A transmission on a conventional channel (one that is neither a control channel nor a voice
// channel p25d asked for), for its start and end lines
struct conv {
  bool active;
  bool logged;             // its start line is out
  uint64_t start;          // sample counts: first and last data unit
  uint64_t last;
  bool known;              // talkgroup (or unit) known, from the header or link control
  bool unit_call;
  uint32_t target;
  uint32_t source;
  char alias[P25_ALIAS_MAX];
  bool encrypted;
  bool emergency;
  int units;               // voice units, words that failed, bits corrected in the voice frames
  int words_bad;
  int bits_fixed;
};

// Decode thread view of a channel. Only that thread touches it, so the decoder's frame and
// message callbacks (when they exist) can be handed a pointer to it and log without locking
struct decoder {
  struct session *sp;
  struct p25p1 *p25;
  double samprate;
  double frequency;        // of the block being decoded
  int64_t block_time;      // sender's time of the block's first sample, 0 if unknown
  uint64_t block_start;    // sample count at the start of the block being decoded
  uint64_t samples;        // samples fed to the decoder since it was created
  uint64_t next_report;    // sample count for the next -v status line
  struct p25_bandplan plan; // channel identifiers learned from this channel's trunking messages
  // Link control words repeat through a transmission, interleaved with others; each distinct
  // word is logged once, then again only after it has not been logged for a while
  struct {
    uint8_t lc[9];
    uint64_t sample;       // when last logged
    bool used;
  } recent_lc[8];
  uint8_t last_es[12];     // last encryption sync logged
  bool have_es;
  int voice_units;         // voice data units and bits corrected in their frames since the last terminator
  int voice_errors;
  struct p25_audio *audio; // voice output stream, NULL without --pcm-out or a vocoder

  // Call following. A control channel's thread feeds its site's trunking logic; the thread of a
  // voice channel p25d asked for feeds the same site's logic its voice units and is told what to do
  // with them. A channel that is neither (conventional, or configured and never granted) has neither
  struct site *site;       // the site, or NULL
  bool control;            // this channel carries the site's trunking
  bool voice;              // this is a voice channel the site asked for
  uint64_t trunk_freq;     // voice: the frequency the trunking logic knows the channel by
  uint32_t call_id;        // voice: call of the last voice unit
  bool seed;               // voice: seed the receiver's frequency with seed_hz when it is created
  float seed_hz;
  struct p25_alias alias;  // talker aliases from link control
  struct work *work;       // to act on after a site's lock is let go
  uint16_t site_nac;       // control: NAC of the last trunking message
  struct conv conv;        // conventional: the transmission in progress
  uint16_t conv_nac;
};

// One for each channel (SSRC) being decoded
struct session {
  struct session *prev;
  struct session *next;
  struct sockaddr_storage sender; // radiod's address; the port differs between status and data
  uint32_t ssrc;

  // From the status stream. Written and read only by the input thread
  chan_t chan;
  struct frontend frontend;
  struct pt_table pt_table[128]; // This sender's payload types, learned from its status
  int samprate;                  // of the stream being fed to the decoder
  bool warned;                   // Unusable stream already reported
  int64_t last_status;           // gps_time_ns() of last status packet
  int64_t last_data;             // and data packet

  // RTP reception, input thread only
  struct rtp_state rtp;          // seq and timestamp are the next ones expected
  struct block *reseq[RESEQ];    // Packets waiting for an earlier one, indexed by sequence number
  int pending;                   // Entries in use in reseq[]

  // Queue to the decode thread
  pthread_t thread;
  bool running;                  // Decode thread started
  pthread_mutex_t qmutex;
  pthread_cond_t qcond;
  struct block *queue;
  struct block *qtail;
  int64_t qsamples;
  atomic_bool terminate;

  // Statistics; written by the input thread, read by the decode thread for the status line
  atomic_uint_fast64_t packets;
  atomic_uint_fast64_t drops;      // Packets never received
  atomic_uint_fast64_t dupes;      // Duplicate or too late
  atomic_uint_fast64_t filled;     // Zero samples fed in place of missing ones
  atomic_uint_fast64_t resyncs;    // Timestamp discontinuities not filled
  atomic_uint_fast64_t overruns;   // Blocks dropped because the decoder fell behind
  atomic_uint_fast64_t unusable;   // Packets of unknown or unsupported format

  // Call following: the decode thread sets site once trunking blocks decode here; from then on
  // the input thread keeps the site's command handle and channel format up to date from this status
  _Atomic(struct site *) site;
};

// A call the trunking logic reported, as p25d acts on it
struct fcall {
  bool used;
  uint32_t id;               // the trunking logic's call_id
  enum p25_trunk_call_type type;
  uint16_t talkgroup;
  uint32_t source;
  uint32_t target;
  uint64_t freq_hz;
  int slot;
  uint32_t flags;            // P25_TRUNK_F_* as last reported
  bool requested;            // its channel was asked for and not released
  bool refused;              // radiod refused its channel
  uint32_t ssrc;             // of its voice channel, when requested
  bool seed;                 // the control channel's carrier offset, for the voice channel's receiver
  float seed_hz;
  int64_t start;
  char alias[P25_ALIAS_MAX];
  int units;                 // voice units received for it, link control and encryption sync words that
  int words_bad;             // failed, and bits corrected in the voice frames
  int bits_fixed;
  int release;               // for the voice channel's thread: held units released, 1 clear, 2 not clear
};

// One per control channel: its trunking logic and the calls followed from it
// Lock order: Sites_mutex, then a site's lock, then Ctl_mutex. Output_mutex is taken alone
struct site {
  struct site *next;         // in Sites (Sites_mutex)
  struct sockaddr_storage sender; // the control channel: radiod's address and the SSRC (fixed)
  uint32_t ssrc;

  pthread_mutex_t lock;      // everything from here to 'ctl'
  struct p25_trunk *trunk;   // NULL while the control channel is not being received
  double freq;               // control channel, Hz, and the NAC it last decoded with
  uint16_t nac;
  int64_t now;               // last time given to the trunking logic: it must not go back
  struct fcall calls[P25_TRUNK_MAX_CALLS];
  uint64_t refused[MAX_REFUSED];
  int nrefused;
  struct p25_trunk_event events[MAX_EVENTS]; // reported by the trunking logic, not yet acted on
  int nevents;
  uint64_t lost_events;

  // Under Ctl_mutex: radiod's command handle and the control channel's format, from its status
  struct chanctl *ctl;
  struct chanctl_format format;
  bool have_format;
};

// What a thread does once it has let go of a site's lock
enum work_kind { WORK_LOG, WORK_REQUEST, WORK_RELEASE, WORK_REFRESH };
struct work {
  enum work_kind kind;
  int64_t when;              // WORK_LOG: time of the event
  uint32_t ssrc;
  uint64_t freq_hz;
  uint32_t call_id;
  char text[400];
};

// Command line params
const char *App_path;
int Verbose;
static char const *Locale;
static char const *Input[MAX_MCAST];  // Input group names
static int Ninputs;
static char const *Source;            // Source specific multicast, if used
static struct sockaddr_storage *Source_socket; // Remains NULL if Source == NULL
static uint32_t Ssrc;                 // Decode only this SSRC, when specified
static int64_t Timeout = 20;          // Seconds without data before a channel is closed
static int Update = 10;               // Seconds of stream between -v status lines
static char const *Output;            // Voice output group (--pcm-out), NULL for none
static char const *Frames_output;     // Vocoder frame output group (--frames-out), NULL for none
static bool Frames_encrypted;         // Also send the frames of encrypted voice units (--frames-encrypted)
static char const *Name = "p25d";     // Service name it is advertised under
static int Mcast_ttl = DEFAULT_TTL;   // of the voice output
static int IP_tos = DEFAULT_IP_TOS;
static bool Follow = true;            // Ask radiod for the voice channels of calls granted on a control channel
static bool Follow_encrypted;         // Including encrypted calls (logged, never heard)
static int Max_calls;                 // Most calls followed at once, 0 = no limit
static uint16_t Allow[MAX_TALKGROUPS],Deny[MAX_TALKGROUPS]; // Talkgroups to follow (none: all) and not to follow
static int Nallow,Ndeny;

// Tuning constants
static double const Max_fill = 1.0;   // Fill gaps up to this many seconds with zeroes; resynchronize on longer ones
static double const Max_queue = 5.0;  // Seconds of samples queued to a decoder before blocks are dropped
// A voice channel asked for goes away this long after the last request or refresh: a little over
// the time after which the trunking logic ends a call it hears nothing of, so a lost release can't
// leave it behind for long
static double const Lifetime = P25_TRUNK_CALL_TIMEOUT * 1e-9 + 2;
static int const Ctl_ttl = 1;         // Commands to radiod, as tune and control send them

// Global variables
static int Data_fd[MAX_MCAST];
static int Status_fd[MAX_MCAST];
static struct session *Sessions;
static pthread_mutex_t Output_mutex = PTHREAD_MUTEX_INITIALIZER; // One line at a time on stdout
static volatile sig_atomic_t Terminate;
static volatile sig_atomic_t Signal;
static struct p25_audio_group *Audio_group;
static struct p25_audio_group *Frames_group;
static pthread_mutex_t Sites_mutex = PTHREAD_MUTEX_INITIALIZER; // the Sites list
static struct site *Sites;            // Never freed before exit, so a decode thread can keep a pointer
static pthread_mutex_t Ctl_mutex = PTHREAD_MUTEX_INITIALIZER;   // Radios[], every chanctl call, site ctl/format
static struct chanctl *Radios[MAX_RADIOS];
static struct sockaddr_storage Radio_addr[MAX_RADIOS];
static int Nradios;

static void closedown(int);
static void verbosity(int);
static void input_loop(void);
static void process_status(int fd);
static void process_data(int fd);
static void scan_sessions(int64_t now);
static void cleanup(void);
static struct session *lookup_session(struct sockaddr_storage const *sender,uint32_t ssrc);
static struct session *create_session(struct sockaddr_storage const *sender,uint32_t ssrc);
static void close_session(struct session *sp,char const *reason);
static int start_decoder(struct session *sp);
static void receive_packet(struct session *sp,struct rtp_header const *rtp,uint8_t const *data,int frames,enum encoding encoding);
static void send_queue(struct session *sp,bool flush);
static struct block *new_block(struct session const *sp,int count,uint32_t timestamp);
static void enqueue_block(struct session *sp,struct block *bp);
static void *decode_task(void *arg);
static int sample_size(enum encoding encoding);
static int convert_iq(float complex *out,uint8_t const *in,int frames,enum encoding encoding);
static int64_t session_time(struct session const *sp,uint32_t timestamp);
static int calculate_deadline(struct timespec *deadline,int64_t timeout);
static void log_event(uint32_t ssrc,double frequency,int64_t when,char const *fmt,va_list ap);
static void session_event(struct session const *sp,int64_t when,char const *fmt,...) __attribute__((format(printf,3,4)));
static void decoder_event(struct decoder const *dp,uint64_t sample,char const *fmt,...) __attribute__((format(printf,3,4)));
static void decoder_dump(struct decoder const *dp,uint64_t sample,char const *label,uint8_t const *data,size_t len) __attribute__((unused));
static void status_line(struct decoder const *dp);
static void decoder_frame(void *arg,struct p25_frame const *frame);
static int64_t decoder_time(struct decoder const *dp,uint64_t sample);
static void observe_status(struct session *sp);
static struct site *get_site(struct session const *sp);
static void site_unlock(struct site *site,struct decoder *dp,int nwork);
static void log_line(uint32_t ssrc,double frequency,int64_t when,char const *fmt,...) __attribute__((format(printf,4,5)));
static void control_message(struct decoder *dp,uint64_t sample,struct p25_msg const *msg);
static void control_block(struct decoder *dp);
static void control_lost(struct decoder *dp);
static void voice_unit(struct decoder *dp,uint64_t sample,struct p25_frame const *frame);
static void link_voice(struct decoder *dp);
static void conv_unit(struct decoder *dp,uint64_t sample,struct p25_frame const *frame);
static void conv_end(struct decoder *dp,uint64_t sample,char const *how);
static void block_done(struct decoder *dp,int count);
static int parse_talkgroups(uint16_t *list,int n,char const *arg);

static struct option Options[] = {
  {"iface", required_argument, NULL, 'A'},
  {"input", required_argument, NULL, 'I'},
  {"encrypted", no_argument, NULL, 'e'},
  {"frames-encrypted", no_argument, NULL, 'E'},
  {"frames-out", required_argument, NULL, 'F'},
  {"talkgroups", required_argument, NULL, 'g'},
  {"locale", required_argument, NULL, 'l'},
  {"max-calls", required_argument, NULL, 'm'},
  {"name", required_argument, NULL, 'N'},
  {"no-follow", no_argument, NULL, 'n'},
  {"source", required_argument, NULL, 'o'},
  {"tos", required_argument, NULL, 'p'},
  {"pcm-out", required_argument, NULL, 'R'},
  {"ssrc", required_argument, NULL, 'S'},
  {"timeout", required_argument, NULL, 't'},
  {"ttl", required_argument, NULL, 'T'},
  {"update", required_argument, NULL, 'u'},
  {"exclude", required_argument, NULL, 'x'},
  {"verbose", no_argument, NULL, 'v'},
  {"version", no_argument, NULL, 'V'},
  {NULL, 0, NULL, 0},
};
static char const Optstring[] = "A:eEF:g:I:l:m:nN:o:p:R:S:t:T:u:vVx:";

static void usage(void){
  fprintf(stderr,"Usage: %s [-v|--verbose] [-V|--version] [-l|--locale locale] [-A|--iface interface] [-o|--source <source-name-or-address>] [-S|--ssrc ssrc] [-t|--timeout seconds] [-u|--update seconds] [-R|--pcm-out audio_mcast_address] [-F|--frames-out frames_mcast_address] [-E|--frames-encrypted] [-N|--name service_name] [-T|--ttl ttl] [-p|--tos tos] [-n|--no-follow] [-g|--talkgroups list] [-x|--exclude list] [-m|--max-calls n] [-e|--encrypted] [-I|--input] iq_mcast_address [iq_mcast_address ...]\n",App_path);
}

int main(int argc,char *argv[]){
  App_path = argv[0];

  // Defaults
  Locale = getenv("LANG");

  int c;
  while((c = getopt_long(argc,argv,Optstring,Options,NULL)) != EOF){
    switch(c){
    case 'A':
      Default_mcast_iface = optarg;
      break;
    case 'I':
      if(Ninputs == MAX_MCAST){
	fprintf(stderr,"Too many multicast addresses; max %d\n",MAX_MCAST);
	break;
      }
      Input[Ninputs++] = optarg;
      break;
    case 'e':
      Follow_encrypted = true;
      break;
    case 'E':
      Frames_encrypted = true;
      break;
    case 'F':
      Frames_output = optarg;
      break;
    case 'g':
      Nallow = parse_talkgroups(Allow,Nallow,optarg);
      break;
    case 'l':
      Locale = optarg;
      break;
    case 'm':
      Max_calls = atoi(optarg);
      break;
    case 'n':
      Follow = false;
      break;
    case 'N':
      Name = optarg;
      break;
    case 'o':
      Source = optarg;
      break;
    case 'p':
      IP_tos = (int)strtol(optarg,NULL,0);
      break;
    case 'R':
      Output = optarg;
      break;
    case 'T':
      Mcast_ttl = (int)strtol(optarg,NULL,0);
      break;
    case 'x':
      Ndeny = parse_talkgroups(Deny,Ndeny,optarg);
      break;
    case 'S':
      {
	char *ptr = NULL;
	long long const x = strtoll(optarg,&ptr,0);
	if(ptr != optarg)
	  Ssrc = (uint32_t)x;
      }
      break;
    case 't':
      {
	char *ptr = NULL;
	long long const x = strtoll(optarg,&ptr,0);
	if(ptr != optarg && x > 0)
	  Timeout = x;
      }
      break;
    case 'u':
      Update = atoi(optarg);
      break;
    case 'v':
      Verbose++;
      break;
    case 'V':
      VERSION();
      exit(EX_OK);
    default:
      usage();
      exit(EX_USAGE);
    }
  }
  setlocale(LC_ALL,Locale);
  setlinebuf(stdout); // Event log, usually appended to a file
  setlinebuf(stderr);

  // Also accept groups without -I option
  for(int i=optind; i < argc; i++){
    if(Ninputs == MAX_MCAST){
      fprintf(stderr,"Too many multicast addresses; max %d\n",MAX_MCAST);
      break;
    }
    Input[Ninputs++] = argv[i];
  }
  if(Ninputs == 0){
    fprintf(stderr,"Specify at least one I/Q multicast group\n");
    usage();
    exit(EX_USAGE);
  }
  if(Ssrc != 0 && Follow){
    // The voice channels it would ask for would be ignored
    fprintf(stderr,"%s: --ssrc given, not following calls\n",App_path);
    Follow = false;
  }
  if(p25_vocoder_name(P25_CODEC_IMBE) == NULL)
    fprintf(stderr,"%s: built without a vocoder (mbelib): no voice output%s\n",App_path,
	    Frames_output != NULL ? " (vocoder frames are sent)" : "");
  if(Frames_encrypted && Frames_output == NULL)
    fprintf(stderr,"%s: --frames-encrypted has no effect without --frames-out\n",App_path);
  if(Source != NULL){
    Source_socket = calloc(1,sizeof(struct sockaddr_storage));
    assert(Source_socket != NULL);
    resolve_mcast(Source,Source_socket,0,NULL,0,0);
  }
  // Data and status for each group: same name, different ports
  // resolve_mcast() keeps retrying until the name resolves, so starting before avahi is ready is OK
  for(int i=0; i < Ninputs; i++){
    struct sockaddr_storage sock;
    char iface[1024];
    resolve_mcast(Input[i],&sock,DEFAULT_RTP_PORT,iface,sizeof(iface),0);
    Data_fd[i] = listen_mcast(Source_socket,&sock,iface);
    resolve_mcast(Input[i],&sock,DEFAULT_STAT_PORT,iface,sizeof(iface),0);
    Status_fd[i] = listen_mcast(Source_socket,&sock,iface);
    if(Data_fd[i] == -1 || Status_fd[i] == -1){
      fprintf(stderr,"Can't set up input from %s, exiting\n",Input[i]);
      exit(EX_TEMPFAIL); // Let systemd restart us
    }
    int const n = 1 << 20; // 1 MB
    if(setsockopt(Data_fd[i],SOL_SOCKET,SO_RCVBUF,&n,sizeof(n)) == -1)
      perror("setsockopt");
    if(Verbose)
      fprintf(stderr,"%s: listening to %s\n",App_path,Input[i]);
  }
  if(Output != NULL && p25_vocoder_name(P25_CODEC_IMBE) != NULL){
    if((Audio_group = p25_audio_open(Output,Default_mcast_iface,Mcast_ttl,IP_tos,Name)) == NULL)
      exit(EX_TEMPFAIL); // Let systemd restart us
    if(Verbose)
      fprintf(stderr,"%s: voice to %s (%s)\n",App_path,Output,p25_vocoder_name(P25_CODEC_IMBE));
  }
  if(Frames_output != NULL){
    // A service name of its own, so the two streams are told apart when browsing
    char name[256];
    snprintf(name,sizeof name,"%s frames",Name);
    if((Frames_group = p25_frames_open(Frames_output,Default_mcast_iface,Mcast_ttl,IP_tos,name,Frames_encrypted)) == NULL)
      exit(EX_TEMPFAIL); // Let systemd restart us
    if(Verbose)
      fprintf(stderr,"%s: vocoder frames to %s%s\n",App_path,Frames_output,Frames_encrypted ? ", encrypted ones too" : "");
  }
  // Graceful signal catch
  signal(SIGINT,closedown);
  signal(SIGQUIT,closedown);
  signal(SIGTERM,closedown);
  signal(SIGPIPE,SIG_IGN);
  signal(SIGUSR1,verbosity);
  signal(SIGUSR2,verbosity);

  input_loop(); // Returns on a signal
  cleanup();
  p25_audio_close(Audio_group);
  p25_audio_close(Frames_group);
  if(Verbose)
    fprintf(stderr,"%s: caught signal %d: %s\n",App_path,(int)Signal,strsignal(Signal));
  exit((Signal == SIGTERM || Signal == SIGINT) ? EX_OK : EX_SOFTWARE);
}

static void closedown(int a){
  Signal = a;
  Terminate = 1; // input_loop() sees it within a second
}

// Increase or decrease logging level, as in radiod
static void verbosity(int a){
  if(a == SIGUSR1)
    Verbose++;
  else if(a == SIGUSR2)
    Verbose = (Verbose <= 0) ? 0 : Verbose - 1;
}

// Read both data and status in one thread, as pcmrecord does,
// so the session table and RTP state need no locks
static void input_loop(void){
  struct pollfd pfd[2*MAX_MCAST];
  for(int i=0; i < Ninputs; i++){
    pfd[2*i].fd = Data_fd[i];
    pfd[2*i].events = POLLIN;
    pfd[2*i+1].fd = Status_fd[i];
    pfd[2*i+1].events = POLLIN;
  }
  int64_t last_scan = gps_time_ns();
  while(!Terminate){
    int const n = poll(pfd,2*Ninputs,1000); // Wait 1 sec max so we can scan the session list
    if(n < 0){
      if(errno == EINTR)
	continue;
      perror("poll");
      break;
    }
    for(int i=0; i < Ninputs; i++){
      if(pfd[2*i+1].revents & (POLLIN|POLLPRI))
	process_status(Status_fd[i]);
      if(pfd[2*i].revents & (POLLIN|POLLPRI))
	process_data(Data_fd[i]);
    }
    int64_t const now = gps_time_ns();
    if(now >= last_scan + BILLION){
      scan_sessions(now);
      last_scan = now;
    }
  }
}

// Channel status from radiod: sample rate, channels, encoding, frequency, and the clock reference for RTP timestamps
static void process_status(int fd){
  uint8_t buffer[PKTSIZE];
  struct sockaddr_storage sender;
  socklen_t socksize = sizeof(sender);
  ssize_t const length = recvfrom(fd,buffer,sizeof(buffer),0,(struct sockaddr *)&sender,&socksize);
  if(length < 0){
    if(errno != EINTR)
      perror("recvfrom status");
    return;
  }
  if(length < 3 || buffer[0] != STATUS)
    return; // Ignore commands

  uint32_t const ssrc = get_ssrc(buffer+1,length-1);
  if(ssrc == 0)
    return; // Front end status only
  if(Ssrc != 0 && ssrc != Ssrc)
    return;

  struct session *sp = lookup_session(&sender,ssrc);
  bool const new_session = (sp == NULL);
  if(sp == NULL && (sp = create_session(&sender,ssrc)) == NULL)
    return;

  // Decode directly into the session's copy, since not every parameter is in every status message
  decode_radio_status(&sp->frontend,&sp->chan,buffer+1,length-1);
  sp->frontend.description[sizeof sp->frontend.description - 1] = '\0';
  sp->last_status = gps_time_ns();

  // Cache this sender's payload type for the data path
  int const type = sp->chan.output.rtp.type & 0x7f;
  sp->pt_table[type].encoding = sp->chan.output.encoding;
  sp->pt_table[type].samprate = sp->chan.output.samprate;
  sp->pt_table[type].channels = sp->chan.output.channels;
  if(Follow)
    observe_status(sp);

  if(new_session && Verbose)
    session_event(sp,0,"new channel: %s, %'d Hz, %d channels, %s, %s demod, filter %+.0f to %+.0f Hz, agc %s, from %s",
		  sp->frontend.description,sp->chan.output.samprate,sp->chan.output.channels,
		  encoding_string(sp->chan.output.encoding),demod_name_from_type(sp->chan.demod_type),
		  sp->chan.filter.min_IF,sp->chan.filter.max_IF,sp->chan.linear.agc ? "on" : "off",
		  formatsock(&sender,false));

  if(!sp->warned && (sp->chan.output.channels != 2 || sample_size(sp->chan.output.encoding) == 0)){
    session_event(sp,0,"can't decode: need 2 channels (I/Q) of s16le, s16be, f32le or f32be; stream is %d channels %s",
		  sp->chan.output.channels,encoding_string(sp->chan.output.encoding));
    sp->warned = true;
  }
}

// RTP data. Packets are dropped until the channel's status has arrived, as in pcmrecord:
// radiod's payload types are dynamic so the status is the only way to know the format
static void process_data(int fd){
  uint8_t buffer[PKTSIZE];
  struct sockaddr_storage sender;
  socklen_t socksize = sizeof(sender);
  ssize_t size = recvfrom(fd,buffer,sizeof(buffer),0,(struct sockaddr *)&sender,&socksize);
  if(size < 0){
    if(errno != EINTR)
      perror("recvfrom");
    return;
  }
  if(size < RTP_MIN_SIZE)
    return; // Too small for RTP, ignore

  struct rtp_header rtp;
  uint8_t const * const dp = ntoh_rtp(&rtp,buffer);
  size -= dp - buffer;
  if(size <= 0)
    return; // Bogus RTP header
  if(rtp.pad){
    // Remove padding
    size -= dp[size-1];
    rtp.pad = 0;
  }
  if(size <= 0)
    return;

  if(Ssrc != 0 && rtp.ssrc != Ssrc)
    return;

  struct session * const sp = lookup_session(&sender,rtp.ssrc);
  if(sp == NULL)
    return; // Wait for the status to create it

  sp->last_data = gps_time_ns();
  atomic_fetch_add(&sp->packets,1);

  struct pt_table const * const pt = &sp->pt_table[rtp.type & 0x7f];
  int const sampsize = sample_size(pt->encoding);
  if(pt->channels != 2 || pt->samprate <= 0 || sampsize == 0){
    atomic_fetch_add(&sp->unusable,1);
    return; // Not yet known, or not I/Q
  }
  int const frames = (int)(size / (2 * sampsize));
  if(frames <= 0)
    return;

  if(!sp->running && start_decoder(sp) != 0)
    return;

  if(pt->samprate != sp->samprate){
    // New stream, or the sample rate changed: deliver what's waiting and start over
    if(sp->samprate != 0){
      send_queue(sp,true);
      if(Verbose)
	session_event(sp,0,"sample rate changed from %'d to %'d Hz",sp->samprate,pt->samprate);
    }
    sp->samprate = pt->samprate;
    sp->rtp.init = false;
  }
  receive_packet(sp,&rtp,dp,frames,pt->encoding);
}

// Resequence, then pass samples to the decoder in RTP timestamp order
// Modelled on pcmrecord's process_data() and send_wav_queue()
static void receive_packet(struct session *sp,struct rtp_header const *rtp,uint8_t const *data,int frames,enum encoding encoding){
  if(sp->rtp.odd_seq_set){
    if(rtp->seq == sp->rtp.odd_seq){
      // Sender probably restarted; flush queue and start over
      send_queue(sp,true);
      sp->rtp.init = false;
      atomic_fetch_add(&sp->resyncs,1);
    } else
      sp->rtp.odd_seq_set = false;
  }
  if(!sp->rtp.init){
    sp->rtp.seq = rtp->seq;
    sp->rtp.timestamp = rtp->timestamp;
    sp->rtp.init = true;
    sp->rtp.odd_seq_set = false;
    if(Verbose > 1)
      session_event(sp,0,"init seq %u timestamp %u",rtp->seq,rtp->timestamp);
  }
  int16_t const seqdiff = rtp->seq - sp->rtp.seq;
  if(seqdiff < 0){
    // Old or duplicate; its place has already been taken. But the sender may have restarted, so remember it
    atomic_fetch_add(&sp->dupes,1);
    sp->rtp.odd_seq = rtp->seq + 1;
    sp->rtp.odd_seq_set = true;
    return;
  } else if(seqdiff >= RESEQ){
    // Give up waiting for the lost packet(s), deliver what we have
    send_queue(sp,true);
    int16_t const lost = rtp->seq - sp->rtp.seq;
    if(lost >= RESEQ){
      // Long outage; the timestamp jump decides between filling and resynchronizing
      atomic_fetch_add(&sp->drops,lost);
      sp->rtp.seq = rtp->seq;
    }
  }
  sp->rtp.odd_seq_set = false;
  struct block ** const qp = &sp->reseq[rtp->seq % RESEQ];
  if(*qp != NULL){
    atomic_fetch_add(&sp->dupes,1); // Already have this one
    return;
  }
  struct block * const bp = new_block(sp,frames,rtp->timestamp);
  if(bp == NULL)
    return;
  convert_iq(bp->samples,data,frames,encoding);
  bp->marker = rtp->marker;
  *qp = bp;
  sp->pending++;
  send_queue(sp,false);
}

// If !flush, deliver everything on the resequencing queue up to the first missing packet
// If flush, empty the entire queue, counting the missing packets as drops
// Timestamp gaps up to Max_fill seconds become zeroes so the decoder's symbol timing isn't broken
static void send_queue(struct session *sp,bool flush){
  for(int i=0; i < RESEQ; i++,sp->rtp.seq++){
    struct block ** const qp = &sp->reseq[sp->rtp.seq % RESEQ];
    struct block * const bp = *qp;
    if(bp == NULL){
      if(!flush || sp->pending == 0)
	break; // Stop on first empty entry if we're not resynchronizing, or when the queue is empty
      atomic_fetch_add(&sp->drops,1);
      continue;
    }
    *qp = NULL;
    sp->pending--;
    int32_t const jump = (int32_t)(bp->timestamp - sp->rtp.timestamp);
    if(jump > 0 && !bp->marker){
      // Timestamp jumped: lost packet(s), or the sender paused
      if(jump <= Max_fill * sp->samprate){
	struct block * const zp = new_block(sp,jump,sp->rtp.timestamp);
	if(zp != NULL){
	  memset(zp->samples,0,jump * sizeof(zp->samples[0]));
	  enqueue_block(sp,zp);
	  atomic_fetch_add(&sp->filled,jump);
	}
	if(Verbose > 1)
	  session_event(sp,bp->time,"timestamp jump %'d samples, filled with zeroes",jump);
      } else {
	atomic_fetch_add(&sp->resyncs,1);
	if(Verbose)
	  session_event(sp,bp->time,"timestamp jump %'d samples (%.1f sec), resynchronizing",jump,(double)jump / sp->samprate);
      }
    } else if(jump < 0){
      // Timestamp went backward, probably a sender restart; just carry on from here
      atomic_fetch_add(&sp->resyncs,1);
      if(Verbose > 1)
	session_event(sp,bp->time,"timestamp went back %'d samples",-jump);
    }
    sp->rtp.timestamp = bp->timestamp + bp->count;
    enqueue_block(sp,bp);
  }
}

// Allocate a block for 'count' samples starting at RTP time 'timestamp', filling in what the decoder needs
static struct block *new_block(struct session const *sp,int count,uint32_t timestamp){
  struct block * const bp = malloc(sizeof(*bp) + count * sizeof(bp->samples[0]));
  if(bp == NULL)
    return NULL;
  bp->next = NULL;
  bp->timestamp = timestamp;
  bp->marker = false;
  bp->samprate = sp->samprate;
  bp->frequency = sp->chan.tune.freq;
  bp->time = session_time(sp,timestamp);
  bp->count = count;
  return bp;
}

// Hand a block to the session's decode thread
static void enqueue_block(struct session *sp,struct block *bp){
  bp->next = NULL;
  pthread_mutex_lock(&sp->qmutex);
  if(sp->qsamples + bp->count > Max_queue * sp->samprate){
    // Decoder has fallen far behind; drop rather than grow without limit
    pthread_mutex_unlock(&sp->qmutex);
    atomic_fetch_add(&sp->overruns,1);
    FREE(bp);
    return;
  }
  if(sp->qtail != NULL)
    sp->qtail->next = bp;
  else
    sp->queue = bp;
  sp->qtail = bp;
  sp->qsamples += bp->count;
  pthread_cond_signal(&sp->qcond);
  pthread_mutex_unlock(&sp->qmutex);
}

// Sender's clock time of an RTP timestamp, in ns since the GPS epoch, from the status stream's
// GPS_TIME/RTP_TIMESNAP pair (as pcmrecord computes file start times). 0 if not yet known
static int64_t session_time(struct session const *sp,uint32_t timestamp){
  if(sp->chan.clocktime == 0 || sp->samprate <= 0)
    return 0;
  return sp->chan.clocktime + (int64_t)BILLION * (int32_t)(timestamp - sp->chan.output.time_snap) / sp->samprate;
}

// Walk through session list, close idle ones
// A channel with a decoder is idle when its data stops; one that has only sent status, when that stops
static void scan_sessions(int64_t now){
  struct session *next = NULL;
  for(struct session *sp = Sessions; sp != NULL; sp = next){
    next = sp->next; // save in case sp is closed
    int64_t const last = sp->running ? sp->last_data : sp->last_status;
    if(now - last >= Timeout * BILLION)
      close_session(sp,"idle timeout");
  }
}

// Find existing session, move it to the top of the list to speed later lookups
// Sessions are defined by {ssrc, sender IP address}; status and data come from different source ports
static struct session *lookup_session(struct sockaddr_storage const *sender,uint32_t ssrc){
  struct session *sp;
  for(sp = Sessions; sp != NULL; sp = sp->next){
    if(sp->ssrc == ssrc && address_match(&sp->sender,sender))
      break;
  }
  if(sp != NULL && sp->prev != NULL){
    sp->prev->next = sp->next;
    if(sp->next != NULL)
      sp->next->prev = sp->prev;
    sp->next = Sessions;
    sp->prev = NULL;
    Sessions->prev = sp;
    Sessions = sp;
  }
  return sp;
}

// Create a new session from its first status packet. The decode thread starts with the first data
static struct session *create_session(struct sockaddr_storage const *sender,uint32_t ssrc){
  struct session * const sp = calloc(1,sizeof(*sp));
  if(sp == NULL)
    return NULL; // Unlikely
  sp->ssrc = ssrc;
  memcpy(&sp->sender,sender,sizeof(sp->sender));
  memcpy(sp->pt_table,PT_table,sizeof(sp->pt_table));
  sp->last_status = sp->last_data = gps_time_ns();
  pthread_mutex_init(&sp->qmutex,NULL);
  pthread_cond_init(&sp->qcond,NULL);
  atomic_init(&sp->terminate,false);
  atomic_init(&sp->site,NULL);

  sp->prev = NULL;
  sp->next = Sessions;
  if(sp->next != NULL)
    sp->next->prev = sp;
  Sessions = sp;
  return sp;
}

static int start_decoder(struct session *sp){
  if(pthread_create(&sp->thread,NULL,decode_task,sp) != 0){
    perror("pthread_create");
    return -1;
  }
  sp->running = true;
  return 0;
}

// Stop the decode thread (it finishes what's queued), remove from the list and free
static void close_session(struct session *sp,char const *reason){
  if(sp == NULL)
    return;
  if(sp->running){
    send_queue(sp,true);
    atomic_store(&sp->terminate,true);
    pthread_mutex_lock(&sp->qmutex);
    pthread_cond_broadcast(&sp->qcond);
    pthread_mutex_unlock(&sp->qmutex);
    pthread_join(sp->thread,NULL);
    sp->running = false;
  }
  if(Verbose)
    session_event(sp,0,"closed (%s): packets %'llu drops %'llu dupes %'llu filled %'llu resyncs %'llu overruns %'llu unusable %'llu",
		  reason,
		  (unsigned long long)sp->packets,(unsigned long long)sp->drops,(unsigned long long)sp->dupes,
		  (unsigned long long)sp->filled,(unsigned long long)sp->resyncs,(unsigned long long)sp->overruns,
		  (unsigned long long)sp->unusable);

  if(sp->prev != NULL)
    sp->prev->next = sp->next;
  else
    Sessions = sp->next;
  if(sp->next != NULL)
    sp->next->prev = sp->prev;

  for(int i=0; i < RESEQ; i++)
    FREE(sp->reseq[i]);
  struct block *next = NULL;
  for(struct block *bp = sp->queue; bp != NULL; bp = next){
    next = bp->next;
    FREE(bp);
  }
  pthread_mutex_destroy(&sp->qmutex);
  pthread_cond_destroy(&sp->qcond);
  FREE(sp);
}

static void cleanup(void){
  while(Sessions != NULL)
    close_session(Sessions,"shutdown");
  // Every decode thread has stopped, and each control channel's has let its calls' channels go.
  // chanctl_destroy() releases any that are left
  pthread_mutex_lock(&Ctl_mutex);
  for(int i=0; i < Nradios; i++)
    chanctl_destroy(Radios[i]);
  Nradios = 0;
  pthread_mutex_unlock(&Ctl_mutex);
  pthread_mutex_lock(&Sites_mutex);
  while(Sites != NULL){
    struct site *site = Sites;
    Sites = site->next;
    delete_p25_trunk(site->trunk);
    pthread_mutex_destroy(&site->lock);
    FREE(site);
  }
  pthread_mutex_unlock(&Sites_mutex);
}

// One per channel: take blocks off the queue and run the receiver over them
static void *decode_task(void *arg){
  struct session * const sp = (struct session *)arg;
  assert(sp != NULL);
  {
    char name[100];
    snprintf(name,sizeof(name),"p25 %u",sp->ssrc);
    pthread_setname(name);
  }
  struct decoder dec = {
    .sp = sp,
  };
  if(Follow && (dec.work = calloc(MAX_WORK,sizeof *dec.work)) == NULL){
    fprintf(stderr,"ssrc %u: out of memory\n",sp->ssrc);
    return NULL;
  }
  dec.audio = p25_audio_create(Audio_group,Frames_group,sp->ssrc); // NULL without --pcm-out or --frames-out
  p25_alias_init(&dec.alias);
  while(true){
    pthread_mutex_lock(&sp->qmutex);
    while(sp->queue == NULL && !atomic_load(&sp->terminate)){
      struct timespec deadline;
      calculate_deadline(&deadline,BILLION); // 1 second backstop
      pthread_cond_timedwait(&sp->qcond,&sp->qmutex,&deadline);
    }
    struct block *bp = sp->queue;
    if(bp != NULL){
      sp->queue = bp->next;
      if(sp->queue == NULL)
	sp->qtail = NULL;
      sp->qsamples -= bp->count;
    }
    pthread_mutex_unlock(&sp->qmutex);
    if(bp == NULL)
      break; // Told to terminate, and nothing left

    dec.frequency = bp->frequency;
    if(Follow && !dec.voice && !dec.control)
      link_voice(&dec); // before the receiver is created, so it can be seeded
    if(bp->samprate != dec.samprate){
      // First block, or the sample rate changed
      p25_audio_call_end(dec.audio);
      if(dec.p25 != NULL)
	delete_p25p1(dec.p25);
      dec.samprate = bp->samprate;
      dec.samples = 0;
      dec.next_report = (uint64_t)(Update * dec.samprate);
      dec.p25 = create_p25p1(dec.samprate);
      if(dec.p25 == NULL)
	fprintf(stderr,"ssrc %u: can't create P25 receiver at %'.0lf Hz (needs at least %d Hz)\n",
		sp->ssrc,dec.samprate,4 * P25_SYMRATE);
      else {
	p25p1_set_frame_handler(dec.p25,decoder_frame,&dec);
	// A voice channel granted on a control channel is sent from the same site, so its carrier
	// is off by about what the control channel's is
	if(dec.voice && dec.seed)
	  p25p1_seed_frequency(dec.p25,dec.seed_hz);
      }
      p25_bandplan_init(&dec.plan);
    }
    dec.frequency = bp->frequency;
    dec.block_time = bp->time;
    dec.block_start = dec.samples;
    if(dec.p25 != NULL){
      p25p1_samples(dec.p25,bp->samples,bp->count); // decoder_frame() runs in here
    }
    block_done(&dec,bp->count);
    if(dec.control)
      control_block(&dec);
    dec.samples += bp->count;
    FREE(bp);
    if(Verbose && Update > 0 && dec.samples >= dec.next_report){
      status_line(&dec);
      dec.next_report += (uint64_t)(Update * dec.samprate);
    }
  }
  if(dec.control)
    control_lost(&dec);
  if(dec.conv.active)
    conv_end(&dec,dec.conv.last,Terminate ? "p25d shutting down" : "channel closed");
  p25_audio_destroy(dec.audio);
  FREE(dec.work);
  if(dec.p25 != NULL)
    delete_p25p1(dec.p25);
  return NULL;
}

// After each block: the voice output's clock, and the end of a conventional transmission that
// stopped without a terminator (the next voice unit overdue by half a second, as p25audio decides)
static void block_done(struct decoder *dp,int count){
  p25_audio_poll(dp->audio,dp->frequency,decoder_time(dp,dp->block_start + count));
  if(dp->conv.active && dp->samples + count - dp->conv.last > (uint64_t)((0.18 + 0.5) * dp->samprate))
    conv_end(dp,dp->conv.last,"timeout");
}

// Log one decoded message for a channel, with the band plan's frequencies where it names channels
static void log_message(struct decoder *dp,uint64_t sample,struct p25_frame const *frame,struct p25_msg *msg,char const *note){
  p25_bandplan_update(&dp->plan,msg);
  char text[512];
  p25_format(text,sizeof(text),msg,&dp->plan);
  decoder_event(dp,sample,"NAC %03x %s%s",frame->nac,text,note);
}
// The end of a transmission: a terminator, or the channel going quiet
static void end_of_voice(struct decoder *dp,uint64_t sample,struct p25_frame const *frame,char const *what){
  if(dp->voice_units > 0)
    decoder_event(dp,sample,"NAC %03x %s after %d voice units (%.1f s), %d bits corrected",frame->nac,what,
		  dp->voice_units,0.18 * dp->voice_units,dp->voice_errors);
  else if(Verbose)
    decoder_event(dp,sample,"NAC %03x %s",frame->nac,what);
  dp->voice_units = dp->voice_errors = 0;
  memset(dp->recent_lc,0,sizeof(dp->recent_lc)); // the next transmission's are logged afresh
  dp->have_es = false;
}
// Has this link control word been logged within the last couple of seconds? If not, note it
static bool lc_seen(struct decoder *dp,uint64_t sample,uint8_t const lc[9]){
  uint64_t const hold = (uint64_t)(2 * dp->samprate);
  int slot = 0;
  for(int i=0; i < 8; i++){
    if(dp->recent_lc[i].used && memcmp(dp->recent_lc[i].lc,lc,9) == 0){
      if(sample - dp->recent_lc[i].sample < hold)
	return true;
      dp->recent_lc[i].sample = sample;
      return false;
    }
    if(!dp->recent_lc[i].used || dp->recent_lc[i].sample < dp->recent_lc[slot].sample)
      slot = dp->recent_lc[i].used && dp->recent_lc[slot].used ? i : (!dp->recent_lc[i].used ? i : slot);
  }
  memcpy(dp->recent_lc[slot].lc,lc,9);
  dp->recent_lc[slot].sample = sample;
  dp->recent_lc[slot].used = true;
  return false;
}
// One data unit from the receiver, in the decode thread
// Trunking messages, link control, encryption sync and the ends of transmissions are the
// program's output and are always logged, decoded to text; link control and encryption sync
// once per change, since they repeat through a transmission.
// -v adds every data unit as it arrives; -vv adds blocks and words that failed their checks
static void decoder_frame(void *arg,struct p25_frame const *frame){
  struct decoder * const dp = (struct decoder *)arg;
  uint64_t const sample = dp->block_start; // to the block; a block is one RTP packet
  if(dp->voice)
    voice_unit(dp,sample,frame); // the trunking logic, then the voice output under its labels
  else
    p25_audio_frame(dp->audio,frame,decoder_time(dp,sample)); // voice output on this module's own rule
  if(!dp->voice && !dp->control)
    conv_unit(dp,sample,frame);
  struct p25_msg msg;
  switch(frame->duid){
  case P25_DUID_TSDU:
    {
      if(frame->crc < 0){
	if(Verbose > 1)
	  decoder_event(dp,sample,"NAC %03x TSBK block %d failed CRC, sync %.1f",frame->nac,frame->block,frame->correlation);
	break;
      }
      uint8_t tsbk[12];
      p25_pack_bits(tsbk,frame->bits,96);
      if(p25_decode_tsbk(&msg,tsbk) == 0){
	log_message(dp,sample,frame,&msg,frame->crc == 1 ? " (1 bit corrected)" : "");
	if(Follow && !dp->voice){
	  dp->site_nac = frame->nac;
	  control_message(dp,sample,&msg);
	}
      }
    }
    break;
  case P25_DUID_HDU:
    if(frame->word != NULL && frame->word->ok){
      uint8_t hdu[15];
      p25_pack_bits(hdu,frame->word->bits,120);
      if(p25_decode_hdu(&msg,hdu) == 0)
	log_message(dp,sample,frame,&msg,"");
    } else if(Verbose > 1)
      decoder_event(dp,sample,"NAC %03x HDU not decoded, sync %.1f",frame->nac,frame->correlation);
    break;
  case P25_DUID_LDU1:
  case P25_DUID_LDU2:
    {
      struct p25_ldu const * const ldu = frame->ldu;
      if(ldu == NULL)
	break;
      int errors = 0;
      for(int i=0; i < P25_IMBE_FRAMES; i++)
	errors += ldu->voice[i].total;
      dp->voice_units++;
      dp->voice_errors += errors;
      if(ldu->word.ok && frame->duid == P25_DUID_LDU1){
	uint8_t lc[9];
	p25_pack_bits(lc,ldu->word.bits,72);
	if(!lc_seen(dp,sample,lc) && p25_decode_lc(&msg,lc,false) == 0)
	  log_message(dp,sample,frame,&msg,"");
      } else if(ldu->word.ok){
	uint8_t es[12];
	p25_pack_bits(es,ldu->word.bits,96);
	if(!dp->have_es || memcmp(es,dp->last_es,sizeof(es)) != 0){
	  // The message indicator changes every superframe of an encrypted call; log the first
	  // and any change of algorithm or key, which are the last three octets
	  bool const same_key = dp->have_es && memcmp(es + 9,dp->last_es + 9,3) == 0;
	  memcpy(dp->last_es,es,sizeof(es));
	  dp->have_es = true;
	  if(!same_key && p25_decode_es(&msg,es) == 0)
	    log_message(dp,sample,frame,&msg,"");
	}
      }
      if(Verbose)
	decoder_event(dp,sample,"NAC %03x LDU%d %s, %d voice bits corrected, sync %.1f",frame->nac,
		      frame->duid == P25_DUID_LDU1 ? 1 : 2,
		      ldu->word.ok ? "ok" : (frame->duid == P25_DUID_LDU1 ? "link control not decoded" : "encryption sync not decoded"),
		      errors,frame->correlation);
    }
    break;
  case P25_DUID_TDU:
    end_of_voice(dp,sample,frame,"TDU");
    break;
  case P25_DUID_TDULC:
    if(frame->word != NULL && frame->word->ok){
      uint8_t lc[9];
      p25_pack_bits(lc,frame->word->bits,72);
      if(p25_decode_lc(&msg,lc,true) == 0)
	log_message(dp,sample,frame,&msg,"");
    } else if(Verbose > 1)
      decoder_event(dp,sample,"NAC %03x TDULC link control not decoded",frame->nac);
    end_of_voice(dp,sample,frame,"TDULC");
    break;
  case P25_DUID_PDU:
    if(frame->pdu != NULL){
      uint8_t octets[(P25_PDU_MAX_BITS + 7) / 8];
      p25_pack_bits(octets,frame->pdu->payload,frame->pdu->nbits);
      if(p25_decode_pdu(&msg,octets,frame->pdu->nbits / 8) == 0){
	log_message(dp,sample,frame,&msg,"");
	if(Follow && !dp->voice && msg.family == P25_FAMILY_MBT){
	  dp->site_nac = frame->nac;
	  control_message(dp,sample,&msg); // multi-block trunking: grants among them
	}
      }
    } else if(Verbose > 1)
      decoder_event(dp,sample,"NAC %03x PDU header failed CRC, sync %.1f",frame->nac,frame->correlation);
    break;
  default:
    if(Verbose > 1)
      decoder_event(dp,sample,"NAC %03x data unit %d, %d bits",frame->nac,frame->duid,frame->nbits);
    break;
  }
}

// Periodic -v line for one channel: frequency (in the event header), receiver state, stream counters
static void status_line(struct decoder const *dp){
  struct session const * const sp = dp->sp;
  struct p25p1_stats st = {0};
  if(dp->p25 != NULL)
    p25p1_get_stats(dp->p25,&st);
  decoder_event(dp,dp->samples,"status: %s, offset %+.1f Hz, filter %s, syncs %'llu weak %'llu, TSBK %'llu bad %'llu, LDU %'llu, words bad %'llu, %'.0lf Hz, packets %'llu drops %'llu dupes %'llu filled %'llu resyncs %'llu overruns %'llu",
		st.locked ? "locked" : "searching",st.frequency_offset,
		st.rxfilter == P25_FILTER_GENTLE ? "gentle" : "sharp",
		(unsigned long long)st.syncs,(unsigned long long)st.weak_syncs,
		(unsigned long long)(st.tsbk_ok + st.tsbk_fixed),(unsigned long long)st.tsbk_bad,
		(unsigned long long)(st.ldu1 + st.ldu2),(unsigned long long)st.word_bad,
		dp->samprate,
		(unsigned long long)atomic_load(&sp->packets),(unsigned long long)atomic_load(&sp->drops),
		(unsigned long long)atomic_load(&sp->dupes),(unsigned long long)atomic_load(&sp->filled),
		(unsigned long long)atomic_load(&sp->resyncs),(unsigned long long)atomic_load(&sp->overruns));
}

// ---------------------------------------------------------------------------
// Call following
//
// Threads: the input thread sees every status packet and keeps one chanctl handle per radiod
// (Ctl_mutex). Each control channel's decode thread owns a site: its trunking logic, fed every
// trunking message and ticked once per block. The decode thread of a voice channel p25d asked for
// feeds the same logic its link control, encryption sync and data units, and gets back the label
// that says what to do with each voice unit. The trunking logic reports what happened through
// trunk_event(), which only copies the event: whoever called into the logic acts on the events
// (bookkeeping under the site's lock, then log lines and commands to radiod after letting it go),
// so no lock is held while writing the log or sending, and the site lock is never taken while
// holding Ctl_mutex.

// Find or create the chanctl handle for the radiod that sent this status, and show it the status.
// For a control channel, also keep its site's handle and channel format current. Input thread
static void observe_status(struct session *sp){
  struct sockaddr_storage const *radio = &sp->frontend.metadata_dest_socket;
  if(radio->ss_family != AF_INET && radio->ss_family != AF_INET6)
    return; // radiod's command address isn't known (yet)
  pthread_mutex_lock(&Ctl_mutex);
  struct chanctl *ctl = NULL;
  for(int i=0; i < Nradios; i++){
    if(address_match(&Radio_addr[i],radio) == 1 && getportnumber(&Radio_addr[i]) == getportnumber(radio)){
      ctl = Radios[i];
      break;
    }
  }
  if(ctl == NULL && Nradios < MAX_RADIOS){
    ctl = chanctl_create(radio,Default_mcast_iface,Ctl_ttl);
    if(ctl == NULL)
      fprintf(stderr,"%s: can't open radiod command channel %s: %s\n",App_path,formatsock(radio,false),strerror(errno));
    else {
      Radio_addr[Nradios] = *radio;
      Radios[Nradios++] = ctl;
      if(Verbose)
	fprintf(stderr,"%s: radiod commands to %s\n",App_path,formatsock(radio,false));
    }
  }
  if(ctl != NULL){
    chanctl_observe(ctl,&sp->frontend,&sp->chan);
    struct site * const site = atomic_load(&sp->site);
    if(site != NULL){
      site->ctl = ctl;
      site->have_format = chanctl_format(&site->format,&sp->frontend,&sp->chan) == 0;
    }
  }
  pthread_mutex_unlock(&Ctl_mutex);
}

// The trunking logic's handler: it runs inside a p25_trunk_*() call, under the site's lock.
// Keep the event for site_unlock()
static void trunk_event(void *arg,struct p25_trunk_event const *event){
  struct site * const site = arg;
  if(site->nevents < MAX_EVENTS)
    site->events[site->nevents++] = *event;
  else
    site->lost_events++;
}

// The site of a control channel, created the first time trunking blocks decode on it, or found
// again if the channel comes back
static struct site *get_site(struct session const *sp){
  pthread_mutex_lock(&Sites_mutex);
  struct site *site;
  for(site = Sites; site != NULL; site = site->next)
    if(site->ssrc == sp->ssrc && address_match(&site->sender,&sp->sender) == 1)
      break;
  if(site == NULL && (site = calloc(1,sizeof *site)) != NULL){
    site->sender = sp->sender;
    site->ssrc = sp->ssrc;
    pthread_mutex_init(&site->lock,NULL);
    site->next = Sites;
    Sites = site;
  }
  pthread_mutex_unlock(&Sites_mutex);
  return site;
}

// Make sure the site has trunking logic. Under its lock
static struct p25_trunk *site_trunk(struct site *site){
  if(site->trunk == NULL){
    // Policy as the options set it. The limit on calls followed at once is applied here rather
    // than in the trunking logic, which would count calls p25d can't receive (Phase 2, refused)
    struct p25_trunk_config const config = {
      .follow_encrypted = Follow_encrypted,
      .allow = Nallow > 0 ? Allow : NULL,
      .nallow = Nallow,
      .deny = Ndeny > 0 ? Deny : NULL,
      .ndeny = Ndeny,
    };
    site->trunk = create_p25_trunk(&config,trunk_event,site);
  }
  return site->trunk;
}

// A time for the trunking logic: the sender's time of the sample, never going back (the
// control and voice threads each run a little behind the stream, by different amounts)
static int64_t site_time(struct site *site,int64_t when){
  if(when == 0)
    when = gps_time_ns();
  if(when < site->now)
    when = site->now;
  site->now = when;
  return when;
}

static struct fcall *find_call(struct site *site,uint32_t id){
  if(id == 0)
    return NULL;
  for(int i=0; i < P25_TRUNK_MAX_CALLS; i++)
    if(site->calls[i].used && site->calls[i].id == id)
      return &site->calls[i];
  return NULL;
}
// The call on a voice channel's frequency
static struct fcall *find_call_freq(struct site *site,uint64_t freq_hz){
  for(int i=0; i < P25_TRUNK_MAX_CALLS; i++)
    if(site->calls[i].used && site->calls[i].freq_hz == freq_hz && site->calls[i].slot < 0)
      return &site->calls[i];
  return NULL;
}
static bool was_refused(struct site const *site,uint64_t freq_hz){
  for(int i=0; i < site->nrefused; i++)
    if(site->refused[i] == freq_hz)
      return true;
  return false;
}
static int requested_count(struct site const *site){
  int n = 0;
  for(int i=0; i < P25_TRUNK_MAX_CALLS; i++)
    n += site->calls[i].used && site->calls[i].requested;
  return n;
}

static struct work *add_work(struct decoder *dp,int *nwork,enum work_kind kind){
  if(*nwork >= MAX_WORK)
    return NULL;
  struct work * const w = &dp->work[(*nwork)++];
  memset(w,0,sizeof *w);
  w->kind = kind;
  return w;
}
static void add_log(struct decoder *dp,int *nwork,int64_t when,char const *fmt,...) __attribute__((format(printf,4,5)));
static void add_log(struct decoder *dp,int *nwork,int64_t when,char const *fmt,...){
  struct work * const w = add_work(dp,nwork,WORK_LOG);
  if(w == NULL)
    return;
  w->when = when;
  va_list ap;
  va_start(ap,fmt);
  vsnprintf(w->text,sizeof w->text,fmt,ap);
  va_end(ap);
}

// Which receiver a voice channel needs, from the call's flags. The one place to add Phase 2:
// a TDMA receiver would be chosen here and created by the voice channel's decode thread
enum receiver { RX_NONE, RX_PHASE1 };
static enum receiver choose_receiver(uint32_t flags,char const **why){
  if(flags & P25_TRUNK_F_TDMA){
    *why = "Phase 2 (TDMA), no receiver for it yet";
    return RX_NONE;
  }
  *why = NULL;
  return RX_PHASE1;
}

// The call's identity for a log line: "group tg 2501 src 1118028" and the like
static int call_text(char *buf,size_t size,struct fcall const *fc){
  int n;
  if(fc->type == P25_TRUNK_GROUP || (fc->type == P25_TRUNK_DATA && fc->talkgroup != 0))
    n = snprintf(buf,size,"%s tg %u src %u",fc->type == P25_TRUNK_DATA ? "data" : "group",fc->talkgroup,fc->source);
  else
    n = snprintf(buf,size,"%s tgt %u src %u",fc->type == P25_TRUNK_UNIT ? "unit" : fc->type == P25_TRUNK_TELEPHONE ? "telephone" : "data",
		 fc->target,fc->source);
  if(strlen(fc->alias) > 0 && n >= 0 && (size_t)n < size)
    n += snprintf(buf + n,size - n," alias \"%s\"",fc->alias);
  if(n >= 0 && (size_t)n < size){
    if(fc->slot >= 0)
      n += snprintf(buf + n,size - n," voice %.6lf MHz slot %d",fc->freq_hz * 1e-6,fc->slot);
    else if(fc->freq_hz != 0)
      n += snprintf(buf + n,size - n," voice %.6lf MHz",fc->freq_hz * 1e-6);
    else
      n += snprintf(buf + n,size - n," voice channel %s","unknown");
  }
  return n;
}
static char const *flag_text(uint32_t flags,char *buf,size_t size){
  snprintf(buf,size,"%s%s%s",flags & P25_TRUNK_F_EMERGENCY ? " emergency" : "",
	   flags & P25_TRUNK_F_ENCRYPTED ? " encrypted" : "",flags & P25_TRUNK_F_PATCHED ? " patched" : "");
  return buf;
}

// Ask for a call's channel. Under the site's lock (Ctl_mutex nests inside it)
static bool want_channel(struct site *site,struct fcall *fc,char const **why){
  if(fc->freq_hz == 0){
    *why = "channel not in the band plan";
    return false;
  }
  if(choose_receiver(fc->flags,why) == RX_NONE)
    return false;
  if(was_refused(site,fc->freq_hz)){
    *why = "radiod refused this frequency";
    fc->refused = true;
    return false;
  }
  if(Max_calls > 0 && requested_count(site) >= Max_calls){
    *why = "already following the most calls allowed (--max-calls)";
    return false;
  }
  pthread_mutex_lock(&Ctl_mutex);
  uint32_t ssrc = 0;
  if(site->ctl != NULL && site->have_format)
    ssrc = chanctl_ssrc(site->ctl,(double)fc->freq_hz,&site->format);
  pthread_mutex_unlock(&Ctl_mutex);
  if(ssrc == 0){
    *why = "radiod's command address or the control channel's format not known yet";
    return false;
  }
  fc->ssrc = ssrc;
  fc->requested = true;
  *why = NULL;
  return true; // the caller logs the call, then asks (ask_channel())
}

// Ask radiod for the call's channel (again: chanctl sends only when needed)
static void ask_channel(struct decoder *dp,int *nwork,struct fcall const *fc){
  struct work * const w = add_work(dp,nwork,WORK_REQUEST);
  if(w != NULL){
    w->ssrc = fc->ssrc;
    w->freq_hz = fc->freq_hz;
    w->call_id = fc->id;
  }
}

static void let_go(struct decoder *dp,int *nwork,struct fcall *fc){
  if(!fc->requested)
    return;
  fc->requested = false;
  struct work * const w = add_work(dp,nwork,WORK_RELEASE);
  if(w != NULL){
    w->ssrc = fc->ssrc;
    w->freq_hz = fc->freq_hz;
    w->call_id = fc->id;
  }
}

static void log_end(struct decoder *dp,int *nwork,struct site const *site,struct fcall const *fc,int64_t when,char const *reason){
  char id[256],flags[64],ssrc[32] = "";
  call_text(id,sizeof id,fc);
  if(fc->ssrc != 0 && !fc->refused)
    snprintf(ssrc,sizeof ssrc," ssrc %u",fc->ssrc);
  if(fc->ssrc != 0 && fc->units + fc->words_bad > 0)
    add_log(dp,nwork,when,"NAC %03x call end %s%s%s after %.1f s, %d voice units, %d words bad, %d bits corrected, %s",
	    site->nac,id,ssrc,flag_text(fc->flags,flags,sizeof flags),(when - fc->start) * 1e-9,
	    fc->units,fc->words_bad,fc->bits_fixed,reason);
  else
    add_log(dp,nwork,when,"NAC %03x call end %s%s%s after %.1f s, %s%s",site->nac,id,ssrc,flag_text(fc->flags,flags,sizeof flags),
	    (when - fc->start) * 1e-9,fc->refused ? "not followed (radiod refused the channel), " : fc->ssrc != 0 ? "no voice received, " : "",reason);
}

// Act on the events the trunking logic reported. Under the site's lock
static int take_events(struct decoder *dp,struct site *site,int nwork){
  if(site->lost_events > 0){
    add_log(dp,&nwork,site->now,"NAC %03x %llu trunking events lost",site->nac,(unsigned long long)site->lost_events);
    site->lost_events = 0;
  }
  for(int k=0; k < site->nevents; k++){
    struct p25_trunk_event const * const e = &site->events[k];
    struct fcall *fc = NULL;
    char id[256],flags[64];
    switch(e->type){
    case P25_TRUNK_CALL_START:
      for(int i=0; i < P25_TRUNK_MAX_CALLS && e->call_id != 0; i++){
	if(!site->calls[i].used){
	  fc = &site->calls[i];
	  break;
	}
      }
      if(fc == NULL){
	add_log(dp,&nwork,e->time,"NAC %03x call not tracked (%s): %s",site->nac,p25_trunk_why_name(e->why_not),e->text);
	break;
      }
      memset(fc,0,sizeof *fc);
      fc->used = true;
      fc->id = e->call_id;
      fc->type = e->call_type;
      fc->talkgroup = e->talkgroup;
      fc->source = e->source;
      fc->target = e->target;
      fc->freq_hz = e->freq_hz;
      fc->slot = e->slot;
      fc->flags = e->flags;
      fc->start = e->time;
      fc->seed = (e->flags & P25_TRUNK_F_SEED) != 0;
      fc->seed_hz = e->seed_offset_hz;
      {
	char const *why = p25_trunk_why_name(e->why_not);
	bool const follow = (e->flags & P25_TRUNK_F_FOLLOW) && want_channel(site,fc,&why);
	call_text(id,sizeof id,fc);
	if(follow){
	  add_log(dp,&nwork,e->time,"NAC %03x call start %s ssrc %u%s",site->nac,id,fc->ssrc,flag_text(fc->flags,flags,sizeof flags));
	  ask_channel(dp,&nwork,fc);
	} else
	  add_log(dp,&nwork,e->time,"NAC %03x call start %s%s, not followed: %s",site->nac,id,flag_text(fc->flags,flags,sizeof flags),why);
      }
      break;
    case P25_TRUNK_CALL_UPDATE:
      if(Verbose > 1)
	add_log(dp,&nwork,e->time,"NAC %03x trunk %s",site->nac,e->text);
      if((fc = find_call(site,e->call_id)) == NULL)
	break;
      fc->talkgroup = e->talkgroup;
      fc->source = e->source;
      fc->target = e->target;
      if(e->flags & P25_TRUNK_F_RELEASE){
	// Held voice units: tell the voice channel's thread. Not clear wins over clear
	int const r = (e->flags & P25_TRUNK_F_ENCRYPTED) ? 2 : 1;
	if(r > fc->release)
	  fc->release = r;
	break;
      }
      fc->flags = e->flags;
      if(fc->requested && !(e->flags & P25_TRUNK_F_FOLLOW)){
	let_go(dp,&nwork,fc);
	call_text(id,sizeof id,fc);
	add_log(dp,&nwork,e->time,"NAC %03x call %s no longer followed: %s",site->nac,id,p25_trunk_why_name(e->why_not));
      } else if(fc->requested){
	// Still on: ask again. chanctl sends only when needed, and this keeps the channel's lifetime fresh
	ask_channel(dp,&nwork,fc);
      } else if((e->flags & P25_TRUNK_F_FOLLOW) && !fc->refused && fc->slot < 0){
	// Now followed (no longer encrypted, or room under --max-calls): it may be heard from here on
	char const *why = NULL;
	if(want_channel(site,fc,&why)){
	  call_text(id,sizeof id,fc);
	  add_log(dp,&nwork,e->time,"NAC %03x call now followed %s ssrc %u%s",site->nac,id,fc->ssrc,flag_text(fc->flags,flags,sizeof flags));
	  ask_channel(dp,&nwork,fc);
	}
      }
      break;
    case P25_TRUNK_CALL_TALKER:
      if(Verbose > 1)
	add_log(dp,&nwork,e->time,"NAC %03x trunk %s",site->nac,e->text);
      if((fc = find_call(site,e->call_id)) != NULL){
	if(fc->source != e->source)
	  fc->alias[0] = '\0'; // someone else
	fc->source = e->source;
      }
      break;
    case P25_TRUNK_CALL_END:
      if((fc = find_call(site,e->call_id)) == NULL)
	break;
      fc->flags = e->flags;
      if(fc->requested || fc->ssrc != 0 || Verbose)
	log_end(dp,&nwork,site,fc,e->time,p25_trunk_end_name(e->end_reason));
      let_go(dp,&nwork,fc);
      fc->used = false;
      break;
    case P25_TRUNK_SITE:
    case P25_TRUNK_CONTROL:
    case P25_TRUNK_PATCH:
    case P25_TRUNK_OTHER:
      if(Verbose)
	add_log(dp,&nwork,e->time,"NAC %03x trunk %s",site->nac,e->text);
      break;
    }
  }
  site->nevents = 0;
  return nwork;
}

// Let go of the site's lock, then do what its events (and 'nwork' items already queued) called for
static void site_unlock(struct site *site,struct decoder *dp,int nwork){
  nwork = take_events(dp,site,nwork);
  double const freq = site->freq;
  uint32_t const ssrc = site->ssrc;
  uint16_t const nac = site->nac;
  pthread_mutex_unlock(&site->lock);

  for(int i=0; i < nwork; i++){
    struct work const * const w = &dp->work[i];
    switch(w->kind){
    case WORK_LOG:
      log_line(ssrc,freq,w->when,"%s",w->text);
      break;
    case WORK_REQUEST:
      {
	pthread_mutex_lock(&Ctl_mutex);
	int r = -1;
	errno = ENOENT;
	if(site->ctl != NULL && site->have_format){
	  struct chanctl_format const format = site->format;
	  r = chanctl_request(site->ctl,w->ssrc,(double)w->freq_hz,&format,Lifetime);
	}
	int const err = errno;
	pthread_mutex_unlock(&Ctl_mutex);
	if(r >= 0)
	  break;
	// Refused: log once per frequency, and stop asking for it
	pthread_mutex_lock(&site->lock);
	bool first = false;
	if((err == ERANGE || err == EEXIST) && !was_refused(site,w->freq_hz)){
	  first = true;
	  if(site->nrefused < MAX_REFUSED)
	    site->refused[site->nrefused++] = w->freq_hz;
	}
	struct fcall * const fc = find_call(site,w->call_id);
	if(fc != NULL && (err == ERANGE || err == EEXIST)){
	  fc->requested = false;
	  fc->refused = true;
	}
	pthread_mutex_unlock(&site->lock);
	if(first || (err != ERANGE && err != EEXIST && Verbose))
	  log_line(ssrc,freq,0,"NAC %03x can't follow calls on %.6lf MHz (ssrc %u): %s%s",nac,w->freq_hz * 1e-6,w->ssrc,
		   err == ERANGE ? "outside the front end's coverage" : err == EEXIST ? "that SSRC is another channel" : strerror(err),
		   first ? "; not asking for it again" : "");
      }
      break;
    case WORK_RELEASE:
      {
	// Not if the same batch asks for the channel again (the frequency was granted to the next call)
	bool again = false;
	for(int j=i+1; j < nwork; j++)
	  if(dp->work[j].kind == WORK_REQUEST && dp->work[j].ssrc == w->ssrc)
	    again = true;
	if(again)
	  break;
	pthread_mutex_lock(&Ctl_mutex);
	if(site->ctl != NULL)
	  chanctl_release(site->ctl,w->ssrc);
	pthread_mutex_unlock(&Ctl_mutex);
      }
      break;
    case WORK_REFRESH:
      pthread_mutex_lock(&Ctl_mutex);
      if(site->ctl != NULL)
	chanctl_refresh(site->ctl,w->ssrc);
      pthread_mutex_unlock(&Ctl_mutex);
      break;
    }
  }
}

// A trunking message decoded on a channel that is not a voice channel p25d asked for: it is a
// control channel, of its own site
static void control_message(struct decoder *dp,uint64_t sample,struct p25_msg const *msg){
  if(dp->site == NULL){
    if((dp->site = get_site(dp->sp)) == NULL)
      return;
    dp->control = true;
    atomic_store(&dp->sp->site,dp->site); // the input thread fills in the command handle and format
  }
  struct site * const site = dp->site;
  pthread_mutex_lock(&site->lock);
  site->freq = dp->frequency;
  site->nac = dp->site_nac;
  struct p25_trunk * const t = site_trunk(site);
  if(t != NULL)
    p25_trunk_control(t,msg,dp->site_nac,site_time(site,decoder_time(dp,sample)));
  site_unlock(site,dp,0);
}

// Once per block of a control channel: calls time out, and the carrier offset for seeding
static void control_block(struct decoder *dp){
  struct site * const site = dp->site;
  pthread_mutex_lock(&site->lock);
  if(site->trunk != NULL){
    site->freq = dp->frequency;
    if(dp->p25 != NULL)
      p25_trunk_set_control(site->trunk,(uint64_t)llrint(dp->frequency),p25p1_frequency_offset(dp->p25));
    p25_trunk_tick(site->trunk,site_time(site,decoder_time(dp,dp->block_start)));
  }
  site_unlock(site,dp,0);
}

// The control channel's stream has gone (its session closed): end its calls, let their channels go
static void control_lost(struct decoder *dp){
  struct site * const site = dp->site;
  pthread_mutex_lock(&site->lock);
  int nwork = take_events(dp,site,0);
  int64_t const now = site_time(site,0);
  for(int i=0; i < P25_TRUNK_MAX_CALLS; i++){
    struct fcall * const fc = &site->calls[i];
    if(!fc->used)
      continue;
    if(fc->requested || fc->ssrc != 0 || Verbose)
      log_end(dp,&nwork,site,fc,now,Terminate ? "p25d shutting down" : "control channel lost");
    let_go(dp,&nwork,fc);
    fc->used = false;
  }
  delete_p25_trunk(site->trunk); // a new one if the channel comes back
  site->trunk = NULL;
  site_unlock(site,dp,nwork);
}

// A voice channel p25d asked for? If some site's call has this SSRC, it is that site's
static void link_voice(struct decoder *dp){
  struct session const * const sp = dp->sp;
  pthread_mutex_lock(&Sites_mutex);
  for(struct site *site = Sites; site != NULL && !dp->voice; site = site->next){
    if(address_match(&site->sender,&sp->sender) != 1)
      continue; // another radiod's
    pthread_mutex_lock(&site->lock);
    for(int i=0; i < P25_TRUNK_MAX_CALLS; i++){
      struct fcall const * const fc = &site->calls[i];
      if(fc->used && fc->requested && fc->ssrc == sp->ssrc){
	dp->site = site;
	dp->voice = true;
	dp->trunk_freq = fc->freq_hz;
	dp->seed = fc->seed;
	dp->seed_hz = fc->seed_hz;
	break;
      }
    }
    pthread_mutex_unlock(&site->lock);
  }
  pthread_mutex_unlock(&Sites_mutex);
  if(dp->voice && Verbose)
    decoder_event(dp,dp->samples,"voice channel for calls granted on ssrc %u, receiver %s",dp->site->ssrc,
		  dp->seed ? "seeded with the control channel's carrier offset" : "not seeded");
  if(dp->voice && dp->seed && Verbose > 1)
    decoder_event(dp,dp->samples,"seed %.9g Hz",dp->seed_hz); // exactly, for comparing with an offline decode
}

// What the trunking logic's label says for the voice output. A held unit whose own label says
// encrypted stays encrypted whatever the release says
static enum p25_audio_label audio_label(struct p25_trunk_label const *l){
  switch(l->decision){
  case P25_TRUNK_VOICE_CLEAR:
    return l->encrypted ? P25_AUDIO_ENCRYPTED : P25_AUDIO_CLEAR;
  case P25_TRUNK_VOICE_HOLD:
    return l->encrypted ? P25_AUDIO_ENCRYPTED : P25_AUDIO_HOLD;
  case P25_TRUNK_VOICE_ENCRYPTED:
    return P25_AUDIO_ENCRYPTED;
  default:
    return P25_AUDIO_NONE;
  }
}

// One data unit on a voice channel p25d asked for: the word it carried, then the unit itself, to
// the trunking logic (as p25trunk.h asks); then the voice output, under the label it gave
static void voice_unit(struct decoder *dp,uint64_t sample,struct p25_frame const *frame){
  struct site * const site = dp->site;
  pthread_mutex_lock(&site->lock);
  uint16_t const site_nac = site->nac;
  pthread_mutex_unlock(&site->lock);
  if(site_nac != 0 && frame->nac != site_nac)
    return; // another system's, or a false frame sync: a "header" decoded from noise would end the call
  int64_t const when = decoder_time(dp,sample);
  int const duid = frame->duid;
  bool const ldu = duid == P25_DUID_LDU1 || duid == P25_DUID_LDU2;
  bool const unit = ldu || duid == P25_DUID_HDU || duid == P25_DUID_TDU || duid == P25_DUID_TDULC || duid == P25_DUID_PDU;
  struct p25_word const *word = NULL;
  if(duid == P25_DUID_HDU || duid == P25_DUID_TDULC)
    word = frame->word;
  else if(ldu && frame->ldu != NULL)
    word = &frame->ldu->word;

  struct p25_msg msg;
  bool have = false;
  uint8_t octets[15];
  if(word != NULL && word->ok){
    switch(duid){
    case P25_DUID_HDU:
      p25_pack_bits(octets,word->bits,120);
      have = p25_decode_hdu(&msg,octets) == 0;
      break;
    case P25_DUID_LDU1:
    case P25_DUID_TDULC:
      p25_pack_bits(octets,word->bits,72);
      have = p25_decode_lc(&msg,octets,duid == P25_DUID_TDULC) == 0;
      break;
    case P25_DUID_LDU2:
      p25_pack_bits(octets,word->bits,96);
      have = p25_decode_es(&msg,octets) == 0;
      break;
    }
  } else if(duid == P25_DUID_TSDU && frame->crc >= 0){
    p25_pack_bits(octets,frame->bits,96); // a trunking block on a voice channel: the logic takes it too
    have = p25_decode_tsbk(&msg,octets) == 0;
  }
  struct p25_alias_result alias;
  bool const new_alias = have && (duid == P25_DUID_LDU1 || duid == P25_DUID_TDULC) && p25_alias_lc(&dp->alias,&msg,&alias)
    && alias.len > 0;

  struct p25_trunk_label label;
  memset(&label,0,sizeof label);
  int release = 0;
  char call_alias[P25_ALIAS_MAX] = "";
  int nwork = 0;
  pthread_mutex_lock(&site->lock);
  struct p25_trunk * const t = site->trunk;
  uint16_t const nac = site->nac;
  if(t != NULL){
    int64_t const now = site_time(site,when);
    if(duid == P25_DUID_TSDU){
      if(have)
	p25_trunk_voice_word(t,dp->trunk_freq,-1,&msg,0,now);
    } else if(unit){
      if(have)
	p25_trunk_voice_word(t,dp->trunk_freq,-1,&msg,word != NULL ? word->erasures : 0,now);
      p25_trunk_voice_unit(t,dp->trunk_freq,-1,duid,now);
      label = *p25_trunk_label(t);
    }
  }
  nwork = take_events(dp,site,nwork); // a call this unit started is in the table now
  if(unit){
    struct fcall * const fc = label.call_id != 0 ? find_call(site,label.call_id) : find_call_freq(site,dp->trunk_freq);
    if(fc != NULL){
      // Held units released since the last unit, by this thread's call into the logic just now or
      // another thread's: they are all units this thread has already handed to the voice output
      release = fc->release;
      fc->release = 0;
      if(new_alias)
	strlcpy(fc->alias,alias.text,sizeof fc->alias);
      strlcpy(call_alias,fc->alias,sizeof call_alias);
      if(ldu){
	fc->units++;
	if(word == NULL || !word->ok)
	  fc->words_bad++;
	for(int i=0; i < P25_IMBE_FRAMES; i++)
	  fc->bits_fixed += frame->ldu->voice[i].total;
	if(fc->requested){
	  struct work * const w = add_work(dp,&nwork,WORK_REFRESH); // voice is arriving: keep the channel
	  if(w != NULL)
	    w->ssrc = fc->ssrc;
	}
      }
    }
  }
  site_unlock(site,dp,nwork);

  if(new_alias)
    decoder_event(dp,sample,"NAC %03x talker alias src %u \"%s\"",frame->nac,label.source,alias.text);
  if((ldu || (duid == P25_DUID_HDU && label.call_id != 0)) && label.call_id != dp->call_id){
    // Another call (or none) on this channel: what was held for the last one is never decoded.
    // Not when the first call is learned (none before): the transmission is the same, and what its
    // header or encryption sync said (clear, and the encryption parameters) stays with it
    if(dp->call_id != 0)
      p25_audio_call_end(dp->audio);
    dp->call_id = label.call_id;
  }
  if(release != 0)
    p25_audio_release(dp->audio,release == 1);
  if(ldu && label.call_id != 0){
    // Stream identity. A group call's stream has the talkgroup as its SSRC, so a listener sees one
    // stream per talkgroup whichever voice channel carries it; other calls keep the channel's SSRC.
    // Talkgroup numbers are unique only within one system: two systems with the same talkgroup
    // number, monitored by one p25d (or several sharing an output group), would share an SSRC.
    // For now run one p25d with its own output group per system; a per-system SSRC base or a
    // talkgroup map may come later
    char desc[256];
    uint32_t ssrc = 0;
    int n;
    if(label.call_type == P25_TRUNK_GROUP && label.destination != 0){
      ssrc = label.destination;
      n = snprintf(desc,sizeof desc,"P25 TG %u",label.destination);
    } else
      n = snprintf(desc,sizeof desc,"P25 %s %u",label.call_type == P25_TRUNK_TELEPHONE ? "telephone" : "unit",label.destination);
    if(n > 0 && (size_t)n < sizeof desc && label.source != 0)
      n += snprintf(desc + n,sizeof desc - n," src %u",label.source);
    if(n > 0 && (size_t)n < sizeof desc && strlen(call_alias) > 0)
      n += snprintf(desc + n,sizeof desc - n," \"%s\"",call_alias);
    if(n > 0 && (size_t)n < sizeof desc)
      snprintf(desc + n,sizeof desc - n," NAC %03x",nac);
    p25_audio_set_stream(dp->audio,ssrc,desc);
  }
  p25_audio_unit(dp->audio,frame,when,ldu ? audio_label(&label) : P25_AUDIO_UNLABELLED);
}

// ---------------------------------------------------------------------------
// Conventional channels: one line when a transmission starts, once its talkgroup (or unit) and
// source are known or after four voice units without them, and one when it ends, as the trunked
// call lines do

static void conv_start_line(struct decoder *dp){
  struct conv * const c = &dp->conv;
  char id[256];
  int n;
  if(c->known)
    n = snprintf(id,sizeof id,"%s %u src %u",c->unit_call ? "unit tgt" : "group tg",c->target,c->source);
  else
    n = snprintf(id,sizeof id,"talkgroup unknown src %u",c->source);
  if(strlen(c->alias) > 0 && n > 0 && (size_t)n < sizeof id)
    snprintf(id + n,sizeof id - n," alias \"%s\"",c->alias);
  decoder_event(dp,c->start,"NAC %03x transmission start %s%s%s",dp->conv_nac,id,
		c->emergency ? " emergency" : "",c->encrypted ? " encrypted" : "");
  c->logged = true;
}

// 'how': terminator, timeout (no voice for 0.5 s past the next unit's time), new transmission
// (a header, or link control naming another talkgroup or source), channel closed, shutdown
static void conv_end(struct decoder *dp,uint64_t sample,char const *how){
  struct conv * const c = &dp->conv;
  if(!c->active)
    return;
  if(c->units > 0 || Verbose){
    if(!c->logged)
      conv_start_line(dp);
    char id[256];
    int n;
    if(c->known)
      n = snprintf(id,sizeof id,"%s %u src %u",c->unit_call ? "unit tgt" : "group tg",c->target,c->source);
    else
      n = snprintf(id,sizeof id,"talkgroup unknown src %u",c->source);
    if(strlen(c->alias) > 0 && n > 0 && (size_t)n < sizeof id)
      snprintf(id + n,sizeof id - n," alias \"%s\"",c->alias);
    double const secs = dp->samprate > 0 ? (double)(c->last - c->start) / dp->samprate + (c->units > 0 ? 0.18 : 0) : 0;
    decoder_event(dp,sample,"NAC %03x transmission end %s%s%s after %.1f s, %d voice units, %d words bad, %d bits corrected, %s",
		  dp->conv_nac,id,c->emergency ? " emergency" : "",c->encrypted ? " encrypted" : "",secs,c->units,c->words_bad,c->bits_fixed,how);
  }
  memset(c,0,sizeof *c);
}

static void conv_begin(struct decoder *dp,uint64_t sample,uint16_t nac){
  memset(&dp->conv,0,sizeof dp->conv);
  dp->conv.active = true;
  dp->conv.start = dp->conv.last = sample;
  dp->conv_nac = nac;
}

static void conv_unit(struct decoder *dp,uint64_t sample,struct p25_frame const *frame){
  struct conv * const c = &dp->conv;
  struct p25_msg msg;
  uint8_t octets[15];
  switch(frame->duid){
  case P25_DUID_HDU:
    if(c->active)
      conv_end(dp,c->last,"new transmission");
    conv_begin(dp,sample,frame->nac);
    if(frame->word != NULL && frame->word->ok){
      p25_pack_bits(octets,frame->word->bits,120);
      if(p25_decode_hdu(&msg,octets) == 0){
	c->known = true;
	c->unit_call = false;
	c->target = msg.group;
	c->encrypted |= msg.algid != 0x80;
      }
    }
    break;
  case P25_DUID_LDU1:
  case P25_DUID_LDU2:
    {
      struct p25_ldu const * const ldu = frame->ldu;
      if(ldu == NULL)
	break;
      if(frame->duid == P25_DUID_LDU1 && ldu->word.ok){
	p25_pack_bits(octets,ldu->word.bits,72);
	if(p25_decode_lc(&msg,octets,false) == 0 && !msg.protect
	   && (msg.kind == P25_LC_GRP_V_CH_USR || msg.kind == P25_LC_MOT_GRG_V_CH_USR || msg.kind == P25_LC_UU_V_CH_USR)){
	  bool const unit_call = msg.kind == P25_LC_UU_V_CH_USR;
	  uint32_t const target = unit_call ? msg.tgt : msg.group;
	  // Another talkgroup or talker with no terminator and header between: another transmission
	  if(c->active && c->known && (c->unit_call != unit_call || c->target != target
				       || (c->source != 0 && msg.src != 0 && c->source != msg.src)))
	    conv_end(dp,c->last,"new transmission");
	  if(!c->active)
	    conv_begin(dp,sample,frame->nac);
	  c->known = true;
	  c->unit_call = unit_call;
	  c->target = target;
	  if(msg.src != 0)
	    c->source = msg.src;
	  c->encrypted |= (msg.svc & P25_SVC_ENCRYPTED) != 0;
	  c->emergency |= (msg.svc & 0x80) != 0;
	}
	struct p25_alias_result alias;
	if(p25_decode_lc(&msg,octets,false) == 0 && p25_alias_lc(&dp->alias,&msg,&alias) && alias.len > 0)
	  strlcpy(c->alias,alias.text,sizeof c->alias);
      } else if(frame->duid == P25_DUID_LDU2 && ldu->word.ok){
	p25_pack_bits(octets,ldu->word.bits,96);
	if(p25_decode_es(&msg,octets) == 0)
	  c->encrypted |= msg.algid != 0x80;
      }
      if(!c->active)
	conv_begin(dp,sample,frame->nac); // late entry
      c->last = sample;
      c->units++;
      if(!ldu->word.ok)
	c->words_bad++;
      for(int i=0; i < P25_IMBE_FRAMES; i++)
	c->bits_fixed += ldu->voice[i].total;
      if(!c->logged && ((c->known && c->source != 0) || c->units >= 4))
	conv_start_line(dp);
    }
    break;
  case P25_DUID_TDU:
  case P25_DUID_TDULC:
    if(c->active)
      conv_end(dp,sample,"terminator");
    break;
  default:
    break;
  }
}

// Talkgroup list: numbers and ranges, comma separated ("100,200-299"), added to list[n]
static int parse_talkgroups(uint16_t *list,int n,char const *arg){
  char const *cp = arg;
  while(*cp != '\0'){
    char *end = NULL;
    long const a = strtol(cp,&end,0);
    long b = a;
    if(end == cp || a < 1 || a > 65535)
      goto bad;
    cp = end;
    if(*cp == '-'){
      b = strtol(cp + 1,&end,0);
      if(end == cp + 1 || b < a || b > 65535)
	goto bad;
      cp = end;
    }
    for(long g = a; g <= b; g++){
      if(n == MAX_TALKGROUPS){
	fprintf(stderr,"Too many talkgroups; max %d\n",MAX_TALKGROUPS);
	exit(EX_USAGE);
      }
      list[n++] = (uint16_t)g;
    }
    if(*cp == ',')
      cp++;
    else if(*cp != '\0')
      goto bad;
  }
  return n;
 bad:
  fprintf(stderr,"Bad talkgroup list \"%s\": numbers 1-65535 or ranges, comma separated\n",arg);
  exit(EX_USAGE);
}

// Bytes per sample (one of I or Q) for the encodings we can decode, 0 for the rest
static int sample_size(enum encoding encoding){
  switch(encoding){
  case S16LE:
  case S16BE:
    return sizeof(int16_t);
  case F32LE:
  case F32BE:
    return sizeof(float);
#ifdef HAS_FLOAT16
  case F16LE:
  case F16BE:
    return sizeof(float16_t);
#endif
  default:
    return 0;
  }
}

// Convert one packet's I/Q payload to complex floats; integers are scaled to +/-1
static int convert_iq(float complex *out,uint8_t const *in,int frames,enum encoding encoding){
  float * const fp = (float *)out; // a float complex is two floats, real part first
  size_t const count = 2 * (size_t)frames;  // I and Q
  switch(encoding){
  case S16BE:
    import_s16_be(fp,in,count);
    break;
  case S16LE:
    import_s16_le(fp,in,count);
    break;
  case F32LE:
    import_f32_le(fp,in,count);
    break;
  case F32BE:
    import_f32_be(fp,in,count);
    break;
#ifdef HAS_FLOAT16
  case F16LE:
    import_f16_le(fp,in,count);
    break;
  case F16BE:
    import_f16_be(fp,in,count);
    break;
#endif
  default:
    return -1;
  }
  return frames;
}

static int calculate_deadline(struct timespec *deadline,int64_t timeout){
  assert(deadline != NULL);
  if(deadline == NULL)
    return -1;
  clock_gettime(CLOCK_REALTIME,deadline);
  if(timeout > 0){
    deadline->tv_nsec += timeout % BILLION;
    deadline->tv_sec += timeout / BILLION;
    if(deadline->tv_nsec >= BILLION){
      deadline->tv_nsec -= BILLION;
      deadline->tv_sec++;
    }
  }
  return 0;
}

// Logging. Every event is one line on standard output:
//   Sat 21 Nov 2026 23:51:02.123456 UTC ssrc 851012 851.012500 MHz <event text>
// The time format is format_gpstime()'s, as packetd and aprsfeed use. 'when' is in ns since the
// GPS epoch like every time in ka9q-radio; 0 means now. Lines from different threads don't mix
static void log_event(uint32_t ssrc,double frequency,int64_t when,char const *fmt,va_list ap){
  char timestring[100];
  format_gpstime(timestring,sizeof(timestring),when != 0 ? when : gps_time_ns());
  pthread_mutex_lock(&Output_mutex);
  fprintf(stdout,"%s ssrc %u %.6lf MHz ",timestring,ssrc,frequency * 1e-6);
  vfprintf(stdout,fmt,ap);
  fputc('\n',stdout);
  pthread_mutex_unlock(&Output_mutex);
}

// A line for a site, from wherever it is acted on
static void log_line(uint32_t ssrc,double frequency,int64_t when,char const *fmt,...){
  va_list ap;
  va_start(ap,fmt);
  log_event(ssrc,frequency,when,fmt,ap);
  va_end(ap);
}

// Event for a channel, from the input thread
static void session_event(struct session const *sp,int64_t when,char const *fmt,...){
  va_list ap;
  va_start(ap,fmt);
  log_event(sp->ssrc,sp->chan.tune.freq,when,fmt,ap);
  va_end(ap);
}

// Sender's time of decoder sample number 'sample', or 0 (now) if the stream's clock isn't known yet
static int64_t decoder_time(struct decoder const *dp,uint64_t sample){
  if(dp->block_time == 0 || dp->samprate <= 0)
    return 0;
  return dp->block_time + llrint(1e9 * (double)(int64_t)(sample - dp->block_start) / dp->samprate);
}

// Event for a channel from its decode thread, stamped with the time of the sample where it began
// This is what the frame and message callbacks will call
static void decoder_event(struct decoder const *dp,uint64_t sample,char const *fmt,...){
  va_list ap;
  va_start(ap,fmt);
  log_event(dp->sp->ssrc,dp->frequency,decoder_time(dp,sample),fmt,ap);
  va_end(ap);
}

// The same, followed by the bytes of a frame or message in hex
static void decoder_dump(struct decoder const *dp,uint64_t sample,char const *label,uint8_t const *data,size_t len){
  char hex[3 * len + 1];
  hex[0] = '\0';
  char *cp = hex;
  for(size_t i=0; i < len; i++)
    cp += snprintf(cp,sizeof(hex) - (cp - hex),"%s%02x",i == 0 ? "" : " ",data[i]);
  decoder_event(dp,sample,"%s %s",label,hex);
}
