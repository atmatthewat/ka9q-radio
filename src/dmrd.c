// DMR decoder daemon for ka9q-radio
// Reads complex baseband (I/Q) RTP streams from radiod, runs one DMR receiver per SSRC (a repeater
// output, both timeslots), logs each transmission, one timestamped line per event, on standard
// output, and sends the clear voice it decodes as RTP audio streams
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
#include "config.h"
#include "defaults.h"
#include "p25audio.h"
#include "dmr.h"
#include "dmrchan.h"
#include "dmrsite.h"
#include "dmraudio.h"
#include "dmrvote.h"
#include "chanctl.h"

// Theory of operation
//
// Threads, sessions and the queue are p25d's (p25d.c, "Theory of operation"): one input thread reads
// every status and data packet of every input group; a session is one {SSRC, sender address and
// port}, made by its first status, which says what the payload types mean and gives the stream's
// clock reference; packets are resequenced in a window of RESEQ, gaps up to Max_fill seconds are
// filled with zeroes so the receiver's symbol timing holds, and blocks go to the channel's own
// decode thread through a queue bounded at Max_queue seconds. A session closes after Timeout seconds
// without data.
//
// One carrier, both slots. Each channel's decode thread runs one struct dmr_chan (dmrchan.c): the
// receiver, the burst sink, the message layer and the call tracker of one carrier. A DMR carrier has
// two timeslots, each with its own transmissions; the tracker labels every voice frame clear,
// encrypted or unconfirmed, and only frames labelled clear are decoded to speech (the hard rule:
// audio of encrypted frames is never put out).
//
// Streams and SSRCs. A group call's speech has the talkgroup as its SSRC, whichever channel carries
// it, as p25d's trunked group calls do, so a listener sees one stream per talkgroup. That matters
// for DMR more than for P25: a wide-area call on a multi-site system (Capacity Plus, IP Site
// Connect) is carried at the same moment by every repeater of the call's sites, and a listener
// monitoring them all would otherwise hear it once per repeater. So every channel's clear frames go
// to one voter (dmrvote.c), which lines the repeaters' copies of the call up and plays each frame
// from the copy received with the fewest errors, falling back to whichever repeater is still
// sending when copies do not line up. A unit-to-unit call, and voice whose destination is not known
// yet, goes out under the channel's SSRC times ten plus the slot (e.g. 4534251); a talkgroup can
// reach such a number only above 1,342,177 (a DMR talkgroup has 24 bits; on a system using larger
// ones two streams could meet: a later change maps them explicitly).
//
// Site-level state is deliberately not here: one radiod and a fixed list of repeater channels for
// now. Which radiod and SSRC serves a frequency, the channel map and grant following belong in a
// site layer kept apart from these per-channel decoders, for trunked systems spanning more than one
// radiod.

#define MAX_MCAST 20   // Maximum number of input groups
#define RESEQ 32       // Resequencing queue, packets. radiod sends one to three packets per 20 ms block

struct block {
  struct block *next;
  uint32_t timestamp;      // RTP timestamp of the first sample
  bool marker;             // RTP marker: don't fill the gap before this packet
  double samprate;         // Hz; a change restarts the decoder
  double frequency;        // Hz, channel frequency from the status stream
  float bb_power,n0;       // radiod's signal power and noise density for the channel, power ratios
  float low,high;          // and its filter edges, Hz: passed on in the speech stream's status
  int64_t time;            // Sender's time of the first sample, ns since GPS epoch; 0 if not yet known
  int count;               // complex samples
  float complex samples[]; // I in the real part, Q in the imaginary, as radiod sends them
};

// One timeslot's transmission, as the voter knows it
struct slot {
  uint32_t ssrc;           // SSRC of the stream its frames go to, 0 = none yet
};

// Decode thread view of a channel
struct decoder {
  struct session *sp;
  struct dmr_chan *chan;
  double samprate;
  double frequency;        // of the block being decoded
  int64_t block_time;      // sender's time of the block's first sample, 0 if unknown
  uint64_t samples;        // since the decoder was created
  uint64_t next_report;    // sample count for the next -v status line
  float bb_power,n0,low,high;
  struct slot slot[2];
  // The carrier's site and its control log. One each per channel for now: grouping a system's
  // repeaters into sites, and sites into a system, is the site's job once dmrd is told which they are
  struct dmr_site *site;
  struct dmr_control_log *log;
  char channel_id[DMR_CHANNEL_ID_MAX]; // the SSRC, or the configured channel's id
  uint64_t site_clock;     // the site's clock, us, never going back
  struct configured_site *configured; // the site from the sites file the carrier belongs to, else NULL
  char const *system_name; // "DMR", or the configured site's system
  uint64_t refresh_voice;  // voice bursts decoded when a followed channel was last kept alive
  int64_t next_refresh;    // signal time of the next check, ns
};

// A site from the sites file (-f): its repeaters, the site state and control log they share, which
// outlive the channels. Which channel is which is decided by frequency, so nothing here assumes the
// channels come from one radiod
struct configured_channel {
  uint64_t frequency_hz;
  uint16_t lcn;
  char channel_id[DMR_CHANNEL_ID_MAX];
  _Atomic uint32_t ssrc;   // of the session decoding it, 0 for none yet
};
struct configured_site {
  char system_name[DMR_SITE_NAME_MAX];
  char site_name[DMR_SITE_NAME_MAX];
  int color_code;
  struct dmr_site *site;
  struct dmr_control_log *log;
  _Atomic int64_t latest;  // the latest signal time any of its channels has decoded, ns since the GPS epoch
  _Atomic uint64_t site_clock;
  int nchannels;
  struct configured_channel *channels;
};

// One for each channel (SSRC) being decoded
struct session {
  struct session *prev;
  struct session *next;
  struct sockaddr_storage sender; // radiod's address and port, the same for status and data
  uint32_t ssrc;

  // From the status stream. Written and read only by the input thread
  chan_t chan;
  struct frontend frontend;
  struct pt_table pt_table[128];
  int samprate;
  bool warned;
  int64_t last_status;
  int64_t last_data;

  // RTP reception, input thread only
  struct rtp_state rtp;
  struct block *reseq[RESEQ];
  int pending;

  // Queue to the decode thread
  pthread_t thread;
  bool running;
  pthread_mutex_t qmutex;
  pthread_cond_t qcond;
  struct block *queue;
  struct block *qtail;
  int64_t qsamples;
  atomic_bool terminate;

  atomic_uint_fast64_t packets;
  atomic_uint_fast64_t drops;
  atomic_uint_fast64_t dupes;
  atomic_uint_fast64_t filled;
  atomic_uint_fast64_t resyncs;
  atomic_uint_fast64_t overruns;
  atomic_uint_fast64_t unusable;
};

// Command line params
const char *App_path;
int Verbose;
static char const *Locale;
static char const *Input[MAX_MCAST];
static int Ninputs;
static char const *Source;
static struct sockaddr_storage *Source_socket;
static uint32_t Ssrc;
static int64_t Timeout = 20;
static int Update = 10;
static char const *Output;            // speech output group (--pcm-out), NULL for none
static char const *Name;              // service name the speech is advertised under; NULL: not advertised
static int Mcast_ttl = DEFAULT_TTL;
static int IP_tos = DEFAULT_IP_TOS;
static int Color_code = -1;           // -c: pinned 0-15, -1 tracked, -2 any
static bool Mobile;                   // -M: also MS and direct mode syncs (simplex, talkaround)
static enum dmr_system_type System_type = DMR_SYSTEM_CONVENTIONAL; // -y
static char const *Sites_file;        // -f
static struct configured_site *Sites;
static int Nsites;

// Call following: the radiods channels may be asked of, each by its command group as its channels'
// status names it, with a channel's format to ask in. Which radiod serves a frequency is decided by
// asking each in turn until one covers it (locate_radio()), so a site may span receivers
#define MAX_RADIOS 8
struct radio {
  struct sockaddr_storage control;
  struct chanctl *ctl;
  struct chanctl_format format;  // of an I/Q channel dmrd decodes from it, not one it asked for
  bool have_format;
};
static struct radio Radios[MAX_RADIOS];
static int Nradios;
static pthread_mutex_t Ctl_mutex = PTHREAD_MUTEX_INITIALIZER; // Radios, and every chanctl call
static bool Follow = true;            // -n: don't
static double Hold = 5.0;             // -H: a followed channel is kept this long after the last sign of a call
static int const Ctl_ttl = 1;         // commands to radiod, as tune and control send them
#define MAX_ASKED 256
static struct {
  uint32_t ssrc;                      // SSRCs dmrd has asked for (under Ctl_mutex): a decoder on one is
  int64_t logged;                     // a followed channel, even once radiod has let it go
} Asked[MAX_ASKED];
static int Nasked;

// Tuning constants
static double const Max_fill = 1.0;   // Fill gaps up to this many seconds with zeroes; resynchronize on longer ones
static double const Max_queue = 5.0;  // Seconds of samples queued to a decoder before blocks are dropped

// Global variables
static int Data_fd[MAX_MCAST];
static int Status_fd[MAX_MCAST];
static struct session *Sessions;
static pthread_mutex_t Output_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t Terminate;
static volatile sig_atomic_t Signal;
static struct p25_audio_group *Audio_group;
static struct dmr_voter *Voter;       // NULL without --pcm-out or a vocoder

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
static void decoder_event(struct decoder const *dp,int64_t when,char const *fmt,...) __attribute__((format(printf,3,4)));
static void voice_frame(void *arg,struct dmr_chan_frame const *f);
static void voice_event(void *arg,struct dmr_chan_event const *e);
static void voice_log(void *arg,int64_t when,char const *text);
static void status_line(struct decoder const *dp);
static void vote_end(void *arg,struct dmr_vote_result const *r);
static void control_line(void *arg,struct dmr_control_line const *line);
static void control_clear(void *arg,struct dmr_site_context const *channel,uint8_t slot,char const *reason);
static int64_t control_wall_clock(void *arg);
static uint64_t control_site_clock(void *arg);
static void load_sites(char const *file);
static void free_sites(void);
static struct configured_site *find_site(uint64_t frequency_hz,struct configured_channel **channel);
static void site_line(void *arg,struct dmr_control_line const *line);
static int64_t site_wall_clock(void *arg);
static uint64_t site_site_clock(void *arg);
static void observe_radio(struct session *sp);
static void site_follow(void *arg,struct dmr_site *site,struct dmr_follow const *f);
static void channel_follow(void *arg,struct dmr_site *site,struct dmr_follow const *f);
static void keep_followed(struct decoder *dp,int64_t now);

static struct option Options[] = {
  {"iface", required_argument, NULL, 'A'},
  {"color-code", required_argument, NULL, 'c'},
  {"hold", required_argument, NULL, 'H'},
  {"no-follow", no_argument, NULL, 'n'},
  {"sites", required_argument, NULL, 'f'},
  {"input", required_argument, NULL, 'I'},
  {"locale", required_argument, NULL, 'l'},
  {"mobile", no_argument, NULL, 'M'},
  {"name", required_argument, NULL, 'N'},
  {"source", required_argument, NULL, 'o'},
  {"tos", required_argument, NULL, 'p'},
  {"pcm-out", required_argument, NULL, 'R'},
  {"ssrc", required_argument, NULL, 'S'},
  {"timeout", required_argument, NULL, 't'},
  {"ttl", required_argument, NULL, 'T'},
  {"update", required_argument, NULL, 'u'},
  {"verbose", no_argument, NULL, 'v'},
  {"version", no_argument, NULL, 'V'},
  {"system-type", required_argument, NULL, 'y'},
  {NULL, 0, NULL, 0},
};
static char const Optstring[] = "A:c:f:H:I:l:MnN:o:p:R:S:t:T:u:vVy:";

static void usage(void){
  fprintf(stderr,"Usage: %s [-v|--verbose] [-V|--version] [-l|--locale locale] [-A|--iface interface] [-o|--source <source-name-or-address>] [-S|--ssrc ssrc] [-t|--timeout seconds] [-u|--update seconds] [-c|--color-code n|any|track] [-M|--mobile] [-y|--system-type conventional|capacity_plus|...] [-f|--sites sites_file] [-n|--no-follow] [-H|--hold seconds] [-R|--pcm-out audio_mcast_address] [-N|--name service_name] [-T|--ttl ttl] [-p|--tos tos] [-I|--input] iq_mcast_address [iq_mcast_address ...]\n",App_path);
}

int main(int argc,char *argv[]){
  App_path = argv[0];
  Locale = getenv("LANG");

  int c;
  while((c = getopt_long(argc,argv,Optstring,Options,NULL)) != EOF){
    switch(c){
    case 'A':
      Default_mcast_iface = optarg;
      break;
    case 'c':
      if(strcmp(optarg,"any") == 0)
        Color_code = -2;
      else if(strcmp(optarg,"track") == 0)
        Color_code = -1;
      else {
        char *ptr = NULL;
        long const x = strtol(optarg,&ptr,0);
        if(ptr == optarg || *ptr != '\0' || x < 0 || x > 15){
          fprintf(stderr,"Bad colour code \"%s\": 0-15, any or track\n",optarg);
          exit(EX_USAGE);
        }
        Color_code = (int)x;
      }
      break;
    case 'f':
      Sites_file = optarg;
      break;
    case 'y':
      if(!dmr_system_type_from_name(optarg,&System_type)){
        fprintf(stderr,"Unknown system type \"%s\": conventional, tier3, capacity_plus, linked_capacity_plus, connect_plus, capacity_max, hytera_xpt or hytera_tier3\n",optarg);
        exit(EX_USAGE);
      }
      break;
    case 'I':
      if(Ninputs == MAX_MCAST){
        fprintf(stderr,"Too many multicast addresses; max %d\n",MAX_MCAST);
        break;
      }
      Input[Ninputs++] = optarg;
      break;
    case 'l':
      Locale = optarg;
      break;
    case 'n':
      Follow = false;
      break;
    case 'H':
      Hold = strtod(optarg,NULL);
      if(Hold < 1)
        Hold = 1;
      break;
    case 'M':
      Mobile = true;
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
    case 'T':
      Mcast_ttl = (int)strtol(optarg,NULL,0);
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
  setlinebuf(stdout);
  setlinebuf(stderr);
  if(Ssrc != 0 && Follow){
    if(Verbose)
      fprintf(stderr,"%s: --ssrc given, not following calls\n",App_path);
    Follow = false;
  }
  if(Sites_file != NULL)
    load_sites(Sites_file); // exits if it can't be read

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
  if(p25_vocoder_name(P25_CODEC_AMBE2) == NULL)
    fprintf(stderr,"%s: built without a vocoder (mbelib): no voice output\n",App_path);
  if(Source != NULL){
    Source_socket = calloc(1,sizeof(struct sockaddr_storage));
    assert(Source_socket != NULL);
    resolve_mcast(Source,Source_socket,0,NULL,0,0);
  }
  for(int i=0; i < Ninputs; i++){
    struct sockaddr_storage sock;
    char iface[1024];
    resolve_mcast(Input[i],&sock,DEFAULT_RTP_PORT,iface,sizeof(iface),0);
    Data_fd[i] = listen_mcast(Source_socket,&sock,iface);
    resolve_mcast(Input[i],&sock,DEFAULT_STAT_PORT,iface,sizeof(iface),0);
    Status_fd[i] = listen_mcast(Source_socket,&sock,iface);
    if(Data_fd[i] == -1 || Status_fd[i] == -1){
      fprintf(stderr,"Can't set up input from %s, exiting\n",Input[i]);
      exit(EX_TEMPFAIL);
    }
    int const n = 1 << 20;
    if(setsockopt(Data_fd[i],SOL_SOCKET,SO_RCVBUF,&n,sizeof(n)) == -1)
      perror("setsockopt");
    if(Verbose)
      fprintf(stderr,"%s: listening to %s\n",App_path,Input[i]);
  }
  if(Output != NULL && p25_vocoder_name(P25_CODEC_AMBE2) != NULL){
    if((Audio_group = p25_audio_open(Output,Default_mcast_iface,Mcast_ttl,IP_tos,Name)) == NULL)
      exit(EX_TEMPFAIL);
    Voter = dmr_voter_create(Audio_group,DMR_VOTE_DELAY_MS * 1000000LL);
    dmr_voter_set_end_handler(Voter,vote_end,NULL);
    if(Verbose)
      fprintf(stderr,"%s: voice to %s (%s)\n",App_path,Output,p25_vocoder_name(P25_CODEC_AMBE2));
  }
  signal(SIGINT,closedown);
  signal(SIGQUIT,closedown);
  signal(SIGTERM,closedown);
  signal(SIGPIPE,SIG_IGN);
  signal(SIGUSR1,verbosity);
  signal(SIGUSR2,verbosity);

  input_loop();
  cleanup();
  free_sites(); // after every channel has gone: their pending counts are written here
  for(int i=0; i < Nradios; i++)
    chanctl_destroy(Radios[i].ctl); // the channels followed are released
  dmr_voter_destroy(Voter);
  p25_audio_close(Audio_group);
  if(Verbose)
    fprintf(stderr,"%s: caught signal %d: %s\n",App_path,(int)Signal,strsignal(Signal));
  exit((Signal == SIGTERM || Signal == SIGINT) ? EX_OK : EX_SOFTWARE);
}

static void closedown(int a){
  Signal = a;
  Terminate = 1;
}

static void verbosity(int a){
  if(a == SIGUSR1)
    Verbose++;
  else if(a == SIGUSR2)
    Verbose = (Verbose <= 0) ? 0 : Verbose - 1;
}

// ---------------------------------------------------------------------------
// Input: as p25d's

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
    int const n = poll(pfd,2*Ninputs,1000);
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
    if(now >= last_scan + BILLION / 4){
      scan_sessions(now);
      last_scan = now;
    }
  }
}

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
    return;
  uint32_t const ssrc = get_ssrc(buffer+1,length-1);
  if(ssrc == 0)
    return;
  if(Ssrc != 0 && ssrc != Ssrc)
    return;
  struct session *sp = lookup_session(&sender,ssrc);
  bool const new_session = (sp == NULL);
  if(sp == NULL && (sp = create_session(&sender,ssrc)) == NULL)
    return;
  decode_radio_status(&sp->frontend,&sp->chan,buffer+1,length-1);
  sp->frontend.description[sizeof sp->frontend.description - 1] = '\0';
  sp->last_status = gps_time_ns();
  int const type = sp->chan.output.rtp.type & 0x7f;
  sp->pt_table[type].encoding = sp->chan.output.encoding;
  sp->pt_table[type].samprate = sp->chan.output.samprate;
  sp->pt_table[type].channels = sp->chan.output.channels;
  if(new_session && Verbose)
    session_event(sp,0,"new channel: %s, %'d Hz, %d channels, %s, %s demod, filter %+.0f to %+.0f Hz, agc %s, from %s",
                  sp->frontend.description,sp->chan.output.samprate,sp->chan.output.channels,
                  encoding_string(sp->chan.output.encoding),demod_name_from_type(sp->chan.demod_type),
                  sp->chan.filter.min_IF,sp->chan.filter.max_IF,sp->chan.linear.agc ? "on" : "off",
                  formatsock(&sender,false));
  if(Follow)
    observe_radio(sp);
  if(!sp->warned && (sp->chan.output.channels != 2 || sample_size(sp->chan.output.encoding) == 0)){
    session_event(sp,0,"can't decode: need 2 channels (I/Q) of s16le, s16be, f32le or f32be; stream is %d channels %s",
                  sp->chan.output.channels,encoding_string(sp->chan.output.encoding));
    sp->warned = true;
  }
}

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
    return;
  struct rtp_header rtp;
  uint8_t const * const dp = ntoh_rtp(&rtp,buffer);
  size -= dp - buffer;
  if(size <= 0)
    return;
  if(rtp.pad){
    size -= dp[size-1];
    rtp.pad = 0;
  }
  if(size <= 0)
    return;
  if(Ssrc != 0 && rtp.ssrc != Ssrc)
    return;
  struct session * const sp = lookup_session(&sender,rtp.ssrc);
  if(sp == NULL)
    return;
  sp->last_data = gps_time_ns();
  atomic_fetch_add(&sp->packets,1);
  struct pt_table const * const pt = &sp->pt_table[rtp.type & 0x7f];
  int const sampsize = sample_size(pt->encoding);
  if(pt->channels != 2 || pt->samprate <= 0 || sampsize == 0){
    atomic_fetch_add(&sp->unusable,1);
    return;
  }
  int const frames = (int)(size / (2 * sampsize));
  if(frames <= 0)
    return;
  if(!sp->running && start_decoder(sp) != 0)
    return;
  if(pt->samprate != sp->samprate){
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

static void receive_packet(struct session *sp,struct rtp_header const *rtp,uint8_t const *data,int frames,enum encoding encoding){
  if(sp->rtp.odd_seq_set){
    if(rtp->seq == sp->rtp.odd_seq){
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
  }
  int16_t const seqdiff = rtp->seq - sp->rtp.seq;
  if(seqdiff < 0){
    atomic_fetch_add(&sp->dupes,1);
    sp->rtp.odd_seq = rtp->seq + 1;
    sp->rtp.odd_seq_set = true;
    return;
  } else if(seqdiff >= RESEQ){
    send_queue(sp,true);
    int16_t const lost = rtp->seq - sp->rtp.seq;
    if(lost >= RESEQ){
      atomic_fetch_add(&sp->drops,lost);
      sp->rtp.seq = rtp->seq;
    }
  }
  sp->rtp.odd_seq_set = false;
  struct block ** const qp = &sp->reseq[rtp->seq % RESEQ];
  if(*qp != NULL){
    atomic_fetch_add(&sp->dupes,1);
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

static void send_queue(struct session *sp,bool flush){
  for(int i=0; i < RESEQ; i++,sp->rtp.seq++){
    struct block ** const qp = &sp->reseq[sp->rtp.seq % RESEQ];
    struct block * const bp = *qp;
    if(bp == NULL){
      if(!flush || sp->pending == 0)
        break;
      atomic_fetch_add(&sp->drops,1);
      continue;
    }
    *qp = NULL;
    sp->pending--;
    int32_t const jump = (int32_t)(bp->timestamp - sp->rtp.timestamp);
    if(jump > 0 && !bp->marker){
      if(jump <= Max_fill * sp->samprate){
        struct block * const zp = new_block(sp,jump,sp->rtp.timestamp);
        if(zp != NULL){
          memset(zp->samples,0,jump * sizeof(zp->samples[0]));
          enqueue_block(sp,zp);
          atomic_fetch_add(&sp->filled,jump);
        }
      } else {
        atomic_fetch_add(&sp->resyncs,1);
        if(Verbose)
          session_event(sp,bp->time,"timestamp jump %'d samples (%.1f sec), resynchronizing",jump,(double)jump / sp->samprate);
      }
    } else if(jump < 0)
      atomic_fetch_add(&sp->resyncs,1);
    sp->rtp.timestamp = bp->timestamp + bp->count;
    enqueue_block(sp,bp);
  }
}

static struct block *new_block(struct session const *sp,int count,uint32_t timestamp){
  struct block * const bp = malloc(sizeof(*bp) + count * sizeof(bp->samples[0]));
  if(bp == NULL)
    return NULL;
  bp->next = NULL;
  bp->timestamp = timestamp;
  bp->marker = false;
  bp->samprate = sp->samprate;
  bp->frequency = sp->chan.tune.freq;
  bp->bb_power = sp->chan.sig.bb_power;
  bp->n0 = sp->chan.sig.n0;
  bp->low = sp->chan.filter.min_IF;
  bp->high = sp->chan.filter.max_IF;
  bp->time = session_time(sp,timestamp);
  bp->count = count;
  return bp;
}

static void enqueue_block(struct session *sp,struct block *bp){
  bp->next = NULL;
  pthread_mutex_lock(&sp->qmutex);
  if(sp->qsamples + bp->count > Max_queue * sp->samprate){
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

static int64_t session_time(struct session const *sp,uint32_t timestamp){
  if(sp->chan.clocktime == 0 || sp->samprate <= 0)
    return 0;
  return sp->chan.clocktime + (int64_t)BILLION * (int32_t)(timestamp - sp->chan.output.time_snap) / sp->samprate;
}

static bool was_asked(uint32_t ssrc);

static void scan_sessions(int64_t now){
  struct session *next = NULL;
  for(struct session *sp = Sessions; sp != NULL; sp = next){
    next = sp->next;
    int64_t const last = sp->running ? sp->last_data : sp->last_status;
    if(now - last >= Timeout * BILLION)
      close_session(sp,"idle timeout");
    else if(Follow && sp->running && now - sp->last_data >= BILLION && was_asked(sp->ssrc))
      // radiod sends a channel's I/Q without a break while it exists: a followed one whose data has
      // stopped is gone, and closing it now means that if it is asked for again, the new channel
      // (its own RTP timestamps, under the same SSRC) starts a session of its own, timed by its status
      close_session(sp,"followed channel released");
  }
}

static bool same_socket(struct sockaddr_storage const *a,struct sockaddr_storage const *b){
  return address_match(a,b) == 1 && getportnumber(a) == getportnumber(b);
}

static struct session *lookup_session(struct sockaddr_storage const *sender,uint32_t ssrc){
  struct session *sp;
  for(sp = Sessions; sp != NULL; sp = sp->next){
    if(sp->ssrc == ssrc && same_socket(&sp->sender,sender))
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

static struct session *create_session(struct sockaddr_storage const *sender,uint32_t ssrc){
  struct session * const sp = calloc(1,sizeof(*sp));
  if(sp == NULL)
    return NULL;
  sp->ssrc = ssrc;
  memcpy(&sp->sender,sender,sizeof(sp->sender));
  memcpy(sp->pt_table,PT_table,sizeof(sp->pt_table));
  sp->last_status = sp->last_data = gps_time_ns();
  pthread_mutex_init(&sp->qmutex,NULL);
  pthread_cond_init(&sp->qcond,NULL);
  atomic_init(&sp->terminate,false);
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
}

// ---------------------------------------------------------------------------
// Decoding

// One per channel: take blocks off the queue and run the carrier's decoder over them. A change of
// sample rate makes the decoder again
static void *decode_task(void *arg){
  struct session * const sp = (struct session *)arg;
  assert(sp != NULL);
  {
    char name[100];
    snprintf(name,sizeof(name),"dmr %u",sp->ssrc);
    pthread_setname(name);
  }
  struct decoder dec = {
    .sp = sp,
  };
  struct dmr_chan_handlers const h = {
    .frame = voice_frame,
    .event = voice_event,
    .log = voice_log,
    .arg = &dec,
  };
  snprintf(dec.channel_id,sizeof dec.channel_id,"%u",sp->ssrc);
  dec.system_name = "DMR";
  struct dmr_chan_config config;
  dmr_chan_config_init(&config);
  config.color_code = Color_code;
  config.mobile_station = config.direct = Mobile;
  config.channel_id = dec.channel_id;
  while(true){
    pthread_mutex_lock(&sp->qmutex);
    while(sp->queue == NULL && !atomic_load(&sp->terminate)){
      struct timespec deadline;
      calculate_deadline(&deadline,BILLION);
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
      break;

    dec.block_time = bp->time; // the control plane's clocks read it from here on
    if(dec.configured == NULL && dec.site == NULL){
      struct configured_channel *ch = NULL;
      dec.configured = find_site((uint64_t)llrint(bp->frequency),&ch);
      if(dec.configured != NULL){
        // One of the sites file's repeaters: the site and its log are shared with the site's other channels
        atomic_store(&ch->ssrc,sp->ssrc);
        strlcpy(dec.channel_id,ch->channel_id,sizeof dec.channel_id);
        dec.system_name = dec.configured->system_name;
        config.site = dec.configured->site;
        config.log = dec.configured->log;
        config.lcn = ch->lcn;
        config.color_code = dec.configured->color_code;
      }
    }
    if(dec.configured != NULL){
      int64_t latest = atomic_load(&dec.configured->latest);
      while(bp->time > latest && !atomic_compare_exchange_weak(&dec.configured->latest,&latest,bp->time))
        ;
    }
    if(dec.configured == NULL && dec.site == NULL){
      // The site and its log: named after the carrier, its clocks the signal's
      struct dmr_control_log_options lo;
      dmr_control_log_options_init(&lo);
      strlcpy(lo.system_name,"DMR",sizeof lo.system_name);
      snprintf(lo.site_name,sizeof lo.site_name,"%.4lf",bp->frequency * 1e-6);
      lo.clock_us = control_wall_clock;
      lo.clock_arg = &dec;
      dec.log = dmr_control_log_create(&lo,control_line,&dec);
      struct dmr_site_config sc;
      dmr_site_config_init(&sc);
      strlcpy(sc.system_name,lo.system_name,sizeof sc.system_name);
      strlcpy(sc.site_name,lo.site_name,sizeof sc.site_name);
      sc.type = System_type;
      // not a repeater of the sites file: a site of its own
      sc.system_color_code = Color_code; // -1 and -2 are the site's TRACK and ANY too
      struct dmr_site_options so;
      dmr_site_options_init(&so);
      so.clock_us = control_site_clock;
      so.clock_arg = &dec;
      so.warnings_to_stderr = false; // they are lines of the log already
      struct dmr_site_handlers sh = {
        .clear = control_clear,
        .follow = channel_follow,
        .arg = &dec,
      };
      dec.site = dmr_site_create(&sc,dec.log,&so,&sh);
      config.site = dec.site;
      config.log = dec.log;
    }
    if(bp->samprate != dec.samprate || (uint64_t)llrint(bp->frequency) != config.frequency_hz){
      config.frequency_hz = (uint64_t)llrint(bp->frequency);
      dmr_chan_destroy(dec.chan); // ends what is in progress: voice_event() runs in here
      dec.samprate = bp->samprate;
      dec.samples = 0;
      dec.next_report = (uint64_t)(Update * dec.samprate);
      dec.chan = dmr_chan_create(&config,dec.samprate,&h);
      if(dec.chan == NULL)
        fprintf(stderr,"ssrc %u: can't create DMR receiver at %'.0lf Hz (needs %d Hz)\n",sp->ssrc,dec.samprate,4 * DMR_SYMBOL_RATE);
    }
    dec.frequency = bp->frequency;
    dec.bb_power = bp->bb_power;
    dec.n0 = bp->n0;
    dec.low = bp->low;
    dec.high = bp->high;
    dmr_voter_set_signal(Voter,sp->ssrc,dec.frequency,dec.bb_power,dec.n0,dec.low,dec.high);
    if(dec.chan != NULL)
      dmr_chan_samples(dec.chan,bp->samples,bp->count,bp->time); // voice_frame(), voice_event() run in here
    if(Follow && dec.chan != NULL)
      keep_followed(&dec,bp->time);
    int64_t const end = bp->time != 0 ? bp->time + llrint(1e9 * bp->count / dec.samprate) : 0;
    dmr_voter_poll(Voter,end); // frames now due are played
    dec.samples += bp->count;
    FREE(bp);
    if(Verbose && Update > 0 && dec.samples >= dec.next_report){
      status_line(&dec);
      dec.next_report += (uint64_t)(Update * dec.samprate);
    }
  }
  dmr_chan_destroy(dec.chan); // ends what is in progress: voice_event() runs in here
  dmr_site_destroy(dec.site);  // only a site of its own: a configured one outlives the channel
  dmr_control_log_destroy(dec.log); // its pending counts are written here
  return NULL;
}

// The stream a frame goes to: a group call's talkgroup, else the channel's own for the slot
static uint32_t frame_ssrc(struct decoder const *dp,struct dmr_chan_frame const *f){
  if(f->group && f->destination != 0)
    return f->destination;
  return dp->sp->ssrc * 10 + f->slot;
}

// The stream's description, for monitor's display: who, then the repeater it is being heard from,
// e.g. DMR TG 97150 src 3107001 "W6XYZ Bob" 442.5375 MHz TS2 CC1
static void describe(char *buf,size_t size,struct decoder const *dp,struct dmr_chan_frame const *f){
  int n;
  if(f->destination == 0)
    n = snprintf(buf,size,"%s",dp->system_name);
  else
    n = snprintf(buf,size,"%s %s %u",dp->system_name,f->group ? "TG" : "unit",f->destination);
  if(n > 0 && (size_t)n < size && f->source != 0)
    n += snprintf(buf + n,size - n," src %u",f->source);
  if(n > 0 && (size_t)n < size && f->alias[0] != '\0')
    n += snprintf(buf + n,size - n," \"%s\"",f->alias);
  if(n > 0 && (size_t)n < size && f->emergency)
    n += snprintf(buf + n,size - n," emergency");
  if(n > 0 && (size_t)n < size)
    snprintf(buf + n,size - n," %.4f MHz TS%d CC%d",dp->frequency * 1e-6,f->slot,f->color_code);
}

// A frame the call tracker released. Only clear frames are heard: they go to the voter
static void voice_frame(void *arg,struct dmr_chan_frame const *f){
  struct decoder * const dp = arg;
  if(f->slot < 1 || f->slot > 2 || f->label != DMR_CHAN_CLEAR || Voter == NULL)
    return;
  struct slot * const s = &dp->slot[f->slot - 1];
  uint32_t const ssrc = frame_ssrc(dp,f);
  if(ssrc != s->ssrc){
    if(s->ssrc != 0)
      dmr_voter_source_end(Voter,s->ssrc,dp->sp->ssrc,f->slot); // the identity changed: a new stream
    s->ssrc = ssrc;
  }
  char desc[256];
  describe(desc,sizeof desc,dp,f);
  dmr_voter_frame(Voter,ssrc,dp->sp->ssrc * 10 + f->slot,desc,dp->sp->ssrc,f->slot,f->bits,f->when);
}

// A transmission started or ended on a slot
static void voice_event(void *arg,struct dmr_chan_event const *e){
  struct decoder * const dp = arg;
  char who[160] = "";
  if(e->destination != 0){
    int n = snprintf(who,sizeof who,"%s %u",e->group ? "TG" : "unit",e->destination);
    if(n > 0 && (size_t)n < sizeof who && e->source != 0)
      snprintf(who + n,sizeof who - n," src %u",e->source);
  } else
    strlcpy(who,"(no LC yet)",sizeof who);
  if(e->start)
    decoder_event(dp,e->when,"slot %d transmission start %s cc %d (%s)",e->slot,who,e->color_code,e->how != NULL ? e->how : "");
  else {
    decoder_event(dp,e->when,"slot %d transmission end %s: %s, %d frames %s",e->slot,who,e->how != NULL ? e->how : "",
                  e->frames,e->label != NULL ? e->label : "");
    if(e->slot >= 1 && e->slot <= 2){
      struct slot * const s = &dp->slot[e->slot - 1];
      if(s->ssrc != 0)
        dmr_voter_source_end(Voter,s->ssrc,dp->sp->ssrc,e->slot);
      s->ssrc = 0;
    }
  }
}

// A voted stream ended: how many frames each repeater supplied
// A line of the carrier's control log (CSBKs, link control, the site's identity, rest channel, grants
// and warnings), on the channel's thread. Repeats are collapsed into counts by the log. Its own
// timestamp is local time; ours is the signal's, as for every other line
// A control log line as dmrd writes it after its own time and channel: slot, colour code, kind, text,
// and a count line's "(xN since ..., last ...)". False for a line not written at this verbosity: link
// control (LC, SLC) says again what the transmission lines say, so it is written only at -v
static bool control_text(char *buf,size_t size,struct dmr_control_line const *line){
  if(!Verbose && (strcmp(line->kind,"LC") == 0 || strcmp(line->kind,"SLC") == 0))
    return false;
  char cc[8] = "-";
  if(line->color_code != DMR_NO_COLOR_CODE)
    snprintf(cc,sizeof cc,"%u",line->color_code);
  // "SLC NULL", not "SLC SLC NULL"
  size_t const k = strlen(line->kind);
  bool const named = strncmp(line->text,line->kind,k) == 0 && line->text[k] == ' ';
  // The count is in the formatted line only, after the text
  char const *count = "";
  if(line->repeats != 0 && line->formatted != NULL){
    char const * const t = strstr(line->formatted,line->text);
    if(t != NULL)
      count = t + strlen(line->text);
  }
  char slot[16] = "";
  if(line->slot != 0)
    snprintf(slot,sizeof slot,"slot %u ",line->slot);
  snprintf(buf,size,"%scc %s %s%s%s%s",slot,cc,named ? "" : line->kind,named ? "" : " ",line->text,count);
  return true;
}

static void control_line(void *arg,struct dmr_control_line const *line){
  struct decoder const * const dp = arg;
  char text[DMR_SITE_LINE_MAX + 64];
  if(control_text(text,sizeof text,line))
    decoder_event(dp,dp->block_time,"%s",text);
}

// A P_CLEAR: the site has released the slot, so its call has ended
static void control_clear(void *arg,struct dmr_site_context const *channel,uint8_t slot,char const *reason){
  (void)arg; (void)reason;
  dmr_chan_end_call(channel->user,slot);
}

// The control plane's clocks: the signal's time where radiod gives it, so that its grace periods and
// counts run with the signal and not with how fast it is decoded
static int64_t control_wall_clock(void *arg){
  struct decoder const * const dp = arg;
  int64_t const gps = dp->block_time != 0 ? dp->block_time : gps_time_ns();
  return gps / 1000 + ((int64_t)UNIX_EPOCH - GPS_UTC_OFFSET) * 1000000;
}
static uint64_t control_site_clock(void *arg){
  struct decoder * const dp = arg;
  int64_t const gps = dp->block_time != 0 ? dp->block_time : gps_time_ns();
  if((uint64_t)(gps / 1000) > dp->site_clock)
    dp->site_clock = (uint64_t)(gps / 1000);
  return dp->site_clock;
}

// ---------------------------------------------------------------------------
// The sites file (-f): one section per site, e.g.
//   [SCMTD 1]
//   system = SCMTD          (default: the section's name)
//   site = 1                (default: the section's name)
//   type = capacity_plus    (default: -y's, else conventional)
//   color-code = 0          (0-15, track, any; default: -c's)
//   freq = "453m4250 460m1375"   the site's repeater outputs
//   lcn = "1 2"             each one's logical channel number, in the same order (trunked systems)
// A channel whose frequency the file lists joins that site; any other is a site of its own

static char const *Site_keys[] = { "system", "site", "type", "color-code", "freq", "lcn", NULL };

static int parse_color_code(char const *s,int def){
  if(s == NULL)
    return def;
  if(strcmp(s,"any") == 0)
    return -2;
  if(strcmp(s,"track") == 0)
    return -1;
  char *ptr = NULL;
  long const x = strtol(s,&ptr,0);
  return (ptr == s || *ptr != '\0' || x < 0 || x > 15) ? -3 : (int)x;
}

static void load_sites(char const *file){
  dictionary *table = iniparser_load(file);
  if(table == NULL){
    fprintf(stderr,"Can't load sites file %s\n",file);
    exit(EX_NOINPUT);
  }
  int const nsect = iniparser_getnsec(table);
  Sites = calloc(nsect > 0 ? (size_t)nsect : 1,sizeof *Sites);
  assert(Sites != NULL);
  for(int sect=0; sect < nsect; sect++){
    char const * const name = iniparser_getsecname(table,sect);
    config_validate_section(stderr,table,name,Site_keys,NULL);
    struct configured_site * const cs = &Sites[Nsites];
    strlcpy(cs->system_name,config_getstring(table,name,"system",name),sizeof cs->system_name);
    strlcpy(cs->site_name,config_getstring(table,name,"site",name),sizeof cs->site_name);
    cs->color_code = parse_color_code(config_getstring(table,name,"color-code",NULL),Color_code);
    enum dmr_system_type type = System_type;
    char const * const t = config_getstring(table,name,"type",NULL);
    if(cs->color_code < -2 || (t != NULL && !dmr_system_type_from_name(t,&type))){
      fprintf(stderr,"%s [%s]: bad %s\n",file,name,cs->color_code < -2 ? "color-code (0-15, track or any)" : "type");
      exit(EX_USAGE);
    }
    // The frequencies, and their LCNs
    char const * const freqs = config_getstring(table,name,"freq",NULL);
    char const * const lcns = config_getstring(table,name,"lcn","");
    if(freqs == NULL){
      fprintf(stderr,"%s [%s]: no freq: skipped\n",file,name);
      continue;
    }
    char fbuf[4096],lbuf[4096];
    strlcpy(fbuf,freqs,sizeof fbuf);
    strlcpy(lbuf,lcns,sizeof lbuf);
    char *fsave = NULL,*lsave = NULL;
    for(char *f = strtok_r(fbuf," \t,\"",&fsave); f != NULL; f = strtok_r(NULL," \t,\"",&fsave)){
      char const * const l = strtok_r(cs->nchannels == 0 ? lbuf : NULL," \t,\"",&lsave);
      double const hz = parse_frequency(f,false);
      if(hz <= 0){
        fprintf(stderr,"%s [%s]: bad frequency %s\n",file,name,f);
        exit(EX_USAGE);
      }
      cs->channels = realloc(cs->channels,(size_t)(cs->nchannels + 1) * sizeof *cs->channels);
      assert(cs->channels != NULL);
      struct configured_channel * const ch = &cs->channels[cs->nchannels++];
      memset(ch,0,sizeof *ch);
      ch->frequency_hz = (uint64_t)llrint(hz);
      ch->lcn = l != NULL ? (uint16_t)strtoul(l,NULL,0) : 0;
      snprintf(ch->channel_id,sizeof ch->channel_id,"%.4lf",hz * 1e-6);
    }
    // The site, its plan and its log
    struct dmr_site_channel_config *plan = calloc((size_t)cs->nchannels,sizeof *plan);
    assert(plan != NULL);
    for(int i=0; i < cs->nchannels; i++){
      dmr_site_channel_config_init(&plan[i]);
      plan[i].lcn = cs->channels[i].lcn;
      plan[i].frequency_hz = cs->channels[i].frequency_hz;
      strlcpy(plan[i].channel_id,cs->channels[i].channel_id,sizeof plan[i].channel_id);
    }
    struct dmr_control_log_options lo;
    dmr_control_log_options_init(&lo);
    strlcpy(lo.system_name,cs->system_name,sizeof lo.system_name);
    strlcpy(lo.site_name,cs->site_name,sizeof lo.site_name);
    lo.clock_us = site_wall_clock;
    lo.clock_arg = cs;
    cs->log = dmr_control_log_create(&lo,site_line,cs);
    struct dmr_site_config sc;
    dmr_site_config_init(&sc);
    strlcpy(sc.system_name,cs->system_name,sizeof sc.system_name);
    strlcpy(sc.site_name,cs->site_name,sizeof sc.site_name);
    sc.type = type;
    sc.system_color_code = cs->color_code;
    sc.nchannels = cs->nchannels;
    sc.channels = plan;
    struct dmr_site_options so;
    dmr_site_options_init(&so);
    so.clock_us = site_site_clock;
    so.clock_arg = cs;
    so.warnings_to_stderr = false;
    struct dmr_site_handlers const sh = {
      .clear = control_clear,
      .follow = site_follow,
      .arg = cs,
    };
    cs->site = dmr_site_create(&sc,cs->log,&so,&sh);
    free(plan);
    if(cs->site == NULL || cs->log == NULL){
      fprintf(stderr,"%s [%s]: can't create the site\n",file,name);
      exit(EX_SOFTWARE);
    }
    if(Verbose)
      fprintf(stderr,"site %s/%s: %s, %d channels\n",cs->system_name,cs->site_name,dmr_system_type_name(type),cs->nchannels);
    Nsites++;
  }
  iniparser_freedict(table);
}

static void free_sites(void){
  for(int i=0; i < Nsites; i++){
    dmr_site_destroy(Sites[i].site);
    dmr_control_log_destroy(Sites[i].log);
    free(Sites[i].channels);
  }
  free(Sites);
  Sites = NULL;
  Nsites = 0;
}

// The configured site and channel of a carrier, by its frequency (within 1 kHz); NULL if none
static struct configured_site *find_site(uint64_t frequency_hz,struct configured_channel **channel){
  for(int i=0; i < Nsites; i++){
    for(int j=0; j < Sites[i].nchannels; j++){
      uint64_t const f = Sites[i].channels[j].frequency_hz;
      if((f > frequency_hz ? f - frequency_hz : frequency_hz - f) <= 1000){
        *channel = &Sites[i].channels[j];
        return &Sites[i];
      }
    }
  }
  return NULL;
}

// A line of a configured site's control log, on the thread of the channel that wrote it. Lines about
// a channel carry its SSRC and frequency, as every other line; lines about the site its name
static void site_line(void *arg,struct dmr_control_line const *line){
  struct configured_site const * const cs = arg;
  int64_t const when = atomic_load(&cs->latest);
  char text[DMR_SITE_LINE_MAX + 64];
  if(!control_text(text,sizeof text,line))
    return;
  for(int j=0; j < cs->nchannels; j++){
    struct configured_channel const * const ch = &cs->channels[j];
    if(strcmp(ch->channel_id,line->channel_id) == 0){
      char ts[100];
      format_gpstime(ts,sizeof ts,when != 0 ? when : gps_time_ns());
      pthread_mutex_lock(&Output_mutex);
      fprintf(stdout,"%s ssrc %u %.6lf MHz %s\n",ts,atomic_load(&ch->ssrc),ch->frequency_hz * 1e-6,text);
      pthread_mutex_unlock(&Output_mutex);
      return;
    }
  }
  char ts[100];
  format_gpstime(ts,sizeof ts,when != 0 ? when : gps_time_ns());
  pthread_mutex_lock(&Output_mutex);
  fprintf(stdout,"%s site %s/%s %s\n",ts,cs->system_name,cs->site_name,text);
  pthread_mutex_unlock(&Output_mutex);
}

// A configured site's clocks: the latest signal time its channels have decoded (they share radiod's
// time base), so they run with the signal as a single channel's do
static int64_t site_wall_clock(void *arg){
  struct configured_site const * const cs = arg;
  int64_t const latest = atomic_load(&cs->latest);
  int64_t const gps = latest != 0 ? latest : gps_time_ns();
  return gps / 1000 + ((int64_t)UNIX_EPOCH - GPS_UTC_OFFSET) * 1000000;
}
static uint64_t site_site_clock(void *arg){
  struct configured_site * const cs = arg;
  int64_t const latest = atomic_load(&cs->latest);
  uint64_t const now = (uint64_t)((latest != 0 ? latest : gps_time_ns()) / 1000);
  uint64_t prev = atomic_load(&cs->site_clock);
  while(now > prev && !atomic_compare_exchange_weak(&cs->site_clock,&prev,now))
    ;
  return now > prev ? now : prev;
}

// ---------------------------------------------------------------------------
// Call following. A site announces each voice call on one of its repeaters (dmr_site_handlers.follow:
// a Capacity Plus Site Status, a grant, their repeats). When no decoder is on that repeater, dmrd asks
// a radiod for a channel there, in the form of the I/Q channels it already decodes from that radiod
// (chanctl.c), for Hold seconds; each repeat of the announcement asks again, and the followed channel's
// decoder keeps it while it carries voice. Its I/Q then arrives like any other channel's, joins the
// site by its frequency, and is decoded and voted as the rest. Repeaters radiod already carries (its
// configured channels, and channels someone else asked for) are left as they are

// The radiod a status packet came from: its command handle, and the format to ask for channels in
static void observe_radio(struct session *sp){
  struct sockaddr_storage const *control = &sp->frontend.metadata_dest_socket;
  if(control->ss_family != AF_INET && control->ss_family != AF_INET6)
    return; // radiod's command address isn't known (yet)
  pthread_mutex_lock(&Ctl_mutex);
  struct radio *r = NULL;
  for(int i=0; i < Nradios && r == NULL; i++){
    if(address_match(&Radios[i].control,control) == 1 && getportnumber(&Radios[i].control) == getportnumber(control))
      r = &Radios[i];
  }
  if(r == NULL && Nradios < MAX_RADIOS){
    struct chanctl * const ctl = chanctl_create(control,Default_mcast_iface,Ctl_ttl);
    if(ctl == NULL)
      fprintf(stderr,"%s: can't open radiod command channel %s: %s\n",App_path,formatsock(control,false),strerror(errno));
    else {
      r = &Radios[Nradios++];
      memset(r,0,sizeof *r);
      r->control = *control;
      r->ctl = ctl;
      if(Verbose)
        fprintf(stderr,"%s: radiod commands to %s\n",App_path,formatsock(control,false));
    }
  }
  if(r != NULL){
    chanctl_observe(r->ctl,&sp->frontend,&sp->chan);
    if(!r->have_format && !chanctl_ours(r->ctl,sp->ssrc) && sp->chan.output.channels == 2
       && sample_size(sp->chan.output.encoding) != 0)
      r->have_format = chanctl_format(&r->format,&sp->frontend,&sp->chan) == 0;
  }
  pthread_mutex_unlock(&Ctl_mutex);
}

// Ask for the repeater an announcement names, unless a decoder is already on it that dmrd did not ask
// for. 'who' and 'when' are for the line written when a channel is first asked for
static void follow(char const *who,int64_t when,struct dmr_follow const *f){
  if(f->frequency_hz == 0)
    return; // nowhere to tune: the site has logged it
  char text[256] = "";
  pthread_mutex_lock(&Ctl_mutex);
  for(int i=0; i < Nradios; i++){
    struct radio * const r = &Radios[i];
    if(!r->have_format)
      continue;
    uint32_t const ssrc = chanctl_ssrc(r->ctl,(double)f->frequency_hz,&r->format);
    int asked = -1;
    for(int j=0; j < Nasked && asked < 0; j++)
      if(Asked[j].ssrc == ssrc)
        asked = j;
    if(f->attached && asked < 0)
      break; // a channel radiod carries anyway: nothing to do
    errno = 0;
    int const rc = chanctl_request(r->ctl,ssrc,(double)f->frequency_hz,&r->format,Hold);
    if(rc < 0 && errno == ERANGE)
      continue; // outside this radiod's front end: the next
    if(rc >= 0 && asked < 0 && Nasked < MAX_ASKED){
      asked = Nasked++;
      Asked[asked].ssrc = ssrc;
      Asked[asked].logged = 0;
    }
    // A line when the channel is asked for while no decoder is on it (at most every 2 s: the
    // announcements repeat until its I/Q arrives)
    bool log = false;
    int64_t const now_ns = gps_time_ns();
    if(rc >= 0 && !f->attached && asked >= 0 && now_ns - Asked[asked].logged >= 2 * (int64_t)BILLION){
      Asked[asked].logged = now_ns;
      log = true;
    }
    static int64_t last_error; // one error line every 30 s: announcements repeat several times a second
    if(rc < 0 && gps_time_ns() - last_error >= 30 * (int64_t)BILLION){
      last_error = gps_time_ns();
      snprintf(text,sizeof text,"can't follow %.6lf MHz: %s",f->frequency_hz * 1e-6,strerror(errno));
    }
    else if(log){
      char lcn[16] = "",ts[8] = "";
      if(f->lcn != 0)
        snprintf(lcn,sizeof lcn," LCN %u",f->lcn);
      if(f->timeslot == 1 || f->timeslot == 2)
        snprintf(ts,sizeof ts," TS%u",f->timeslot);
      snprintf(text,sizeof text,"follow %.6lf MHz%s%s ssrc %u: %s",f->frequency_hz * 1e-6,lcn,ts,ssrc,f->what);
    }
    break;
  }
  pthread_mutex_unlock(&Ctl_mutex);
  if(text[0] != '\0'){
    char ts[100];
    format_gpstime(ts,sizeof ts,when != 0 ? when : gps_time_ns());
    pthread_mutex_lock(&Output_mutex);
    fprintf(stdout,"%s %s %s\n",ts,who,text);
    pthread_mutex_unlock(&Output_mutex);
  }
}

static void site_follow(void *arg,struct dmr_site *site,struct dmr_follow const *f){
  (void)site;
  struct configured_site const * const cs = arg;
  if(!Follow)
    return;
  char who[2 * DMR_SITE_NAME_MAX + 8];
  snprintf(who,sizeof who,"site %s/%s",cs->system_name,cs->site_name);
  follow(who,atomic_load(&cs->latest),f);
}
static void channel_follow(void *arg,struct dmr_site *site,struct dmr_follow const *f){
  (void)site;
  struct decoder const * const dp = arg;
  if(!Follow)
    return;
  char who[64];
  snprintf(who,sizeof who,"ssrc %u %.6lf MHz",dp->sp->ssrc,dp->frequency * 1e-6);
  follow(who,dp->block_time,f);
}

static bool was_asked(uint32_t ssrc){
  pthread_mutex_lock(&Ctl_mutex);
  bool asked = false;
  for(int j=0; j < Nasked && !asked; j++)
    asked = Asked[j].ssrc == ssrc;
  pthread_mutex_unlock(&Ctl_mutex);
  return asked;
}

// A followed channel is kept while it carries voice, checked twice a second. Not any burst: a repeater
// that is also a rest channel sends its beacons between calls
static void keep_followed(struct decoder *dp,int64_t now){
  if(now == 0 || now < dp->next_refresh)
    return;
  dp->next_refresh = now + BILLION / 2;
  struct dmr_chan_stats st;
  dmr_chan_get_stats(dp->chan,&st);
  if(st.voice_bursts == dp->refresh_voice)
    return;
  dp->refresh_voice = st.voice_bursts;
  pthread_mutex_lock(&Ctl_mutex);
  for(int i=0; i < Nradios; i++){
    if(chanctl_ours(Radios[i].ctl,dp->sp->ssrc)){
      chanctl_refresh(Radios[i].ctl,dp->sp->ssrc);
      break;
    }
  }
  pthread_mutex_unlock(&Ctl_mutex);
}

static void vote_end(void *arg,struct dmr_vote_result const *r){
  (void)arg;
  char text[512];
  int n = snprintf(text,sizeof text,"stream %u ended: %d frames played, %d lost;",r->ssrc,r->frames,r->lost);
  for(int i=0; i < r->sources && n > 0 && (size_t)n < sizeof text; i++)
    n += snprintf(text + n,sizeof text - n," %u slot %d chose %d of %d (%d corrections)%s",r->source[i].channel,
                  r->source[i].slot,r->source[i].chosen,r->source[i].frames,r->source[i].fec,
                  r->source[i].aligned ? "" : " unaligned");
  pthread_mutex_lock(&Output_mutex);
  char timestring[100];
  format_gpstime(timestring,sizeof(timestring),gps_time_ns());
  fprintf(stdout,"%s %s\n",timestring,text);
  pthread_mutex_unlock(&Output_mutex);
}

static void voice_log(void *arg,int64_t when,char const *text){
  struct decoder * const dp = arg;
  if(Verbose)
    decoder_event(dp,when,"%s",text);
}

static void status_line(struct decoder const *dp){
  struct dmr_chan_stats st;
  memset(&st,0,sizeof st);
  dmr_chan_get_stats(dp->chan,&st);
  decoder_event(dp,0,"bursts %'llu syncs %'llu acquisitions %'llu voice %'llu frames clear %'llu encrypted %'llu unconfirmed %'llu cc %d offset %+.0f Hz",
                (unsigned long long)st.bursts,(unsigned long long)st.syncs,(unsigned long long)st.acquisitions,
                (unsigned long long)st.voice_bursts,(unsigned long long)st.frames_clear,(unsigned long long)st.frames_encrypted,
                (unsigned long long)st.frames_unconfirmed,st.color_code,st.frequency_offset);
}

// ---------------------------------------------------------------------------
// Helpers, as p25d's

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

static int convert_iq(float complex *out,uint8_t const *in,int frames,enum encoding encoding){
  float * const fp = (float *)out;
  size_t const count = 2 * (size_t)frames;
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

// Logging, as p25d's: one line per event on standard output
//   Mon 23 Nov 2026 21:02:03.123456 UTC ssrc 453425 453.425000 MHz <event text>
static void log_event(uint32_t ssrc,double frequency,int64_t when,char const *fmt,va_list ap){
  char timestring[100];
  format_gpstime(timestring,sizeof(timestring),when != 0 ? when : gps_time_ns());
  pthread_mutex_lock(&Output_mutex);
  fprintf(stdout,"%s ssrc %u %.6lf MHz ",timestring,ssrc,frequency * 1e-6);
  vfprintf(stdout,fmt,ap);
  fputc('\n',stdout);
  pthread_mutex_unlock(&Output_mutex);
}

static void session_event(struct session const *sp,int64_t when,char const *fmt,...){
  va_list ap;
  va_start(ap,fmt);
  log_event(sp->ssrc,sp->chan.tune.freq,when,fmt,ap);
  va_end(ap);
}

static void decoder_event(struct decoder const *dp,int64_t when,char const *fmt,...){
  va_list ap;
  va_start(ap,fmt);
  log_event(dp->sp->ssrc,dp->frequency,when,fmt,ap);
  va_end(ap);
}
