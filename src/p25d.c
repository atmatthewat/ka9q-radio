// P25 decoder daemon for ka9q-radio
// Reads complex baseband (I/Q) RTP streams from radiod, runs one P25 Phase 1 receiver per SSRC
// and logs what it decodes, one timestamped line per event, on standard output
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
#include "p25p1.h"
#include "p25msg.h"

#define MAX_MCAST 20   // Maximum number of input groups
#define RESEQ 32       // Resequencing queue, packets. radiod sends one to three packets per 20 ms block

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

// Tuning constants
static double const Max_fill = 1.0;   // Fill gaps up to this many seconds with zeroes; resynchronize on longer ones
static double const Max_queue = 5.0;  // Seconds of samples queued to a decoder before blocks are dropped

// Global variables
static int Data_fd[MAX_MCAST];
static int Status_fd[MAX_MCAST];
static struct session *Sessions;
static pthread_mutex_t Output_mutex = PTHREAD_MUTEX_INITIALIZER; // One line at a time on stdout
static volatile sig_atomic_t Terminate;
static volatile sig_atomic_t Signal;

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

static struct option Options[] = {
  {"iface", required_argument, NULL, 'A'},
  {"input", required_argument, NULL, 'I'},
  {"locale", required_argument, NULL, 'l'},
  {"source", required_argument, NULL, 'o'},
  {"ssrc", required_argument, NULL, 'S'},
  {"timeout", required_argument, NULL, 't'},
  {"update", required_argument, NULL, 'u'},
  {"verbose", no_argument, NULL, 'v'},
  {"version", no_argument, NULL, 'V'},
  {NULL, 0, NULL, 0},
};
static char const Optstring[] = "A:I:l:o:S:t:u:vV";

static void usage(void){
  fprintf(stderr,"Usage: %s [-v|--verbose] [-V|--version] [-l|--locale locale] [-A|--iface interface] [-o|--source <source-name-or-address>] [-S|--ssrc ssrc] [-t|--timeout seconds] [-u|--update seconds] [-I|--input] iq_mcast_address [iq_mcast_address ...]\n",App_path);
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
    case 'l':
      Locale = optarg;
      break;
    case 'o':
      Source = optarg;
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
  // Graceful signal catch
  signal(SIGINT,closedown);
  signal(SIGQUIT,closedown);
  signal(SIGTERM,closedown);
  signal(SIGPIPE,SIG_IGN);
  signal(SIGUSR1,verbosity);
  signal(SIGUSR2,verbosity);

  input_loop(); // Returns on a signal
  cleanup();
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

    if(bp->samprate != dec.samprate){
      // First block, or the sample rate changed
      if(dec.p25 != NULL)
	delete_p25p1(dec.p25);
      dec.samprate = bp->samprate;
      dec.samples = 0;
      dec.next_report = (uint64_t)(Update * dec.samprate);
      dec.p25 = create_p25p1(dec.samprate);
      if(dec.p25 == NULL)
	fprintf(stderr,"ssrc %u: can't create P25 receiver at %'.0lf Hz (needs at least %d Hz)\n",
		sp->ssrc,dec.samprate,4 * P25_SYMRATE);
      else
	p25p1_set_frame_handler(dec.p25,decoder_frame,&dec);
      p25_bandplan_init(&dec.plan);
    }
    dec.frequency = bp->frequency;
    dec.block_time = bp->time;
    dec.block_start = dec.samples;
    if(dec.p25 != NULL){
      p25p1_samples(dec.p25,bp->samples,bp->count); // decoder_frame() runs in here
    }
    dec.samples += bp->count;
    FREE(bp);
    if(Verbose && Update > 0 && dec.samples >= dec.next_report){
      status_line(&dec);
      dec.next_report += (uint64_t)(Update * dec.samprate);
    }
  }
  if(dec.p25 != NULL)
    delete_p25p1(dec.p25);
  return NULL;
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
      if(p25_decode_tsbk(&msg,tsbk) == 0)
	log_message(dp,sample,frame,&msg,frame->crc == 1 ? " (1 bit corrected)" : "");
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
      if(p25_decode_pdu(&msg,octets,frame->pdu->nbits / 8) == 0)
	log_message(dp,sample,frame,&msg,"");
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
  decoder_event(dp,dp->samples,"status: %s, offset %+.1f Hz, syncs %'llu weak %'llu, TSBK %'llu bad %'llu, LDU %'llu, words bad %'llu, %'.0lf Hz, packets %'llu drops %'llu dupes %'llu filled %'llu resyncs %'llu overruns %'llu",
		st.locked ? "locked" : "searching",st.frequency_offset,
		(unsigned long long)st.syncs,(unsigned long long)st.weak_syncs,
		(unsigned long long)(st.tsbk_ok + st.tsbk_fixed),(unsigned long long)st.tsbk_bad,
		(unsigned long long)(st.ldu1 + st.ldu2),(unsigned long long)st.word_bad,
		dp->samprate,
		(unsigned long long)atomic_load(&sp->packets),(unsigned long long)atomic_load(&sp->drops),
		(unsigned long long)atomic_load(&sp->dupes),(unsigned long long)atomic_load(&sp->filled),
		(unsigned long long)atomic_load(&sp->resyncs),(unsigned long long)atomic_load(&sp->overruns));
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
