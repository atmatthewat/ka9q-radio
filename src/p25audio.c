// Voice output for the P25 decoder: IMBE vocoder (mbelib, optional) and per-channel RTP audio
// streams with radiod-style status, so monitor plays them and pcmrecord records them
// Copyright 2026, Matthew Kaufman, KA6SQG

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef HAVE_MBELIB
#include <mbelib.h>
#endif

#include "misc.h"
#include "multicast.h"
#include "rtp.h"
#include "status.h"
#include "timing.h"
#include "avahi.h"
#include "p25msg.h"
#include "p25audio.h"

// One IMBE frame is 20 ms; the RTP clock is the sender's clock at 8 kHz
#define NS_PER_SAMPLE (BILLION / P25_AUDIO_SAMPRATE)          // 125,000
#define FRAME_NS ((int64_t)P25_AUDIO_FRAME * NS_PER_SAMPLE)   // 20 ms
#define LDU_NS (P25_IMBE_FRAMES * FRAME_NS)                   // 180 ms
#define LDU_DIBITS (P25_SYMRATE * LDU_NS / BILLION)          // 864 dibits from one voice data unit to the next

static int64_t const Hang = BILLION / 2;  // A gap in voice longer than this ends the transmission
static int const Status_interval = 25;    // Data packets between status packets: radiod's default 'update' (defaults.h)
#ifdef HAVE_MBELIB
static int const Max_repeats = 3;         // Consecutive frame repeats before muting, as mbelib and jmbe do
static int const Uvquality = 3;           // mbelib unvoiced synthesis quality, as its own programs use
static float const Mbe_gain = 7;          // mbelib's float output to 16-bit PCM, as its mbe_floattoshort()
#endif

// ---------------------------------------------------------------------------
// Vocoder

struct p25_vocoder {
  enum p25_codec codec;
  float error_rate;        // epsilon R of TIA-102.BABA
  int repeats;             // consecutive frames repeated
#ifdef HAVE_MBELIB
  mbe_parms cur,prev,enhanced;
#endif
};

char const *p25_vocoder_name(enum p25_codec codec){
#ifdef HAVE_MBELIB
  if(codec == P25_CODEC_IMBE)
    return "mbelib " MBELIB_VERSION;
#endif
  (void)codec;
  return NULL;
}

struct p25_vocoder *p25_vocoder_create(enum p25_codec codec){
  if(p25_vocoder_name(codec) == NULL)
    return NULL;
  struct p25_vocoder *v = calloc(1,sizeof *v);
  if(v == NULL)
    return NULL;
  v->codec = codec;
  p25_vocoder_reset(v);
  return v;
}

void p25_vocoder_reset(struct p25_vocoder *v){
  if(v == NULL)
    return;
  v->error_rate = 0;
  v->repeats = 0;
#ifdef HAVE_MBELIB
  mbe_initMbeParms(&v->cur,&v->prev,&v->enhanced);
#endif
}

void p25_vocoder_destroy(struct p25_vocoder *v){
  FREE(v);
}

// TIA-102.BABA: eR = 0.95 eR + 0.000365 eT; repeat the previous frame when e0 >= 2 and
// eT >= 10 + 40 eR (or when the fundamental frequency is invalid); mute while eR > 0.0875,
// and after more than three repeats in a row
enum p25_voice p25_vocoder_decode(struct p25_vocoder *v,int16_t pcm[P25_AUDIO_FRAME],uint8_t const *bits,int e0,int total){
  assert(v != NULL && pcm != NULL);
  bool repeat = true; // a lost frame is repeated
  if(bits != NULL){
    v->error_rate = 0.95f * v->error_rate + 0.000365f * total;
    repeat = e0 >= 2 && total >= 10 + 40 * v->error_rate;
  }
  bool const mute = v->error_rate > 0.0875f;
#ifdef HAVE_MBELIB
  if(!repeat && !mute){
    char d[P25_IMBE_INFO_BITS]; // u0 .. u7, each msb first, which is mbelib's imbe_d[] order
    for(int i=0; i < P25_IMBE_INFO_BITS; i++)
      d[i] = (char)(bits[i] & 1);
    if(mbe_decodeImbe4400Parms(d,&v->cur,&v->prev) != 0)
      repeat = true; // invalid fundamental or harmonic count
  }
  if(repeat){
    mbe_useLastMbeParms(&v->cur,&v->prev);
    v->repeats++;
  } else
    v->repeats = 0;
  if(mute || v->repeats > Max_repeats){
    memset(pcm,0,P25_AUDIO_FRAME * sizeof pcm[0]);
    mbe_initMbeParms(&v->cur,&v->prev,&v->enhanced);
    return P25_VOICE_MUTED;
  }
  // The rest of mbe_processImbe4400Dataf(), whose own repeat rule is 'more than 5 bits corrected'
  float f[P25_AUDIO_FRAME];
  mbe_moveMbeParms(&v->cur,&v->prev);
  mbe_spectralAmpEnhance(&v->cur);
  mbe_synthesizeSpeechf(f,&v->cur,&v->enhanced,Uvquality);
  mbe_moveMbeParms(&v->cur,&v->enhanced);
  for(int i=0; i < P25_AUDIO_FRAME; i++){
    float const s = Mbe_gain * f[i];
    pcm[i] = (int16_t)(s > 32767 ? 32767 : s < -32767 ? -32767 : lrintf(s));
  }
  return repeat ? P25_VOICE_REPEAT : P25_VOICE_SPEECH;
#else
  (void)repeat; (void)mute;
  memset(pcm,0,P25_AUDIO_FRAME * sizeof pcm[0]);
  return P25_VOICE_MUTED;
#endif
}

// ---------------------------------------------------------------------------
// Output group, shared by every channel

struct p25_audio_group {
  int fd;                               // unconnected: data and status leave from the same port, as from radiod
  struct sockaddr_storage data;         // group:5004
  struct sockaddr_storage status;       // group:5006
  int ttl;
  uint8_t pt;                           // RTP payload type for 8 kHz mono s16be
  atomic_flag send_error_logged;
};

static socklen_t socklen(struct sockaddr_storage const *s){
  return s->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
}

struct p25_audio_group *p25_audio_open(char const *target,char const *iface,int ttl,int tos,char const *service_name){
  if(target == NULL || strlen(target) == 0)
    return NULL;
  struct p25_audio_group *g = calloc(1,sizeof *g);
  if(g == NULL)
    return NULL;
  atomic_flag_clear(&g->send_error_logged);
  // Split "name[:port][,iface]" as resolve_mcast() does
  char host[256];
  strlcpy(host,target,sizeof host);
  char ifname[256] = {0};
  char *cp = strrchr(host,',');
  if(cp != NULL){
    *cp++ = '\0';
    strlcpy(ifname,cp,sizeof ifname);
  }
  int port = DEFAULT_RTP_PORT;
  struct in6_addr v6;
  if(inet_pton(AF_INET6,host,&v6) == 1){
    struct sockaddr_in6 * const sin6 = (struct sockaddr_in6 *)&g->data;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = v6;
  } else {
    if((cp = strrchr(host,':')) != NULL){
      *cp++ = '\0';
      port = atoi(cp);
    }
    struct sockaddr_in * const sin = (struct sockaddr_in *)&g->data;
    sin->sin_family = AF_INET;
    if(inet_pton(AF_INET,host,&sin->sin_addr) != 1){
      // A name: hash it into 239.0.0.0/8 and advertise it, as radiod does for its output streams
      uint32_t const addr = make_maddr(host);
      sin->sin_addr.s_addr = htonl(addr);
      if(service_name != NULL){
        char ttlmsg[128];
        snprintf(ttlmsg,sizeof ttlmsg,"TTL=%d",ttl);
        avahi_start(service_name,"_rtp._udp",DEFAULT_RTP_PORT,host,addr,ttlmsg);
      }
    }
  }
  setport(&g->data,port);
  g->status = g->data;
  setport(&g->status,DEFAULT_STAT_PORT);
  g->ttl = ttl;
  if(strlen(ifname) == 0 && iface != NULL)
    strlcpy(ifname,iface,sizeof ifname);
  g->fd = output_mcast(&g->data,strlen(ifname) > 0 ? ifname : NULL,ttl,tos);
  if(g->fd < 0){
    fprintf(stderr,"p25 audio: can't set up output to %s: %s\n",target,strerror(errno));
    FREE(g);
    return NULL;
  }
  int const pt = pt_from_info(P25_AUDIO_SAMPRATE,1,S16BE); // 125, a static entry
  if(pt < 0){
    fprintf(stderr,"p25 audio: no RTP payload type for %d Hz mono s16be\n",P25_AUDIO_SAMPRATE);
    close(g->fd);
    FREE(g);
    return NULL;
  }
  g->pt = (uint8_t)pt;
  return g;
}

void p25_audio_close(struct p25_audio_group *g){
  if(g == NULL)
    return;
  close(g->fd);
  FREE(g);
}

// ---------------------------------------------------------------------------
// One channel's stream

struct p25_audio {
  struct p25_audio_group *group;
  struct p25_vocoder *vocoder;
  uint32_t ssrc;
  uint16_t seq;
  uint32_t timestamp;      // RTP timestamp of the next sample
  int64_t next_time;       // sender's time of that sample; timestamp == next_time / NS_PER_SAMPLE
  bool active;             // in a transmission
  bool marker;             // the next packet starts one
  int status_count;        // data packets until the next status

  // What the status carries
  double frequency;
  uint16_t nac;
  bool have_call;
  bool unit_call;          // unit to unit: 'target' is a unit, else a talkgroup
  uint32_t target;
  uint32_t source;
  bool encrypted;          // seen in this call; stays set until the call ends, so no part of it is decoded
  int64_t last_unit;       // time at the end of the last voice data unit, decoded or not
  uint64_t last_dibit;     // receiver's dibit count at the end of the last one decoded
  char description[128];
  double energy;           // sum of squared samples (full scale 1) since the last status
  int64_t energy_samples;
  uint64_t samples;        // sent

  struct p25_audio_stats stats;
};

struct p25_audio *p25_audio_create(struct p25_audio_group *g,uint32_t ssrc){
  if(g == NULL)
    return NULL;
  struct p25_audio *a = calloc(1,sizeof *a);
  if(a == NULL)
    return NULL;
  a->vocoder = p25_vocoder_create(P25_CODEC_IMBE);
  if(a->vocoder == NULL){
    FREE(a);
    return NULL; // built without a vocoder
  }
  a->group = g;
  a->ssrc = ssrc;
  a->seq = (uint16_t)random();
  return a;
}

void p25_audio_destroy(struct p25_audio *a){
  if(a == NULL)
    return;
  p25_audio_end(a);
  p25_vocoder_destroy(a->vocoder);
  FREE(a);
}

void p25_audio_get_stats(struct p25_audio const *a,struct p25_audio_stats *stats){
  if(a != NULL && stats != NULL)
    *stats = a->stats;
}

static void send_error(struct p25_audio *a,char const *what){
  a->stats.errors++;
  if(!atomic_flag_test_and_set(&a->group->send_error_logged))
    fprintf(stderr,"p25 audio ssrc %u: %s send failed: %s (further messages suppressed)\n",a->ssrc,what,strerror(errno));
}

static void make_description(struct p25_audio *a){
  char *cp = a->description;
  size_t room = sizeof a->description;
  int n = 0;
  if(a->have_call){
    if(a->unit_call)
      n = snprintf(cp,room,"P25 unit %u",a->target);
    else
      n = snprintf(cp,room,"P25 TG %u",a->target);
    if(n > 0 && (size_t)n < room && a->source != 0)
      n += snprintf(cp + n,room - n," src %u",a->source);
  } else
    n = snprintf(cp,room,"P25 NAC %03x",a->nac);
  if(n > 0 && (size_t)n < room && a->encrypted)
    snprintf(cp + n,room - n," encrypted");
}

// Channel status in radiod's format (radio_status.c encode_radio_status()), with the fields
// monitor and pcmrecord use. 'closing': output level -infinity, as radiod sends when its squelch closes
static void send_status(struct p25_audio *a,bool closing){
  struct p25_audio_group const * const g = a->group;
  uint8_t packet[2048];
  uint8_t *bp = packet;
  *bp++ = STATUS;
  encode_int32(&bp,OUTPUT_SSRC,a->ssrc);
  make_description(a);
  encode_string(&bp,DESCRIPTION,a->description,strlen(a->description));
  // The clock reference: RTP timestamp 'timestamp' is sender time 'next_time'
  int64_t const now = a->next_time != 0 ? a->next_time : gps_time_ns();
  encode_int64(&bp,GPS_TIME,now);
  encode_int32(&bp,RTP_TIMESNAP,a->timestamp);
  encode_double(&bp,RADIO_FREQUENCY,a->frequency);
  encode_int32(&bp,OUTPUT_SAMPRATE,P25_AUDIO_SAMPRATE);
  encode_int32(&bp,OUTPUT_CHANNELS,1);
  encode_int(&bp,OUTPUT_ENCODING,S16BE);
  encode_byte(&bp,RTP_PT,g->pt);
  float level = -INFINITY;
  if(!closing && a->energy_samples > 0 && a->energy > 0)
    level = (float)(10 * log10(a->energy / a->energy_samples));
  encode_float(&bp,OUTPUT_LEVEL,level);
  encode_float(&bp,GAIN,0); // dB: the vocoder's output as it comes
  a->energy = 0;
  a->energy_samples = 0;
  encode_int64(&bp,OUTPUT_DATA_PACKETS,a->stats.packets);
  encode_int64(&bp,OUTPUT_SAMPLES,a->samples);
  encode_socket(&bp,OUTPUT_DATA_DEST_SOCKET,&g->data);
  encode_int32(&bp,OUTPUT_TTL,g->ttl);
  encode_int32(&bp,STATUS_INTERVAL,Status_interval);
  encode_int64(&bp,OUTPUT_METADATA_PACKETS,a->stats.status + 1);
  encode_int64(&bp,OUTPUT_ERRORS,a->stats.errors);
  encode_eol(&bp);
  assert(bp <= packet + sizeof packet);
  if(sendto(g->fd,packet,bp - packet,0,(struct sockaddr const *)&g->status,socklen(&g->status)) < 0)
    send_error(a,"status");
  a->stats.status++;
  a->status_count = Status_interval;
}

// Start a transmission whose first sample is at sender time 'start'
static void start_spurt(struct p25_audio *a,int64_t start){
  a->next_time = start - start % NS_PER_SAMPLE;
  a->timestamp = (uint32_t)(a->next_time / NS_PER_SAMPLE);
  a->active = true;
  a->marker = true;
  a->stats.spurts++;
  a->status_count = 0;     // status goes out ahead of the first data: pcmrecord creates its session only from status
  p25_vocoder_reset(a->vocoder);
}

void p25_audio_end(struct p25_audio *a){
  if(a == NULL || !a->active)
    return;
  send_status(a,true);
  a->active = false;
  p25_vocoder_reset(a->vocoder);
}

// One packet per 20 ms frame, as radiod sends 8 kHz PCM
static void send_frame(struct p25_audio *a,int16_t const pcm[P25_AUDIO_FRAME]){
  struct p25_audio_group const * const g = a->group;
  struct rtp_header rtp = {
    .version = RTP_VERS,
    .type = g->pt,
    .seq = a->seq,
    .timestamp = a->timestamp,
    .ssrc = a->ssrc,
    .marker = a->marker,
  };
  uint8_t packet[RTP_MIN_SIZE + 2 * P25_AUDIO_FRAME];
  uint8_t *dp = hton_rtp(packet,&rtp);
  for(int i=0; i < P25_AUDIO_FRAME; i++){
    dp = put16(dp,(uint16_t)pcm[i]);
    float const s = pcm[i] * (1.0f / 32768);
    a->energy += s * s;
  }
  a->energy_samples += P25_AUDIO_FRAME;
  if(a->status_count <= 0)
    send_status(a,false); // at the start of a transmission and every Status_interval packets, as radiod
  a->status_count--;
  if(sendto(g->fd,packet,dp - packet,0,(struct sockaddr const *)&g->data,socklen(&g->data)) < 0)
    send_error(a,"data");
  a->marker = false;
  a->seq++;
  a->timestamp += P25_AUDIO_FRAME;
  a->next_time += FRAME_NS;
  a->samples += P25_AUDIO_FRAME;
  a->stats.packets++;
}

void p25_audio_pcm(struct p25_audio *a,int16_t const *pcm,int count,int64_t when){
  if(a == NULL || pcm == NULL)
    return;
  if(!a->active)
    start_spurt(a,when != 0 ? when : gps_time_ns());
  for(int i=0; i + P25_AUDIO_FRAME <= count; i += P25_AUDIO_FRAME)
    send_frame(a,pcm + i);
}

// Decode one IMBE frame (or a lost one, f == NULL) and send it
static void voice_frame(struct p25_audio *a,struct p25_imbe const *f){
  int16_t pcm[P25_AUDIO_FRAME];
  enum p25_voice const r = f != NULL ? p25_vocoder_decode(a->vocoder,pcm,f->u,f->e0,f->total)
    : p25_vocoder_decode(a->vocoder,pcm,NULL,0,0);
  a->stats.frames++;
  if(f == NULL)
    a->stats.lost++;
  if(r == P25_VOICE_REPEAT)
    a->stats.repeats++;
  else if(r == P25_VOICE_MUTED)
    a->stats.muted++;
  send_frame(a,pcm);
}

void p25_audio_poll(struct p25_audio *a,double frequency,int64_t when){
  if(a == NULL)
    return;
  a->frequency = frequency;
  int64_t const t = when != 0 ? when : gps_time_ns();
  if(a->last_unit != 0 && t - a->last_unit > LDU_NS + Hang){
    // The next voice data unit is overdue by more than Hang: the call is over even without a terminator
    p25_audio_end(a);
    a->last_unit = 0;
    a->have_call = false;
    a->encrypted = false;
  }
}

// Call details and encryption from the header, link control and encryption sync words
static void call_info(struct p25_audio *a,struct p25_frame const *frame){
  uint8_t octets[15];
  struct p25_msg msg;
  switch(frame->duid){
  case P25_DUID_HDU:
    if(frame->word == NULL || !frame->word->ok)
      return;
    p25_pack_bits(octets,frame->word->bits,120);
    if(p25_decode_hdu(&msg,octets) != 0)
      return;
    a->encrypted |= msg.algid != 0x80; // 0x80: unencrypted
    a->have_call = true;
    a->unit_call = false;
    a->target = msg.group;
    a->source = 0;
    break;
  case P25_DUID_LDU1:
    if(frame->ldu == NULL || !frame->ldu->word.ok)
      return;
    p25_pack_bits(octets,frame->ldu->word.bits,72);
    if(p25_decode_lc(&msg,octets,false) != 0)
      return;
    if(msg.protect){
      a->encrypted = true;
      return;
    }
    switch(msg.kind){
    case P25_LC_GRP_V_CH_USR:
    case P25_LC_MOT_GRG_V_CH_USR:
      a->have_call = true;
      a->unit_call = false;
      a->target = msg.group;
      a->source = msg.src;
      a->encrypted |= (msg.svc & 0x40) != 0; // service options: E (encrypted)
      break;
    case P25_LC_UU_V_CH_USR:
      a->have_call = true;
      a->unit_call = true;
      a->target = msg.tgt;
      a->source = msg.src;
      a->encrypted |= (msg.svc & 0x40) != 0;
      break;
    default:
      break;
    }
    break;
  case P25_DUID_LDU2:
    if(frame->ldu == NULL || !frame->ldu->word.ok)
      return;
    p25_pack_bits(octets,frame->ldu->word.bits,96);
    if(p25_decode_es(&msg,octets) != 0)
      return;
    a->encrypted |= msg.algid != 0x80;
    break;
  default:
    break;
  }
}

void p25_audio_frame(struct p25_audio *a,struct p25_frame const *frame,int64_t when){
  if(a == NULL || frame == NULL)
    return;
  int64_t const t = when != 0 ? when : gps_time_ns();
  a->nac = frame->nac;
  switch(frame->duid){
  case P25_DUID_HDU:
    p25_audio_end(a); // a header starts a new call
    a->have_call = false;
    a->encrypted = false;
    call_info(a,frame);
    break;
  case P25_DUID_LDU1:
  case P25_DUID_LDU2:
    {
      struct p25_ldu const * const ldu = frame->ldu;
      if(ldu == NULL)
        break;
      int64_t const prev_unit = a->last_unit;
      a->last_unit = t;
      call_info(a,frame);
      if(a->encrypted){
        p25_audio_end(a);
        a->stats.encrypted++;
        break;
      }
      int64_t const start = t - LDU_NS; // sender time of this unit's first voice frame
      if(a->active){
        // Lost voice data units are counted on the receiver's dibit clock, which the sender's
        // clock references (GPS_TIME, RTP_TIMESNAP pairs, refreshed with each status) can't jitter.
        // The sender's clock only shows a gap the receiver didn't see (p25d resynchronizes on a
        // long timestamp jump instead of filling it): more time passed than dibits by over Hang
        int64_t const dibits = (int64_t)(frame->dibit - a->last_dibit);
        int64_t const units = (dibits + LDU_DIBITS / 2) / LDU_DIBITS - 1;
        int64_t const unseen = (t - prev_unit) - dibits * BILLION / P25_SYMRATE;
        if(prev_unit == 0 || unseen > Hang || units * LDU_NS > Hang){
          p25_audio_end(a);
        } else {
          // Fill with lost frames, which the vocoder repeats and then mutes
          for(int64_t i=0; i < units * P25_IMBE_FRAMES; i++)
            voice_frame(a,NULL);
        }
      }
      if(!a->active)
        start_spurt(a,start);
      for(int i=0; i < P25_IMBE_FRAMES; i++)
        voice_frame(a,&ldu->voice[i]);
      a->last_dibit = frame->dibit;
    }
    break;
  case P25_DUID_TDU:
  case P25_DUID_TDULC:
    p25_audio_end(a);
    a->have_call = false;
    a->encrypted = false;
    a->last_unit = 0;
    break;
  default:
    break;
  }
}
