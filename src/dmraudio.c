// Voice output for the DMR decoder: clear AMBE+2 frames to 8 kHz speech on a ka9q-radio audio stream
// (see dmraudio.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "timing.h"
#include "p25p2unit.h"
#include "dmraudio.h"

// Theory of operation
//
// What comes in. The call tracker (dmrcall.c) decides which frames may be heard: only frames it has
// labelled clear reach this module, in order, each with the time its burst was on the air. A DMR
// voice burst carries three 20 ms AMBE+2 frames and a timeslot has a burst every 60 ms, so a call's
// frames arrive at an even 20 ms spacing (the second frame of a burst straddles the sync, but its
// time is still the burst's start plus 20 ms).
//
// The vocoder. DMR's vocoder is the AMBE+2 half rate (3600 x 2450) vocoder of P25 Phase 2, with
// the same frame FEC: p25p2_ambe_decode() turns the 72 bits as sent into the 49 information bits and
// the two error counts, and p25_vocoder_decode() (p25audio.c, mbelib) makes 160 samples at 8 kHz,
// repeating or muting as its rules say. The speech goes out through p25_audio_pcm(), which numbers,
// stamps and paces the packets and sends the status radiod sends with its own streams, so monitor
// and pcmrecord take the stream as they take radiod's.
//
// Timing. The stream's RTP clock runs at 8 kHz from the sender time of its first frame, 160 a frame,
// so a recording lines up with the I/Q. A frame later than the next one due means frames went
// missing (a burst lost to a fade, or held back and never released): up to Max_fill of them are
// fed to the vocoder as lost, so the gap keeps its length in the speech (the vocoder repeats the
// last good frame, then mutes); a longer gap, or a frame more than a frame early, ends the
// transmission and starts a new one. A transmission whose next frame is Timeout late ends by itself
// (dmr_audio_poll()), so monitor's squelch closes.

static int64_t const Frame_ns = 20 * 1000000LL;      // one AMBE+2 frame
static int64_t const Max_fill = 500 * 1000000LL;     // longest gap filled with lost frames
static int64_t const Timeout = 1000 * 1000000LL;     // a transmission ends this long after its last frame

struct dmr_audio {
  struct p25_audio *out;
  struct p25_vocoder *vocoder;
  uint32_t ssrc;
  bool active;
  int64_t next;           // sender time the next frame is due, while active
  int64_t last;           // gps_time_ns() view of the last frame's time
  struct dmr_audio_stats stats;
};

struct dmr_audio *dmr_audio_create(struct p25_audio_group *group,uint32_t ssrc){
  if(group == NULL || p25_vocoder_name(P25_CODEC_AMBE2) == NULL)
    return NULL;
  struct dmr_audio *a = calloc(1,sizeof *a);
  if(a == NULL)
    return NULL;
  a->ssrc = ssrc;
  a->out = p25_audio_create(group,NULL,ssrc);
  a->vocoder = p25_vocoder_create(P25_CODEC_AMBE2);
  if(a->out == NULL || a->vocoder == NULL){
    dmr_audio_destroy(a);
    return NULL;
  }
  return a;
}

void dmr_audio_destroy(struct dmr_audio *a){
  if(a == NULL)
    return;
  dmr_audio_end(a);
  p25_audio_destroy(a->out);
  p25_vocoder_destroy(a->vocoder);
  FREE(a);
}

void dmr_audio_end(struct dmr_audio *a){
  if(a == NULL || !a->active)
    return;
  p25_audio_end(a->out);
  a->active = false;
}

bool dmr_audio_active(struct dmr_audio const *a){
  return a != NULL && a->active;
}

// One frame (bits NULL: lost) at sender time 'when'
static void decode(struct dmr_audio *a,struct p25p2_ambe const *f,int64_t when){
  int16_t pcm[P25_AUDIO_FRAME];
  enum p25_voice const v = f != NULL
    ? p25_vocoder_decode(a->vocoder,pcm,f->bits,f->data_errors[0],f->data_errors[0] + f->data_errors[1])
    : p25_vocoder_decode(a->vocoder,pcm,NULL,0,0);
  if(v == P25_VOICE_REPEAT)
    a->stats.repeats++;
  else if(v == P25_VOICE_MUTED)
    a->stats.muted++;
  p25_audio_pcm(a->out,pcm,P25_AUDIO_FRAME,when);
}

void dmr_audio_frame(struct dmr_audio *a,uint8_t const frame[DMR_VOICE_FRAME_BITS],int64_t when){
  if(a == NULL || frame == NULL)
    return;
  if(when == 0)
    when = gps_time_ns();
  if(a->active){
    int64_t const late = when - a->next;
    if(late > Max_fill || late < -Frame_ns)
      dmr_audio_end(a); // too long a gap to fill, or out of order: a new transmission
    else {
      // Fill the frames that are missing, keeping the gap's length (half a frame of slack)
      while(when - a->next >= Frame_ns / 2){
        decode(a,NULL,a->next);
        a->stats.lost++;
        a->next += Frame_ns;
      }
    }
  }
  if(!a->active){
    p25_vocoder_reset(a->vocoder);
    a->active = true;
    a->stats.spurts++;
  }
  struct p25p2_ambe f;
  p25p2_ambe_decode(&f,frame);
  decode(a,&f,when);
  a->stats.frames++;
  a->next = when + Frame_ns;
  a->last = when;
}

void dmr_audio_poll(struct dmr_audio *a,int64_t when){
  if(a == NULL || !a->active)
    return;
  if(when == 0)
    when = gps_time_ns();
  if(when - a->next > Timeout)
    dmr_audio_end(a);
}

void dmr_audio_set_stream(struct dmr_audio *a,uint32_t ssrc,char const *description){
  if(a == NULL)
    return;
  if(ssrc != a->ssrc){
    dmr_audio_end(a); // p25_audio_set_stream() would end it too, without telling us
    a->ssrc = ssrc;
  }
  p25_audio_set_stream(a->out,ssrc,description);
}

void dmr_audio_set_signal(struct dmr_audio *a,double frequency,float bb_power,float n0,float low,float high){
  if(a == NULL)
    return;
  p25_audio_set_signal(a->out,bb_power,n0,low,high);
  p25_audio_poll(a->out,frequency,0); // the frequency for the status; p25audio's own timeout never fires here
}

void dmr_audio_get_stats(struct dmr_audio const *a,struct dmr_audio_stats *stats){
  if(a == NULL || stats == NULL)
    return;
  *stats = a->stats;
}
