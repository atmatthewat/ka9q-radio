// Voting between the repeaters that carry the same DMR call (see dmrvote.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "timing.h"
#include "p25p2unit.h"
#include "dmraudio.h"
#include "dmrvote.h"

// Theory of operation
//
// Why. On a multi-site system (Capacity Plus, IP Site Connect) a wide-area call goes out at the same
// moment from every repeater of the sites it is on, each with its own path to the receiver: one may
// fade while another is clean. A voter, as simulcast and multi-site receivers have, makes one stream
// of the call and takes each 20 ms frame from the repeater that received it best.
//
// Which copies are the same frame. The repeaters send the same vocoder frames, so after FEC the
// copies of a frame carry the same information bits, but not at the same time: on the air here they
// were 30 to 60 ms apart (slots and sites are not aligned), and a repeater may join a call late. So a
// stream's frames are numbered from the first copy of its first frame (frame k is due at base + 20 k
// ms), and each repeater slot (a source) is lined up once, by content: its frames' first two vectors
// (u0 and u1, 24 bits that each have their own Golay code) are compared with the stream's recent
// frames, and the source is aligned when three of its consecutive frames, each received without a
// Golay failure, match three consecutive frames of the stream at one offset and at no other within
// Search_back frames before to Search_ahead after where their time puts them. Silence and other
// repeated frames match in many places and so align nothing; the next spoken frames do. From then on a
// source's frame number follows from its time, 20 ms a frame, which is exact within a transmission. A
// source that is all there is is not kept waiting: when no aligned source has offered a frame for
// Takeover (300 ms), the next unaligned one is aligned by its time alone. On a system whose repeaters
// do not send identical frames the stream thus follows one repeater and moves to another when that one
// fades, rather than going silent. The first source is aligned by definition, and a stream's base is
// its first frame.
//
// Not the same call. On some systems a talkgroup number is local to each repeater (amateur DMR's
// TG 2 or TG 9, say), so two repeaters can carry different conversations under one number at once.
// Their frames never line up: a source still unaligned after Align_limit frames (1 s) is moved, with
// the frames it was holding, to a stream of its own (the caller names it: dmrd uses the channel's SSRC
// times ten plus the slot) for the rest of its transmission. Its first second is then played late.
//
// Which copy. Each frame is played Delay after it is due, from the copy with the fewest Golay
// corrections (c0 + c1, 0 for a clean frame; a c0 whose fourth error its parity caught counts 4); a tie
// keeps the repeater the last frame came from, so the stream does not hop for nothing. A frame no
// source has supplied by then is lost: dmraudio fills it (the vocoder repeats, then mutes), and a copy
// that comes later is dropped. Delay (120 ms) covers the spread between repeaters and the blocks the
// channel threads work in; frames a tracker held until a later word said clear may come later still,
// and are then played at once if their frame is not yet past, or dropped.
//
// Only clear frames come in (dmrd passes nothing else), so voting never lets a frame through that its
// own repeater's tracker had not labelled clear.
//
// End. A stream ends when every source has ended and every frame due has been played, or when no
// frame has come for Idle; its result (frames played, lost, and per source the frames offered,
// chosen, and the corrections in them) goes to the end handler.

enum {
  MAX_STREAMS = 32,
  MAX_SOURCES = 8,
  RING = 128,           // frames of a stream kept: 2.56 s
  SEARCH_BACK = 40,     // alignment: frames before a source's time position (800 ms)
  SEARCH_AHEAD = 10,    // ... and after (200 ms)
  ALIGN_RUN = 3,        // consecutive matching frames
  ALIGN_LIMIT = 50,     // frames a source has to align (1 s)
  MAX_CHANNELS = 32,
};
static int64_t const Frame_ns = 20000000;
static int64_t const Idle_ns = 1000000000;
static int64_t const Takeover_ns = 300000000;

struct candidate {
  bool have;
  int64_t k;             // frame number it is for (ring slot check)
  int fec;
  int source;
  uint32_t u01;          // u0 << 12 | u1 of the best copy, for alignment
  bool clean;            // its Golay words decoded
  uint8_t bits[DMR_VOICE_FRAME_BITS];
};

struct pending {         // an unaligned source's recent frames
  int64_t when;
  uint32_t u01;
  bool clean;
  int fec;
  uint8_t bits[DMR_VOICE_FRAME_BITS];
};

struct source {
  bool used;
  uint32_t channel;
  int slot;
  bool ended;
  bool aligned;
  bool given_up;
  int64_t first_when;    // aligned: the time of frame number k0
  int64_t k0;
  int npending;
  struct pending pend[ALIGN_LIMIT];
  uint32_t moved_to;     // given up: its frames go to this stream instead
  char description[256]; // its latest: the stream takes it on when a frame of it is played
  int offered;
  int chosen;
  int fec;
  int64_t last_when;
};

struct stream {
  bool used;
  uint32_t ssrc;
  char description[256];
  struct dmr_audio *audio;
  int64_t base;          // time of frame 0
  int64_t next_k;        // next frame to play
  int64_t last_frame;    // time of the last frame offered (any source)
  int64_t last_aligned;  // ... by an aligned source
  int64_t max_k;         // highest frame number offered
  int last_source;
  struct candidate ring[RING];
  struct source src[MAX_SOURCES];
  int frames;
  int lost;
};

struct signal {
  uint32_t channel;
  double frequency;
  float bb_power,n0,low,high;
};

struct dmr_voter {
  pthread_mutex_t lock;
  struct p25_audio_group *group;
  int64_t delay;
  int64_t now;           // latest time any channel has reported
  dmr_vote_end_fn end_fn;
  void *end_arg;
  struct stream streams[MAX_STREAMS];
  struct signal signals[MAX_CHANNELS];
};

struct dmr_voter *dmr_voter_create(struct p25_audio_group *group,int64_t delay_ns){
  struct dmr_voter *v = calloc(1,sizeof *v);
  if(v == NULL)
    return NULL;
  pthread_mutex_init(&v->lock,NULL);
  v->group = group;
  v->delay = delay_ns;
  return v;
}

static void end_stream(struct dmr_voter *v,struct stream *s);

void dmr_voter_destroy(struct dmr_voter *v){
  if(v == NULL)
    return;
  pthread_mutex_lock(&v->lock);
  for(int i=0; i < MAX_STREAMS; i++)
    if(v->streams[i].used)
      end_stream(v,&v->streams[i]);
  pthread_mutex_unlock(&v->lock);
  pthread_mutex_destroy(&v->lock);
  FREE(v);
}

void dmr_voter_set_end_handler(struct dmr_voter *v,dmr_vote_end_fn fn,void *arg){
  if(v == NULL)
    return;
  v->end_fn = fn;
  v->end_arg = arg;
}

void dmr_voter_set_signal(struct dmr_voter *v,uint32_t channel,double frequency,float bb_power,float n0,float low,float high){
  if(v == NULL)
    return;
  pthread_mutex_lock(&v->lock);
  struct signal *free_entry = NULL;
  for(int i=0; i < MAX_CHANNELS; i++){
    struct signal * const g = &v->signals[i];
    if(g->channel == channel){
      free_entry = g;
      break;
    }
    if(g->channel == 0 && free_entry == NULL)
      free_entry = g;
  }
  if(free_entry != NULL)
    *free_entry = (struct signal){channel,frequency,bb_power,n0,low,high};
  pthread_mutex_unlock(&v->lock);
}

static struct signal const *find_signal(struct dmr_voter const *v,uint32_t channel){
  for(int i=0; i < MAX_CHANNELS; i++)
    if(v->signals[i].channel == channel)
      return &v->signals[i];
  return NULL;
}

static int64_t round_frames(int64_t ns){
  return ns >= 0 ? (ns + Frame_ns / 2) / Frame_ns : -((-ns + Frame_ns / 2) / Frame_ns);
}

static void end_stream(struct dmr_voter *v,struct stream *s){
  dmr_audio_end(s->audio);
  if(v->end_fn != NULL){
    struct dmr_vote_result r;
    memset(&r,0,sizeof r);
    r.ssrc = s->ssrc;
    r.frames = s->frames;
    r.lost = s->lost;
    for(int i=0; i < MAX_SOURCES; i++){
      struct source const * const c = &s->src[i];
      if(!c->used)
        continue;
      int const n = r.sources++;
      r.source[n].channel = c->channel;
      r.source[n].slot = c->slot;
      r.source[n].chosen = c->chosen;
      r.source[n].frames = c->offered;
      r.source[n].fec = c->fec;
      r.source[n].aligned = c->aligned;
    }
    v->end_fn(v->end_arg,&r);
  }
  dmr_audio_destroy(s->audio);
  memset(s,0,sizeof *s);
}

// Play every frame due by 'now'
static void play(struct dmr_voter *v,struct stream *s,int64_t now){
  while(s->base + s->next_k * Frame_ns + v->delay <= now){
    int64_t const k = s->next_k++;
    struct candidate * const c = &s->ring[k % RING];
    if(!c->have || c->k != k){
      s->lost++;
      continue; // dmraudio fills the gap at the next frame
    }
    struct source * const src = &s->src[c->source];
    src->chosen++;
    s->last_source = c->source;
    if(src->description[0] != '\0' && strcmp(src->description,s->description) != 0){
      // The repeater it comes from now, or what is newly known of the call
      strlcpy(s->description,src->description,sizeof s->description);
      dmr_audio_set_stream(s->audio,s->ssrc,s->description);
    }
    struct signal const * const g = find_signal(v,src->channel);
    if(g != NULL)
      dmr_audio_set_signal(s->audio,g->frequency,g->bb_power,g->n0,g->low,g->high);
    dmr_audio_frame(s->audio,c->bits,s->base + k * Frame_ns);
    s->frames++;
    // Keep the content for later alignments; the copy has been played
    c->have = true;
  }
}

// Offer one aligned copy of frame k
static void offer(struct stream *s,int si,int64_t k,int fec,uint32_t u01,bool clean,uint8_t const *bits){
  struct source * const src = &s->src[si];
  src->offered++;
  src->fec += fec;
  if(k < s->next_k)
    return; // its frame has been played already
  if(k >= s->next_k + RING)
    return; // too far ahead to keep
  if(k > s->max_k)
    s->max_k = k;
  struct candidate * const c = &s->ring[k % RING];
  if(c->have && c->k == k){
    if(fec > c->fec)
      return;
    if(fec == c->fec && c->source == s->last_source)
      return; // a tie keeps the repeater last played
    if(fec == c->fec && si != s->last_source && c->source != s->last_source && si > c->source)
      return; // a tie between two others: the first to offer
  }
  c->have = true;
  c->k = k;
  c->fec = fec;
  c->source = si;
  c->u01 = u01;
  c->clean = clean;
  memcpy(c->bits,bits,DMR_VOICE_FRAME_BITS);
}

// Try to line up an unaligned source from its pending frames
static void try_align(struct stream *s,int si){
  struct source * const src = &s->src[si];
  // The latest ALIGN_RUN consecutive clean frames
  int const n = src->npending;
  if(n < ALIGN_RUN)
    return;
  struct pending const * const run = &src->pend[n - ALIGN_RUN];
  for(int i=0; i < ALIGN_RUN; i++){
    if(!run[i].clean)
      return;
    if(i > 0 && round_frames(run[i].when - run[i-1].when) != 1)
      return;
  }
  int64_t const nominal = round_frames(run[0].when - s->base);
  int matches = 0;
  int64_t found = 0;
  for(int64_t k = nominal - SEARCH_BACK; k <= nominal + SEARCH_AHEAD; k++){
    if(k < 0)
      continue;
    bool ok = true;
    for(int i=0; i < ALIGN_RUN && ok; i++){
      struct candidate const * const c = &s->ring[(k + i) % RING];
      ok = c->have && c->k == k + i && c->clean && c->u01 == run[i].u01;
    }
    if(ok){
      matches++;
      found = k;
    }
  }
  if(matches != 1)
    return; // none yet, or ambiguous (silence)
  src->aligned = true;
  src->k0 = found;
  src->first_when = run[0].when;
  // Its pending frames are offered now
  for(int i=0; i < n; i++){
    struct pending const * const p = &src->pend[i];
    offer(s,si,found + round_frames(p->when - run[0].when),p->fec,p->u01,p->clean,p->bits);
  }
  src->npending = 0;
}

static struct stream *find_stream(struct dmr_voter *v,uint32_t ssrc,bool create){
  struct stream *free_entry = NULL;
  for(int i=0; i < MAX_STREAMS; i++){
    struct stream * const s = &v->streams[i];
    if(s->used && s->ssrc == ssrc)
      return s;
    if(!s->used && free_entry == NULL)
      free_entry = s;
  }
  if(!create || free_entry == NULL)
    return NULL;
  memset(free_entry,0,sizeof *free_entry);
  free_entry->used = true;
  free_entry->ssrc = ssrc;
  free_entry->audio = dmr_audio_create(v->group,ssrc);
  return free_entry;
}

static int find_source(struct stream *s,uint32_t channel,int slot,bool create){
  int free_entry = -1;
  for(int i=0; i < MAX_SOURCES; i++){
    struct source const * const c = &s->src[i];
    if(c->used && c->channel == channel && c->slot == slot)
      return i;
    if(!c->used && free_entry < 0)
      free_entry = i;
  }
  if(!create || free_entry < 0)
    return -1;
  struct source * const c = &s->src[free_entry];
  memset(c,0,sizeof *c);
  c->used = true;
  c->channel = channel;
  c->slot = slot;
  return free_entry;
}

static void frame(struct dmr_voter *v,uint32_t ssrc,uint32_t own_ssrc,char const *description,uint32_t channel,
                  int slot,uint8_t const bits[DMR_VOICE_FRAME_BITS],int64_t when,int depth);

void dmr_voter_frame(struct dmr_voter *v,uint32_t ssrc,uint32_t own_ssrc,char const *description,uint32_t channel,int slot,
                     uint8_t const bits[DMR_VOICE_FRAME_BITS],int64_t when){
  if(v == NULL || bits == NULL)
    return;
  if(when == 0)
    when = gps_time_ns();
  pthread_mutex_lock(&v->lock);
  frame(v,ssrc,own_ssrc,description,channel,slot,bits,when,0);
  pthread_mutex_unlock(&v->lock);
}

// Under the lock
static void frame(struct dmr_voter *v,uint32_t ssrc,uint32_t own_ssrc,char const *description,uint32_t channel,
                  int slot,uint8_t const bits[DMR_VOICE_FRAME_BITS],int64_t when,int depth){
  struct p25p2_ambe a;
  p25p2_ambe_decode(&a,bits);
  int const fec = a.errors[0] + a.errors[1];
  bool const clean = a.errors[0] < 4;
  uint32_t const u01 = ((uint32_t)a.u[0] << 12) | a.u[1];

  struct stream *s = find_stream(v,ssrc,false);
  if(s != NULL && s->last_frame != 0 && when - s->last_frame > Idle_ns && when > s->last_frame){
    end_stream(v,s); // a new transmission on a stream long silent: start afresh
    s = NULL;
  }
  bool const fresh = s == NULL;
  if(s == NULL && (s = find_stream(v,ssrc,true)) == NULL)
    return;
  if(fresh){
    s->base = when;
    s->next_k = 0;
    strlcpy(s->description,description != NULL ? description : "",sizeof s->description);
    dmr_audio_set_stream(s->audio,ssrc,s->description);
  }
  int const si = find_source(s,channel,slot,true);
  if(si < 0)
    return;
  struct source * const src = &s->src[si];
  if(description != NULL)
    strlcpy(src->description,description,sizeof src->description);
  if(src->moved_to != 0 && depth == 0){
    frame(v,src->moved_to,src->moved_to,description,channel,slot,bits,when,1);
    return;
  }
  src->ended = false;
  src->last_when = when;
  if(when > s->last_frame)
    s->last_frame = when;
  if(fresh){
    // The first source defines the frame numbers
    src->aligned = true;
    src->k0 = 0;
    src->first_when = when;
  }
  if(!src->aligned && s->last_aligned != 0 && when - s->last_aligned > Takeover_ns){
    // Nothing aligned is coming: this source carries on, placed by its time
    src->aligned = true;
    src->given_up = false;
    src->npending = 0;
    src->k0 = round_frames(when - s->base);
    src->first_when = when;
  }
  if(src->aligned){
    offer(s,si,src->k0 + round_frames(when - src->first_when),fec,u01,clean,bits);
    if(when > s->last_aligned)
      s->last_aligned = when;
  } else if(!src->given_up){
    if(src->npending == (int)(sizeof src->pend / sizeof src->pend[0])){
      memmove(src->pend,src->pend + 1,(src->npending - 1) * sizeof src->pend[0]);
      src->npending--;
    }
    struct pending * const p = &src->pend[src->npending++];
    p->when = when;
    p->u01 = u01;
    p->clean = clean;
    p->fec = fec;
    memcpy(p->bits,bits,DMR_VOICE_FRAME_BITS);
    src->offered++;
    try_align(s,si);
    if(src->aligned){
      src->offered--; // try_align() offered (and counted) its pending frames
      if(when > s->last_aligned)
        s->last_aligned = when;
    }
    else if(src->offered >= ALIGN_LIMIT){
      src->given_up = true;
      if(own_ssrc != 0 && own_ssrc != ssrc && depth == 0){
        // Another conversation: its own stream, its held frames first
        src->moved_to = own_ssrc;
        int const n = src->npending;
        src->npending = 0;
        for(int i=0; i < n; i++)
          frame(v,own_ssrc,own_ssrc,description,channel,slot,src->pend[i].bits,src->pend[i].when,1);
        src->offered -= n;
      } else
        src->npending = 0;
    }
  } else
    src->offered++;
}

void dmr_voter_source_end(struct dmr_voter *v,uint32_t ssrc,uint32_t channel,int slot){
  if(v == NULL)
    return;
  pthread_mutex_lock(&v->lock);
  struct stream * const s = find_stream(v,ssrc,false);
  if(s != NULL){
    int const si = find_source(s,channel,slot,false);
    if(si >= 0){
      s->src[si].ended = true;
      uint32_t const moved = s->src[si].moved_to;
      struct stream * const m = moved != 0 ? find_stream(v,moved,false) : NULL;
      int const mi = m != NULL ? find_source(m,channel,slot,false) : -1;
      if(mi >= 0)
        m->src[mi].ended = true;
    }
  }
  pthread_mutex_unlock(&v->lock);
}

void dmr_voter_poll(struct dmr_voter *v,int64_t now){
  if(v == NULL)
    return;
  if(now == 0)
    now = gps_time_ns();
  pthread_mutex_lock(&v->lock);
  if(now > v->now)
    v->now = now;
  now = v->now; // channels report a little apart: the stream plays by the latest
  for(int i=0; i < MAX_STREAMS; i++){
    struct stream * const s = &v->streams[i];
    if(!s->used)
      continue;
    play(v,s,now);
    bool all_ended = true;
    for(int j=0; j < MAX_SOURCES; j++)
      if(s->src[j].used && !s->src[j].ended)
        all_ended = false;
    if((all_ended && s->next_k > s->max_k) || now - s->last_frame > Idle_ns + v->delay)
      end_stream(v,s);
  }
  pthread_mutex_unlock(&v->lock);
}
