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
// channel threads work in; a frame later still is played at once if its frame is not yet past, or
// dropped.
//
// Only clear frames come in (dmrd passes nothing else), so voting never lets a frame through that its
// own repeater's tracker had not labelled clear.
//
// Whose clock. Each channel's times are its own radiod's (the RTP timestamps its status ties to that
// radiod's clock), and channels decode in their own threads, so at any moment their times differ: by
// the blocks they work in, by tens of milliseconds between radiods, by more when a clock is wrong or a
// thread falls behind. A stream is therefore played by its own sources' times only, each taken onto the
// stream's frame numbers by that source's alignment (a source aligned to frame k0 by its frame at
// first_when is ahead of the stream by first_when - (base + 20 k0 ms)): the newest of those is the
// stream's time. A channel that carries none of the stream's sources never moves it, so one radiod's
// clock running ahead, or a channel that is idle, takes no frame from a stream it has no part in. When
// no source has reported a time, the newest frame offered stands in for it.
//
// End. A stream ends when every source has ended and every frame due has been played, or when no
// frame has come for Idle by its time, or (its channels gone, so nothing moves its time) for Gone by
// the local clock, after what it holds is played; its result (frames played, lost, and per source the
// frames offered, chosen, and the corrections in them) goes to the end handler.

enum {
  MAX_STREAMS = 32,
  MAX_SOURCES = 8,
  RING = 128,           // frames of a stream kept: 2.56 s
  SEARCH_BACK = 40,     // alignment: frames before a source's time position (800 ms)
  SEARCH_AHEAD = 10,    // ... and after (200 ms)
  ALIGN_RUN = 3,        // consecutive matching frames
  ALIGN_LIMIT = 50,     // frames a source has to align (1 s)
  MAX_CHANNELS = 256,   // channels whose signal measurements are kept
};
static int64_t const Frame_ns = 20000000;
static int64_t const Idle_ns = 1000000000;
static int64_t const Takeover_ns = 300000000;
static int64_t const Gone_ns = 5000000000;

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
  uint32_t channel;      // the receiver (unique); 'label' is its channel SSRC, for the results
  uint32_t label;
  int slot;
  bool ended;
  bool aligned;
  bool given_up;
  int64_t first_when;    // aligned: the time of frame number k0
  int64_t k0;
  int npending;
  struct pending pend[ALIGN_LIMIT];
  uint32_t moved_to;     // given up: its frames go to this stream instead
  int tries;             // frames of this transmission offered while not aligned (the alignment limit)
  uint32_t own_ssrc;     // the stream its frames go to if it is another conversation
  char description[256]; // its latest: the stream takes it on when a frame of it is played
  int offered;
  int chosen;
  int fec;
  int64_t last_when;
  int64_t offset;        // aligned: how far its times are ahead of the stream's (first_when - base - 20 k0 ms)
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
  int64_t latest;        // newest time of an aligned source's frame, in the stream's time; 0 none
  int64_t last_local;    // local clock when a frame was last offered (for Gone)
  int last_source;
  struct candidate ring[RING];
  struct source src[MAX_SOURCES];
  int frames;
  int lost;
};

struct signal {           // a receiver: its signal measurements, and the newest time it has reported
  uint32_t channel;      // the receiver
  double frequency;
  float bb_power,n0,low,high;
  int64_t now;           // its newest time (dmr_voter_poll()); 0 not yet
  uint64_t updated;      // the voter's count of updates when it was last set: the stalest goes when full
};

struct dmr_voter {
  pthread_mutex_t lock;
  struct p25_audio_group *group;
  int64_t delay;
  int64_t now;           // the newest time given for every stream (receiver 0); 0 none
  uint64_t signal_updates;
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

// A receiver's entry, made if need be (under the lock). Receivers come and go (a followed channel is a
// new one each time): when the table is full the entry set longest ago, a receiver that is gone, makes
// room
static struct signal *receiver_entry(struct dmr_voter *v,uint32_t channel){
  struct signal *stalest = NULL;
  for(int i=0; i < MAX_CHANNELS; i++){
    struct signal * const g = &v->signals[i];
    if(g->channel == channel){
      g->updated = ++v->signal_updates;
      return g;
    }
    // An empty entry if there is one, else the one set longest ago
    if(stalest == NULL || (stalest->channel != 0 && (g->channel == 0 || g->updated < stalest->updated)))
      stalest = g;
  }
  memset(stalest,0,sizeof *stalest);
  stalest->channel = channel;
  stalest->updated = ++v->signal_updates;
  return stalest;
}

void dmr_voter_set_signal(struct dmr_voter *v,uint32_t channel,double frequency,float bb_power,float n0,float low,float high){
  if(v == NULL)
    return;
  pthread_mutex_lock(&v->lock);
  struct signal * const g = receiver_entry(v,channel);
  g->frequency = frequency;
  g->bb_power = bb_power;
  g->n0 = n0;
  g->low = low;
  g->high = high;
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
      r.source[n].channel = c->label;
      r.source[n].receiver = c->channel;
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
  bool all_ended = true;
  for(int j=0; j < MAX_SOURCES; j++)
    if(s->src[j].used && !s->src[j].ended)
      all_ended = false;
  while(s->base + s->next_k * Frame_ns + v->delay <= now){
    // Past the last frame offered with every source ended, nothing more is coming: not lost frames
    if(all_ended && s->next_k > s->max_k)
      break;
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
  if(s->base + k * Frame_ns > s->latest)
    s->latest = s->base + k * Frame_ns;
  s->last_local = gps_time_ns();
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
  src->offset = src->first_when - (s->base + found * Frame_ns);
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
                  uint32_t label,int slot,uint8_t const bits[DMR_VOICE_FRAME_BITS],int64_t when,int depth);

void dmr_voter_frame(struct dmr_voter *v,uint32_t ssrc,uint32_t own_ssrc,char const *description,uint32_t channel,uint32_t label,int slot,
                     uint8_t const bits[DMR_VOICE_FRAME_BITS],int64_t when){
  if(v == NULL || bits == NULL)
    return;
  if(when == 0)
    when = gps_time_ns();
  pthread_mutex_lock(&v->lock);
  frame(v,ssrc,own_ssrc,description,channel,label,slot,bits,when,0);
  pthread_mutex_unlock(&v->lock);
}

// Under the lock
static void frame(struct dmr_voter *v,uint32_t ssrc,uint32_t own_ssrc,char const *description,uint32_t channel,
                  uint32_t label,int slot,uint8_t const bits[DMR_VOICE_FRAME_BITS],int64_t when,int depth){
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
  src->label = label;
  if(description != NULL)
    strlcpy(src->description,description,sizeof src->description);
  if(src->ended){
    // The source's next transmission: what this one decided (given up, moved to its own stream, held
    // frames) is not carried into it. Its counts, and its entry (candidates still to be played name it),
    // stay. It keeps its place by time only while it is the stream's one live source; beside another it
    // aligns afresh, by content
    bool others = false;
    for(int i=0; i < MAX_SOURCES && !others; i++)
      others = i != si && s->src[i].used && !s->src[i].ended && s->src[i].aligned;
    src->moved_to = 0;
    src->given_up = false;
    src->npending = 0;
    src->tries = 0;
    if(others)
      src->aligned = false;
  }
  if(src->moved_to != 0 && depth == 0){
    frame(v,src->moved_to,src->moved_to,description,channel,label,slot,bits,when,1);
    return;
  }
  src->ended = false;
  src->last_when = when;
  src->own_ssrc = own_ssrc;
  if(when > s->last_frame)
    s->last_frame = when;
  if(fresh){
    // The first source defines the frame numbers
    src->aligned = true;
    src->k0 = 0;
    src->first_when = when;
    src->offset = 0;
  }
  if(!src->aligned && s->last_aligned != 0 && when - s->last_aligned > Takeover_ns){
    // Nothing aligned is coming: this source carries on, placed by its time
    src->aligned = true;
    src->given_up = false;
    src->npending = 0;
    src->k0 = round_frames(when - s->base);
    src->first_when = when;
    src->offset = src->first_when - (s->base + src->k0 * Frame_ns);
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
    src->tries++;
    try_align(s,si);
    if(src->aligned){
      src->offered--; // try_align() offered (and counted) its pending frames
      if(when > s->last_aligned)
        s->last_aligned = when;
    }
    else if(src->tries >= ALIGN_LIMIT){
      src->given_up = true;
      if(own_ssrc != 0 && own_ssrc != ssrc && depth == 0){
        // Another conversation: its own stream, its held frames first
        src->moved_to = own_ssrc;
        int const n = src->npending;
        src->npending = 0;
        for(int i=0; i < n; i++)
          frame(v,own_ssrc,own_ssrc,description,channel,label,slot,src->pend[i].bits,src->pend[i].when,1);
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
      struct source * const src = &s->src[si];
      // A transmission that ended before it either lined up or ran into the alignment limit is another
      // conversation too short to tell: its held frames go to its own stream, as they would have
      if(!src->aligned && !src->given_up && src->npending > 0 && src->own_ssrc != 0 && src->own_ssrc != ssrc){
        int const n = src->npending;
        src->npending = 0;
        src->moved_to = src->own_ssrc;
        for(int i=0; i < n; i++)
          frame(v,src->own_ssrc,src->own_ssrc,src->description,channel,src->label,slot,src->pend[i].bits,src->pend[i].when,1);
        src->offered -= n;
      }
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

// A stream's time (under the lock): the newest its aligned sources' receivers have reported, each taken
// onto the stream's frame numbers, else the newest frame offered; the time given for every stream, if
// newer. 0: none yet
static int64_t stream_time(struct dmr_voter const *v,struct stream const *s){
  int64_t t = s->latest;
  for(int j=0; j < MAX_SOURCES; j++){
    struct source const * const src = &s->src[j];
    if(!src->used || !src->aligned)
      continue;
    struct signal const * const g = find_signal(v,src->channel);
    if(g != NULL && g->now != 0 && g->now - src->offset > t)
      t = g->now - src->offset;
  }
  if(v->now > t)
    t = v->now;
  return t;
}

void dmr_voter_poll(struct dmr_voter *v,uint32_t receiver,int64_t now){
  if(v == NULL || now == 0)
    return; // a receiver that knows no time yet (no status) says nothing
  pthread_mutex_lock(&v->lock);
  if(receiver == 0){
    if(now > v->now)
      v->now = now;
  } else {
    struct signal * const g = receiver_entry(v,receiver);
    if(now > g->now)
      g->now = now;
  }
  int64_t const local = gps_time_ns();
  for(int i=0; i < MAX_STREAMS; i++){
    struct stream * const s = &v->streams[i];
    if(!s->used)
      continue;
    int64_t const t = stream_time(v,s);
    if(t != 0)
      play(v,s,t);
    bool all_ended = true;
    for(int j=0; j < MAX_SOURCES; j++)
      if(s->src[j].used && !s->src[j].ended)
        all_ended = false;
    if((all_ended && s->next_k > s->max_k) || (t != 0 && s->latest != 0 && t - s->latest > Idle_ns + v->delay))
      end_stream(v,s);
    else if(s->last_local != 0 && local - s->last_local > Gone_ns){
      // Nothing moves its time any more: what it holds is played, then it ends
      play(v,s,s->base + (s->max_k + 1) * Frame_ns + v->delay);
      end_stream(v,s);
    }
  }
  pthread_mutex_unlock(&v->lock);
}
