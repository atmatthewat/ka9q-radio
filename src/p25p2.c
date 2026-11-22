// P25 Phase 2 (TDMA) receiver: IQ samples in, bursts out
// Level, frequency correction of each block by its own estimate, root raised cosine matched
// filter, symbol timing, the phase change over one symbol (H-DQPSK is differentially encoded
// pi/4 QPSK), then TDMA framing: fragment sync, the ISCH, descrambling, the two timeslots
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "p25p2isch.h"
#include "digital.h"
#include "p25p2.h"

// Timing loop bandwidths (normalized, per symbol). Acquisition is wide so that the first
// timeslot of a carrier (dibits 20-179, before its first S-ISCH) decodes whatever the initial
// timing phase; with frame sync the loop narrows. One stage by default
static float const Acquire_bw = 0.4f;
static float const Track_bw = 0.012f;
static float const Settle_time = 0.5f; // seconds of held sync before an optional second stage
static float const Loop_damping = 1.0f;
static float const Error_gain = 0.42f;
// Symbol rate error the timing loop may integrate: transmitter plus receiver clock errors are tens of ppm
static float const Rate_limit = 0.0003f;
static int const Interp_phases = 32;
// Frequency: the block estimate's corner while acquiring; with frame sync it is frozen and the
// decided symbols move it, by this fraction of each block's residual (a time constant of about
// seven blocks). The 1 Hz corner is for running without that
static double const Afc_acquire_corner = 20.0; // Hz
static double const Afc_track_corner = 1.0;    // Hz
static float const Dd_gain = 0.15f;
// After frame sync is lost the frequency is held this long before the block estimate takes
// over again: a carrier does not move between transmissions
static float const Afc_hold_time = 30.0f; // seconds
// The block estimate's residual is measured after this lowpass, flat over the signal (+-3600 Hz)
// so it adds no data dependent bias, and narrow enough that noise across a wider stream does
// not pull the estimate toward the stream's centre
static double const Measure_cutoff = 4000.0; // Hz
static double const Measure_span = 95.0 / 24000.0; // seconds
// Receive matched filter: the transmitter's root raised cosine, rolloff 0.2, +-8 symbols
static double const Rrc_alpha = 0.2;
static int const Rrc_span = 8; // symbols each side
// Level: per-sample power smoothing, 1/2000 at 24 kHz
static double const Level_time = 1.0 / 12.0; // seconds
// A sync found only turned by +-90 or 180 degrees means a frequency error of +-1500 or 3000 Hz
// (each symbol turned a quadrant); the move is undone if frame sync does not follow within
// four fragments
static float const Quadrant_hz = P25P2_SYMRATE / 4.0f;
static int const Rotation_revert = 4 * P25P2_FRAGMENT_DIBITS;
// Longest block processed at once
static double const Max_block_time = 0.1; // seconds

// Framing (fragment layout and sync thresholds, in bit errors of the 40-bit S-ISCH sync)
enum {
  SYNC_DIBITS = 20,
  FRAGMENT = P25P2_FRAGMENT_DIBITS,
  SYNC1 = 360,             // the two S-ISCHs, before bursts C and D
  SYNC2 = 540,
  PAIR = SYNC2 - SYNC1,
  ISCH1 = 0,               // the two I-ISCHs, before bursts A and B
  ISCH2 = 180,
  HUNT = 4,                // acquire on a sync this close ...
  HUNT_PARTNER = 6,        // ... with the other one 180 dibits away this close
  TRACK = 7,               // a fragment keeps sync with either sync this close (a one-dibit slip scores 8 or 9)
  CLEAN = 4,               // both this close: aligned, no slip search
  SLIP1 = 6,               // both syncs this close at +-1 dibit
  SLIP2 = 5,               // ... at +-2
  MAX_SLIP = 2,
  NO_SYNC = 99,
  MISSES = 2,              // fragments without sync before sync is lost
  ISCH_TRUST = 3,          // an I-ISCH corrected by more bits than this does not override the flywheel
  ROTATION_TOLERANCE = 2,  // dibits: a rotated sync repeats one fragment later
  RING = 4096,             // dibit history, a power of two above the four fragments the framer may keep
  SEARCH_TRIM = 4 * FRAGMENT,
  SEARCH_KEEP = 2 * FRAGMENT,
};
static uint64_t const NONE = ~(uint64_t)0;
static int const Burst_offset[4] = { 20, 200, 380, 560 };
// S-ISCH sync, as dibits (01 = 1, 11 = 3)
static uint8_t const Sync_pattern[SYNC_DIBITS] = { 1,1,1,3, 1,1,3,1, 1,1,1,3, 3,3,1,3, 3,3,3,3 };
static float const Nominal_phase[4] = { M_PI_4, 3 * M_PI_4, -M_PI_4, -3 * M_PI_4 };

struct slot {
  struct p25p2_burst b;
  uint8_t bits[P25P2_BURST_BITS];
  float conf[P25P2_BURST_DIBITS];
};

struct p25p2 {
  double samprate;
  struct level level;
  struct freqtrack afc;      // the block estimate; rotates the measurement copy
  struct freqtrack shift;    // rotates the signal by the updated estimate
  struct rxfilter measure;
  struct rxfilter rrc;
  struct symsync sync;
  bool matched;
  bool primed;
  float complex prev_symbol;
  int max_block;
  float complex *block,*copy;
  struct softdibit *dibits;
  int ndibits,max_dibits;
  uint64_t rx_dibits;        // dibits out of the receive chain, counted a block at a time

  // frequency control
  bool frame_synced;
  bool seed_pending,seed_hold;
  float seed_value;
  bool afc_held;             // the block estimate is frozen (frame sync or a held seed)
  bool afc_from_sync;        // the estimate came from frame sync on this carrier
  uint64_t last_sync_dibit;
  uint64_t hold_dibits;
  bool rotation_pending;
  float rotation_hz;
  uint64_t rotation_deadline;
  enum p25p2_dd dd_mode;
  double dd_re,dd_im;        // sum of -d^4 / |d|^2 over the block's differential symbols
  double dd_error;           // sum of (phase - nominal phase of the decision)
  int dd_symbols;

  // timing loop stages
  float settled_bw;
  uint64_t settle_dibits;
  bool settled;
  uint64_t synced_since;

  // framer
  bool synced;
  struct softdibit ring[RING];
  uint64_t buf_start;        // oldest dibit the framer still holds
  uint64_t total;            // dibits in
  uint64_t frag_start;       // next fragment's first dibit (synced)
  uint64_t pending_first;    // a sync that may be the first of a pair (searching)
  int last_position;         // superframe position of the last fragment, -1 unknown
  bool position_known;
  bool position_from_isch;
  bool just_acquired;
  int misses;
  int isch_info[2],isch_errors[2];
  uint64_t last_rotation_report,rotation_candidate;
  int rotation_q;

  // scrambling
  bool scr_valid;
  uint64_t scr_seed;
  uint8_t seq[P25P2_SUPERFRAME_SLOTS][P25P2_BURST_BITS];
  bool scr_pending,scr_pending_valid;
  uint64_t scr_pending_seed;
  bool delivering,reparse;

  // the fragment being delivered and its decoded contents
  struct slot slots[4];
  struct p25p2_ess_collector ess[2];
  struct p25p2_ambe frames[P25P2_MAX_FRAMES];
  struct p25p2_ess ess_out;
  struct p25p2_mac mac;

  struct p25p2_stats stats;
  p25p2_burst_handler handler;
  void *handler_arg;
  p25p2_dibit_tap tap;
  void *tap_arg;
};

static void frame_dibit(struct p25p2 *p,struct softdibit const *sd);

// ---------------- scrambling ----------------

static uint64_t scr_seed(uint32_t wacn,uint16_t sysid,uint16_t nac){
  return (uint64_t)(wacn & 0xfffff) << 24 | (uint64_t)(sysid & 0xfff) << 12 | (nac & 0xfff);
}
// 44-bit register shifting left, output its bit 43, feedback 43 ^ 33 ^ 19 ^ 14 ^ 8 ^ 3; a zero
// seed is all ones. Superframe timeslot k is xored with stream bits 20 + 360 k on: the stream
// starts halfway through the superframe's first ISCH, and each timeslot is 320 of every 360
static void sequence_from_seed(uint8_t seq[P25P2_SUPERFRAME_SLOTS][P25P2_BURST_BITS],uint64_t seed){
  uint64_t const mask = ((uint64_t)1 << 44) - 1;
  uint64_t reg = seed & mask;
  if(reg == 0)
    reg = mask;
  for(int i=0; i < 20 + 360 * P25P2_SUPERFRAME_SLOTS; i++){
    uint64_t const out = (reg >> 43) & 1;
    int const k = (i - 20) / 360,b = (i - 20) % 360;
    if(i >= 20 && b < P25P2_BURST_BITS)
      seq[k][b] = (uint8_t)out;
    uint64_t const fb = out ^ (reg >> 33) ^ (reg >> 19) ^ (reg >> 14) ^ (reg >> 8) ^ (reg >> 3);
    reg = ((reg << 1) | (fb & 1)) & mask;
  }
  // The DUID is sent in the clear
  static int const duid_bits[8] = { 0, 1, 74, 75, 244, 245, 318, 319 };
  for(int k=0; k < P25P2_SUPERFRAME_SLOTS; k++)
    for(int i=0; i < 8; i++)
      seq[k][duid_bits[i]] = 0;
}
void p25p2_scrambling_sequence(uint8_t seq[P25P2_SUPERFRAME_SLOTS][P25P2_BURST_BITS],uint32_t wacn,
			       uint16_t sysid,uint16_t nac){
  sequence_from_seed(seq,scr_seed(wacn,sysid,nac));
}
// Take up parameters set since the last fragment
static void refresh_scrambling(struct p25p2 *p){
  if(!p->scr_pending)
    return;
  p->scr_pending = false;
  if(p->scr_pending_valid && (!p->scr_valid || p->scr_pending_seed != p->scr_seed))
    sequence_from_seed(p->seq,p->scr_pending_seed);
  p->scr_valid = p->scr_pending_valid;
  p->scr_seed = p->scr_pending_seed;
}
void p25p2_set_scrambling(struct p25p2 *p,uint32_t wacn,uint16_t sysid,uint16_t nac){
  uint64_t const seed = scr_seed(wacn,sysid,nac);
  if(p->delivering && (!p->scr_valid || seed != p->scr_seed))
    p->reparse = true;
  p->scr_pending = true;
  p->scr_pending_valid = true;
  p->scr_pending_seed = seed;
}
void p25p2_clear_scrambling(struct p25p2 *p){
  p->scr_pending = true;
  p->scr_pending_valid = false;
}

// ---------------- frequency and timing loops driven by frame sync ----------------

static void reset_to_acquisition(struct p25p2 *p){
  p->frame_synced = false;
  p->settled = false;
  lock_symsync(&p->sync,false);
  reset_symsync_rate(&p->sync); // drop the rate estimate noise has walked
  // Hold the frequency where frame sync left it; the block estimate only acquires a carrier
  // not yet synced (or not for Afc_hold_time)
  set_freqtrack_corner(&p->afc,p->afc_held ? 0 : Afc_acquire_corner);
}
static void frame_sync(struct p25p2 *p,bool synced){
  if(synced == p->frame_synced)
    return;
  if(!synced){
    reset_to_acquisition(p);
    return;
  }
  p->frame_synced = true;
  p->rotation_pending = false;
  // From here the decided symbols move the estimate; the block estimate is frozen
  set_freqtrack_corner(&p->afc,p->dd_mode == P25P2_DD_OFF ? Afc_track_corner : 0);
  p->afc_held = p->dd_mode != P25P2_DD_OFF;
  p->afc_from_sync = true;
  p->last_sync_dibit = p->rx_dibits;
  p->synced_since = p->rx_dibits;
  p->settled = false;
  lock_symsync(&p->sync,true);
}
// The framer found the sync with every dibit turned by 'q' quadrants (+90 degrees each)
static void rotated_sync(struct p25p2 *p,int q){
  q = ((q % 4) + 4) % 4;
  if(q == 0)
    return;
  float const move = (q == 2 ? 2.0f : q == 1 ? 1.0f : -1.0f) * Quadrant_hz;
  seed_freqtrack(&p->afc,p->afc.estimate + move);
  p->stats.rotated_syncs++;
  p->rotation_pending = true;
  p->rotation_hz = move;
  p->rotation_deadline = p->rx_dibits + Rotation_revert;
}

// ---------------- framer ----------------

static inline struct softdibit const *at(struct p25p2 const *p,uint64_t index){
  return &p->ring[index & (RING - 1)];
}
// Bit errors between the sync pattern, each dibit turned by q * 90 degrees, and the 20 dibits
// from stream index 'index'
static int sync_errors_at(struct p25p2 const *p,uint64_t index,int q){
  if(index < p->buf_start || index + SYNC_DIBITS > p->total)
    return 99;
  static int const turn[4] = { 1, 3, 0, 2 }; // +90 degrees: 00 -> 01 -> 11 -> 10 -> 00
  int errors = 0;
  for(int i=0; i < SYNC_DIBITS; i++){
    int expected = Sync_pattern[i];
    for(int k=0; k < q; k++)
      expected = turn[expected];
    errors += __builtin_popcount((unsigned)(at(p,index + i)->dibit ^ expected));
  }
  return errors;
}
static void trim_search(struct p25p2 *p){
  if(p->total - p->buf_start > SEARCH_TRIM)
    p->buf_start = p->total - SEARCH_KEEP;
}
static void trim_synced(struct p25p2 *p){
  if(p->frag_start > p->buf_start + FRAGMENT)
    p->buf_start = p->frag_start - FRAGMENT;
}
static void lose_sync(struct p25p2 *p){
  p->synced = false;
  p->misses = 0;
  p->last_position = -1;
  p->position_known = false;
  p->pending_first = NONE;
  p->stats.sync_losses++;
  for(int ts=0; ts < 2; ts++)
    p25p2_ess_reset(&p->ess[ts]);
  frame_sync(p,false);
  trim_search(p);
}

// The superframe position of the fragment at 'fs': from I-ISCH 1 (channel 0) or I-ISCH 2
// (channel 1), whichever needed fewer corrections; if neither, one on from the last; until one
// decodes after acquisition, a guess (0). A heavily corrected I-ISCH that contradicts the
// position carried on is more likely a mis-decode
static int fragment_position(struct p25p2 *p,uint64_t fs){
  int const predicted = p->last_position >= 0 ? (p->last_position + 1) % 3 : -1;
  int position = -1,corrected = 99;
  for(int ch=0; ch < 2; ch++){
    uint64_t word = 0;
    uint64_t const base = fs + (ch == 0 ? ISCH1 : ISCH2);
    for(int d=0; d < P25P2_ISCH_DIBITS; d++)
      word = (word << 2) | at(p,base + d)->dibit;
    int info = -1;
    int const e = isch_decode_word(word,ch,&info);
    p->isch_info[ch] = e >= 0 ? info : -1;
    p->isch_errors[ch] = e;
    if(e < 0)
      continue;
    p->stats.isch[ch]++;
    int const seq = (info >> 3) & 3;
    if(seq < 3 && e < corrected){
      position = seq;
      corrected = e;
    }
  }
  if(position >= 0 && predicted >= 0 && position != predicted && corrected > ISCH_TRUST)
    position = -1;
  p->position_from_isch = position >= 0;
  if(position >= 0){
    p->position_known = true;
    p->stats.position_isch++;
  } else if(predicted >= 0){
    position = predicted;
    p->stats.position_flywheel++;
  } else
    position = 0;
  p->last_position = position;
  return position;
}

// A timeslot's running voice position, five per superframe, or -1 when the superframe
// position is not known (the sixth burst of a timeslot in a superframe is its SACCH)
static int64_t voice_position(struct p25p2_burst const *b){
  if(!b->position_known)
    return -1;
  int const n = b->superframe_slot >> 1;
  if(n > 4)
    return -1;
  int64_t const start = (int64_t)b->dibit - 20 - 180 * b->superframe_slot;
  int64_t const superframe = (start + 1080) / 2160;
  return superframe * 5 + n;
}

// Decode one burst's contents and hand it up
static void deliver(struct p25p2 *p,struct slot *s){
  struct p25p2_burst * const b = &s->b;
  int const ts = b->timeslot;
  b->bits = s->bits;
  b->confidence = s->conf;
  b->nframes = 0;
  b->voice = NULL;
  b->ess = NULL;
  b->mac = NULL;
  bool const readable = b->descrambled || !p25p2_duid_scrambled(b->duid);
  if(!b->reparsed){
    if(b->duid >= 0)
      p->stats.bursts[ts][b->duid]++;
    else
      p->stats.unknown[ts]++;
    if(!readable)
      p->stats.undescrambled[ts]++;
  }
  if(readable && p25p2_duid_mac_chan(b->duid) >= 0){
    p25p2_mac_decode_burst(&p->mac,b->duid,s->bits,s->conf);
    b->mac = &p->mac;
    if(p->mac.crc_ok){
      p->stats.mac_ok[ts]++;
      // A new transmission (or none): its ESS must not be assembled from the last one's
      int const type = p->mac.bits[0] << 2 | p->mac.bits[1] << 1 | p->mac.bits[2];
      if(type == P25_MAC_PTT || type == P25_MAC_END_PTT || type == P25_MAC_IDLE || type == P25_MAC_HANGTIME)
	p25p2_ess_reset(&p->ess[ts]);
    } else
      p->stats.mac_bad[ts]++;
  } else if(readable && p25p2_duid_voice(b->duid)){
    int64_t const vi = voice_position(b);
    if(b->duid == P25P2_DUID_4V)
      p25p2_ess_add(&p->ess[ts],s->bits,vi);
    else {
      if(p25p2_ess_decode(&p->ess[ts],&p->ess_out,s->bits,vi))
	p->stats.ess_ok[ts]++;
      else
	p->stats.ess_bad[ts]++;
      b->ess = &p->ess_out;
    }
    b->nframes = p25p2_voice_decode(p->frames,b->duid,s->bits);
    b->voice = p->frames;
    for(int i=0; i < b->nframes; i++){
      p->stats.voice_frames[ts]++;
      p->stats.ambe_errors[ts] += (uint64_t)(p->frames[i].errors[0] + p->frames[i].errors[1]);
    }
  }
  if(p->handler != NULL)
    p->handler(p->handler_arg,b);
}

// The dibit offset (0, +-1, +-2) at which the fragment's syncs fit best, or NO_SYNC
static int best_offset(struct p25p2 const *p,uint64_t fs){
  static int const offsets[5] = { 0, 1, -1, 2, -2 };
  int best = NO_SYNC,best_score = 1000;
  for(int i=0; i < 5; i++){
    int const k = offsets[i];
    uint64_t const shifted = (uint64_t)((int64_t)fs + k);
    int const e1 = sync_errors_at(p,shifted + SYNC1,0);
    int const e2 = sync_errors_at(p,shifted + SYNC2,0);
    bool ok;
    if(k == 0)
      ok = e1 <= TRACK || e2 <= TRACK;
    else {
      int const threshold = (k == 1 || k == -1) ? SLIP1 : SLIP2;
      ok = e1 <= threshold && e2 <= threshold;
    }
    if(ok && e1 + e2 < best_score){ // ties keep the smaller offset
      best = k;
      best_score = e1 + e2;
    }
  }
  return best;
}

// One fragment while synced: both S-ISCHs where expected (or a dibit or two away: the timing
// loop can slip), the position from the I-ISCHs, then the four bursts. Timeslots A, B, C, D
// carry channels 0, 1, 0, 1, except in the superframe's last fragment, where C carries 1 and
// D carries 0; the scrambling segment follows the burst's place in the superframe
static void process_fragment(struct p25p2 *p){
  // The fragment acquisition found, and one whose syncs are both clean where expected, are
  // aligned and delivered at once; others wait for the dibits a +2 offset needs
  bool const aligned = p->just_acquired || (sync_errors_at(p,p->frag_start + SYNC1,0) <= CLEAN
					    && sync_errors_at(p,p->frag_start + SYNC2,0) <= CLEAN);
  if(!aligned && p->total < p->frag_start + FRAGMENT + MAX_SLIP)
    return;
  p->just_acquired = false;
  int const slip = aligned ? 0 : best_offset(p,p->frag_start);
  uint64_t fs = p->frag_start;
  bool const synced = slip != NO_SYNC;
  if(synced && slip != 0){
    fs = (uint64_t)((int64_t)fs + slip);
    p->stats.slips++;
  }
  int const sync_errors = sync_errors_at(p,fs + SYNC1,0) + sync_errors_at(p,fs + SYNC2,0);
  p->frag_start = fs + FRAGMENT; // the next fragment follows whether or not this one is usable
  if(!synced){
    // No sync where one must be: the carrier has gone or the timing has slipped. Drop the
    // fragment (noise decodes as plausible DUIDs)
    p->stats.missed_fragments++;
    if(++p->misses >= MISSES)
      lose_sync(p);
    else {
      if(p->last_position >= 0)
	p->last_position = (p->last_position + 1) % 3; // it still occupies a position
      trim_synced(p);
    }
    return;
  }
  p->misses = 0;
  p->stats.fragments++;
  int const position = fragment_position(p,fs);
  bool const last = position == 2;
  int const channel[4] = { 0, 1, last ? 1 : 0, last ? 0 : 1 };
  refresh_scrambling(p);
  p->delivering = true;
  for(int i=0; i < 4; i++){
    struct slot * const s = &p->slots[i];
    struct p25p2_burst * const b = &s->b;
    memset(b,0,sizeof *b);
    b->timeslot = channel[i];
    b->fragment = position;
    b->superframe_slot = position * 4 + i;
    b->position_from_isch = p->position_from_isch;
    b->position_known = p->position_known;
    b->isch = i < 2 ? p->isch_info[i] : -1;
    b->isch_errors = i < 2 ? p->isch_errors[i] : -1;
    b->sync_errors = sync_errors;
    b->dibit = fs + Burst_offset[i];
    for(int d=0; d < P25P2_BURST_DIBITS; d++){
      struct softdibit const *sd = at(p,b->dibit + d);
      s->bits[2*d] = (sd->dibit >> 1) & 1;
      s->bits[2*d+1] = sd->dibit & 1;
      s->conf[d] = sd->confidence;
    }
    b->duid = p25p2_duid_decode(s->bits,s->conf,&b->duid_errors);
    if(p->scr_valid && p25p2_duid_scrambled(b->duid)){
      for(int k=0; k < P25P2_BURST_BITS; k++)
	s->bits[k] ^= p->seq[b->superframe_slot][k];
      b->descrambled = true;
    }
    deliver(p,s);
  }
  // Parameters that arrived during this fragment (a network status broadcast in one of its
  // unscrambled bursts): deliver again the scrambled bursts that went out undescrambled
  if(p->reparse){
    p->reparse = false;
    refresh_scrambling(p);
    if(p->scr_valid){
      for(int i=0; i < 4; i++){
	struct slot * const s = &p->slots[i];
	if(s->b.descrambled || !p25p2_duid_scrambled(s->b.duid))
	  continue;
	for(int k=0; k < P25P2_BURST_BITS; k++)
	  s->bits[k] ^= p->seq[s->b.superframe_slot][k];
	s->b.descrambled = true;
	s->b.reparsed = true;
	p->stats.reparsed++;
	deliver(p,s);
      }
    }
  }
  p->delivering = false;
  trim_synced(p);
}

// 'start' is signed: a sync pair in the first 540 dibits of the stream belongs to a fragment
// that began before it. One that began before the dibits held cannot be extracted: start at
// the next
static void acquire(struct p25p2 *p,int64_t start){
  while(start < (int64_t)p->buf_start)
    start += FRAGMENT;
  p->synced = true;
  p->frag_start = (uint64_t)start;
  p->misses = 0;
  p->last_position = -1;
  p->position_known = false;
  p->just_acquired = true;
  p->stats.acquisitions++;
  frame_sync(p,true);
  if(p->total >= p->frag_start + FRAGMENT)
    process_fragment(p);
}

// A sync pair with every dibit turned by the same quadrant: the frequency is off by +-1500 Hz
// (or 3000) and differential detection turns each symbol by 90 (180) degrees. Reported at most
// once a fragment, and only when the same rotation is found again one fragment later: single
// rotated pairs turn up in other signals now and then, a rotated TDMA carrier repeats every
// fragment
static void hunt_rotated(struct p25p2 *p,uint64_t hit){
  if(hit < p->buf_start + PAIR)
    return;
  if(p->last_rotation_report != NONE && hit < p->last_rotation_report + FRAGMENT)
    return;
  for(int q=1; q < 4; q++){
    if(sync_errors_at(p,hit,q) <= HUNT && sync_errors_at(p,hit - PAIR,q) <= HUNT_PARTNER){
      uint64_t const expected = p->rotation_candidate + FRAGMENT;
      if(p->rotation_candidate != NONE && q == p->rotation_q
	 && hit + ROTATION_TOLERANCE >= expected && hit <= expected + ROTATION_TOLERANCE){
	p->rotation_candidate = NONE;
	p->last_rotation_report = hit;
	rotated_sync(p,q);
      } else if(p->rotation_candidate == NONE || hit > expected + ROTATION_TOLERANCE){
	p->rotation_candidate = hit;
	p->rotation_q = q;
      }
      return;
    }
  }
}

// Acquisition: a sync is either the fragment's first S-ISCH or its second. Acquire only when
// the other is there too: 180 dibits earlier (the hit was the second), else 180 later (it was
// the first). Taking a lone sync as the first locks one timeslot late three times in four
static void hunt(struct p25p2 *p){
  if(p->pending_first != NONE && p->total >= p->pending_first + PAIR + SYNC_DIBITS){
    uint64_t const first = p->pending_first;
    p->pending_first = NONE;
    if(sync_errors_at(p,first + PAIR,0) <= HUNT_PARTNER){
      acquire(p,(int64_t)first - SYNC1);
      return;
    }
  }
  if(p->total < SYNC_DIBITS)
    return;
  uint64_t const hit = p->total - SYNC_DIBITS;
  int const e = sync_errors_at(p,hit,0);
  if(e > HUNT)
    hunt_rotated(p,hit);
  if(e <= HUNT){
    if(hit >= p->buf_start + PAIR && sync_errors_at(p,hit - PAIR,0) <= HUNT_PARTNER){
      p->pending_first = NONE;
      acquire(p,(int64_t)hit - SYNC2);
      return;
    }
    if(p->pending_first == NONE)
      p->pending_first = hit;
  }
  trim_search(p);
}

static void frame_dibit(struct p25p2 *p,struct softdibit const *sd){
  p->ring[p->total & (RING - 1)] = *sd;
  p->total++;
  p->stats.dibits++;
  if(!p->synced)
    hunt(p);
  else if(p->total >= p->frag_start + FRAGMENT)
    process_fragment(p);
}

// ---------------- receive chain ----------------

// Called by the timing loop for every interpolated sample: symbols and the midpoints between them
static void sync_output(void *arg,float complex y,bool is_symbol){
  struct p25p2 * const p = arg;
  if(!is_symbol)
    return;
  float complex const z = y * conjf(p->prev_symbol);
  p->prev_symbol = y;
  struct softdibit const sd = make_softdibit(z);
  // Residual frequency from the symbols: the fourth power of each differential symbol takes
  // out H-DQPSK's +-45 and +-135 degree steps (power weighted, unambiguous to +-750 Hz), or
  // the phase error against each decision (unweighted, the same span)
  double const re = crealf(z),im = cimagf(z);
  double const m2 = re * re + im * im;
  if(m2 > 0){
    double const r2 = re * re - im * im,i2 = 2 * re * im; // z^2
    p->dd_re -= (r2 * r2 - i2 * i2) / m2;
    p->dd_im -= 2 * r2 * i2 / m2;
  }
  p->dd_error += sd.phase - Nominal_phase[sd.dibit];
  p->dd_symbols++;
  if(p->ndibits < p->max_dibits)
    p->dibits[p->ndibits++] = sd;
}

static void run_block(struct p25p2 *p,float complex const *iq,int count){
  if(!p->primed){
    // From its default the level estimate would take a tenth of a second to reach a weak stream's level
    prime_level(&p->level,iq,count);
    p->primed = true;
  }
  if(p->seed_pending){
    p->seed_pending = false;
    seed_freqtrack(&p->afc,p->seed_value);
    p->rotation_pending = false;
    if(p->seed_hold && !p->afc_from_sync){
      // A held seed (a grant): the block estimate stays frozen until frame sync
      p->afc_held = true;
      p->last_sync_dibit = p->rx_dibits;
      set_freqtrack_corner(&p->afc,0);
    }
    p->seed_hold = false;
  }
  if(p->rotation_pending && p->rx_dibits >= p->rotation_deadline){
    p->rotation_pending = false;
    if(!p->frame_synced){
      seed_freqtrack(&p->afc,p->afc.estimate - p->rotation_hz);
      p->stats.rotation_reverts++;
    }
  }
  float complex * const buf = p->block;
  memcpy(buf,iq,(size_t)count * sizeof *buf);
  run_level(&p->level,buf,count);

  // Frequency: the residual is measured on a copy corrected by the current estimate and
  // lowpassed, the estimate updated, and this same block corrected by the update, so a
  // carrier's first timeslot is corrected too. The unfiltered copy gives the coherence (the
  // filter would make white noise look coherent) and a large residual the filter under-reads
  memcpy(p->copy,buf,(size_t)count * sizeof *buf);
  shift_freqtrack(&p->afc,p->copy,count,p->afc.estimate);
  measure_freqtrack(&p->afc,p->copy,count);
  run_rxfilter(&p->measure,p->copy,count);
  float residual = 0;
  bool const valid = freqtrack_residual(&p->afc,p->copy,count,&residual);
  update_freqtrack(&p->afc,valid,residual,count);
  shift_freqtrack(&p->shift,buf,count,p->afc.estimate);

  if(p->matched)
    run_rxfilter(&p->rrc,buf,count);

  p->ndibits = 0;
  p->dd_re = p->dd_im = 0;
  p->dd_error = 0;
  p->dd_symbols = 0;
  run_symsync(&p->sync,buf,count,sync_output,p);
  p->rx_dibits += (uint64_t)p->ndibits;

  // With frame sync the decisions move the estimate, from the next block
  if(p->frame_synced && p->dd_mode != P25P2_DD_OFF){
    p->last_sync_dibit = p->rx_dibits;
    double hz = 0;
    bool ok = false;
    if(p->dd_mode == P25P2_DD_FOURTH_POWER && (p->dd_re != 0 || p->dd_im != 0)){
      hz = atan2(p->dd_im,p->dd_re) * P25P2_SYMRATE / (8 * M_PI);
      ok = true;
    } else if(p->dd_mode == P25P2_DD_DECISIONS && p->dd_symbols > 0){
      hz = p->dd_error / p->dd_symbols * P25P2_SYMRATE / (2 * M_PI);
      ok = true;
    }
    if(ok){
      adjust_freqtrack(&p->afc,Dd_gain * (float)hz);
      p->stats.dd_updates++;
    }
  } else if(p->frame_synced){
    p->last_sync_dibit = p->rx_dibits;
  } else if(p->afc_held && p->rx_dibits - p->last_sync_dibit > p->hold_dibits){
    p->afc_held = false;
    p->afc_from_sync = false;
    set_freqtrack_corner(&p->afc,Afc_acquire_corner);
  }

  if(p->tap != NULL)
    for(int i=0; i < p->ndibits; i++)
      p->tap(p->tap_arg,&p->dibits[i]);
  for(int i=0; i < p->ndibits; i++)
    frame_dibit(p,&p->dibits[i]);

  // Optional second stage of the timing loop once frame sync has been held a while
  if(p->frame_synced && !p->settled && p->settled_bw != p->sync.track_bw
     && p->rx_dibits - p->synced_since >= p->settle_dibits){
    p->settled = true;
    set_symsync_bandwidth(&p->sync,p->settled_bw);
  }
}

struct p25p2 *create_p25p2(double samprate){
  if(samprate < 4 * P25P2_SYMRATE) // the loops want at least 4 samples per symbol
    return NULL;
  struct p25p2 * const p = calloc(1,sizeof *p);
  if(p == NULL)
    return NULL;
  p->samprate = samprate;
  p->prev_symbol = 1;
  p->matched = true;
  p->dd_mode = P25P2_DD_FOURTH_POWER;
  p->pending_first = NONE;
  p->last_position = -1;
  p->last_rotation_report = NONE;
  p->rotation_candidate = NONE;
  p->hold_dibits = (uint64_t)(Afc_hold_time * P25P2_SYMRATE);
  p->settled_bw = Track_bw;
  p->settle_dibits = (uint64_t)(Settle_time * P25P2_SYMRATE);
  p->max_block = (int)ceil(Max_block_time * samprate);
  p->max_dibits = (int)(p->max_block * 1.1 * P25P2_SYMRATE / samprate) + 16;
  p->block = calloc((size_t)p->max_block,sizeof *p->block);
  p->copy = calloc((size_t)p->max_block,sizeof *p->copy);
  p->dibits = calloc((size_t)p->max_dibits,sizeof *p->dibits);
  init_level(&p->level,samprate,Level_time);
  init_freqtrack(&p->afc,samprate,Afc_acquire_corner);
  init_freqtrack(&p->shift,samprate,0);
  int const measure_taps = (int)lrint(Measure_span * samprate) | 1;
  if(p->block == NULL || p->copy == NULL || p->dibits == NULL
     || init_rxfilter(&p->measure,samprate,Measure_cutoff,measure_taps,0) != 0
     || init_rrcfilter(&p->rrc,samprate,P25P2_SYMRATE,Rrc_alpha,Rrc_span) != 0
     || init_symsync(&p->sync,samprate,P25P2_SYMRATE,Interp_phases,Acquire_bw,Track_bw,Loop_damping,Error_gain,Rate_limit) != 0){
    delete_p25p2(p);
    return NULL;
  }
  return p;
}
void delete_p25p2(struct p25p2 *p){
  if(p == NULL)
    return;
  free_rxfilter(&p->measure);
  free_rxfilter(&p->rrc);
  free_symsync(&p->sync);
  free(p->block);
  free(p->copy);
  free(p->dibits);
  free(p);
}
void p25p2_set_burst_handler(struct p25p2 *p,p25p2_burst_handler handler,void *arg){
  p->handler = handler;
  p->handler_arg = arg;
}
void p25p2_set_dibit_tap(struct p25p2 *p,p25p2_dibit_tap tap,void *arg){
  p->tap = tap;
  p->tap_arg = arg;
}
void p25p2_samples(struct p25p2 *p,float complex const *iq,int count){
  assert(p != NULL);
  while(count > 0){
    int const n = count > p->max_block ? p->max_block : count;
    run_block(p,iq,n);
    iq += n;
    count -= n;
  }
}
void p25p2_dibit(struct p25p2 *p,struct softdibit const *sd){
  frame_dibit(p,sd);
}
void p25p2_seed_frequency(struct p25p2 *p,float offset,bool hold){
  if(hold && p->afc_from_sync)
    return; // frame sync on this carrier has given it its own estimate
  p->seed_pending = true;
  p->seed_value = offset;
  p->seed_hold = hold;
}
float p25p2_frequency_offset(struct p25p2 const *p){
  return p->afc.estimate;
}
void p25p2_set_decision_directed(struct p25p2 *p,enum p25p2_dd mode){
  p->dd_mode = mode;
}
void p25p2_set_loop_bandwidths(struct p25p2 *p,float acquire,float track,float settled,float settle_time){
  if(acquire >= 0)
    p->sync.acquire_bw = acquire;
  if(track >= 0){
    if(p->settled_bw == p->sync.track_bw && settled < 0)
      p->settled_bw = track; // still one stage
    p->sync.track_bw = track;
  }
  if(settled >= 0)
    p->settled_bw = settled;
  if(settle_time >= 0)
    p->settle_dibits = (uint64_t)(settle_time * P25P2_SYMRATE);
  if(acquire >= 0 && !p->sync.locked)
    set_symsync_bandwidth(&p->sync,p->sync.acquire_bw);
}
void p25p2_set_matched_filter(struct p25p2 *p,bool enable){
  p->matched = enable;
}
void p25p2_get_stats(struct p25p2 const *p,struct p25p2_stats *stats){
  *stats = p->stats;
  stats->locked = p->synced;
  stats->frequency_offset = p->afc.estimate;
  stats->timing_error = p->sync.error_ema;
}
