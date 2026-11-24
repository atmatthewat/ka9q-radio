// DMR frame sync and TDMA slot framing (see dmrsink.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dmrfec.h"
#include "dmrsink.h"

// Theory of operation
//
// Geometry. A slot period is 144 dibits: 12 of CACH on a base station's outbound carrier (guard
// time on a mobile station's or in direct mode), then the 132-dibit burst, whose 24-dibit sync or
// EMB field sits in its middle, 54 dibits in. The sync therefore ends at dibit 89 of the period
// (Sync_end_offset). When it is found, the CACH and the first half of the burst have already gone
// by, so every soft dibit is kept in a ring of the last 1024 (Ring), and the burst is complete 54
// dibits later. A frame is the two alternating channels (timeslots) of one transmitter's periods.
//
// Measures. The sync correlation is the sum over the 24 sync dibits of cos(phase - ideal phase),
// 24 for a perfect sync. Every sync word is outer symbols only (+-135 degrees), and the ten come in
// pairs that are each other's inverse (voice / data, reverse channel / reserved), so with
// cos(a - b) = cos a cos b + sin a sin b the cosine half, -sum(cos) / sqrt 2, is common to all of
// them and one signed sum of sines serves a pair: ten patterns cost five 24-term sums a dibit
// (best_sync()). The level error of a sync is the mean of phase - ideal over its symbols (those
// within Level_error_range of their level; a symbol further off is a symbol error), clamped at
// Max_level: a carrier offset the receiver has not taken out shifts every symbol alike, so it is
// the one direct reading of the carrier there is. The levelled correlation is the correlation with
// that level taken off first. Bits come from a dibit's phase alone, a level taken off, with a
// 4-level slicer's geometry: the first bit is the sign, with confidence |phase| / 45 degrees, the
// second is inner / outer, with confidence ||phase| - 90 degrees| / 45 degrees, both at most 1.
//
// Searching (no frame held). Every dibit the last 24 are correlated against the enabled patterns;
// a window reaching candidate_sync (14) is judged Slot_type_tail (5) dibits later, when the second
// half of a data burst's slot type has arrived. Each window is judged on its own: taking the best of
// neighbouring windows would let a chance near-sync of another pattern a dibit away shadow a weak
// true one.
//   strong_sync (20.5) or better: accepted on the correlation alone (a pinned colour code is still
//     obeyed: a data sync whose slot type decodes to another code is refused, a voice sync waits).
//   weak_sync (17) or better: accepted only with validation and only once there is a colour code to
//     match (a strong sync's or a pinned one; with DMR_CC_ANY the validator limits are all 0). A data
//     sync needs its slot type (Golay(20,8)) to decode within weak_slot_type_limit_bs (1) weighted
//     errors on a base station sync, weak_slot_type_limit (0) otherwise, to that colour code; a base
//     station sync also needs its CACH's TACT (Hamming(7,4)) within weak_tact_limit (0); a voice sync
//     waits until the EMBs (QR(16,7)) of the next two bursts of its slot, 288 and 576 dibits on, have
//     both decoded within Tight_limit (1) to that colour code, or until another sync is accepted a
//     whole number of periods from it, and the bursts since are then replayed from the ring; a reverse
//     channel sync has no validator and is never taken this way.
//   candidate_sync or better: a near miss. With its level error taken off and, with a receiver, the
//     window re-sampled at the timing that maximises its levelled correlation (a hill climb from an
//     eighth of a symbol down to one interpolator arm, within Max_retime_symbols), a window reaching
//     retimed_sync (18) is judged as a weak sync. Never as a strong one: the best of many timings of a
//     noise window is good far more often than the window itself.
//
// Half a symbol off. A Gardner timing loop has a second, unstable, equilibrium on the midpoints
// between the symbols, and coming up near it a loop can hang there for several bursts (Gardner's
// hang-up: the error averages out on both sides). As sampled its syncs then read 3 - 11, half a
// symbol earlier 17 - 24, so no window reaches candidate_sync and the frame is acquired only when
// the loop has slid off by itself, at the carrier's third burst or later. So, searching and with a
// receiver (half_symbol_search), every dibit is also taken half a symbol earlier (resample() of the
// newest symbol, which needs no sample still to come) into a ring of its own, and the same windows
// are correlated on those. One that reaches candidate_sync is judged Slot_type_tail dibits later as a
// near miss is, from the timing half a symbol earlier and no further than a nudge reaches
// (Max_nudge_symbols): the climb's best levelled correlation reaching retimed_sync is judged as a weak
// sync, and the window at half a symbol, if it reached strong_sync, as a strong one (it is one timing,
// as a window as sampled is). Taken (or a voice sync left waiting for its EMBs), the burst so far is
// re-sampled there and the receiver nudged there, in two steps when that is more than one nudge
// moves; looking back then finds the period before, whose climb reaches it from either side.
//
// Acquisition (a sync accepted with no frame held). The burst so far is re-sampled from the
// receiver's history at the timing that maximises its sync (on a rigid grid of nominal symbol
// periods through the sync where the receiver can: its timing loop, at its wide acquisition
// bandwidth, was slewing under those symbols), the receiver's timing is nudged there and the
// receiver is told it is frame locked; once the acquiring burst is in, its second half is re-sampled
// on that rigid grid too (rigid_tail), not as the loops sampled it after the nudge, still settling.
// The Look_back_periods (2) periods ahead of the acquiring sync are in the ring too, and their
// position is now known: a levelled sync of weak_sync or better there (with a receiver, every
// pattern of the acquiring family at its own best timing, as far back as the history reaches)
// starts the frame that much earlier. A transmission's first sync is seldom the one
// the search takes, so this is what recovers most first bursts. A frame begun by a weak sync is not
// believed until a second burst is confirmed: its first burst waits and is dropped if the frame is
// lost first. A strong sync's burst goes out alone (a lone CSBK is a burst). The next
// settling_bursts sync bursts are each re-sampled at their own sync's best timing as well, while the
// loops settle, when that gains Settling_gain (0.3) of correlation.
//
// Levels. The receiver's frequency correction steps once a block, so what a sync reads is not
// exactly what the dibits either side of it had. Where the receiver says which correction each
// symbol had (frequency_correction_at), a level read at one dibit is taken off another less what the
// correction moved between the two times the receiver's radians per Hz. Where it does not, the
// acquiring burst's head has the sync's level and its second half finds its own (blind_level(): the
// shift on a grid of Blind_level_step between 0 and the sync's level, Blind_level_margin beyond both,
// that brings the dibits nearest the four levels, then the mean residual there). Every later sync
// burst has its own level error taken off it whole; a voice burst B-F has the last sync's (of the same
// transmitter: any on a base station frame, its channel's otherwise), times level_carry_decay (0.9) a
// period.
//
// In a frame (the flywheel). One period every 144 dibits, the two channels alternating. At each
// period's expected position, in this order: a correlation of strong_sync makes a sync burst; an EMB
// within Tight_limit to the colour code (without error after two periods with no confirmation: the
// carrier may be gone) makes a voice burst B-F; a correlation of locked_sync (14; mid_superframe_sync
// (16) where the count expects voice B-F; weak_sync after two periods with no confirmation) makes a
// sync burst; an EMB with two errors to the colour code and with the LCSS its position has makes a
// voice burst, only where the count expects one; otherwise the period is unconfirmed. Below
// strong_sync a frame keeps its family and, in direct mode, its timeslots (frame_keeps_family): noise
// on a lost burst reaches locked_sync on one of the nine patterns now and then, and taken on another
// family's pattern it would change the frame's mode and slot numbering until the next real sync.
//   An unconfirmed period inside a voice call (two voice bursts confirmed on the channel) is handed on
// as the voice burst the count expects, sync none and EMB not valid, for at most channel_miss_limit
// (2) periods in a row: its voice frames have FEC of their own. Any other unconfirmed period is not
// handed on: nothing says what it is, or that it is a burst.
//   A frame is tentative until two bursts are confirmed. It is dropped, and the receiver unlocked,
// after loss_bursts (12, 360 ms) periods in a row without a confirmation (Tentative_loss_bursts (4)
// while tentative); on a mobile station or direct mode frame, which has a burst every other period,
// the tentative limit is doubled.
//   The other channel of a mobile station or direct mode frame is idle until a sync is found on it by
// the searching rules: noise there must not become bursts. A channel that had a transmitter and has
// missed channel_miss_limit bursts is idle too; since its voice bursts B-F carry no sync it also comes
// back on an EMB that decodes without error to the frame's colour code (emb_revives_channel), but only
// while the frame would still be held for the channel's last burst. Both channels of a base station
// frame are live at once, which gives voice late entry on the other slot.
//   A sync elsewhere: in a tentative frame, a data sync by the searching rules (a voice sync waits for
// its EMBs); in a confirmed frame, a strong sync within Slip_dibits (2) of the expected position moves
// the frame and keeps its state (a timing slip), and elsewhere only a strong data sync whose slot type
// decodes within Tight_limit to the frame's colour code, or a strong voice sync and its two EMBs, takes
// the frame there (a re-frame). A carrier's own payload is full of near-syncs.
//
// The receiver. Of every sync burst whose levelled correlation reaches afc_sync (17), the level error
// in Hz goes to the receiver's frequency loop with the dibit it was read at (the receiver takes it
// against the correction that dibit had): the first syncs of a frame as a running mean (gain 1, 1/2,
// 1/3 ...), then at afc_gain (0.1). Not from a tentative frame: its latest reading waits for the
// second confirmation, so that a false sync from noise cannot leave the loop far off. With a
// transmitter on one channel of a mobile station or direct mode frame, the receiver's loops are held
// from each burst's last dibit to the next burst's first (hold_empty_periods).
//
// Slot numbers. Base station: the TACT's TC bit, by a vote (2 for a TACT without error, 1 for a
// corrected one, saturating at +-Slot_score_limit (16)), so alternation fills in where a TACT fails
// and one wrong TC changes nothing. A frame's first bursts are held back (Max_held (3) at most) until
// the score reaches Slot_confident (3): the CACH of a transmission's first burst is its first 12
// symbols, and a wrong TC there would put a call's first header on the other slot. Direct mode: the
// sync pattern (TS1 / TS2). Mobile station: an inbound burst carries no slot number, so the frame's
// first channel is 1 and the other 2 (the burst's mode says the number is relative).
//
// Voice superframes, per channel: A from the voice sync, then B-F by count. Without a count (late
// entry) the position comes from the EMB's LCSS: first = B, last = E, single fragment = F, and a
// continuation is C or D (unknown; the burst after a continuation is then D or E). A count from a
// voice sync of mid_superframe_sync or better is not overruled by the LCSS.
//
// Colour code. A data burst with a strong sync and a slot type within Tight_limit sets it (when
// tracked), as does an error-free EMB in a superframe begun by a strong voice sync. An error-free EMB
// of another code ends the channel's voice call (another system's voice).
//
// Nothing gates on signal level and no burst is skipped for its content: idle bursts and both slots
// are always handed on.

enum {
  Sync_end_offset = DMR_CACH_DIBITS + DMR_SYNC_OFFSET_DIBITS + DMR_SYNC_DIBITS - 1, // 89
  Slot_type_tail = 5,       // dibits of the slot type after the sync
  Ring = 1024,              // soft dibits kept (a power of two)
  Tentative_loss_bursts = 4,
  Slip_dibits = 2,
  Slot_confident = 3,
  Slot_score_limit = 16,
  Max_held = 3,
  Look_back_periods = 2,
  Voice_confirm_dibits = 2 * DMR_SLOT_DIBITS, // a slot's next burst
  Max_retime_dibits = 200,  // within the receiver's history
  Pairs = 5,
};
static float const Tight_limit = 1.0f;      // an EMB (or a re-frame's slot type) believed by itself
static float const Max_retime_symbols = 0.45f;
static float const Max_nudge_symbols = 0.49f; // the most the receiver's nudge moves (nudge_symsync())
static float const Settling_gain = 0.3f;
static float const Max_level = 1.0f;        // radians: a sync's level error is clamped here
static float const Level_error_range = 1.3f;
static float const Blind_level_step = 0.075f;
static float const Blind_level_margin = 0.2f;
static float const Pi = 3.14159265358979323846f;
static float const Inv_sqrt2 = 0.70710678118654752f;
static float const Eps = 1.0e-4f;

// std::min, std::max and std::clamp's comparisons, NaN included
static inline float minf(float a,float b){ return b < a ? b : a; }
static inline float maxf(float a,float b){ return a < b ? b : a; }
static inline float clampf(float v,float lo,float hi){ return v < lo ? lo : hi < v ? hi : v; }

// ---------------- colour code tracker ----------------

enum { Cc_entries = 3 };
struct cc_tracker {
  enum dmr_cc_mode mode;
  bool have;           // a code is current
  uint8_t current;
  struct {
    uint8_t cc;
    uint32_t count;
    uint64_t last_seen;
  } entries[Cc_entries]; // observations by code, least recently seen evicted (telemetry)
  uint64_t clock;
  uint64_t changes;
};
static void cc_track(struct cc_tracker *t){
  t->mode = DMR_CC_TRACK;
  t->have = false;
}
static void cc_pin(struct cc_tracker *t,uint8_t cc){
  t->mode = DMR_CC_PINNED;
  t->have = true;
  t->current = cc & 0xf;
}
static void cc_any(struct cc_tracker *t){
  t->mode = DMR_CC_ANY;
  t->have = false;
}
static void cc_count(struct cc_tracker *t,uint8_t cc){
  t->clock++;
  for(int i=0; i < Cc_entries; i++){
    if(t->entries[i].count != 0 && t->entries[i].cc == cc){
      t->entries[i].count++;
      t->entries[i].last_seen = t->clock;
      return;
    }
  }
  int slot = 0;
  for(int i=0; i < Cc_entries; i++){
    if(t->entries[i].count == 0){
      slot = i;
      break;
    }
    if(t->entries[i].last_seen < t->entries[slot].last_seen)
      slot = i;
  }
  t->entries[slot].cc = cc;
  t->entries[slot].count = 1;
  t->entries[slot].last_seen = t->clock;
}
// A code from a burst framed by a strong sync
static void cc_observe(struct cc_tracker *t,uint8_t cc){
  cc &= 0xf;
  cc_count(t,cc);
  if(t->mode != DMR_CC_TRACK)
    return;
  bool const changed = !t->have || t->current != cc;
  t->current = cc;
  t->have = true;
  if(changed)
    t->changes++;
}
// The code required now; false: none (any, or tracking before the first strong observation)
static bool cc_required(struct cc_tracker const *t,uint8_t *cc){
  if(t->mode == DMR_CC_ANY || !t->have)
    return false;
  if(cc != NULL)
    *cc = t->current;
  return true;
}
static bool cc_matches(struct cc_tracker const *t,uint8_t cc){
  uint8_t r;
  return !cc_required(t,&r) || r == (cc & 0xf);
}
static void cc_reset(struct cc_tracker *t){
  memset(t->entries,0,sizeof t->entries);
  t->clock = 0;
  if(t->mode == DMR_CC_TRACK)
    t->have = false;
}

// ---------------- the sink ----------------

struct reading {
  float value;      // as read from dibits demodulated with frequency correction 'correction'
  float correction;
  bool follows;     // taken off another dibit less what the correction moved since
};
struct candidate {
  bool active;
  int64_t end;      // the sync's last dibit
  enum dmr_sync pattern;
  float correlation;
};
struct pending_voice {
  bool active;
  int64_t end;
  enum dmr_sync pattern;
  float correlation;
  int stage;        // EMBs seen
  uint8_t cc;
};
struct forced {
  bool active;
  int64_t end;
  enum dmr_sync pattern;
};
struct channel {
  bool confirmed_once;
  int miss_run;
  enum dmr_kind next;          // the voice burst the count expects; DMR_KIND_DATA: no superframe
  bool exact;                  // the count is from a voice sync of mid_superframe_sync or better
  bool from_sync;              // this superframe's voice sync was found
  bool strong_voice;           // ... and was strong
  bool previous_continuation;  // the last burst was a continuation of unknown position
  int voice_confirmed;         // voice bursts of this call confirmed by a sync or an EMB
  float level;                 // DMR_LEVEL_CARRY
  float level_correction;
  int level_age;
};
struct sync_score {
  enum dmr_sync pattern;
  float correlation;
};
static struct sync_score const No_sync = { DMR_SYNC_NONE, -100.0f };
struct climb {
  bool ok;
  int offset;       // arms, later positive
  float centre;
  float best;
};
enum verdict { V_STRONG, V_WEAK, V_VOICE_PENDING, V_BELOW_WEAK, V_NO_VALIDATOR, V_NO_CC, V_TACT, V_SLOT_TYPE, V_CC };
enum taken { TAKEN_NONE = 0, TAKEN_SYNC, TAKEN_EMB };

struct dmr_sink {
  struct dmr_sink_config config;
  bool have_timing;
  struct dmr_sink_timing timing;
  struct cc_tracker tracker;
  dmr_burst_handler burst_handler;
  void *burst_arg;
  dmr_event_handler acquired_handler,lost_handler;
  void *acquired_arg,*lost_arg;
  dmr_clock clock;
  void *clock_arg;
  struct dmr_sink_counters counters;

  bool enabled[DMR_SYNC_PATTERNS];
  enum dmr_sync pair_first[Pairs],pair_second[Pairs];
  float sign[Pairs][DMR_SYNC_DIBITS];

  // The ring, by symbol index
  float phase[Ring],sin[Ring],cos[Ring];
  uint64_t count;           // dibits since the (re)start
  int64_t now;              // index of the newest
  int64_t first_index;      // index of the first since the (re)start

  struct candidate candidates[8]; // by the sync's last dibit: at most one a dibit, due 5 later
  // Half a symbol off: each dibit sampled half a symbol earlier, while searching (store_half()),
  // from half_from on
  float half_sin[Ring],half_cos[Ring];
  int64_t half_from;
  struct candidate half_candidates[8];
  int retime_base;          // arms retime_head()'s climbs start from (half a symbol earlier, or 0)
  bool acquired_rigid;      // the acquiring burst's head was re-sampled on a rigid grid ...
  int acquired_rigid_offset; // ... at this offset (its tail follows: rigid_tail)
  int pending_nudge_arms;   // what a nudge of more than one could move is still to do (nudge_receiver())
  struct pending_voice pending_voice[4];

  // The frame
  bool locked;
  int64_t origin;           // first dibit of the period in progress
  int channel_index;
  struct channel channels[2];
  enum dmr_station mode;
  int confirmed;
  int miss_run;
  int slot_score;
  bool slot_known;
  bool slot_trusted;        // the TC votes have agreed once in this frame: bursts no longer held
  bool channel0_is_slot1;
  float level,level_correction;
  int level_age;
  float radians_per_hz;
  bool follow_correction;   // the receiver tells its frequency corrections
  int64_t acquired_end;
  int acquired_back;        // periods the frame was begun ahead of acquired_end
  struct forced forced[8];
  struct {
    struct dmr_burst burst;
    int channel;
  } held[Max_held];
  int held_count;
  int settling;
  bool receiver_locked;
  int afc_syncs;            // syncs of this frame reported to the receiver
  struct {
    bool valid;
    float error_hz;
    int64_t symbol;
  } afc_pending;            // a tentative frame's latest sync, for when the frame is confirmed
  bool holding;             // the receiver's loops are held
  bool weak_frame;          // the frame was begun by a weak sync
  bool have_emitted;
  int64_t last_emitted_start;
};

static void lose_frame(struct dmr_sink *s);
static void process_period(struct dmr_sink *s);

void dmr_sink_config_defaults(struct dmr_sink_config *c){
  assert(c != NULL);
  memset(c,0,sizeof *c);
  c->base_station = c->mobile_station = c->direct = c->reverse_channel = true;
  c->cc_mode = DMR_CC_TRACK;
  c->pinned_cc = 0;
  c->retime = true;
  c->look_back = true;
  c->lock_receiver_on_bursty = true;
  c->settling_bursts = DMR_SETTLING_BURSTS;
  c->level_correction = DMR_LEVEL_CARRY;
  c->level_carry_decay = DMR_LEVEL_CARRY_DECAY;
  c->acquisition_tail_blind = true;
  c->afc = true;
  c->afc_gain = DMR_AFC_GAIN;
  c->afc_sync = DMR_AFC_SYNC;
  c->hold_empty_periods = true;
  c->level_follows_correction = true;
  c->acquisition_tail_follows = true;
  c->rigid_grid = true;
  c->frame_keeps_family = true;
  c->emb_revives_channel = true;
  c->half_symbol_search = true;
  c->rigid_tail = true;
  c->strong_sync = DMR_STRONG_SYNC;
  c->weak_sync = DMR_WEAK_SYNC;
  c->retimed_sync = DMR_RETIMED_SYNC;
  c->candidate_sync = DMR_CANDIDATE_SYNC;
  c->locked_sync = DMR_LOCKED_SYNC;
  c->mid_superframe_sync = DMR_MID_SUPERFRAME_SYNC;
  c->weak_slot_type_limit_bs = DMR_WEAK_SLOT_TYPE_LIMIT_BS;
  c->weak_slot_type_limit = DMR_WEAK_SLOT_TYPE_LIMIT;
  c->weak_tact_limit = DMR_WEAK_TACT_LIMIT;
  c->loss_bursts = DMR_LOSS_BURSTS;
  c->channel_miss_limit = DMR_CHANNEL_MISS_LIMIT;
}

static void apply_cc_config(struct dmr_sink *s){
  switch(s->config.cc_mode){
  case DMR_CC_PINNED:
    cc_pin(&s->tracker,s->config.pinned_cc);
    break;
  case DMR_CC_ANY:
    cc_any(&s->tracker);
    break;
  default:
    cc_track(&s->tracker);
    break;
  }
}

struct dmr_sink *create_dmr_sink(struct dmr_sink_config const *config,struct dmr_sink_timing const *timing){
  assert(config != NULL);
  if(timing != NULL && (timing->set_frame_locked == NULL || timing->resample == NULL
			|| timing->arms_per_symbol == NULL || timing->nudge == NULL))
    return NULL;
  struct dmr_sink *s = calloc(1,sizeof *s);
  if(s == NULL)
    return NULL;
  s->config = *config;
  enum dmr_sync const first[Pairs] = { DMR_SYNC_BS_VOICE, DMR_SYNC_MS_VOICE, DMR_SYNC_DIRECT_VOICE_TS1,
				       DMR_SYNC_DIRECT_VOICE_TS2, DMR_SYNC_MS_REVERSE };
  enum dmr_sync const second[Pairs] = { DMR_SYNC_BS_DATA, DMR_SYNC_MS_DATA, DMR_SYNC_DIRECT_DATA_TS1,
					DMR_SYNC_DIRECT_DATA_TS2, DMR_SYNC_RESERVED };
  for(int pair=0; pair < Pairs; pair++){
    s->pair_first[pair] = first[pair];
    s->pair_second[pair] = second[pair];
    for(int i=0; i < DMR_SYNC_DIBITS; i++)
      s->sign[pair][i] = (dmr_sync_dibit(first[pair],i) & 2) ? -1.0f : 1.0f;
  }
  if(config->base_station)
    s->enabled[DMR_SYNC_BS_VOICE] = s->enabled[DMR_SYNC_BS_DATA] = true;
  if(config->mobile_station){
    s->enabled[DMR_SYNC_MS_VOICE] = s->enabled[DMR_SYNC_MS_DATA] = true;
    if(config->reverse_channel)
      s->enabled[DMR_SYNC_MS_REVERSE] = true;
  }
  if(config->direct){
    s->enabled[DMR_SYNC_DIRECT_VOICE_TS1] = s->enabled[DMR_SYNC_DIRECT_DATA_TS1] = true;
    s->enabled[DMR_SYNC_DIRECT_VOICE_TS2] = s->enabled[DMR_SYNC_DIRECT_DATA_TS2] = true;
  }
  apply_cc_config(s);
  for(int i=0; i < Ring; i++)
    s->cos[i] = 1.0f;
  s->mode = DMR_STATION_UNKNOWN;
  s->channel0_is_slot1 = true;
  s->half_from = -1;
  s->radians_per_hz = DMR_DEFAULT_LEVEL_RADIANS_PER_HZ;
  if(timing != NULL){
    s->have_timing = true;
    s->timing = *timing;
    s->radians_per_hz = timing->level_radians_per_hz > 0 ? timing->level_radians_per_hz : DMR_DEFAULT_LEVEL_RADIANS_PER_HZ;
    s->follow_correction = timing->frequency_correction_at != NULL;
  }
  for(int c=0; c < 2; c++)
    s->channels[c].next = DMR_KIND_DATA;
  return s;
}
void delete_dmr_sink(struct dmr_sink *s){
  free(s);
}
void dmr_sink_set_burst_handler(struct dmr_sink *s,dmr_burst_handler handler,void *arg){
  s->burst_handler = handler;
  s->burst_arg = arg;
}
void dmr_sink_set_acquired_handler(struct dmr_sink *s,dmr_event_handler handler,void *arg){
  s->acquired_handler = handler;
  s->acquired_arg = arg;
}
void dmr_sink_set_lost_handler(struct dmr_sink *s,dmr_event_handler handler,void *arg){
  s->lost_handler = handler;
  s->lost_arg = arg;
}
void dmr_sink_set_clock(struct dmr_sink *s,dmr_clock clock,void *arg){
  s->clock = clock;
  s->clock_arg = arg;
}
bool dmr_sink_locked(struct dmr_sink const *s){
  return s->locked;
}
bool dmr_sink_confirmed(struct dmr_sink const *s){
  return s->locked && s->confirmed >= 2;
}
enum dmr_station dmr_sink_station(struct dmr_sink const *s){
  return s->locked ? s->mode : DMR_STATION_UNKNOWN;
}
int dmr_sink_color_code(struct dmr_sink const *s){
  uint8_t cc;
  return cc_required(&s->tracker,&cc) ? cc : -1;
}
uint32_t dmr_sink_color_code_observations(struct dmr_sink const *s,uint8_t cc){
  for(int i=0; i < Cc_entries; i++)
    if(s->tracker.entries[i].count != 0 && s->tracker.entries[i].cc == (cc & 0xf))
      return s->tracker.entries[i].count;
  return 0;
}
uint64_t dmr_sink_color_code_changes(struct dmr_sink const *s){
  return s->tracker.changes;
}
struct dmr_sink_counters const *dmr_sink_counters(struct dmr_sink const *s){
  return &s->counters;
}
// The patterns of the families the configuration enabled, of one family only when mode says which
void dmr_sink_restrict_family(struct dmr_sink *s,enum dmr_station mode){
  struct dmr_sink_config const *config = &s->config;
  bool const all = mode == DMR_STATION_UNKNOWN;
  memset(s->enabled,0,sizeof s->enabled);
  if(config->base_station && (all || mode == DMR_STATION_BS))
    s->enabled[DMR_SYNC_BS_VOICE] = s->enabled[DMR_SYNC_BS_DATA] = true;
  if(config->mobile_station && (all || mode == DMR_STATION_MS)){
    s->enabled[DMR_SYNC_MS_VOICE] = s->enabled[DMR_SYNC_MS_DATA] = true;
    if(config->reverse_channel)
      s->enabled[DMR_SYNC_MS_REVERSE] = true;
  }
  if(config->direct && (all || mode == DMR_STATION_DIRECT)){
    s->enabled[DMR_SYNC_DIRECT_VOICE_TS1] = s->enabled[DMR_SYNC_DIRECT_DATA_TS1] = true;
    s->enabled[DMR_SYNC_DIRECT_VOICE_TS2] = s->enabled[DMR_SYNC_DIRECT_DATA_TS2] = true;
  }
}

struct dmr_sink_config const *dmr_sink_config(struct dmr_sink const *s){
  return &s->config;
}
uint64_t dmr_sink_acquired_sync_end(struct dmr_sink const *s){
  return s->acquired_end > 0 ? (uint64_t)s->acquired_end : 0;
}
int dmr_sink_acquired_back_periods(struct dmr_sink const *s){
  return s->acquired_back;
}
int dmr_sink_summary(struct dmr_sink const *s,char *line,int size){
  struct dmr_sink_counters const *c = &s->counters;
  uint64_t syncs = 0;
  for(int p=0; p < DMR_SYNC_PATTERNS; p++)
    syncs += c->syncs[p];
#define U(x) ((unsigned long long)(x))
  return snprintf(line,(size_t)size,
		  "locked=%d mode=%d cc=%d bursts=%llu syncs=%llu (bsV=%llu bsD=%llu msV=%llu msD=%llu rc=%llu"
		  " dV1=%llu dD1=%llu dV2=%llu dD2=%llu) emb=%llu late=%llu unconf=%llu/%llu acq=%llu"
		  " (strong=%llu weak=%llu retimed=%llu voice=%llu) lost=%llu reframe=%llu slip=%llu"
		  " weak_rej(cc0=%llu tact=%llu st=%llu cc=%llu rc=%llu voice=%llu) cc_mismatch=%llu tc=%llu revived=%llu",
		  s->locked ? 1 : 0,(int)dmr_sink_station(s),dmr_sink_color_code(s),
		  U(c->bursts_emitted),U(syncs),U(c->syncs[0]),U(c->syncs[1]),U(c->syncs[2]),U(c->syncs[3]),
		  U(c->syncs[4]),U(c->syncs[5]),U(c->syncs[6]),U(c->syncs[7]),U(c->syncs[8]),U(c->emb_bursts),
		  U(c->late_entry_bursts),U(c->unconfirmed_emitted),U(c->flywheel_unconfirmed),U(c->acquisitions),
		  U(c->strong_syncs),U(c->weak_syncs),U(c->retimed_syncs),U(c->voice_syncs_confirmed),U(c->losses),
		  U(c->reframes),U(c->slips),U(c->weak_rejected_no_cc),U(c->weak_rejected_tact),
		  U(c->weak_rejected_slot_type),U(c->weak_rejected_cc),U(c->weak_rejected_no_validator),
		  U(c->voice_syncs_unconfirmed),U(c->cc_mismatches),U(c->tc_disagreements),U(c->channels_revived));
#undef U
}

void dmr_sink_reset(struct dmr_sink *s){
  if(s->locked)
    lose_frame(s);
  s->count = 0;
  for(int i=0; i < 8; i++)
    s->candidates[i].active = false;
  for(int i=0; i < 8; i++)
    s->half_candidates[i].active = false;
  s->half_from = -1;
  s->pending_nudge_arms = 0;
  for(int i=0; i < 4; i++)
    s->pending_voice[i].active = false;
  s->have_emitted = false;
}
void dmr_sink_reset_color_code(struct dmr_sink *s){
  cc_reset(&s->tracker);
  apply_cc_config(s);
}

// ---------------- measures ----------------

// The nominal phase of a dibit: 00 +45, 01 +135, 10 -45, 11 -135 degrees
static float ideal_phase(int dibit){
  float const magnitude = (dibit & 1) ? 0.75f * Pi : 0.25f * Pi;
  return (dibit & 2) ? -magnitude : magnitude;
}
// Hard bits and confidences of a level (radians, the 45 / 135 degree frame)
static void slice_level(float level,uint8_t *bits2,float *confidence2){
  float const magnitude = fabsf(level);
  bits2[0] = level < 0.0f ? 1 : 0;
  bits2[1] = magnitude > 0.5f * Pi ? 1 : 0;
  confidence2[0] = minf(magnitude / (0.25f * Pi),1.0f);
  confidence2[1] = minf(fabsf(magnitude - 0.5f * Pi) / (0.25f * Pi),1.0f);
}
// A sync's mean level error over the symbols within Level_error_range of their level, clamped at
// +-Max_level; 0 if fewer than half the symbols count (*counted, if not NULL: how many did)
static float level_error(float const *phases24,enum dmr_sync pattern,int *counted){
  float sum = 0.0f;
  int n = 0;
  for(int i=0; i < DMR_SYNC_DIBITS; i++){
    float const d = phases24[i] - ideal_phase(dmr_sync_dibit(pattern,i));
    if(fabsf(d) < Level_error_range){
      sum += d;
      n++;
    }
  }
  if(counted != NULL)
    *counted = n;
  if(n < DMR_SYNC_DIBITS / 2)
    return 0.0f;
  return clampf(sum / (float)n,-Max_level,Max_level);
}
static float correlate_levelled(float const *phases24,enum dmr_sync pattern){
  float const level = level_error(phases24,pattern,NULL);
  float sum = 0.0f;
  for(int i=0; i < DMR_SYNC_DIBITS; i++)
    sum += cosf(phases24[i] - level - ideal_phase(dmr_sync_dibit(pattern,i)));
  return sum;
}

// ---------------- the ring ----------------

static inline size_t ring_index(int64_t index){
  return (size_t)((uint64_t)index & (Ring - 1));
}
static void store(struct dmr_sink *s,int64_t index,float phase){
  size_t const r = ring_index(index);
  s->phase[r] = phase;
  s->sin[r] = sinf(phase);
  s->cos[r] = cosf(phase);
}
static bool in_ring(struct dmr_sink const *s,int64_t first){
  return first >= s->first_index && s->now - first < Ring;
}
// The best enabled pattern for the 24 dibits ending at 'end', of a ring of sines and cosines
static struct sync_score best_sync_in(struct dmr_sink const *s,float const *sines,float const *cosines,int64_t end){
  float common = 0.0f;
  for(int i=0; i < DMR_SYNC_DIBITS; i++)
    common -= cosines[ring_index(end - DMR_SYNC_DIBITS + 1 + i)];
  struct sync_score best = No_sync;
  for(int pair=0; pair < Pairs; pair++){
    bool const a = s->enabled[s->pair_first[pair]];
    bool const b = s->enabled[s->pair_second[pair]];
    if(!a && !b)
      continue;
    float sum = 0.0f;
    for(int i=0; i < DMR_SYNC_DIBITS; i++)
      sum += s->sign[pair][i] * sines[ring_index(end - DMR_SYNC_DIBITS + 1 + i)];
    float const ca = (common + sum) * Inv_sqrt2,cb = (common - sum) * Inv_sqrt2;
    if(a && ca > best.correlation)
      best = (struct sync_score){ s->pair_first[pair], ca };
    if(b && cb > best.correlation)
      best = (struct sync_score){ s->pair_second[pair], cb };
  }
  return best;
}
// ... of the ring as sampled
static struct sync_score best_sync(struct dmr_sink const *s,int64_t end){
  return best_sync_in(s,s->sin,s->cos,end);
}
static float correlation_of(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern){
  float sum = 0.0f;
  for(int i=0; i < DMR_SYNC_DIBITS; i++){
    size_t const r = ring_index(end - DMR_SYNC_DIBITS + 1 + i);
    int const d = dmr_sync_dibit(pattern,i);
    sum += (-s->cos[r] + ((d & 2) ? -s->sin[r] : s->sin[r])) * Inv_sqrt2;
  }
  return sum;
}
// A pattern the frame's own transmitter sends in the period in progress: its family's and, on a
// direct mode frame whose numbering is known, this timeslot's
static bool own_pattern(struct dmr_sink const *s,enum dmr_sync pattern){
  if(dmr_mode_of(pattern) != s->mode)
    return false;
  if(s->mode != DMR_STATION_DIRECT || !s->slot_known)
    return true;
  bool const slot1 = (s->channel_index == 0) == s->channel0_is_slot1;
  bool const ts1 = pattern == DMR_SYNC_DIRECT_VOICE_TS1 || pattern == DMR_SYNC_DIRECT_DATA_TS1;
  return slot1 == ts1;
}
static struct sync_score best_own_sync(struct dmr_sink const *s,int64_t end){
  struct sync_score best = No_sync;
  for(int p=0; p < DMR_SYNC_PATTERNS; p++){
    if(!s->enabled[p] || !own_pattern(s,(enum dmr_sync)p))
      continue;
    float const c = correlation_of(s,end,(enum dmr_sync)p);
    if(c > best.correlation)
      best = (struct sync_score){ (enum dmr_sync)p, c };
  }
  return best;
}
static void sync_phases(struct dmr_sink const *s,int64_t end,float *phases24){
  for(int i=0; i < DMR_SYNC_DIBITS; i++)
    phases24[i] = s->phase[ring_index(end - DMR_SYNC_DIBITS + 1 + i)];
}
static float measure_level(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern){
  float phases[DMR_SYNC_DIBITS];
  sync_phases(s,end,phases);
  return level_error(phases,pattern,NULL);
}
static float levelled_correlation_of(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern){
  float phases[DMR_SYNC_DIBITS];
  sync_phases(s,end,phases);
  return correlate_levelled(phases,pattern);
}
static struct sync_score best_levelled_sync(struct dmr_sink const *s,int64_t end){
  float phases[DMR_SYNC_DIBITS];
  sync_phases(s,end,phases);
  struct sync_score best = No_sync;
  for(int p=0; p < DMR_SYNC_PATTERNS; p++){
    if(!s->enabled[p])
      continue;
    float const c = correlate_levelled(phases,(enum dmr_sync)p);
    if(c > best.correlation)
      best = (struct sync_score){ (enum dmr_sync)p, c };
  }
  return best;
}
static struct reading flat(float value){
  return (struct reading){ value, 0.0f, false };
}
static float correction_at(struct dmr_sink const *s,int64_t symbol){
  return s->timing.frequency_correction_at(s->timing.arg,(uint64_t)(symbol > 0 ? symbol : 0));
}
// A level read at dibit 'at'
static struct reading level_from(struct dmr_sink const *s,float value,int64_t at){
  if(!s->follow_correction || !s->config.level_follows_correction)
    return flat(value);
  return (struct reading){ value, correction_at(s,at), true };
}
static struct reading search_level(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern){
  if(s->config.level_correction == DMR_LEVEL_OFF)
    return flat(0.0f);
  return level_from(s,measure_level(s,end,pattern),end - DMR_SYNC_DIBITS / 2);
}
// Bits and confidences of 'dibits' dibits from 'first', a level taken off
static void soft_bits(struct dmr_sink const *s,int64_t first,int dibits,struct reading const *level,uint8_t *bits,float *confidence){
  if(!level->follows){
    for(int i=0; i < dibits; i++)
      slice_level(s->phase[ring_index(first + i)] - level->value,bits + 2 * i,confidence + 2 * i);
    return;
  }
  for(int i=0; i < dibits; i++){
    float const moved = correction_at(s,first + i) - level->correction;
    slice_level(s->phase[ring_index(first + i)] - (level->value - moved * s->radians_per_hz),bits + 2 * i,confidence + 2 * i);
  }
}
// Distance of a level from the nearer nominal one of its sign, outward positive
static float blind_residual(float v){
  float const magnitude = fabsf(v);
  float const nearest = magnitude > 0.5f * Pi ? 0.75f * Pi : 0.25f * Pi;
  return magnitude - nearest;
}
// The level error of 'count' dibits with nothing known about them: the shift in [lo,hi] that brings
// them nearest the four nominal levels (a grid of Blind_level_step, then the mean residual there).
// The levels are 90 degrees apart, so hi - lo has to be less. Saturated dibits are left out
static float blind_level(struct dmr_sink const *s,int64_t first,int count,float lo,float hi){
  float best = lo,best_cost = 1.0e30f;
  int const steps = (int)((hi - lo) / Blind_level_step);
  for(int step=0; step <= steps; step++){
    float const shift = lo + (float)step * Blind_level_step;
    float cost = 0.0f;
    for(int i=0; i < count; i++){
      float const phase = s->phase[ring_index(first + i)];
      if(fabsf(phase) > Pi - 0.01f)
	continue;
      float const r = blind_residual(phase - shift);
      cost += r * r;
    }
    if(cost < best_cost){
      best_cost = cost;
      best = shift;
    }
  }
  float sum = 0.0f;
  int n = 0;
  for(int i=0; i < count; i++){
    float const phase = s->phase[ring_index(first + i)];
    if(fabsf(phase) > Pi - 0.01f)
      continue;
    float const v = phase - best;
    sum += v < 0.0f ? -blind_residual(v) : blind_residual(v);
    n++;
  }
  if(n < count / 2)
    return clampf(0.0f,lo,hi);
  return clampf(best + sum / (float)n,lo,hi);
}
// The slot type of the burst whose sync ends at 'end': 5 dibits before the sync, 5 after it
static struct dmr_soft decode_slot_type(struct dmr_sink const *s,int64_t end,struct reading const *head,struct reading const *tail,float limit){
  uint8_t bits[20];
  float confidence[20];
  soft_bits(s,end - DMR_SYNC_DIBITS - 4,5,head,bits,confidence);
  soft_bits(s,end + 1,5,tail,bits + 10,confidence + 10);
  return dmr_golay20_decode(bits,confidence,limit);
}
// The EMB: the first and last 4 dibits of the sync / EMB field
static struct dmr_soft decode_emb(struct dmr_sink const *s,int64_t end,struct reading const *level,float limit){
  uint8_t bits[16];
  float confidence[16];
  soft_bits(s,end - DMR_SYNC_DIBITS + 1,4,level,bits,confidence);
  soft_bits(s,end - 3,4,level,bits + 8,confidence + 8);
  return dmr_qr16_decode(bits,confidence,limit);
}
// The TACT of the CACH ahead of the burst; cach and cach_confidence may be NULL
static struct dmr_soft decode_tact(struct dmr_sink const *s,int64_t end,struct reading const *level,float limit,
				   uint8_t *cach,float *cach_confidence){
  uint8_t bits[DMR_CACH_BITS];
  float confidence[DMR_CACH_BITS];
  soft_bits(s,end - Sync_end_offset,DMR_CACH_DIBITS,level,bits,confidence);
  uint8_t tact[7];
  float tact_confidence[7];
  dmr_cach_split(bits,confidence,tact,tact_confidence,NULL,NULL);
  if(cach != NULL)
    memcpy(cach,bits,sizeof bits);
  if(cach_confidence != NULL)
    memcpy(cach_confidence,confidence,sizeof confidence);
  return dmr_tact_decode(tact,tact_confidence,limit);
}

// ---------------- searching ----------------

// What a search makes of a sync window (no side effects)
static enum verdict search_verdict(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern,float correlation,bool allow_strong){
  bool const voice = dmr_is_voice_sync(pattern),data = dmr_is_data_sync(pattern);
  struct reading const level = search_level(s,end,pattern);
  bool const pinned = s->tracker.mode == DMR_CC_PINNED;
  if(allow_strong && correlation >= s->config.strong_sync){
    if(pinned && voice)
      return V_VOICE_PENDING;
    if(pinned && data && in_ring(s,end - DMR_SYNC_DIBITS - 4)){
      struct dmr_soft const st = decode_slot_type(s,end,&level,&level,DMR_GOLAY20_MAX_ERRORS);
      if(st.valid && !cc_matches(&s->tracker,(uint8_t)(st.data >> 4)))
	return V_CC;
    }
    return V_STRONG;
  }
  if(correlation < s->config.weak_sync)
    return V_BELOW_WEAK;
  if(!voice && !data)
    return V_NO_VALIDATOR;
  uint8_t required = 0;
  bool const have_required = cc_required(&s->tracker,&required);
  bool const any = s->tracker.mode == DMR_CC_ANY;
  if(!have_required && !any)
    return V_NO_CC;
  bool const bs = dmr_mode_of(pattern) == DMR_STATION_BS;
  if(bs){
    if(!in_ring(s,end - Sync_end_offset))
      return V_TACT;
    if(!decode_tact(s,end,&level,any ? 0.0f : s->config.weak_tact_limit,NULL,NULL).valid)
      return V_TACT;
  }
  if(voice)
    return V_VOICE_PENDING;
  if(!in_ring(s,end - DMR_SYNC_DIBITS - 4))
    return V_SLOT_TYPE;
  float const limit = any ? 0.0f : (bs ? s->config.weak_slot_type_limit_bs : s->config.weak_slot_type_limit);
  struct dmr_soft const st = decode_slot_type(s,end,&level,&level,limit);
  if(!st.valid)
    return V_SLOT_TYPE;
  if(have_required && (uint8_t)(st.data >> 4) != required)
    return V_CC;
  return V_WEAK;
}
static void count_rejection(struct dmr_sink *s,enum verdict v){
  switch(v){
  case V_NO_CC:
    s->counters.weak_rejected_no_cc++;
    break;
  case V_TACT:
    s->counters.weak_rejected_tact++;
    break;
  case V_SLOT_TYPE:
    s->counters.weak_rejected_slot_type++;
    break;
  case V_CC:
    s->counters.weak_rejected_cc++;
    break;
  case V_NO_VALIDATOR:
    s->counters.weak_rejected_no_validator++;
    break;
  default:
    break;
  }
}
// The candidate's distance from the nearest expected sync position of the frame (-72 .. 71 dibits)
static int offset_from_expected(struct dmr_sink const *s,int64_t end){
  int64_t d = (end - (s->origin + Sync_end_offset)) % DMR_SLOT_DIBITS;
  if(d < 0)
    d += DMR_SLOT_DIBITS;
  if(d >= DMR_SLOT_DIBITS / 2)
    d -= DMR_SLOT_DIBITS;
  return (int)d;
}

// One timing of a climb: the sync at 'at' arms, levelled
static bool climb_score(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern,bool rigid,int at,float *value){
  struct softdibit w[DMR_SYNC_DIBITS];
  uint64_t const first = (uint64_t)(end - DMR_SYNC_DIBITS + 1);
  if(rigid){
    if(s->timing.resample_rigid == NULL
       || !s->timing.resample_rigid(s->timing.arg,(uint64_t)(end - DMR_SYNC_DIBITS / 2),at,first,DMR_SYNC_DIBITS,w))
      return false;
  } else if(!s->timing.resample(s->timing.arg,first,DMR_SYNC_DIBITS,at,w))
    return false;
  float phases[DMR_SYNC_DIBITS];
  for(int i=0; i < DMR_SYNC_DIBITS; i++)
    phases[i] = w[i].phase;
  *value = correlate_levelled(phases,pattern);
  return true;
}
static void climb_at(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern,bool rigid,int o,float *value){
  if(!climb_score(s,end,pattern,rigid,o,value))
    *value = -1.0e9f;
}
// Hill climb of the levelled sync correlation over timing: from an eighth of a symbol down to one
// interpolator arm, within Max_retime_symbols of 'base' arms (and within [lo,hi] arms in all). The
// climb's offset is the whole offset, base included
static struct climb climb_timing_from(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern,bool rigid,int base,int lo,int hi){
  struct climb climb = { false, 0, 0.0f, 0.0f };
  if(!s->have_timing || end - DMR_SYNC_DIBITS + 1 < s->first_index)
    return climb;
  float const arms_per_symbol = s->timing.arms_per_symbol(s->timing.arg);
  if(!climb_score(s,end,pattern,rigid,base,&climb.centre))
    return climb;
  int const max_arms = (int)(Max_retime_symbols * arms_per_symbol);
  int step = (int)(arms_per_symbol / 8.0f);
  if(step < 1)
    step = 1;
  int offset = 0;
  float best = climb.centre,left = 0.0f,right = 0.0f;
#define ALLOWED(o) ((o) >= -max_arms && (o) <= max_arms && base + (o) >= lo && base + (o) <= hi)
  climb_at(s,end,pattern,rigid,base - step,&left);
  climb_at(s,end,pattern,rigid,base + step,&right);
  while(step >= 1){
    if(left > right && left > best && ALLOWED(offset - step)){
      offset -= step;
      right = best;
      best = left;
      climb_at(s,end,pattern,rigid,base + offset - step,&left);
    } else if(right > left && right > best && ALLOWED(offset + step)){
      offset += step;
      left = best;
      best = right;
      climb_at(s,end,pattern,rigid,base + offset + step,&right);
    } else {
      step /= 2;
      if(step >= 1){
	climb_at(s,end,pattern,rigid,base + offset - step,&left);
	climb_at(s,end,pattern,rigid,base + offset + step,&right);
      }
    }
  }
#undef ALLOWED
  climb.ok = true;
  climb.offset = base + offset;
  climb.best = best;
  return climb;
}
// ... from the timing as sampled, unbounded but for Max_retime_symbols
static struct climb climb_timing(struct dmr_sink const *s,int64_t end,enum dmr_sync pattern,bool rigid){
  return climb_timing_from(s,end,pattern,rigid,0,INT_MIN / 2,INT_MAX / 2);
}
static float arms_per_symbol(struct dmr_sink const *s){
  return s->timing.arms_per_symbol(s->timing.arg);
}
static void nudge(struct dmr_sink *s,int offset_arms){
  s->timing.nudge(s->timing.arg,(float)offset_arms / arms_per_symbol(s));
}

// ---------------- half a symbol off ----------------

// Arms of half a symbol, and the most a nudge moves the receiver (< 0.5 symbol)
static int half_symbol_arms(struct dmr_sink const *s){
  return (int)lroundf(0.5f * arms_per_symbol(s));
}
static int max_nudge_arms(struct dmr_sink const *s){
  return (int)(Max_nudge_symbols * arms_per_symbol(s));
}
// The earliest a climb from half a symbol earlier goes: three quarters of a symbol (later than half a
// symbol, the window as sampled is the nearer, and its own climb reaches it)
static int half_search_low(struct dmr_sink const *s){
  return -half_symbol_arms(s) - half_symbol_arms(s) / 2;
}
// Searching: dibit 'index' (the newest) half a symbol earlier, into the half ring. Returns whether
// the half ring is being kept (from half_from on)
static bool store_half(struct dmr_sink *s,int64_t index){
  if(!s->have_timing || !s->config.retime || !s->config.half_symbol_search || s->locked){
    s->half_from = -1;
    return false;
  }
  struct softdibit d;
  if(!s->timing.resample(s->timing.arg,(uint64_t)index,1,-half_symbol_arms(s),&d)){
    s->half_from = -1;
    return false;
  }
  size_t const r = ring_index(index);
  s->half_sin[r] = sinf(d.phase);
  s->half_cos[r] = cosf(d.phase);
  if(s->half_from < 0)
    s->half_from = index;
  return true;
}
// The receiver's sampling instant moved 'arms' (earlier negative): what one nudge moves now, the
// rest at the next dibit (see dmr_sink_dibit())
static void nudge_receiver(struct dmr_sink *s,int arms){
  int const max = max_nudge_arms(s);
  int const now = arms < -max ? -max : arms > max ? max : arms;
  if(now != 0)
    nudge(s,now);
  s->pending_nudge_arms = arms - now;
}
// The rest of such a nudge, at the next dibit: the phase to keep of it (delivered at the first
// nudge's timing, it is re-sampled at the rest, which is earlier: no sample is still to come)
static float finish_nudge(struct dmr_sink *s,struct softdibit const *sd,int64_t index){
  int const rest = s->pending_nudge_arms;
  s->pending_nudge_arms = 0;
  if(rest == 0 || !s->have_timing)
    return sd->phase;
  nudge(s,rest);
  struct softdibit resampled;
  if(rest < 0 && s->timing.resample(s->timing.arg,(uint64_t)index,1,rest,&resampled))
    return resampled.phase;
  return sd->phase;
}

// ---------------- voice syncs waiting for their EMBs ----------------

static void add_pending_voice(struct dmr_sink *s,struct candidate const *c){
  struct pending_voice *slot = &s->pending_voice[0];
  for(int i=0; i < 4; i++){
    struct pending_voice *v = &s->pending_voice[i];
    if(v->active && v->end == c->end)
      return;
    if(!v->active){
      slot = v;
      break;
    }
    if(v->end < slot->end)
      slot = v;
  }
  *slot = (struct pending_voice){ true, c->end, c->pattern, c->correlation, 0, 0 };
}

// ---------------- frames ----------------

static void force(struct dmr_sink *s,int64_t end,enum dmr_sync pattern){
  struct forced *slot = &s->forced[0];
  for(int i=0; i < 8; i++){
    struct forced *f = &s->forced[i];
    if(!f->active){
      slot = f;
      break;
    }
    if(f->end < slot->end)
      slot = f;
  }
  *slot = (struct forced){ true, end, pattern };
}
static struct forced const *forced_at(struct dmr_sink const *s,int64_t end){
  for(int i=0; i < 8; i++)
    if(s->forced[i].active && s->forced[i].end == end)
      return &s->forced[i];
  return NULL;
}
static void send(struct dmr_sink *s,struct dmr_burst const *b){
  s->counters.bursts_emitted++;
  s->counters.bursts[b->mode & 3]++;
  if(s->burst_handler != NULL)
    s->burst_handler(s->burst_arg,b);
}
static bool unvouched(struct dmr_sink const *s){
  return s->weak_frame && s->confirmed < 2;
}
static void flush_held(struct dmr_sink *s){
  for(int i=0; i < s->held_count; i++){
    struct dmr_burst *b = &s->held[i].burst;
    b->slot = s->slot_known ? (((s->held[i].channel == 0) == s->channel0_is_slot1) ? 1 : 2) : 0;
    send(s,b);
  }
  s->held_count = 0;
}
// The frame is going: its held bursts go out, unless nothing has vouched for it
static void release_held(struct dmr_sink *s){
  if(unvouched(s)){
    s->counters.held_discarded += (uint64_t)s->held_count;
    s->held_count = 0;
  } else
    flush_held(s);
}
// A burst on its way out. On a base station frame the first bursts wait (Max_held at most) until
// the TACTs agree on the slot numbering; the first burst of a frame begun by a weak sync waits for a
// second confirmed burst, and is dropped if the frame is lost first
static void deliver(struct dmr_sink *s,struct dmr_burst const *b){
  if(abs(s->slot_score) >= Slot_confident)
    s->slot_trusted = true;
  bool const numbering = s->mode == DMR_STATION_BS && !s->slot_trusted;
  if((numbering || unvouched(s)) && s->held_count < Max_held){
    s->held[s->held_count].burst = *b;
    s->held[s->held_count].channel = s->channel_index;
    if(++s->held_count == Max_held && !unvouched(s))
      flush_held(s);
    return;
  }
  flush_held(s);
  send(s,b);
}
// The receiver is told of the frame (see lock_receiver_on_bursty)
static void lock_receiver(struct dmr_sink *s,enum dmr_station mode){
  if(!s->have_timing || s->receiver_locked)
    return;
  if(mode != DMR_STATION_BS && !s->config.lock_receiver_on_bursty)
    return;
  s->receiver_locked = true;
  s->timing.set_frame_locked(s->timing.arg,true);
}
static void reset_channels(struct dmr_sink *s){
  memset(s->channels,0,sizeof s->channels);
  s->channels[0].next = s->channels[1].next = DMR_KIND_DATA;
}

// The receiver's nudge of a head re-timed from half a symbol off may be more than one nudge moves
static void retime_nudge(struct dmr_sink *s,bool half,int arms){
  if(half)
    nudge_receiver(s,arms);
  else
    nudge(s,arms);
}
// CACH + first half + sync (and what has come since) at the timing that maximises the sync
// correlation; the receiver samples there from the next symbol on. From a sync found half a symbol
// off (retime_base, see evaluate_half_candidate()) both climbs start half a symbol earlier, the
// newest dibit is re-sampled too (an earlier timing needs no sample still to come) and the
// receiver's nudge may be more than one nudge moves (nudge_receiver())
static void retime_head(struct dmr_sink *s,int64_t end,enum dmr_sync pattern){
  bool const half = s->retime_base != 0;
  int64_t const first = end - Sync_end_offset > s->first_index ? end - Sync_end_offset : s->first_index;
  int const count = (int)(s->now - first) + (half ? 1 : 0); // up to the symbol before this one
  if(count < DMR_SYNC_DIBITS || count > Max_retime_dibits)
    return;
  int const lo = half ? half_search_low(s) : INT_MIN / 2;
  int const hi = half ? 0 : INT_MAX / 2;
  struct climb const climb = climb_timing_from(s,end,pattern,false,s->retime_base,lo,hi);
  if(s->config.rigid_grid){
    // On a rigid grid through the sync; the receiver's nudge stays the relative climb's
    struct climb const rigid = climb_timing_from(s,end,pattern,true,s->retime_base,lo,hi);
    struct softdibit grid[Max_retime_dibits];
    int const head = (int)(end + 1 - first);
    if(rigid.ok && s->timing.resample_rigid != NULL
       && s->timing.resample_rigid(s->timing.arg,(uint64_t)(end - DMR_SYNC_DIBITS / 2),rigid.offset,(uint64_t)first,head,grid)){
      for(int i=0; i < head; i++)
	store(s,first + i,grid[i].phase);
      // (the dibits since the sync, where the samples a later timing of the newest needs are in)
      if(count > head && s->timing.resample_rigid(s->timing.arg,(uint64_t)(end - DMR_SYNC_DIBITS / 2),rigid.offset,
						  (uint64_t)(end + 1),count - head,grid)){
	for(int i=0; i < count - head; i++)
	  store(s,end + 1 + i,grid[i].phase);
      }
      if(climb.ok && climb.offset != 0)
	retime_nudge(s,half,climb.offset);
      s->acquired_rigid = true;
      s->acquired_rigid_offset = rigid.offset;
      s->counters.retimed_acquisitions++;
      return;
    }
  }
  if(!climb.ok || climb.offset == 0)
    return;
  struct softdibit window[Max_retime_dibits];
  if(!s->timing.resample(s->timing.arg,(uint64_t)first,count,climb.offset,window))
    return;
  for(int i=0; i < count; i++)
    store(s,first + i,window[i].phase);
  retime_nudge(s,half,climb.offset);
  s->counters.retimed_acquisitions++;
}

// The Look_back_periods periods ahead of an acquiring sync: a sync of weak_sync or better at a
// period's expected position, as sampled or (where the receiver's history reaches) with the period
// re-sampled at the timing that maximises it, starts the frame there. Returns how many periods back
static int look_back(struct dmr_sink *s,int64_t end,enum dmr_sync acquiring){
  int back = 0;
  for(int k=1; k <= Look_back_periods; k++){
    int64_t const at = end - (int64_t)k * DMR_SLOT_DIBITS;
    int64_t const first = at - Sync_end_offset;
    if(!in_ring(s,first))
      break;
    struct sync_score score = best_levelled_sync(s,at);
    if(s->have_timing && s->config.retime && score.correlation < DMR_SYNC_DIBITS - 1.0f){
      // As sampled the best pattern may be the wrong one: every pattern of the acquiring sync's
      // family at its own best timing
      struct softdibit probe;
      bool const rigid = s->config.rigid_grid && s->timing.resample_rigid != NULL
	&& s->timing.resample_rigid(s->timing.arg,(uint64_t)(at - DMR_SYNC_DIBITS / 2),0,(uint64_t)at,1,&probe);
      struct climb best = { false, 0, 0.0f, 0.0f };
      enum dmr_sync best_pattern = score.pattern;
      for(int p=0; p < DMR_SYNC_PATTERNS; p++){
	if(!s->enabled[p] || dmr_mode_of((enum dmr_sync)p) != dmr_mode_of(acquiring))
	  continue;
	struct climb const climb = climb_timing(s,at,(enum dmr_sync)p,rigid);
	if(climb.ok && (!best.ok || climb.best > best.best)){
	  best = climb;
	  best_pattern = (enum dmr_sync)p;
	}
      }
      struct softdibit window[DMR_SLOT_DIBITS];
      if(best.ok && best.best > score.correlation){
	if(rigid){
	  if(s->timing.resample_rigid(s->timing.arg,(uint64_t)(at - DMR_SYNC_DIBITS / 2),best.offset,(uint64_t)first,
				      DMR_SLOT_DIBITS,window)){
	    for(int i=0; i < DMR_SLOT_DIBITS; i++)
	      store(s,first + i,window[i].phase);
	    score = (struct sync_score){ best_pattern, levelled_correlation_of(s,at,best_pattern) };
	    s->counters.retimed_look_backs++;
	  }
	} else if(best.offset == 0){
	  score = (struct sync_score){ best_pattern, best.best };
	} else if(s->timing.resample(s->timing.arg,(uint64_t)first,DMR_SLOT_DIBITS,best.offset,window)){
	  for(int i=0; i < DMR_SLOT_DIBITS; i++)
	    store(s,first + i,window[i].phase);
	  score = (struct sync_score){ best_pattern, levelled_correlation_of(s,at,best_pattern) };
	  s->counters.retimed_look_backs++;
	}
      }
    }
    if(score.correlation < s->config.weak_sync)
      continue;
    force(s,at,score.pattern);
    back = k;
    s->counters.look_back_syncs++;
  }
  return back;
}

// A sync accepted away from the frame (or with no frame): the frame starts at its period.
// weak: accepted on validation, not on its correlation (see deliver())
static void acquire(struct dmr_sink *s,int64_t end,enum dmr_sync pattern,bool retimed,bool weak){
  bool const was_locked = s->locked;
  release_held(s); // of the frame this one replaces
  s->weak_frame = weak;
  s->acquired_rigid = false;
  if(!retimed && s->have_timing && s->config.retime)
    retime_head(s,end,pattern);

  s->origin = end - Sync_end_offset;
  s->channel_index = 0;
  reset_channels(s);
  s->mode = dmr_mode_of(pattern);
  s->confirmed = 0;
  s->miss_run = 0;
  s->slot_score = 0;
  s->slot_known = false;
  s->slot_trusted = false;
  s->level = 0.0f;
  s->level_correction = 0.0f;
  s->level_age = 0;
  for(int i=0; i < 8; i++)
    s->forced[i].active = false;
  force(s,end,pattern);
  s->acquired_end = end;

  // Voice syncs waiting on this frame: "another sync at the right distance". The frame starts at
  // the earliest, and the periods since are replayed from the ring
  int back = 0;
  for(int i=0; i < 4; i++){
    struct pending_voice *v = &s->pending_voice[i];
    if(!v->active || v->end >= end)
      continue;
    int64_t const distance = end - v->end;
    if(distance % DMR_SLOT_DIBITS != 0 || distance > 4 * DMR_SLOT_DIBITS || !in_ring(s,v->end - Sync_end_offset))
      continue;
    force(s,v->end,v->pattern);
    int const periods = (int)(distance / DMR_SLOT_DIBITS);
    if(periods > back)
      back = periods;
    v->active = false;
    s->counters.voice_syncs_confirmed++;
  }
  // With no frame before: the bursts just ahead of this one, whose syncs the search did not take
  if(!was_locked && s->config.look_back){
    int const lb = look_back(s,end,pattern);
    if(lb > back)
      back = lb;
  }
  s->settling = s->config.settling_bursts;
  s->origin -= (int64_t)back * DMR_SLOT_DIBITS;
  s->channel_index = back & 1;
  s->acquired_back = back;
  // The frequency loop's running mean starts again: a new frame, or another transmitter's
  s->afc_syncs = 0;
  s->afc_pending.valid = false;

  if(!was_locked){
    s->locked = true;
    s->counters.acquisitions++;
    lock_receiver(s,dmr_mode_of(pattern));
    if(s->acquired_handler != NULL)
      s->acquired_handler(s->acquired_arg);
  } else
    s->counters.reframes++;
}

static void confirm_voice(struct dmr_sink *s,struct pending_voice const *v){
  s->counters.voice_syncs_confirmed++;
  if(s->locked && offset_from_expected(s,v->end) == 0){
    // On the frame we have: an idle channel come alive. Its bursts A and B are behind bursts
    // already handed on; it goes on from C, the burst now arriving
    struct channel *ch = &s->channels[s->channel_index];
    ch->confirmed_once = true;
    ch->miss_run = 0;
    ch->next = DMR_KIND_VOICE_C;
    ch->voice_confirmed = 2;
    ch->exact = true;
    ch->from_sync = true;
    ch->strong_voice = false;
    ch->previous_continuation = false;
    return;
  }
  acquire(s,v->end,v->pattern,true,false);
}
static void check_pending_voice(struct dmr_sink *s){
  for(int i=0; i < 4; i++){
    struct pending_voice *v = &s->pending_voice[i];
    if(!v->active)
      continue;
    int64_t const age = s->now - v->end;
    if(age > 2 * Voice_confirm_dibits){
      v->active = false;
      continue;
    }
    if(age != Voice_confirm_dibits && age != 2 * Voice_confirm_dibits)
      continue;
    struct reading const none = flat(0.0f);
    struct dmr_soft const emb = decode_emb(s,s->now,&none,DMR_QR16_MAX_ERRORS);
    uint8_t const cc = (uint8_t)(emb.data >> 3);
    uint8_t required = 0;
    bool ok = emb.valid && emb.weighted_errors <= Tight_limit + Eps;
    if(cc_required(&s->tracker,&required))
      ok = ok && cc == required;
    else
      ok = ok && emb.errors == 0 && (v->stage == 0 || cc == v->cc);
    if(!ok){
      s->counters.voice_syncs_unconfirmed++;
      v->active = false;
      continue;
    }
    if(v->stage == 0){
      v->stage = 1;
      v->cc = cc;
      continue;
    }
    struct pending_voice const confirmed = *v;
    v->active = false;
    confirm_voice(s,&confirmed);
  }
}

// A near miss: the same window with its level error taken off and, with a receiver, at the best
// nearby timing; if that reaches retimed_sync it is judged as a weak sync
static void near_miss(struct dmr_sink *s,struct candidate const *c){
  bool const can_retime = s->have_timing && s->config.retime;
  struct climb const climb = can_retime ? climb_timing(s,c->end,c->pattern,false) : (struct climb){ false, 0, 0.0f, 0.0f };
  int const offset = climb.ok ? climb.offset : 0;
  float const expected = climb.ok ? climb.best : levelled_correlation_of(s,c->end,c->pattern);
  if(expected < s->config.retimed_sync)
    return;
  int64_t const first = c->end - Sync_end_offset > s->first_index ? c->end - Sync_end_offset : s->first_index;
  int const count = (int)(s->now - first); // up to the symbol before this one
  float saved[Max_retime_dibits];
  if(offset != 0){
    if(count < DMR_SYNC_DIBITS + Slot_type_tail || count > Max_retime_dibits)
      return;
    struct softdibit window[Max_retime_dibits];
    if(!s->timing.resample(s->timing.arg,(uint64_t)first,count,offset,window))
      return;
    for(int i=0; i < count; i++){
      saved[i] = s->phase[ring_index(first + i)];
      store(s,first + i,window[i].phase);
    }
  }
  float const correlation = levelled_correlation_of(s,c->end,c->pattern);
  enum verdict const verdict = correlation >= s->config.retimed_sync ? search_verdict(s,c->end,c->pattern,correlation,false)
    : V_BELOW_WEAK;
  if(verdict == V_WEAK){
    s->counters.retimed_syncs++;
    if(offset != 0){
      s->counters.retimed_acquisitions++;
      nudge(s,offset);
    }
    acquire(s,c->end,c->pattern,true,true);
    return;
  }
  if(offset != 0){
    for(int i=0; i < count; i++)
      store(s,first + i,saved[i]);
  }
  if(verdict == V_VOICE_PENDING)
    add_pending_voice(s,c);
}

static void evaluate_candidate(struct dmr_sink *s,struct candidate const *c){
  int const delta = s->locked ? offset_from_expected(s,c->end) : 0;
  if(s->locked && delta == 0)
    return; // the frame's own position: process_period()'s business
  if(dmr_sink_confirmed(s)){
    if(c->correlation < s->config.strong_sync)
      return;
    if(abs(delta) <= Slip_dibits){
      // A timing slip: the frame moves, its state stays
      s->origin += delta;
      if(c->end == s->origin + Sync_end_offset)
	force(s,c->end,c->pattern);
      s->counters.slips++;
      s->counters.strong_syncs++;
      return;
    }
    // Elsewhere: a re-frame needs more than the correlation
    if(dmr_is_data_sync(c->pattern)){
      if(!in_ring(s,c->end - DMR_SYNC_DIBITS - 4))
	return;
      struct reading const level = search_level(s,c->end,c->pattern);
      struct dmr_soft const st = decode_slot_type(s,c->end,&level,&level,Tight_limit);
      if(!st.valid)
	return;
      if(!cc_matches(&s->tracker,(uint8_t)(st.data >> 4))){
	s->counters.cc_mismatches++;
	return;
      }
      s->counters.strong_syncs++;
      acquire(s,c->end,c->pattern,false,false);
    } else if(dmr_is_voice_sync(c->pattern))
      add_pending_voice(s,c);
    return;
  }
  // Searching, or a tentative frame: the searching rules. A tentative frame is not given up for a
  // sync with nothing but its correlation and no slot type to show: a voice sync waits for its EMBs
  enum verdict const verdict = search_verdict(s,c->end,c->pattern,c->correlation,true);
  if(s->locked && verdict == V_STRONG && !dmr_is_data_sync(c->pattern)){
    if(dmr_is_voice_sync(c->pattern))
      add_pending_voice(s,c);
    return;
  }
  if(verdict == V_STRONG || verdict == V_WEAK){
    if(verdict == V_STRONG)
      s->counters.strong_syncs++;
    else
      s->counters.weak_syncs++;
    acquire(s,c->end,c->pattern,false,verdict == V_WEAK);
    return;
  }
  if(verdict == V_VOICE_PENDING){
    add_pending_voice(s,c);
    return;
  }
  count_rejection(s,verdict);
  near_miss(s,c);
}

// A window that reached candidate_sync half a symbol earlier than sampled. As a near miss: the
// timing that maximises its levelled correlation, from half a symbol earlier (within
// Max_retime_symbols, and not later than as sampled nor earlier than half_search_low()); a window
// reaching retimed_sync there is judged as a weak sync, one that reached strong_sync at half a
// symbol (one timing, as a window as sampled is) as a strong one. Taken, the frame is acquired as
// from any sync, its head re-timed from half a symbol earlier (retime_head()); a voice sync left
// waiting for its EMBs has the window kept at that timing and the receiver nudged there
static void evaluate_half_candidate(struct dmr_sink *s,struct candidate const *c){
  if(s->locked || !s->have_timing)
    return;
  struct climb const climb = climb_timing_from(s,c->end,c->pattern,false,-half_symbol_arms(s),half_search_low(s),0);
  if(!climb.ok)
    return;
  bool const strong = c->correlation >= s->config.strong_sync;
  if(!strong && climb.best < s->config.retimed_sync)
    return;
  int64_t const first = c->end - Sync_end_offset > s->first_index ? c->end - Sync_end_offset : s->first_index;
  int const count = (int)(s->now - first) + 1; // up to this one: an earlier timing needs no samples to come
  if(count < DMR_SYNC_DIBITS + Slot_type_tail || count > Max_retime_dibits)
    return;
  struct softdibit window[Max_retime_dibits];
  if(!s->timing.resample(s->timing.arg,(uint64_t)first,count,climb.offset,window))
    return;
  float saved[Max_retime_dibits];
  for(int i=0; i < count; i++){
    saved[i] = s->phase[ring_index(first + i)];
    store(s,first + i,window[i].phase);
  }
  float const levelled = levelled_correlation_of(s,c->end,c->pattern);
  enum verdict verdict = V_BELOW_WEAK;
  if(strong)
    verdict = search_verdict(s,c->end,c->pattern,c->correlation,true);
  if(verdict != V_STRONG && verdict != V_WEAK && verdict != V_VOICE_PENDING && levelled >= s->config.retimed_sync)
    verdict = search_verdict(s,c->end,c->pattern,levelled,false);
  if(verdict != V_STRONG && verdict != V_WEAK && verdict != V_VOICE_PENDING){
    for(int i=0; i < count; i++)
      store(s,first + i,saved[i]);
    return;
  }
  // The receiver samples there from the next symbol on; the half ring restarts at the new timing
  s->half_from = -1;
  for(int i=0; i < 8; i++)
    s->half_candidates[i].active = false;
  if(verdict == V_VOICE_PENDING){
    nudge_receiver(s,climb.offset);
    add_pending_voice(s,c);
    return;
  }
  s->counters.half_symbol_syncs++;
  if(verdict == V_STRONG)
    s->counters.strong_syncs++;
  else
    s->counters.weak_syncs++;
  s->retime_base = -half_symbol_arms(s);
  acquire(s,c->end,c->pattern,false,verdict == V_WEAK);
  s->retime_base = 0;
}

// A channel of a mobile station or direct mode frame with a transmitter on it
static bool channel_live(struct dmr_sink const *s,struct channel const *ch){
  return ch->confirmed_once && ch->miss_run < s->config.channel_miss_limit;
}
static void set_hold(struct dmr_sink *s,bool hold){
  if(hold == s->holding)
    return;
  s->holding = hold;
  if(hold)
    s->counters.loop_holds++;
  if(s->have_timing && s->timing.hold_loops != NULL)
    s->timing.hold_loops(s->timing.arg,hold);
}
// The receiver's loops, for the dibit that comes next. On a mobile station or direct mode frame with
// a transmitter on one channel only, the other channel's periods are empty, and so is the guard time
// ahead of each burst: the loops are held from a burst's last dibit to the next burst's first. With
// a transmitter on both channels, or on neither, they run
static void update_hold(struct dmr_sink *s){
  bool hold = false;
  if(s->locked && s->mode != DMR_STATION_BS && s->mode != DMR_STATION_UNKNOWN && s->config.hold_empty_periods){
    bool const here = channel_live(s,&s->channels[s->channel_index]);
    bool const other = channel_live(s,&s->channels[s->channel_index ^ 1]);
    int const position = (int)(s->now + 1 - s->origin); // of the next dibit in its period
    if(here && !other)
      hold = position < DMR_CACH_DIBITS;
    else if(!here && other)
      hold = true;
  }
  set_hold(s,hold);
}

static void flush_frequency_error(struct dmr_sink *s){
  if(!s->afc_pending.valid || s->confirmed < 2)
    return;
  s->afc_pending.valid = false;
  s->afc_syncs++;
  s->counters.afc_reports++;
  float const gain = maxf(s->config.afc_gain,1.0f / (float)s->afc_syncs);
  if(s->timing.apply_frequency_error != NULL)
    s->timing.apply_frequency_error(s->timing.arg,s->afc_pending.error_hz,(uint64_t)s->afc_pending.symbol,gain);
}
// A sync's level error as the carrier's offset from the correction its symbols had, for the
// receiver's frequency loop; a tentative frame's waits for its second confirmation
static void report_frequency_error(struct dmr_sink *s,int64_t end,enum dmr_sync pattern){
  if(!s->have_timing || !s->config.afc || !s->receiver_locked)
    return;
  float phases[DMR_SYNC_DIBITS];
  sync_phases(s,end,phases);
  int counted = 0;
  float const level = level_error(phases,pattern,&counted);
  if(counted < DMR_SYNC_DIBITS / 2 || correlate_levelled(phases,pattern) < s->config.afc_sync)
    return;
  s->afc_pending.valid = true;
  s->afc_pending.error_hz = level / s->radians_per_hz;
  s->afc_pending.symbol = end - DMR_SYNC_DIBITS / 2;
  flush_frequency_error(s);
}

static void lose_frame(struct dmr_sink *s){
  release_held(s);
  s->locked = false;
  reset_channels(s);
  for(int i=0; i < 8; i++)
    s->forced[i].active = false;
  s->counters.losses++;
  set_hold(s,false);
  if(s->have_timing && s->receiver_locked)
    s->timing.set_frame_locked(s->timing.arg,false);
  s->receiver_locked = false;
  if(s->lost_handler != NULL)
    s->lost_handler(s->lost_arg);
}

static enum dmr_kind next_voice(enum dmr_kind kind){
  switch(kind){
  case DMR_KIND_VOICE_A: return DMR_KIND_VOICE_B;
  case DMR_KIND_VOICE_B: return DMR_KIND_VOICE_C;
  case DMR_KIND_VOICE_C: return DMR_KIND_VOICE_D;
  case DMR_KIND_VOICE_D: return DMR_KIND_VOICE_E;
  case DMR_KIND_VOICE_E: return DMR_KIND_VOICE_F;
  case DMR_KIND_VOICE_F: return DMR_KIND_VOICE_A;
  default: return DMR_KIND_VOICE_UNKNOWN;
  }
}
// The LCSS a voice burst at this position carries: B first, C and D continuation, E last, F single
static bool lcss_fits(enum dmr_kind kind,enum dmr_lcss lcss){
  switch(kind){
  case DMR_KIND_VOICE_B: return lcss == DMR_LCSS_FIRST;
  case DMR_KIND_VOICE_C:
  case DMR_KIND_VOICE_D: return lcss == DMR_LCSS_CONTINUATION;
  case DMR_KIND_VOICE_E: return lcss == DMR_LCSS_LAST;
  case DMR_KIND_VOICE_F: return lcss == DMR_LCSS_SINGLE;
  default: return false;
  }
}
static bool in_voice(struct channel const *ch){
  return ch->next != DMR_KIND_DATA;
}
static void end_voice(struct channel *ch){
  ch->next = DMR_KIND_DATA;
  ch->exact = ch->from_sync = ch->strong_voice = ch->previous_continuation = false;
  ch->voice_confirmed = 0;
}
// The position of a voice burst with this LCSS on a channel, by count or by the LCSS sequence
static enum dmr_kind voice_kind(struct channel *ch,enum dmr_lcss lcss){
  bool const counted = ch->next >= DMR_KIND_VOICE_B && ch->next <= DMR_KIND_VOICE_F;
  if(counted && ch->exact){
    ch->previous_continuation = false;
    return ch->next;
  }
  enum dmr_kind kind = DMR_KIND_VOICE_UNKNOWN;
  switch(lcss){
  case DMR_LCSS_FIRST:
    kind = DMR_KIND_VOICE_B;
    break;
  case DMR_LCSS_LAST:
    kind = DMR_KIND_VOICE_E;
    break;
  case DMR_LCSS_SINGLE:
    kind = DMR_KIND_VOICE_F;
    break;
  case DMR_LCSS_CONTINUATION:
    if(ch->next == DMR_KIND_VOICE_C || ch->next == DMR_KIND_VOICE_D)
      kind = ch->next;
    else if(ch->previous_continuation)
      kind = DMR_KIND_VOICE_D;
    break;
  }
  ch->previous_continuation = kind == DMR_KIND_VOICE_UNKNOWN;
  return kind;
}
static struct reading carried_level(struct dmr_sink const *s,struct channel const *ch){
  if(s->config.level_correction != DMR_LEVEL_CARRY)
    return flat(0.0f);
  bool const bs = s->mode == DMR_STATION_BS;
  float const level = bs ? s->level : ch->level;
  int const age = bs ? s->level_age : ch->level_age;
  struct reading carried = flat(level * powf(s->config.level_carry_decay,(float)age));
  carried.correction = bs ? s->level_correction : ch->level_correction;
  carried.follows = s->follow_correction && s->config.level_follows_correction;
  return carried;
}
// The TC bit of a TACT says which timeslot this channel is: a vote
static void vote_slot(struct dmr_sink *s,uint8_t tc,int weight){
  bool const says = (s->channel_index == 0) == (tc == 0); // channel 0 is timeslot 1
  if(s->slot_known && says != s->channel0_is_slot1)
    s->counters.tc_disagreements++;
  int score = s->slot_score + (says ? weight : -weight);
  score = score < -Slot_score_limit ? -Slot_score_limit : score > Slot_score_limit ? Slot_score_limit : score;
  s->slot_score = score;
  if(s->slot_score > 0)
    s->channel0_is_slot1 = true;
  else if(s->slot_score < 0)
    s->channel0_is_slot1 = false;
  else
    s->channel0_is_slot1 = says; // a tie: the latest
  s->slot_known = true;
}
static uint64_t system_clock_us(void){
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME,&ts);
  return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000;
}

// One slot period of the frame, complete in the ring
static void process_period(struct dmr_sink *s){
  int64_t const origin = s->origin;
  int64_t const end = origin + Sync_end_offset;
  int64_t const burst_start = origin + DMR_CACH_DIBITS;
  struct channel *ch = &s->channels[s->channel_index];
  bool const bs_before = s->mode == DMR_STATION_BS;

  struct sync_score score = best_sync(s,end);
  struct forced const *forced = forced_at(s,end);
  if(forced != NULL){
    score = (struct sync_score){ forced->pattern, correlation_of(s,end,forced->pattern) };
  } else if(s->config.frame_keeps_family && score.correlation < s->config.strong_sync && !own_pattern(s,score.pattern)){
    // Below a strong sync a frame keeps its family and its timeslots
    struct sync_score const own = best_own_sync(s,end);
    if(own.pattern != DMR_SYNC_NONE)
      score = own;
  }

  enum taken taken = TAKEN_NONE;
  struct reading const carried = carried_level(s,ch);
  struct dmr_soft emb;
  memset(&emb,0,sizeof emb);
  uint8_t required = 0;
  bool const have_required = cc_required(&s->tracker,&required);
  bool const live = bs_before || (ch->confirmed_once && ch->miss_run < s->config.channel_miss_limit);
  if(forced != NULL){
    taken = TAKEN_SYNC;
  } else if(!live){
    // The idle channel of a bursty frame: a sync here is taken as a search would take it
    if(score.correlation >= s->config.weak_sync){
      enum verdict const verdict = search_verdict(s,end,score.pattern,score.correlation,true);
      if(verdict == V_STRONG || verdict == V_WEAK)
	taken = TAKEN_SYNC;
      else if(verdict == V_VOICE_PENDING){
	struct candidate const c = { true, end, score.pattern, score.correlation };
	add_pending_voice(s,&c);
      } else
	count_rejection(s,verdict);
    }
    // A channel that had a transmitter and missed bursts (a fade): an EMB without error to the
    // frame's colour code brings it back, while the frame would still be held for its last burst
    if(taken == TAKEN_NONE && s->config.emb_revives_channel && ch->confirmed_once
       && 2 * (ch->miss_run + 1) <= s->config.loss_bursts && have_required){
      emb = decode_emb(s,end,&carried,DMR_QR16_MAX_ERRORS);
      if(emb.valid && emb.weighted_errors <= Eps && (uint8_t)(emb.data >> 3) == required){
	taken = TAKEN_EMB;
	s->counters.channels_revived++;
      }
    }
  } else {
    emb = decode_emb(s,end,&carried,DMR_QR16_MAX_ERRORS);
    uint8_t const emb_cc = (uint8_t)(emb.data >> 3);
    // Nothing confirmed for two periods: the carrier may be gone, and noise passes an EMB within
    // one error far more often than one without
    float const tight_limit = s->miss_run >= 2 ? 0.0f : Tight_limit;
    bool const tight = emb.valid && emb.weighted_errors <= tight_limit + Eps;
    bool cc_ok = cc_matches(&s->tracker,emb_cc);
    if(emb.valid && emb.errors == 0 && ch->strong_voice && in_voice(ch) && s->tracker.mode == DMR_CC_TRACK
       && (!cc_required(&s->tracker,&required) || required != emb_cc)){
      // The superframe began with a strong voice sync: its EMB sets the colour code
      if(!cc_ok)
	s->counters.cc_mismatches++;
      cc_observe(&s->tracker,emb_cc);
      cc_ok = true;
    }
    bool const have_required_now = cc_required(&s->tracker,&required);
    // An EMB without error and with another colour code: another system's voice on our frame
    bool const foreign = emb.valid && emb.errors == 0 && !cc_ok;
    if(foreign)
      s->counters.cc_mismatches++;
    bool const mid_superframe = ch->next >= DMR_KIND_VOICE_B && ch->next <= DMR_KIND_VOICE_F;
    // (the same two periods without a confirmation: a sync has to be a weak one at least)
    float const need = s->miss_run >= 2 ? s->config.weak_sync
      : mid_superframe ? s->config.mid_superframe_sync : s->config.locked_sync;
    if(score.correlation >= s->config.strong_sync){
      taken = TAKEN_SYNC;
    } else if(tight && cc_ok){
      taken = TAKEN_EMB;
    } else if(score.correlation >= need){
      taken = TAKEN_SYNC;
    } else if(emb.valid && have_required_now && cc_ok && mid_superframe && ch->miss_run == 0
	      && lcss_fits(ch->next,(enum dmr_lcss)(emb.data & 3u))){
      // Two errors corrected: only where the count expects a voice burst, and only with the LCSS
      // that burst has
      taken = TAKEN_EMB;
    } else if(foreign){
      end_voice(ch); // not ours to count through
    }
  }

  struct dmr_burst b;
  dmr_burst_init(&b);
  struct reading head_level = carried,tail_level = carried; // up to the sync's end / after it
  bool emit = false;

  if(taken == TAKEN_SYNC && forced == NULL && s->have_timing && s->config.retime && s->settling > 0){
    // The receiver's loops are still settling: this burst at its own sync's best timing, and the
    // receiver nudged there
    s->settling--;
    struct climb const climb = climb_timing(s,end,score.pattern,false);
    struct softdibit window[DMR_SLOT_DIBITS];
    if(climb.ok && climb.offset != 0 && climb.best > climb.centre + Settling_gain
       && s->timing.resample(s->timing.arg,(uint64_t)origin,DMR_SLOT_DIBITS,climb.offset,window)){
      for(int i=0; i < DMR_SLOT_DIBITS; i++)
	store(s,origin + i,window[i].phase);
      nudge(s,climb.offset);
      score.correlation = correlation_of(s,end,score.pattern);
      s->counters.retimed_settling++;
    }
  }
  if(forced != NULL && end == s->acquired_end && s->acquired_rigid && s->have_timing && s->config.retime
     && s->config.rigid_grid && s->config.rigid_tail && s->timing.resample_rigid != NULL){
    // The burst the frame was acquired on: its second half on the grid its head was re-sampled on
    // (retime_head()), not as the receiver's loops sampled it after the nudge, still settling. (The
    // newest dibit may need samples not in yet at a later timing: without it, then)
    s->acquired_rigid = false;
    struct softdibit grid[DMR_BURST_DIBITS];
    uint64_t const anchor = (uint64_t)(end - DMR_SYNC_DIBITS / 2);
    int const tail = (int)(s->now - end);
    for(int count = tail; count >= tail - 1; count--){
      if(count <= 0 || count > DMR_BURST_DIBITS || !s->timing.resample_rigid(s->timing.arg,anchor,s->acquired_rigid_offset,(uint64_t)(end + 1),count,grid))
	continue;
      for(int i=0; i < count; i++)
	store(s,end + 1 + i,grid[i].phase);
      s->counters.rigid_tails++;
      break;
    }
  }

  if(taken == TAKEN_SYNC){
    enum dmr_station const mode = dmr_mode_of(score.pattern);
    if(mode != s->mode){
      flush_held(s);
      s->mode = mode;
      s->slot_trusted = false;
      s->slot_known = false;
      s->slot_score = 0;
    }
    s->counters.syncs[score.pattern]++;
    report_frequency_error(s,end,score.pattern);
    // The sync's level error. On the bursts a frame is acquired on it holds for the head only: the
    // correction is still stepping a block at a time there
    bool const acquiring = end <= s->acquired_end;
    bool const later = s->config.level_correction == DMR_LEVEL_SYNC_BURSTS || s->config.level_correction == DMR_LEVEL_CARRY;
    head_level = tail_level = flat(0.0f);
    if(s->config.level_correction != DMR_LEVEL_OFF && (acquiring || later)){
      head_level = level_from(s,measure_level(s,end,score.pattern),end - DMR_SYNC_DIBITS / 2);
      if(!acquiring || (head_level.follows && s->config.acquisition_tail_follows))
	tail_level = head_level;
      else if(s->config.acquisition_tail_blind){
	// Between nothing and what the sync read (the correction only takes off), and a little beyond
	tail_level = level_from(s,blind_level(s,end + 1,DMR_SYNC_OFFSET_DIBITS,minf(0.0f,head_level.value) - Blind_level_margin,
					      maxf(0.0f,head_level.value) + Blind_level_margin),
				end + 1 + DMR_SYNC_OFFSET_DIBITS / 2);
	tail_level.follows = false; // it is the tail's own
      }
    }
    if(s->config.level_correction == DMR_LEVEL_CARRY){
      s->level = ch->level = tail_level.value;
      s->level_correction = ch->level_correction = tail_level.correction;
      s->level_age = ch->level_age = 0;
    }
    b.sync = score.pattern;
    b.sync_correlation = score.correlation;
    {
      // What the sync reads of the carrier, as the burst is in the ring (re-timed, not levelled)
      float phases[DMR_SYNC_DIBITS];
      sync_phases(s,end,phases);
      int counted = 0;
      float const level = level_error(phases,score.pattern,&counted);
      b.level_error_valid = counted >= DMR_SYNC_DIBITS / 2;
      b.level_error_hz = b.level_error_valid ? level / s->radians_per_hz : 0.0f;
    }
    if(dmr_is_data_sync(score.pattern)){
      b.kind = DMR_KIND_DATA;
      struct dmr_soft const st = decode_slot_type(s,end,&head_level,&tail_level,DMR_GOLAY20_MAX_ERRORS);
      if(st.valid){
	b.slot_type_valid = true;
	b.color_code = (uint8_t)(st.data >> 4);
	b.data_type = (enum dmr_data_type)(st.data & 0xfu);
	b.slot_type_errors = (uint8_t)st.errors;
	if(score.correlation >= s->config.strong_sync && st.weighted_errors <= Tight_limit + Eps)
	  cc_observe(&s->tracker,b.color_code);
	else if(!cc_matches(&s->tracker,b.color_code))
	  s->counters.cc_mismatches++;
      }
      end_voice(ch);
    } else if(dmr_is_voice_sync(score.pattern)){
      b.kind = DMR_KIND_VOICE_A;
      ch->next = DMR_KIND_VOICE_B;
      ch->exact = score.correlation >= s->config.mid_superframe_sync;
      ch->from_sync = true;
      ch->strong_voice = score.correlation >= s->config.strong_sync;
      ch->previous_continuation = false;
      ch->voice_confirmed++;
    } else {
      b.kind = DMR_KIND_REVERSE_CHANNEL;
      end_voice(ch);
    }
    emit = true;
  } else if(taken == TAKEN_EMB){
    b.emb_valid = true;
    b.emb_errors = (uint8_t)emb.errors;
    b.color_code = (uint8_t)(emb.data >> 3);
    b.emb_pi = ((emb.data >> 2) & 1u) != 0;
    b.emb_lcss = (enum dmr_lcss)(emb.data & 3u);
    b.kind = voice_kind(ch,b.emb_lcss);
    ch->next = next_voice(b.kind);
    s->counters.emb_bursts++;
    ch->voice_confirmed++;
    if(!ch->from_sync)
      s->counters.late_entry_bursts++;
    if(b.kind == DMR_KIND_VOICE_F)
      ch->from_sync = false; // the next superframe's sync is still to come
    emit = true;
  } else {
    // Neither. Inside a voice call (two voice bursts confirmed) the burst is still the one the count
    // expects, and its voice frames have their own FEC: handed on, for channel_miss_limit periods in
    // a row at most. Anywhere else nothing says what it is (or that it is a burst at all)
    emit = in_voice(ch) && ch->voice_confirmed >= 2 && ch->miss_run < s->config.channel_miss_limit;
    if(in_voice(ch)){
      b.kind = ch->next;
      ch->next = next_voice(ch->next);
      ch->previous_continuation = false;
      if(emit && !ch->from_sync)
	s->counters.late_entry_bursts++;
      if(b.kind == DMR_KIND_VOICE_F)
	ch->from_sync = false;
    } else
      b.kind = DMR_KIND_DATA;
  }

  // Carry: the level ages a period on both channels
  s->level_age++;
  s->channels[0].level_age++;
  s->channels[1].level_age++;

  // The CACH (base station frames)
  bool const bs = s->mode == DMR_STATION_BS;
  if(bs && origin >= s->first_index){
    b.has_cach = true;
    struct dmr_soft const tact = decode_tact(s,end,&head_level,1.0f,b.cach,b.cach_confidence);
    if(tact.valid){
      b.tact_valid = true;
      b.tact_errors = (uint8_t)tact.errors;
      b.tact_access_busy = ((tact.data >> 3) & 1u) != 0;
      b.tact_channel = (uint8_t)((tact.data >> 2) & 1u);
      b.tact_lcss = (enum dmr_lcss)(tact.data & 3u);
      if(taken != TAKEN_NONE)
	vote_slot(s,b.tact_channel,tact.errors == 0 ? 2 : 1);
    }
  }

  // The slot number
  if(taken == TAKEN_SYNC && s->mode == DMR_STATION_DIRECT){
    bool const ts1 = score.pattern == DMR_SYNC_DIRECT_VOICE_TS1 || score.pattern == DMR_SYNC_DIRECT_DATA_TS1;
    s->channel0_is_slot1 = (s->channel_index == 0) == ts1;
    s->slot_known = true;
  } else if(taken != TAKEN_NONE && s->mode == DMR_STATION_MS && !s->slot_known){
    s->channel0_is_slot1 = s->channel_index == 0;
    s->slot_known = true;
  }
  b.slot = s->slot_known ? (((s->channel_index == 0) == s->channel0_is_slot1) ? 1 : 2) : 0;
  b.mode = s->mode;

  int const head_dibits = DMR_SYNC_OFFSET_DIBITS + DMR_SYNC_DIBITS;
  soft_bits(s,burst_start,head_dibits,&head_level,b.bits,b.confidence);
  soft_bits(s,burst_start + head_dibits,DMR_BURST_DIBITS - head_dibits,&tail_level,b.bits + 2 * head_dibits,
	    b.confidence + 2 * head_dibits);
  b.dibit_clock = (uint64_t)burst_start;
  uint64_t const now_us = s->clock != NULL ? s->clock(s->clock_arg,(uint64_t)s->now) : system_clock_us();
  uint64_t const elapsed_us = (uint64_t)(s->now - burst_start) * 1000000ULL / (uint64_t)DMR_SYMBOL_RATE;
  b.timestamp_us = now_us > elapsed_us ? now_us - elapsed_us : 0;

  // Channel and frame accounting
  bool const confirmed = taken != TAKEN_NONE;
  b.confirmed = confirmed; // false: placed by the count alone
  if(confirmed){
    ch->confirmed_once = true;
    ch->miss_run = 0;
    s->miss_run = 0;
    if(s->confirmed < 1000)
      s->confirmed++;
    s->counters.flywheel_confirmed++;
    flush_frequency_error(s);
  } else {
    ch->miss_run++;
    if(ch->miss_run >= s->config.channel_miss_limit)
      end_voice(ch);
    s->miss_run++;
    s->counters.flywheel_unconfirmed++;
  }

  // Hand on: in order, and only bursts that are whole in the ring
  if(emit && burst_start >= s->first_index && s->now - origin < Ring && (!s->have_emitted || burst_start > s->last_emitted_start)){
    if(!confirmed)
      s->counters.unconfirmed_emitted++;
    s->have_emitted = true;
    s->last_emitted_start = burst_start;
    deliver(s,&b);
  }

  for(int i=0; i < 8; i++)
    if(s->forced[i].active && s->forced[i].end <= end)
      s->forced[i].active = false;
  s->origin = origin + DMR_SLOT_DIBITS;
  s->channel_index ^= 1;

  // (a bursty frame has a burst every other period only)
  int const tentative = s->mode == DMR_STATION_BS ? Tentative_loss_bursts : 2 * Tentative_loss_bursts;
  int const limit = s->confirmed >= 2 ? s->config.loss_bursts : tentative;
  if(!confirmed && s->miss_run >= limit)
    lose_frame(s);
}

void dmr_sink_dibit(struct dmr_sink *s,struct softdibit const *sd,uint64_t symbol_index){
  int64_t const index = (int64_t)symbol_index;
  if(s->count != 0 && index != s->now + 1)
    dmr_sink_reset(s);
  if(s->count == 0)
    s->first_index = index;
  s->now = index;
  s->count++;
  store(s,index,s->pending_nudge_arms != 0 ? finish_nudge(s,sd,index) : sd->phase);
  bool const half_search = store_half(s,index);
  if(s->count < (uint64_t)DMR_SYNC_DIBITS)
    return;

  struct sync_score const score = best_sync(s,index);
  bool const expected_here = s->locked && index == s->origin + Sync_end_offset;
  // Every window that reaches candidate_sync is judged on its own, Slot_type_tail dibits later
  if(!expected_here && score.correlation >= s->config.candidate_sync)
    s->candidates[(uint64_t)index & 7] = (struct candidate){ true, index, score.pattern, score.correlation };
  // The same of the dibits half a symbol earlier (see Half a symbol off)
  if(half_search && index - s->half_from >= DMR_SYNC_DIBITS - 1){
    struct sync_score const half = best_sync_in(s,s->half_sin,s->half_cos,index);
    if(half.correlation >= s->config.candidate_sync)
      s->half_candidates[(uint64_t)index & 7] = (struct candidate){ true, index, half.pattern, half.correlation };
  }
  struct candidate *due = &s->candidates[(uint64_t)(index - Slot_type_tail) & 7];
  if(due->active && due->end == index - Slot_type_tail){
    struct candidate const candidate = *due;
    due->active = false;
    evaluate_candidate(s,&candidate);
  }
  struct candidate *half_due = &s->half_candidates[(uint64_t)(index - Slot_type_tail) & 7];
  if(half_due->active && half_due->end == index - Slot_type_tail){
    struct candidate const candidate = *half_due;
    half_due->active = false;
    evaluate_half_candidate(s,&candidate);
  }
  check_pending_voice(s);
  while(s->locked && s->now >= s->origin + DMR_SLOT_DIBITS - 1)
    process_period(s);
  update_hold(s);
}
