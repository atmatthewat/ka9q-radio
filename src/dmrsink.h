// DMR (ETSI TS 102 361) frame sync and TDMA slot framing: soft dibits in, one struct dmr_burst per
// received burst out, with the colour code the weak syncs and EMBs must carry.
// dmrsink.c has the theory of operation; dmrrx.h joins this to the receiver
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRSINK_H
#define _DMRSINK_H 1

#include <stdbool.h>
#include <stdint.h>

#include "digital.h"
#include "dmr.h"

// Sync correlation thresholds (out of 24) and validator limits (weighted errors, dmrfec.h);
// dmrsink.c says what each is for
#define DMR_STRONG_SYNC 20.5f          // taken on the correlation alone
#define DMR_WEAK_SYNC 17.0f            // taken with validation
#define DMR_RETIMED_SYNC 18.0f         // a near miss, levelled and re-timed: judged as a weak sync
#define DMR_CANDIDATE_SYNC 14.0f       // looked at at all
#define DMR_LOCKED_SYNC 14.0f          // at a frame's expected position
#define DMR_MID_SUPERFRAME_SYNC 16.0f  // ... where the count expects voice B-F
#define DMR_WEAK_SLOT_TYPE_LIMIT_BS 1.0f  // a weak base station data sync's slot type
#define DMR_WEAK_SLOT_TYPE_LIMIT 0.0f     // any other weak data sync's
#define DMR_WEAK_TACT_LIMIT 0.0f          // a weak base station sync's TACT
#define DMR_AFC_GAIN 0.1f              // of a sync's frequency error, once the frame is settled
#define DMR_AFC_SYNC 17.0f             // levelled correlation from which a sync's error is reported
#define DMR_LEVEL_CARRY_DECAY 0.9f     // a carried level error, per slot period
enum {
  DMR_LOSS_BURSTS = 12,        // periods without a confirmation: the frame is lost
  DMR_CHANNEL_MISS_LIMIT = 2,  // unconfirmed voice bursts in a row handed on per channel
  DMR_SETTLING_BURSTS = 6,     // sync bursts after an acquisition that are re-timed too
};
// Radians of soft dibit phase per Hz of carrier offset with no receiver to say otherwise: the
// soft dibit frame's 135 degrees at 1944 Hz
#define DMR_DEFAULT_LEVEL_RADIANS_PER_HZ (0.75f * 3.14159265358979323846f / 1944.0f)

// The colour code weak syncs and EMBs must carry
enum dmr_cc_mode {
  DMR_CC_TRACK = 0, // the last strong observation's; none (nothing that needs one is taken) until then
  DMR_CC_PINNED,    // the configured one
  DMR_CC_ANY,       // none is required; the other validators then ask more
};

// What is done with a sync's mean level error
enum dmr_level_correction {
  DMR_LEVEL_OFF = 0,
  DMR_LEVEL_ACQUISITION_HEAD, // taken off the head (CACH, first half, sync) of the bursts a frame is acquired on
  DMR_LEVEL_SYNC_BURSTS,      // and off every later burst with a sync, each its own, the whole burst
  DMR_LEVEL_CARRY,            // and off the bursts without one (voice B-F): the last sync's, decaying
};

struct dmr_sink_config {
  // Station families whose syncs are looked for (a repeater output: base_station only)
  bool base_station,mobile_station,direct;
  bool reverse_channel;            // the MS standalone reverse channel sync (with mobile_station)
  enum dmr_cc_mode cc_mode;
  uint8_t pinned_cc;
  bool retime;                     // re-sample from the receiver's history (acquisition and near misses)
  bool look_back;                  // on acquisition, look at the two periods ahead of the acquiring sync
  bool lock_receiver_on_bursty;    // tell the receiver of a mobile station or direct mode frame too
  int settling_bursts;             // sync bursts after an acquisition re-timed at their own sync
  enum dmr_level_correction level_correction;
  float level_carry_decay;         // DMR_LEVEL_CARRY: per slot period
  bool acquisition_tail_blind;     // the acquiring burst's second half gets its own decision-directed level
  bool afc;                        // each sync's frequency error goes to the receiver
  float afc_gain,afc_sync;
  bool hold_empty_periods;         // the receiver's loops are held through a bursty frame's empty periods
  bool level_follows_correction;   // a level read at one dibit is taken off another less what the correction moved
  bool acquisition_tail_follows;   // ... and the acquiring burst's second half then has the sync's level, followed
  bool rigid_grid;                 // the acquiring burst and the looked-back periods re-sampled on a rigid grid
  bool frame_keeps_family;         // below a strong sync a held frame takes only its own family's patterns
  bool emb_revives_channel;        // an idle channel of a bursty frame comes back on an error-free EMB
  bool half_symbol_search;         // searching, the dibits are looked at half a symbol earlier as well
  bool rigid_tail;                 // the acquiring burst's second half re-sampled on its head's rigid grid
  float strong_sync,weak_sync,retimed_sync,candidate_sync,locked_sync,mid_superframe_sync;
  float weak_slot_type_limit_bs,weak_slot_type_limit,weak_tact_limit;
  int loss_bursts;
  int channel_miss_limit;
};
// Every field to its default: all families, colour code tracked, every feature on
void dmr_sink_config_defaults(struct dmr_sink_config *config);

struct dmr_sink_counters {
  uint64_t syncs[DMR_SYNC_PATTERNS]; // sync bursts, by pattern
  uint64_t strong_syncs;          // frames begun (or moved) by a strong sync
  uint64_t weak_syncs;            // ... by a validated weak sync
  uint64_t retimed_syncs;         // ... by a near miss accepted after re-timing
  uint64_t half_symbol_syncs;     // ... by a sync found half a symbol off (also counted strong / weak)
  uint64_t voice_syncs_confirmed; // ... by a voice sync confirmed by its EMBs
  uint64_t retimed_acquisitions;  // acquisitions whose head was re-sampled
  uint64_t look_back_syncs;       // syncs found ahead of an acquiring sync, at the frame's positions
  uint64_t retimed_look_backs;    // ... whose period was re-sampled
  uint64_t retimed_settling;      // sync bursts after an acquisition re-sampled at their own best timing
  uint64_t rigid_tails;           // acquiring bursts whose second half was re-sampled on the grid
  uint64_t afc_reports;          // syncs whose frequency error went to the receiver
  uint64_t loop_holds;            // times the receiver's loops were held for an empty period
  // Weak syncs refused, by the validator that refused them
  uint64_t weak_rejected_no_cc,weak_rejected_tact,weak_rejected_slot_type,weak_rejected_cc;
  uint64_t weak_rejected_no_validator; // reverse channel syncs
  uint64_t voice_syncs_unconfirmed;    // waiting voice syncs whose EMBs did not decode
  // Flywheel
  uint64_t flywheel_confirmed;    // periods confirmed by a sync or an EMB
  uint64_t flywheel_unconfirmed;  // periods with neither
  uint64_t emb_bursts;
  uint64_t late_entry_bursts;     // voice bursts of superframes whose voice sync was not found
  uint64_t channels_revived;      // idle channels of a bursty frame brought back by an EMB
  uint64_t unconfirmed_emitted;
  uint64_t held_discarded;        // first bursts of weak-sync frames that nothing confirmed
  uint64_t cc_mismatches;
  uint64_t tc_disagreements;      // TACTs whose TC bit disagreed with the slot numbering
  uint64_t slips,reframes,acquisitions,losses;
  uint64_t bursts_emitted;
  uint64_t bursts[4];             // emitted, by enum dmr_station
};

// The receiver as the sink needs it (dmrrx.c fills one in). set_frame_locked, resample,
// arms_per_symbol and nudge are required; any of the rest may be NULL (or 0), and is then taken as a
// receiver that does not do that. Without a timing at all the sink frames the dibits as they come
struct dmr_sink_timing {
  void *arg;
  void (*set_frame_locked)(void *arg,bool locked);  // frame sync acquired / lost
  // Symbols first .. first + count - 1 sampled offset_arms interpolator arms later; false if they
  // are not (yet, or any more) available
  bool (*resample)(void *arg,uint64_t first,int count,int offset_arms,struct softdibit *out);
  float (*arms_per_symbol)(void *arg);
  void (*nudge)(void *arg,float symbols);           // the sampling instant from the next symbol on, later positive
  // A sync's 24 known symbols read the carrier error_hz above the correction they were demodulated
  // with; symbol is the middle of the sync, gain the fraction of the way to move to that carrier
  void (*apply_frequency_error)(void *arg,float error_hz,uint64_t symbol,float gain);
  // The frequency correction (Hz) a symbol was demodulated with. NULL: the receiver does not tell
  float (*frequency_correction_at)(void *arg,uint64_t symbol);
  float level_radians_per_hz;                       // 0: DMR_DEFAULT_LEVEL_RADIANS_PER_HZ
  void (*hold_loops)(void *arg,bool hold);          // the periods that follow are empty / a burst is coming
  // Symbols first .. first + count - 1 on a rigid grid of nominal symbol periods through the instant
  // symbol 'anchor' was sampled at, moved offset_arms arms later; false if not available
  bool (*resample_rigid)(void *arg,uint64_t anchor,int offset_arms,uint64_t first,int count,struct softdibit *out);
};

// A burst, valid during the call
typedef void (*dmr_burst_handler)(void *arg,struct dmr_burst const *burst);
typedef void (*dmr_event_handler)(void *arg);
// Microseconds at symbol index 'symbol', the newest dibit the sink has; a burst's timestamp_us is
// this less the dibits since the burst's first
typedef uint64_t (*dmr_clock)(void *arg,uint64_t symbol);

struct dmr_sink;
// timing may be NULL; it is copied
struct dmr_sink *create_dmr_sink(struct dmr_sink_config const *config,struct dmr_sink_timing const *timing);
void delete_dmr_sink(struct dmr_sink *s);
void dmr_sink_set_burst_handler(struct dmr_sink *s,dmr_burst_handler handler,void *arg);
// The first accepted sync of a frame / the frame dropped; dmr_sink_locked() changes with them
void dmr_sink_set_acquired_handler(struct dmr_sink *s,dmr_event_handler handler,void *arg);
void dmr_sink_set_lost_handler(struct dmr_sink *s,dmr_event_handler handler,void *arg);
// Default: the system clock (CLOCK_REALTIME)
void dmr_sink_set_clock(struct dmr_sink *s,dmr_clock clock,void *arg);

// One soft dibit (only its phase is used) and the receiver's symbol index, consecutive: a jump
// restarts the search
void dmr_sink_dibit(struct dmr_sink *s,struct softdibit const *sd,uint64_t index);
// Back to searching with an empty ring; the colour code, counters and handlers stay. A frame in
// progress is dropped: its held bursts go out first (if it was vouched for), the lost handler fires
void dmr_sink_reset(struct dmr_sink *s);
// Forget the tracked colour code too (a channel retuned to another system)
void dmr_sink_reset_color_code(struct dmr_sink *s);

bool dmr_sink_locked(struct dmr_sink const *s);           // a frame is held
bool dmr_sink_confirmed(struct dmr_sink const *s);        // ... and two of its bursts were confirmed
enum dmr_station dmr_sink_station(struct dmr_sink const *s); // the frame's family (unknown while searching)
int dmr_sink_color_code(struct dmr_sink const *s);        // the code required now, or -1
uint32_t dmr_sink_color_code_observations(struct dmr_sink const *s,uint8_t cc); // strong observations of a code
uint64_t dmr_sink_color_code_changes(struct dmr_sink const *s); // times the tracked code changed
struct dmr_sink_counters const *dmr_sink_counters(struct dmr_sink const *s);
struct dmr_sink_config const *dmr_sink_config(struct dmr_sink const *s);
// Tools: the last dibit of the sync the frame was last acquired (or re-framed) on, and how many slot
// periods ahead of that sync the frame was begun (look-back, or waiting voice syncs it confirmed).
// Meaningful once an acquisition has happened (counters' acquisitions)
uint64_t dmr_sink_acquired_sync_end(struct dmr_sink const *s);
int dmr_sink_acquired_back_periods(struct dmr_sink const *s);
// Look for one station family's syncs only from now on (DMR_STATION_BS, _MS, _DIRECT), or for every family
// the configuration enabled (DMR_STATION_UNKNOWN). On the sink's thread, between bursts
void dmr_sink_restrict_family(struct dmr_sink *s,enum dmr_station mode);
// One line for a periodic summary (no newline); returns what snprintf() does
int dmr_sink_summary(struct dmr_sink const *s,char *line,int size);

#endif
