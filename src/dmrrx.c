// DMR receiver for one carrier: the 4FSK demodulator and its burst sink (see dmrrx.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <math.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "dmrrx.h"
#include "ka9q-math.h"

// Theory of operation
//
// The chain, per block of samples:
//   level control (unity RMS) -> frequency correction -> receive lowpass (4500 Hz)
//   -> FM discriminator, arg(x[n] conj(x[n-1])), radians per sample
//   -> root raised cosine matched filter on the frequency (alpha 0.2, 8 symbols each side)
//   -> x the timing input gain -> symbol timing (Gardner detector, 32-arm interpolator, PI loop)
//   -> x Level_correction -> 4-level slicer (the soft dibit) -> the burst sink, one symbol at a time
// The level control, frequency loop, receive filter and symbol timing are dsync.c's.
//
// The detector. DMR shapes the frequency of its 4FSK with a root raised cosine (TS 102 361-1
// 10.2.2: deviations +-648 and +-1944 Hz, alpha 0.2), so the matched filter belongs after an FM
// discriminator, on the frequency itself; with it the symbol instants are free of intersymbol
// interference. (A one-symbol differential detector, as P25 Phase 1's C4FM receiver uses, integrates
// the frequency over a symbol instead and reads the RRC-shaped symbols with a spread of their own.)
// The matched filter's taps sum to one, so a held frequency passes as itself. The timing loop runs
// on the filtered frequency as a real signal (run_symsync_real()).
//
// Levels. The discriminator gives radians per sample; times samples per symbol that is the phase
// advance over a symbol, nominally 2 pi 648 / 4800 (48.6 degrees) for an inner symbol and
// 2 pi 1944 / 4800 (145.8 degrees) for an outer one. Scaled by 135 / 145.8 (Mapper_scale) these land
// on the soft dibit frame the P25 receiver's make_softdibit() produces, +-45 and +-135 degrees, so the
// sink works in the same frame. The receive lowpass takes a little of the widest swings and the
// discriminator averages over a sample, so the chain reads every level a few percent low;
// Level_correction (1.05) puts them back. The timing input gain (DMR_RX_TIMING_INPUT_GAIN, 0.7)
// scales the loop's input only and is divided out again before the slicer: the Gardner error is a
// product of two samples and the loop clips it at +-0.15, so the loop's gain goes with the square
// of the level, and this sets where it works best.
//
// The slicer. The input is a frequency, not an angle, so nothing wraps: a plain 4-level slicer with
// thresholds at 0 and +-90 degrees, in which an outer symbol beyond +-180 degrees is still an outer
// symbol; the confidence is the distance to the nearest threshold over the 45 degrees a nominal level
// has, saturating at 1 (an outer symbol past its level is more certain, not less); the phase is the
// scaled value clamped at +-pi, so the sink's cosine correlation does not wrap an overshoot onto the
// other sign. Dibit to symbol is TS 102 361-1 table 10.3: 01 +3, 00 +1, 10 -1, 11 -3.
//
// Loops and lock. Frame sync is the lock, and it is the sink's decision: in a frame the timing loop
// narrows to the track bandwidth and the frequency loop's corner to Afc_track_corner (1 Hz); when the
// frame is lost the timing loop widens to the acquire bandwidth and forgets its rate estimate (noise
// has walked it), and the frequency estimate is held where it is for afc_hold_symbols (30 s) before
// its corner widens to Afc_acquire_corner (10 Hz). A repeater drops its carrier between transmissions
// and comes back on the same frequency, while on the noise between them a wide loop walks; a sync is
// all outer symbols and correlates through an offset of a few hundred Hz, so another transmitter
// keying up during the hold still locks, and the lock ends the hold. A lock change the sink makes
// inside a block takes effect for the timing loop at the end of the block. The receiver never
// declares lock itself and never gates on signal level. Acquisition is wide (0.5 radians per symbol)
// because a DMR sync is in the middle of its burst and a transmission's first sync ends 19 ms after
// key-up: the loop has 90 symbols to find the timing.
//
// What the sink tells the receiver beyond the lock:
//   The carrier, from each sync (apply_frequency_error()). The block frequency estimate reads the
// centroid of the spectrum, and a DMR burst's mean symbol is not zero, so it settles off the carrier
// on real content. A sync's 24 known symbols read the carrier itself, as their common level shift.
// From the sink's first such report in a frame the block estimate is frozen (corner 0) and the
// correction moves by the reports alone, each stated against the correction the sync's middle symbol
// was demodulated with (kept for the last Symbol_ring symbols), so that a report about an older sync,
// and the block a correction takes to act, do not put the loop wrong. Reports made during a block are
// summed and applied as a new estimate after it.
//   The empty periods (hold_loops()). On a mobile station or direct mode frame the carrier is keyed
// for 27.5 ms in 60; through the empty periods the timing loop takes no error (bandwidth 0, sampling
// at the nominal rate: its rate estimate is dropped at each hold, since what it integrated over one
// burst is mostly noise) and the frequency estimate does not move. At the release the sampling
// instant is moved by what the transmitter's clock gained on the nominal one through the hold: the
// loop's ratio averaged over the symbols it ran on locked and unheld (Rate_average_symbols, about
// eight bursts) times the symbols held.
//   Past symbols at another timing. The sink finds a burst's sync in its middle, so the 66 dibits
// ahead of it were sampled at whatever timing the loop had then. Symbol k is the synchronizer's
// output symbol_output[k], and symsync_near() re-interpolates any output still in its history (2048
// input samples, 512 symbols less the interpolator's span) at whole interpolator arms earlier or
// later: resample() does that relative to where each symbol was sampled, resample_rigid() on a grid
// of nominal symbol periods through one symbol's instant, whatever the loop did in between.
//
// The frequency correction a symbol had is its block's, or the block before's for the first
// Chain_delay_samples (51) of a block: the receive lowpass (15 samples), the matched filter (32) and
// the interpolator (4) lie between the correction and the symbol.
//
// Arithmetic. Every stage keeps one order of operations, statement by statement (that is why it
// uses run_rxfilter_parts() and run_symsync_real()): its tests compare the output bit for bit with
// an independent implementation of the same design, built the same way. Built with contraction
// across statements (the tree's -ffp-contract=fast) the roundings differ a little from that.

#define MAPPER_PI 3.14159265358979323846f
#define NOMINAL_OUTER_RADIANS (2.0f * MAPPER_PI * 1944.0f / 4800.0f) // phase advance of an outer symbol
static float const Mapper_pi = MAPPER_PI;
static float const Mapper_scale = (0.75f * MAPPER_PI) / NOMINAL_OUTER_RADIANS; // 135 / 145.8
static float const Inner_level = 0.25f * MAPPER_PI;
static float const Threshold = 0.5f * MAPPER_PI;   // inner / outer
static float const Symbol_rate = 4800.0f;
static float const Level_correction = 1.05f;
static float const Level_alpha = 0.0005f;          // level control smoothing, per sample
static float const Afc_acquire_corner = 10.0f;     // Hz
static float const Afc_track_corner = 1.0f;        // Hz
static float const Rxfilter_cutoff = 4500.0f;      // Hz
static int const Rxfilter_taps = 31;
static float const Rxfilter_rolloff = 0.7f;
static float const Rrc_alpha = 0.2f;
static double const Rrc_span = 8;                  // symbols each side of the centre
static int const Interpolator_arms = 32;
static float const Loop_damping = 1.0f;
static float const Loop_error_gain = 0.42f;
static float const Rate_limit = 0.0003f;           // the rate estimate stays within +-300 ppm
static int const Interpolator_digits = 6;
static double const Rate_average_symbols = 1024.0;
static int const Chain_delay_samples = 51;
enum { Symbol_ring = 1024 }; // a power of two; twice the synchronizer's history in symbols

// std::min, std::max and std::clamp's comparisons, NaN included
static inline float minf(float a,float b){ return b < a ? b : a; }
static inline float maxf(float a,float b){ return a < b ? b : a; }
static inline float clampf(float v,float lo,float hi){ return v < lo ? lo : hi < v ? hi : v; }

struct dmr_rx {
  // The demodulator
  double samprate;
  float samples_per_symbol;
  float timing_input_gain;
  float acquire_bandwidth,track_bandwidth;
  float symbol_scale;          // synchronizer output -> the slicer's radians per symbol
  float nominal_ratio;         // outputs (two a symbol) per input sample
  struct level level;
  struct freqtrack ft;
  struct rotator rotator;
  struct rxfilter rxfilter;
  struct realfilter rrc;
  struct symsync sync;
  float complex discriminator_previous;
  double rate_error_ppm;
  double burst_rate_ppm;       // the same over the symbols of a locked loop that is not held
  uint64_t hold_start;         // symbol count at the hold
  uint64_t symbol_output[Symbol_ring]; // symbol index -> synchronizer output
  float symbol_correction[Symbol_ring]; // the correction each symbol was demodulated with
  uint64_t symbol_count;
  atomic_bool frame_locked;
  bool was_locked;
  bool in_block;
  // Timing loop lock changes made during a block, applied after it. They alternate, so the first
  // and how many say them all
  bool lock_change_first;      // true: the first was a lock
  int lock_changes;
  float block_correction,previous_block_correction;
  int symbols_this_block;
  bool decision_directed;
  float pending_step;          // the sink's frequency steps, applied after the block
  bool loops_held;
  uint64_t afc_blocks,afc_samples;
  double afc_sum;
  float afc_min,afc_max;
  bool afc_held;
  uint64_t afc_hold_start;     // symbol count at the frame loss
  uint64_t afc_hold_symbols;
  _Atomic float pending_seed;  // NAN: none
  _Atomic float afc_offset;
  uint64_t blocks,samples;
  float complex *block;
  float *frequency;
  int capacity;

  struct dmr_sink *sink;
  dmr_dibit_tap tap;
  void *tap_arg;
  dmr_symbol_handler symbol_handler;
  void *symbol_arg;
  dmr_lock_handler lock_handler;
  void *lock_arg;
  dmr_correction_handler correction_handler;
  void *correction_arg;
};

void dmr_rx_config_defaults(struct dmr_rx_config *c){
  assert(c != NULL);
  memset(c,0,sizeof *c);
  dmr_sink_config_defaults(&c->sink);
  c->samprate = DMR_RX_SAMPRATE;
  c->acquire_bandwidth = DMR_RX_ACQUIRE_BANDWIDTH;
  c->track_bandwidth = DMR_RX_TRACK_BANDWIDTH;
  c->timing_input_gain = DMR_RX_TIMING_INPUT_GAIN;
  c->afc_hold_symbols = DMR_RX_AFC_HOLD_SYMBOLS;
}

// ---------------- the slicer ----------------

static struct softdibit map_level(float radians_per_symbol){
  struct softdibit sd = { 0, 0.0f, 0.0f };
  if(isnan(radians_per_symbol))
    return sd; // no finite sample: dibit 00, no confidence
  float const scaled = radians_per_symbol * Mapper_scale;
  if(scaled >= 0.0f)
    sd.dibit = scaled > Threshold ? 1 : 0;
  else
    sd.dibit = scaled < -Threshold ? 3 : 2;
  float const magnitude = fabsf(scaled);
  float const distance = minf(magnitude,fabsf(magnitude - Threshold));
  sd.confidence = minf(distance / Inner_level,1.0f);
  sd.phase = clampf(scaled,-Mapper_pi,Mapper_pi);
  return sd;
}
// The synchronizer's output is the filtered frequency in radians per sample times the timing input gain
static struct softdibit map_symbol(struct dmr_rx const *rx,float complex y){
  return map_level(crealf(y) * rx->symbol_scale);
}

// ---------------- loops ----------------

// The frequency loop's corner: 0 (the estimate does not move) while the loops are held, while the
// correction is the syncs' and during the hold after a frame loss
static void update_afc_corner(struct dmr_rx *rx){
  float corner = Afc_acquire_corner;
  if(rx->loops_held)
    corner = 0.0f;
  else if(atomic_load_explicit(&rx->frame_locked,memory_order_relaxed))
    corner = rx->decision_directed ? 0.0f : Afc_track_corner;
  else if(rx->afc_held)
    corner = 0.0f;
  set_freqtrack_corner(&rx->ft,corner);
}
// The timing loop's bandwidth: 0 while held (the loop's output is then its rate estimate), else
// the track or the acquire one
static void apply_timing_bandwidth(struct dmr_rx *rx){
  set_symsync_bandwidth(&rx->sync,rx->loops_held ? 0.0f : rx->sync.locked ? rx->track_bandwidth : rx->acquire_bandwidth);
}
static void apply_timing_lock_changes(struct dmr_rx *rx){
  for(int i=0; i < rx->lock_changes; i++){
    bool const lock = (i & 1) ? !rx->lock_change_first : rx->lock_change_first;
    if(lock)
      lock_symsync(&rx->sync,true);
    else {
      lock_symsync(&rx->sync,false);
      reset_symsync_rate(&rx->sync); // drop the rate estimate noise has walked
      rx->rate_error_ppm = 0.0;
      rx->burst_rate_ppm = 0.0;
    }
  }
  if(rx->lock_changes != 0 && rx->loops_held)
    apply_timing_bandwidth(rx); // lock_symsync() set a bandwidth
  rx->lock_changes = 0;
}
static void update_lock_state(struct dmr_rx *rx){
  bool const now = atomic_load_explicit(&rx->frame_locked,memory_order_relaxed);
  if(now == rx->was_locked)
    return;
  rx->was_locked = now;
  if(rx->lock_handler != NULL)
    rx->lock_handler(rx->lock_arg,now);
}
static void release_afc_hold_if_due(struct dmr_rx *rx){
  if(!rx->afc_held || rx->symbol_count - rx->afc_hold_start < rx->afc_hold_symbols)
    return;
  rx->afc_held = false;
  update_afc_corner(rx);
}
// After the block's symbols the sink's frequency steps become the estimate, the correction from
// the next block on (a seeded estimate is taken as the correction at the next update; a block of
// one sample carries no measurement)
static void apply_pending_frequency_step(struct dmr_rx *rx){
  if(rx->pending_step == 0.0f)
    return;
  seed_freqtrack(&rx->ft,rx->ft.estimate + rx->pending_step);
  rx->pending_step = 0.0f;
  float complex const one = 0;
  update_freqtrack_block(&rx->ft,&one,1);
}
static void reset_afc_statistics(struct dmr_rx *rx){
  rx->afc_blocks = 0;
  rx->afc_samples = 0;
  rx->afc_sum = 0.0;
  rx->afc_min = rx->afc_max = 0.0f;
}
static void update_afc_statistics(struct dmr_rx *rx,int n){
  float const estimate = rx->ft.estimate;
  if(rx->afc_blocks == 0)
    rx->afc_min = rx->afc_max = estimate;
  rx->afc_min = minf(rx->afc_min,estimate);
  rx->afc_max = maxf(rx->afc_max,estimate);
  rx->afc_sum += estimate;
  rx->afc_blocks++;
  rx->afc_samples += (uint64_t)n;
}

// ---------------- the sink's view of the receiver ----------------

static void set_frame_locked(void *arg,bool locked){
  struct dmr_rx *rx = arg;
  if(locked == atomic_load_explicit(&rx->frame_locked,memory_order_relaxed))
    return;
  atomic_store_explicit(&rx->frame_locked,locked,memory_order_relaxed);
  rx->decision_directed = false;
  if(locked)
    rx->afc_held = false;
  else {
    rx->afc_held = rx->afc_hold_symbols > 0;
    rx->afc_hold_start = rx->symbol_count;
  }
  if(rx->lock_changes == 0)
    rx->lock_change_first = locked;
  rx->lock_changes++;
  update_afc_corner(rx);
  if(!rx->in_block){
    apply_timing_lock_changes(rx);
    update_lock_state(rx);
  }
}
static bool resample(void *arg,uint64_t first,int count,int offset_arms,struct softdibit *out){
  struct dmr_rx const *rx = arg;
  if(count < 0 || first + (uint64_t)count > rx->symbol_count)
    return false;
  if(count == 0)
    return true;
  if(rx->symbol_count - first > Symbol_ring)
    return false;
  for(int i=0; i < count; i++){
    uint64_t const symbol = first + (uint64_t)i;
    float complex y;
    if(!symsync_near(&rx->sync,rx->symbol_output[symbol & (Symbol_ring - 1)],offset_arms,&y))
      return false;
    out[i] = map_symbol(rx,y);
  }
  return true;
}
static float arms_per_symbol(void *arg){
  struct dmr_rx const *rx = arg;
  return symsync_arms_per_symbol(&rx->sync);
}
static bool resample_rigid(void *arg,uint64_t anchor,int offset_arms,uint64_t first,int count,struct softdibit *out){
  struct dmr_rx const *rx = arg;
  if(count < 0 || anchor >= rx->symbol_count || rx->symbol_count - anchor > Symbol_ring)
    return false;
  // (a grid point further from the anchor than the history is deep has no samples)
  int64_t const distance = (int64_t)first - (int64_t)anchor;
  int64_t const reach = Symbol_ring;
  if(distance < -reach || distance + count > reach)
    return false;
  uint64_t const output = rx->symbol_output[anchor & (Symbol_ring - 1)];
  double const arms = (double)symsync_arms_per_symbol(&rx->sync);
  for(int i=0; i < count; i++){
    double const symbols = (double)(distance + i);
    float complex y;
    if(!symsync_near(&rx->sync,output,offset_arms + (int)lround(symbols * arms),&y))
      return false;
    out[i] = map_symbol(rx,y);
  }
  return true;
}
static void nudge(void *arg,float symbols){
  struct dmr_rx *rx = arg;
  nudge_symsync(&rx->sync,symbols);
}
static float frequency_correction_at(void *arg,uint64_t symbol){
  struct dmr_rx const *rx = arg;
  if(symbol >= rx->symbol_count)
    return rx->ft.applied;
  if(rx->symbol_count - symbol > Symbol_ring)
    symbol = rx->symbol_count - Symbol_ring;
  return rx->symbol_correction[symbol & (Symbol_ring - 1)];
}
// The carrier read error_hz above the correction symbol 'symbol' had; the correction moves the
// fraction 'gain' of the way there. Ignored without a frame
static void apply_frequency_error(void *arg,float error_hz,uint64_t symbol,float gain){
  struct dmr_rx *rx = arg;
  if(!atomic_load_explicit(&rx->frame_locked,memory_order_relaxed) || !isfinite(error_hz))
    return;
  float const carrier = frequency_correction_at(rx,symbol) + error_hz;
  float const estimate = rx->ft.estimate + rx->pending_step;
  rx->pending_step += clampf(gain,0.0f,1.0f) * (carrier - estimate);
  if(!rx->decision_directed){
    rx->decision_directed = true;
    update_afc_corner(rx);
  }
}
static void hold_loops(void *arg,bool hold){
  struct dmr_rx *rx = arg;
  if(hold == rx->loops_held)
    return;
  rx->loops_held = hold;
  if(hold){
    reset_symsync_rate(&rx->sync);
    rx->rate_error_ppm = 0.0;
    rx->hold_start = rx->symbol_count;
  } else {
    // The symbols went by at the transmitter's rate, not the nominal one
    double const symbols = (double)(rx->symbol_count - rx->hold_start) * rx->burst_rate_ppm * 1e-6;
    if(fabs(symbols) > 1e-4)
      nudge_symsync(&rx->sync,(float)-symbols);
  }
  apply_timing_bandwidth(rx);
  update_afc_corner(rx);
}

// ---------------- the demodulator ----------------

static void on_symbol(struct dmr_rx *rx,float complex y){
  uint64_t const index = rx->symbol_count++;
  double const ratio_ppm = ((double)rx->sync.ratio / rx->nominal_ratio - 1.0) * 1e6;
  rx->rate_error_ppm += (ratio_ppm - rx->rate_error_ppm) / Rate_average_symbols;
  if(!rx->loops_held && rx->sync.locked)
    rx->burst_rate_ppm += (ratio_ppm - rx->burst_rate_ppm) / Rate_average_symbols;
  rx->symbol_output[index & (Symbol_ring - 1)] = rx->sync.outputs_out - 1;
  bool const early = (float)(rx->symbols_this_block++) * rx->samples_per_symbol < (float)Chain_delay_samples;
  rx->symbol_correction[index & (Symbol_ring - 1)] = early ? rx->previous_block_correction : rx->block_correction;
  struct softdibit const sd = map_symbol(rx,y);
  if(rx->tap != NULL)
    rx->tap(rx->tap_arg,&sd,index);
  dmr_sink_dibit(rx->sink,&sd,index);
  if(rx->symbol_handler != NULL)
    rx->symbol_handler(rx->symbol_arg,index);
}
static void on_output(void *arg,float complex y,bool is_symbol){
  if(is_symbol)
    on_symbol(arg,y);
}

struct dmr_rx *create_dmr_rx(struct dmr_rx_config const *config){
  assert(config != NULL);
  if(config->samprate < 2 * (double)Symbol_rate || !(config->timing_input_gain > 0))
    return NULL;
  struct dmr_rx *rx = calloc(1,sizeof *rx);
  if(rx == NULL)
    return NULL;
  rx->samprate = config->samprate;
  float const fs = (float)config->samprate;
  rx->samples_per_symbol = fs / Symbol_rate;
  rx->timing_input_gain = config->timing_input_gain;
  rx->acquire_bandwidth = config->acquire_bandwidth;
  rx->track_bandwidth = config->track_bandwidth;
  rx->symbol_scale = fs / Symbol_rate / config->timing_input_gain * Level_correction;
  rx->nominal_ratio = 2.0f * Symbol_rate / fs;
  rx->afc_hold_symbols = config->afc_hold_symbols;
  rx->discriminator_previous = 1;
  atomic_init(&rx->frame_locked,false);
  atomic_init(&rx->pending_seed,NAN);
  atomic_init(&rx->afc_offset,0.0f);

  // Unit RMS; init_level() takes a time constant
  init_level(&rx->level,config->samprate,1.0 / (Level_alpha * config->samprate));
  init_freqtrack(&rx->ft,fs,Afc_acquire_corner); // wide until frame sync
  init_rotator(&rx->rotator);
  bool ok = init_rxfilter(&rx->rxfilter,config->samprate,Rxfilter_cutoff,Rxfilter_taps,Rxfilter_rolloff) == 0;
  ok = ok && init_rrc_realfilter(&rx->rrc,config->samprate,Symbol_rate,Rrc_alpha,Rrc_span) == 0;
  // GNU Radio's MMSE interpolator table is six figures; see set_symsync_digits()
  ok = ok && init_symsync(&rx->sync,fs,Symbol_rate,Interpolator_arms,config->acquire_bandwidth,config->track_bandwidth,
			  Loop_damping,Loop_error_gain,Rate_limit) == 0;
  ok = ok && set_symsync_digits(&rx->sync,Interpolator_digits) == 0;
  struct dmr_sink_timing const timing = {
    .arg = rx,
    .set_frame_locked = set_frame_locked,
    .resample = resample,
    .arms_per_symbol = arms_per_symbol,
    .nudge = nudge,
    .apply_frequency_error = apply_frequency_error,
    .frequency_correction_at = frequency_correction_at,
    .level_radians_per_hz = 2.0f * Mapper_pi / Symbol_rate * Mapper_scale * Level_correction,
    .hold_loops = hold_loops,
    .resample_rigid = resample_rigid,
  };
  rx->sink = ok ? create_dmr_sink(&config->sink,&timing) : NULL;
  if(rx->sink == NULL){
    delete_dmr_rx(rx);
    return NULL;
  }
  return rx;
}
void delete_dmr_rx(struct dmr_rx *rx){
  if(rx == NULL)
    return;
  delete_dmr_sink(rx->sink);
  free_rxfilter(&rx->rxfilter);
  free_realfilter(&rx->rrc);
  free_symsync(&rx->sync);
  free(rx->block);
  free(rx->frequency);
  free(rx);
}

void dmr_rx_set_burst_handler(struct dmr_rx *rx,dmr_burst_handler handler,void *arg){
  dmr_sink_set_burst_handler(rx->sink,handler,arg);
}
void dmr_rx_set_acquired_handler(struct dmr_rx *rx,dmr_event_handler handler,void *arg){
  dmr_sink_set_acquired_handler(rx->sink,handler,arg);
}
void dmr_rx_set_lost_handler(struct dmr_rx *rx,dmr_event_handler handler,void *arg){
  dmr_sink_set_lost_handler(rx->sink,handler,arg);
}
void dmr_rx_set_clock(struct dmr_rx *rx,dmr_clock clock,void *arg){
  dmr_sink_set_clock(rx->sink,clock,arg);
}
void dmr_rx_set_lock_handler(struct dmr_rx *rx,dmr_lock_handler handler,void *arg){
  rx->lock_handler = handler;
  rx->lock_arg = arg;
}
void dmr_rx_set_symbol_handler(struct dmr_rx *rx,dmr_symbol_handler handler,void *arg){
  rx->symbol_handler = handler;
  rx->symbol_arg = arg;
}
void dmr_rx_set_dibit_tap(struct dmr_rx *rx,dmr_dibit_tap tap,void *arg){
  rx->tap = tap;
  rx->tap_arg = arg;
}
void dmr_rx_set_correction_handler(struct dmr_rx *rx,dmr_correction_handler handler,void *arg){
  rx->correction_handler = handler;
  rx->correction_arg = arg;
}
void dmr_rx_seed_frequency(struct dmr_rx *rx,float offset){
  atomic_store_explicit(&rx->pending_seed,offset,memory_order_relaxed);
}
void dmr_rx_reset_color_code(struct dmr_rx *rx){
  dmr_sink_reset_color_code(rx->sink);
}
void dmr_rx_flush(struct dmr_rx *rx){
  dmr_sink_reset(rx->sink);
}
void dmr_rx_soft_dibit(struct dmr_rx *rx,struct softdibit const *sd,uint64_t index){
  dmr_sink_dibit(rx->sink,sd,index);
  if(rx->symbol_handler != NULL)
    rx->symbol_handler(rx->symbol_arg,index);
}
bool dmr_rx_locked(struct dmr_rx const *rx){
  return atomic_load_explicit(&rx->frame_locked,memory_order_relaxed);
}
float dmr_rx_frequency_offset(struct dmr_rx const *rx){
  return atomic_load_explicit(&rx->afc_offset,memory_order_relaxed);
}
uint64_t dmr_rx_symbol_count(struct dmr_rx const *rx){
  return rx->symbol_count;
}
void dmr_rx_restrict_family(struct dmr_rx *rx,enum dmr_station mode){
  if(rx != NULL)
    dmr_sink_restrict_family(rx->sink,mode);
}
struct dmr_sink const *dmr_rx_sink(struct dmr_rx const *rx){
  return rx->sink;
}
void dmr_rx_get_status(struct dmr_rx const *rx,struct dmr_rx_status *st){
  memset(st,0,sizeof *st);
  st->frame_locked = dmr_rx_locked(rx);
  st->timing_locked = rx->sync.locked;
  st->afc_held = rx->afc_held;
  st->decision_directed = rx->decision_directed;
  st->loops_held = rx->loops_held;
  st->afc_offset = rx->ft.estimate;
  st->afc_min = rx->afc_min;
  st->afc_max = rx->afc_max;
  st->afc_mean = rx->afc_blocks != 0 ? (float)(rx->afc_sum / (double)rx->afc_blocks) : 0.0f;
  st->afc_samples = rx->afc_samples;
  st->timing_error = rx->sync.error_ema;
  st->rate_error_ppm = (float)rx->rate_error_ppm;
  st->timing_ratio = rx->sync.ratio / rx->nominal_ratio;
  st->symbols = rx->symbol_count;
  st->samples = rx->samples;
}

// The FM discriminator: the phase advance from the previous sample, radians
static float discriminate(struct dmr_rx *rx,float complex x){
  float complex const product = x * conjf(rx->discriminator_previous);
  rx->discriminator_previous = x;
  return atan2f(cimagf(product),crealf(product));
}

void dmr_rx_samples(struct dmr_rx *rx,float complex const *iq,int n){
  if(n <= 0)
    return;
  if(rx->blocks++ == 0){
    // Start the level control at the input's level: from 1 it takes seconds to reach a weak one
    double power = 0.0;
    for(int i=0; i < n; i++)
      power += cnrmf(iq[i]);
    if(power > 0.0){
      float const rms = (float)sqrt(power / (double)n);
      rx->level.power = rms * rms;
    }
  }
  rx->samples += (uint64_t)n;
  float const seed = atomic_exchange_explicit(&rx->pending_seed,NAN,memory_order_relaxed);
  if(!isnan(seed)){
    seed_freqtrack(&rx->ft,seed);
    reset_afc_statistics(rx);
  }
  if(n > rx->capacity){
    float complex *block = realloc(rx->block,(size_t)n * sizeof *block);
    float *frequency = realloc(rx->frequency,(size_t)n * sizeof *frequency);
    if(block != NULL)
      rx->block = block;
    if(frequency != NULL)
      rx->frequency = frequency;
    if(block == NULL || frequency == NULL)
      return; // no memory: the block is lost
    rx->capacity = n;
  }
  float complex * const block = rx->block;
  memcpy(block,iq,(size_t)n * sizeof *block);
  run_level(&rx->level,block,n);

  // Block-rate frequency loop: correct (here, or already upstream), receive lowpass, then estimate
  // the residual and set the next block's correction
  rx->previous_block_correction = rx->block_correction;
  rx->block_correction = rx->ft.applied;
  rx->symbols_this_block = 0;
  if(rx->correction_handler == NULL){
    set_rotator(&rx->rotator,rx->samprate,-(double)rx->ft.applied);
    run_rotator(&rx->rotator,block,n);
  }
  measure_freqtrack(&rx->ft,block,n);
  run_rxfilter_parts(&rx->rxfilter,block,n);
  update_freqtrack_block(&rx->ft,block,n);

  // Discriminator and matched filter; the timing loop takes the filtered frequency as a real signal
  float * const frequency = rx->frequency;
  for(int i=0; i < n; i++)
    frequency[i] = rx->timing_input_gain * realfilter_sample(&rx->rrc,discriminate(rx,block[i]));

  // Synchronizer, slicer and sink one symbol at a time, so a nudge made at a symbol acts from the
  // next one; then the timing loop's lock changes
  rx->in_block = true;
  run_symsync_real(&rx->sync,frequency,n,on_output,rx);
  rx->in_block = false;
  apply_timing_lock_changes(rx);
  release_afc_hold_if_due(rx);
  // What the sink measured in this block is the correction from the next one
  apply_pending_frequency_step(rx);
  if(rx->correction_handler != NULL)
    rx->correction_handler(rx->correction_arg,rx->ft.applied);
  update_afc_statistics(rx,n);
  update_lock_state(rx);
  atomic_store_explicit(&rx->afc_offset,rx->ft.estimate,memory_order_relaxed);
}
