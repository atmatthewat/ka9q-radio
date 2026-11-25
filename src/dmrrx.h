// DMR (ETSI TS 102 361) receiver for one carrier: complex baseband in, bursts out.
// The 4FSK demodulator (FM discriminator and matched filter, symbol timing, soft dibits) joined to
// the burst sink (dmrsink.h), which frames the TDMA slots and tells the demodulator what it knows of
// the frame. dmrrx.c has the theory of operation
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRRX_H
#define _DMRRX_H 1

#include <complex.h>
#include <stdbool.h>
#include <stdint.h>

#include "digital.h"
#include "dmr.h"
#include "dmrsink.h"

// The demodulator's defaults; dmrrx.c says where they come from
#define DMR_RX_SAMPRATE 19200.0          // Hz: 4 samples per symbol
#define DMR_RX_ACQUIRE_BANDWIDTH 0.5f    // timing loop natural frequency, radians per symbol, searching
#define DMR_RX_TRACK_BANDWIDTH 0.016f    // ... with frame sync held
#define DMR_RX_TIMING_INPUT_GAIN 0.7f    // on the matched filter's output into the timing loop
#define DMR_RX_AFC_HOLD_SYMBOLS (30ULL * 4800ULL) // the frequency estimate held after a frame is lost

struct dmr_rx_config {
  struct dmr_sink_config sink;  // station families, colour code, thresholds (dmrsink.h)
  double samprate;              // Hz, at least 2 samples per symbol; 19200 is what everything is tuned for
  float acquire_bandwidth;
  float track_bandwidth;
  float timing_input_gain;      // > 0
  uint64_t afc_hold_symbols;    // 0: no hold, the frequency loop widens as soon as a frame is lost
};
// Every field to its default (dmr_sink_config_defaults() for the sink: all station families,
// colour code tracked)
void dmr_rx_config_defaults(struct dmr_rx_config *config);

// What the receiver says of itself (for a periodic summary line)
struct dmr_rx_status {
  bool frame_locked;      // the sink holds a frame (the demodulator's loops are narrow)
  bool timing_locked;     // the timing loop is at its tracking bandwidth (follows frame_locked at the end of a block)
  bool afc_held;          // the frequency estimate is frozen after a frame loss
  bool decision_directed; // in a frame, the frequency correction moves by the syncs' readings alone
  bool loops_held;        // through an empty period of a bursty frame
  float afc_offset;       // Hz: the carrier's offset from the centre of the stream as the receiver has it
  float afc_min,afc_max,afc_mean; // Hz, of the estimate after each block since start or the last seed
  uint64_t afc_samples;   // samples behind those
  float timing_error;     // smoothed |Gardner error| / energy: timing quality telemetry
  float rate_error_ppm;   // symbol clock against nominal, positive fast (0 after a frame loss)
  float timing_ratio;     // the timing loop's resampling ratio for the last symbol, relative to nominal
  uint64_t symbols;       // symbols delivered so far (the next symbol's index)
  uint64_t samples;       // samples taken
};

// Every soft dibit as the demodulator makes it, before the sink (tools)
typedef void (*dmr_dibit_tap)(void *arg,struct softdibit const *sd,uint64_t index);
// Each symbol after the sink has taken it, with its index: the owner's per-symbol clock (timeouts)
typedef void (*dmr_symbol_handler)(void *arg,uint64_t index);
// Frame sync acquired (true) or lost (false), after the block in which it changed
typedef void (*dmr_lock_handler)(void *arg,bool locked);
// The frequency correction (Hz) for the next block, when something upstream applies it
typedef void (*dmr_correction_handler)(void *arg,float offset);

struct dmr_rx;
struct dmr_rx *create_dmr_rx(struct dmr_rx_config const *config); // NULL: bad config, or no memory
void delete_dmr_rx(struct dmr_rx *rx);

// Handlers; set them before the first sample. All run on the thread that feeds the samples
void dmr_rx_set_burst_handler(struct dmr_rx *rx,dmr_burst_handler handler,void *arg);
void dmr_rx_set_acquired_handler(struct dmr_rx *rx,dmr_event_handler handler,void *arg); // the sink's first sync of a frame
void dmr_rx_set_lost_handler(struct dmr_rx *rx,dmr_event_handler handler,void *arg);     // the sink dropped the frame
// The sink's clock for timestamp_us: microseconds at a symbol index. Default: the system clock.
// A burst carries dibit_clock, the symbol index of its first dibit, so an owner keeping its own time
// base can restamp it
void dmr_rx_set_clock(struct dmr_rx *rx,dmr_clock clock,void *arg);
void dmr_rx_set_lock_handler(struct dmr_rx *rx,dmr_lock_handler handler,void *arg);
void dmr_rx_set_symbol_handler(struct dmr_rx *rx,dmr_symbol_handler handler,void *arg);
void dmr_rx_set_dibit_tap(struct dmr_rx *rx,dmr_dibit_tap tap,void *arg);
// Unset (the default), the receiver shifts each block by its frequency correction itself. Set, it
// calls the handler after each block with the correction for the next block, and expects the
// samples to arrive already shifted by it (a channel filter's own oscillator); either way a
// correction applies from the block after the one it was decided on
void dmr_rx_set_correction_handler(struct dmr_rx *rx,dmr_correction_handler handler,void *arg);

// 'count' samples at the configured rate, any block size; bursts and events come out of this call
void dmr_rx_samples(struct dmr_rx *rx,float complex const *iq,int count);
// A soft dibit straight to the sink, bypassing the demodulator (a dibit file, tests); index as the
// demodulator would number it, consecutive. Not to be mixed with dmr_rx_samples()
void dmr_rx_soft_dibit(struct dmr_rx *rx,struct softdibit const *sd,uint64_t index);
// The end of the input: a frame in progress is dropped and its held bursts go out
void dmr_rx_flush(struct dmr_rx *rx);
// A known carrier offset (Hz), e.g. a control channel's; taken at the next block. Any thread
void dmr_rx_seed_frequency(struct dmr_rx *rx,float offset);
// Forget the tracked colour code (a channel retuned to another system)
void dmr_rx_reset_color_code(struct dmr_rx *rx);

bool dmr_rx_locked(struct dmr_rx const *rx);           // frame sync held; any thread
float dmr_rx_frequency_offset(struct dmr_rx const *rx); // Hz, after the last block; any thread
uint64_t dmr_rx_symbol_count(struct dmr_rx const *rx);  // symbols delivered (the next symbol's index)
void dmr_rx_get_status(struct dmr_rx const *rx,struct dmr_rx_status *status);
struct dmr_sink const *dmr_rx_sink(struct dmr_rx const *rx); // the sink's state, counters and summary (dmrsink.h)
void dmr_rx_restrict_family(struct dmr_rx *rx,enum dmr_station mode); // dmr_sink_restrict_family(), on the rx's thread

// The demodulator's symbol delay: a dibit on the air at input sample 4 i is symbol i + this
// (receive lowpass 15 samples, matched filter 32, interpolator 4: 51 samples, 13 symbols at 19200 Hz)
enum { DMR_RX_DELAY_SYMBOLS = 13 };

#endif
