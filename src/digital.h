// Receive pieces shared by the digital mode decoders (p25d now; DMR and others later)
// All work on a complex baseband (IQ) stream from radiod:
// receive filter, level control, frequency tracking, symbol timing, soft symbols
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DIGITAL_H
#define _DIGITAL_H 1

#include <complex.h>
#include <stdbool.h>
#include <stdint.h>

// Lowpass FIR with real taps for complex baseband
// Raised-cosine shaped response: flat to cutoff * (1 - rolloff), -6 dB at the cutoff,
// zero beyond cutoff * (1 + rolloff); rolloff 0 is a plain windowed sinc. Hamming window, unity DC gain
struct rxfilter {
  int ntaps;
  int pos;
  float *taps;
  float complex *history; // Stored twice so each output is one contiguous dot product
};
int init_rxfilter(struct rxfilter *f,double samprate,double cutoff,int ntaps,double rolloff);
void free_rxfilter(struct rxfilter *f);
void run_rxfilter(struct rxfilter *f,float complex *buffer,int count); // in place

// Level control: scale to unity RMS with a slow power estimate
// The timing loop's gain depends on amplitude, so this is needed whatever radiod's own AGC is doing
struct level {
  float alpha; // per-sample smoothing factor
  float power; // smoothed |x|^2
};
void init_level(struct level *l,double samprate,double time_constant);
void prime_level(struct level *l,float complex const *buffer,int count); // start at this block's level
void run_level(struct level *l,float complex *buffer,int count); // in place

// Frequency tracking, updated once per block
// The block is rotated by the correction decided after the previous block, the residual is
// estimated from the lag-one product sum (unambiguous to +/- samprate/2), and the estimate is
// smoothed with a one-pole corner. Blocks that look like white noise leave the estimate alone
struct lagone {
  double re,im,power;
};
struct freqtrack {
  double samprate;
  double sample_factor;   // per-sample smoothing factor for the chosen corner
  float estimate;         // Hz, the loop state: signal's offset from the centre of the stream
  float applied;          // Hz, the correction used for the current block
  float max_offset;       // Hz
  float coherence;        // |sum| / power of the last unfiltered block, 0..1
  bool seed_pending;
  bool unfiltered_pending;
  struct lagone unfiltered;
  uint64_t phase;         // rotation oscillator
};
void init_freqtrack(struct freqtrack *ft,double samprate,double corner);
void set_freqtrack_corner(struct freqtrack *ft,double corner);
void seed_freqtrack(struct freqtrack *ft,float offset);
void correct_freqtrack(struct freqtrack *ft,float complex *buffer,int count); // rotate by -applied, in place
void measure_freqtrack(struct freqtrack *ft,float complex const *buffer,int count); // corrected, before the receive filter
// Residual offset (Hz) of a corrected and receive-filtered block from its lag-one products.
// Returns false if the block has no usable signal
bool freqtrack_residual(struct freqtrack const *ft,float complex const *buffer,int count,float *residual);
// Close the loop for this block of 'count' samples with a residual from freqtrack_residual()
// or from the decoder's own decisions; valid false = no estimate, hold
void update_freqtrack(struct freqtrack *ft,bool valid,float residual,int count);

// Symbol timing: polyphase interpolator to two samples per symbol, Gardner detector, PI loop
// Wide loop until told the signal is locked (e.g. by frame sync), narrow after
enum { SYMSYNC_TAPS = 8, SYMSYNC_HISTORY = 1024, SYMSYNC_OUTPUTS = 512 }; // history sizes are powers of two

typedef void (*symsync_output)(void *arg,float complex sample,bool is_symbol);

struct symsync {
  int nphases;
  float *taps;                 // nphases x SYMSYNC_TAPS, oldest sample first
  float complex window[2 * SYMSYNC_TAPS];
  int wpos;
  float base_ratio;            // outputs per input sample (2 x symbol rate / sample rate)
  float ratio;
  float accumulator;
  // Gardner detector
  bool expect_midpoint;
  float complex prev,mid;
  float error_ema;             // telemetry: smoothed |e| / energy
  // loop filter
  float kp,ki;
  float integral;
  float out_min,out_max,int_min,int_max;
  float acquire_bw,track_bw,damping,error_gain;
  bool locked;
  bool ignore_next_error;
  // history, for re-sampling past outputs at other timing
  uint64_t samples_in,outputs_out;
  float complex history[2 * SYMSYNC_HISTORY];
  struct {
    uint64_t newest;
    uint16_t arm;
  } outputs[SYMSYNC_OUTPUTS];
};
int init_symsync(struct symsync *s,double samprate,double symrate,int nphases,
		 float acquire_bw,float track_bw,float damping,float error_gain,float rate_limit);
void free_symsync(struct symsync *s);
void run_symsync(struct symsync *s,float complex const *buffer,int count,symsync_output out,void *arg);
void lock_symsync(struct symsync *s,bool locked); // narrow or widen the loop
void reset_symsync_rate(struct symsync *s);       // forget the symbol rate error estimate
// Output 'output' (0-based count) re-interpolated 'arms' interpolator steps later (negative: earlier)
bool symsync_near(struct symsync const *s,uint64_t output,int arms,float complex *result);
void nudge_symsync(struct symsync *s,float symbols); // move the sampling instant, |symbols| < 0.5
void slip_symsync(struct symsync *s);                // take the midpoints as the symbols from now on
static inline float symsync_arms_per_symbol(struct symsync const *s){
  return 2.0f * (float)s->nphases / s->base_ratio;
}

// One 4-level symbol after one-symbol differential detection
// dibit 0 = 00 at +45 deg, 1 = 01 at +135, 2 = 10 at -45, 3 = 11 at -135
// (C4FM levels +1, +3, -1, -3; the same for pi/4 DQPSK)
struct softdibit {
  uint8_t dibit;
  float confidence; // 0 on a decision boundary, 1 at an ideal point
  float phase;      // radians
};
struct softdibit make_softdibit(float complex z);

#endif
