// P25 Phase 1 receiver: IQ samples in, soft dibits out
// One chain for C4FM and the linear simulcast modulations: level, frequency correction,
// receive lowpass, symbol timing, then the phase change over one symbol. For C4FM that
// phase change is the integral of the deviation over the symbol, i.e. the standard
// integrate-and-dump receiver; for pi/4 DQPSK it is the differential detector
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "digital.h"
#include "p25.h"
#include "nco.h"

// Timing loop bandwidths (normalized, per symbol): wide to acquire, narrow once frame sync is held
static float const Acquire_bw = 0.08f;
static float const Track_bw = 0.004f;
static float const Loop_damping = 1.0f;
static float const Error_gain = 0.42f;
// Symbol rate error the timing loop may integrate: transmitter plus receiver clock errors are tens of ppm
static float const Rate_limit = 0.0003f;
static int const Interp_phases = 32;
// Frequency tracking corners
static double const Afc_acquire_corner = 10.0; // Hz
static double const Afc_track_corner = 1.0;
// Receive lowpass between the frequency correction and the timing loop
static double const Rx_cutoff = 3300.0; // Hz
static double const Rx_rolloff = 0.7;
static double const Rx_span = 31.0 / 19200.0; // filter length, seconds
static double const Level_time = 1.0 / 9.6;   // seconds

struct p25p1 {
  double samprate;
  struct level level;
  struct freqtrack afc;
  struct rxfilter rxf;
  struct symsync sync;
  bool primed;
  bool locked;
  float complex prev_symbol; // differential detector memory
  bool decision_directed;    // frequency from the decided symbols while locked
  double dd_error;           // sum of (phase - nominal phase of the decision) over this block's symbols
  int dd_symbols;
  float complex *scratch;
  int scratch_len;
  p25_dibit_tap tap;
  void *tap_arg;
};

struct p25p1 *create_p25p1(double samprate){
  if(samprate < 4 * P25_SYMRATE) // the loops want at least 4 samples per symbol
    return NULL;
  struct p25p1 * const p = calloc(1,sizeof *p);
  if(p == NULL)
    return NULL;
  p->samprate = samprate;
  p->prev_symbol = 1;
  p->decision_directed = true;
  int ntaps = (int)lrint(Rx_span * samprate);
  ntaps |= 1; // odd, so the filter has a centre tap
  init_level(&p->level,samprate,Level_time);
  init_freqtrack(&p->afc,samprate,Afc_acquire_corner);
  if(init_rxfilter(&p->rxf,samprate,Rx_cutoff,ntaps,Rx_rolloff) != 0
     || init_symsync(&p->sync,samprate,P25_SYMRATE,Interp_phases,Acquire_bw,Track_bw,Loop_damping,Error_gain,Rate_limit) != 0){
    delete_p25p1(p);
    return NULL;
  }
  return p;
}
void delete_p25p1(struct p25p1 *p){
  if(p == NULL)
    return;
  free_rxfilter(&p->rxf);
  free_symsync(&p->sync);
  free(p->scratch);
  free(p);
}
void p25p1_set_dibit_tap(struct p25p1 *p,p25_dibit_tap tap,void *arg){
  p->tap = tap;
  p->tap_arg = arg;
}
void p25p1_set_locked(struct p25p1 *p,bool locked){
  if(locked == p->locked)
    return;
  p->locked = locked;
  lock_symsync(&p->sync,locked);
  if(!locked)
    reset_symsync_rate(&p->sync); // drop the rate estimate noise has walked
  set_freqtrack_corner(&p->afc,locked ? Afc_track_corner : Afc_acquire_corner);
}
void p25p1_set_decision_directed(struct p25p1 *p,bool enable){
  p->decision_directed = enable;
}
float p25p1_frequency_offset(struct p25p1 const *p){
  return p->afc.estimate;
}
// Called by the timing loop for every interpolated sample: symbols and the midpoints between them
static void sync_output(void *arg,float complex y,bool is_symbol){
  struct p25p1 * const p = arg;
  if(!is_symbol)
    return;
  float complex const z = y * conjf(p->prev_symbol);
  p->prev_symbol = y;
  struct softdibit const sd = make_softdibit(z);
  // Phase error against the decision: +/-45 degrees at most, so +/-600 Hz
  static float const nominal[4] = { M_PI_4, 3 * M_PI_4, -M_PI_4, -3 * M_PI_4 };
  p->dd_error += sd.phase - nominal[sd.dibit];
  p->dd_symbols++;
  if(p->tap != NULL)
    p->tap(p->tap_arg,&sd);
}
void p25p1_samples(struct p25p1 *p,float complex const *iq,int count){
  assert(p != NULL);
  if(count <= 0)
    return;
  if(count > p->scratch_len){
    float complex * const s = realloc(p->scratch,(size_t)count * sizeof *s);
    if(s == NULL)
      return;
    p->scratch = s;
    p->scratch_len = count;
  }
  float complex * const buf = p->scratch;
  memcpy(buf,iq,(size_t)count * sizeof *buf);
  if(!p->primed){
    // From its default the level estimate would take a tenth of a second to reach a weak stream's level
    prime_level(&p->level,buf,count);
    p->primed = true;
  }
  run_level(&p->level,buf,count);
  // Frequency: correct with the estimate from the previous block, then estimate the residual.
  // Acquiring: from the lag-one products of the receive-filtered block. Unfiltered, noise away
  // from the signal pulls the estimate toward the centre of the stream; the unfiltered block still
  // supplies the coherence test and a large residual.
  // Tracking: from the decided symbols. The lag-one estimate is the mean frequency, and the mean
  // frequency of a 4-level signal moves with the data: a control channel sends more -1 and -3 than
  // +1 and +3 and reads 50 to 60 Hz low. The phase error against each decision has no such bias
  correct_freqtrack(&p->afc,buf,count);
  measure_freqtrack(&p->afc,buf,count);
  run_rxfilter(&p->rxf,buf,count);
  float residual = 0;
  bool valid = freqtrack_residual(&p->afc,buf,count,&residual);
  p->dd_error = 0;
  p->dd_symbols = 0;
  run_symsync(&p->sync,buf,count,sync_output,p);
  if(p->locked && p->decision_directed && p->dd_symbols > 0){
    residual = (float)(p->dd_error / p->dd_symbols * P25_SYMRATE / (2 * M_PI));
    valid = true;
  }
  update_freqtrack(&p->afc,valid,residual,count);
}
