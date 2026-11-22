// Receive filter, level control, frequency tracking and symbol timing
// for the digital mode decoders (see digital.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "digital.h"
#include "nco.h"

// ---------------- receive filter ----------------

int init_rxfilter(struct rxfilter *f,double samprate,double cutoff,int ntaps,double rolloff){
  assert(f != NULL);
  if(f == NULL || ntaps < 1 || cutoff <= 0 || cutoff >= samprate / 2)
    return -1;
  memset(f,0,sizeof *f);
  f->taps = calloc((size_t)ntaps,sizeof *f->taps);
  f->history = calloc(2 * (size_t)ntaps,sizeof *f->history);
  if(f->taps == NULL || f->history == NULL){
    free_rxfilter(f);
    return -1;
  }
  f->ntaps = ntaps;
  double const fc = cutoff / samprate; // cycles/sample
  double const mid = (ntaps - 1) / 2.0;
  double sum = 0;
  for(int i=0; i < ntaps; i++){
    double const t = i - mid;
    double const x = 2 * fc * t; // in units of the sinc's zero spacing
    double const sinc = fabs(t) < 1e-12 ? 1.0 : sin(M_PI * x) / (M_PI * x);
    double rc = 1;
    if(rolloff > 0){
      double const d = 1 - 4 * rolloff * rolloff * x * x;
      rc = fabs(d) < 1e-9 ? M_PI / 4 : cos(M_PI * rolloff * x) / d;
    }
    double const window = ntaps > 1 ? 0.54 - 0.46 * cos(2 * M_PI * i / (ntaps - 1)) : 1.0;
    f->taps[i] = (float)(sinc * rc * window);
    sum += f->taps[i];
  }
  for(int i=0; i < ntaps; i++)
    f->taps[i] = (float)(f->taps[i] / sum);
  return 0;
}
void free_rxfilter(struct rxfilter *f){
  if(f == NULL)
    return;
  free(f->taps);
  free(f->history);
  memset(f,0,sizeof *f);
}
void run_rxfilter(struct rxfilter *f,float complex *buffer,int count){
  assert(f != NULL && f->taps != NULL);
  int const n = f->ntaps;
  float const * restrict const taps = f->taps;
  for(int k=0; k < count; k++){
    f->history[f->pos] = f->history[f->pos + n] = buffer[k];
    if(++f->pos == n)
      f->pos = 0;
    // Oldest first from history[pos]; the taps are symmetric so the order is moot
    float complex const * restrict const w = f->history + f->pos;
    float complex acc = 0;
    for(int i=0; i < n; i++)
      acc += taps[i] * w[i];
    buffer[k] = acc;
  }
}

// ---------------- level control ----------------

void init_level(struct level *l,double samprate,double time_constant){
  assert(l != NULL);
  double a = 1.0 / (time_constant * samprate);
  if(a > 1)
    a = 1;
  l->alpha = (float)a;
  l->power = 1;
}
void prime_level(struct level *l,float complex const *buffer,int count){
  double power = 0;
  for(int i=0; i < count; i++)
    power += cnrmf(buffer[i]);
  if(count > 0 && power > 0)
    l->power = (float)(power / count);
}
void run_level(struct level *l,float complex *buffer,int count){
  float power = l->power;
  float const alpha = l->alpha;
  for(int i=0; i < count; i++){
    power += alpha * (cnrmf(buffer[i]) - power);
    buffer[i] *= 1.0f / sqrtf(power > 1e-10f ? power : 1e-10f);
  }
  l->power = power;
}

// ---------------- frequency tracking ----------------

// A block whose lag-one coherence is at or below the floor is white-noise-like and carries
// no frequency; full weight from floor + span up
static double const Coherence_floor = 0.15;
static double const Coherence_span = 0.25;
// Above this filtered residual the unfiltered one may stand in for it (a cold start far off
// centre, where the receive filter cuts into the signal and under-reads it)
static double const Wide_residual = 500.0; // Hz

// Lag-one products within a block (not the pair across the block boundary: it straddles
// two corrections)
static struct lagone lag_one(float complex const *y,int count){
  struct lagone s = {0};
  for(int i=1; i < count; i++){
    float complex const p = y[i] * conjf(y[i-1]);
    s.re += crealf(p);
    s.im += cimagf(p);
    s.power += cnrmf(y[i-1]);
  }
  return s;
}
static inline bool lagone_valid(struct lagone const *s){
  return (s->re != 0 || s->im != 0) && s->power > 0;
}
static inline double lagone_hz(struct lagone const *s,double samprate){
  return atan2(s->im,s->re) * samprate / (2 * M_PI);
}
void set_freqtrack_corner(struct freqtrack *ft,double corner){
  // Per-sample one-pole factor for this corner; a block of n samples applies it n times
  double const w = 2 * M_PI * corner / ft->samprate;
  double const c = cos(w);
  ft->sample_factor = c - 1 + sqrt(c * c - 4 * c + 3);
}
void init_freqtrack(struct freqtrack *ft,double samprate,double corner){
  assert(ft != NULL);
  memset(ft,0,sizeof *ft);
  ft->samprate = samprate;
  ft->max_offset = 6000;
  set_freqtrack_corner(ft,corner);
}
// A known offset becomes the estimate. Like every correction it applies from the next block;
// the current block's residual, measured against the old correction, is not blended in
void seed_freqtrack(struct freqtrack *ft,float offset){
  ft->estimate = fminf(fmaxf(offset,-ft->max_offset),ft->max_offset);
  ft->seed_pending = true;
}
void correct_freqtrack(struct freqtrack *ft,float complex *buffer,int count){
  double f = -(double)ft->applied / ft->samprate;
  if(f < -0.5 || f >= 0.5)
    f = 0;
  uint64_t const increment = set_nco(f);
  uint64_t phase = ft->phase;
  for(int i=0; i < count; i++){
    buffer[i] *= nco(phase);
    phase += increment;
  }
  ft->phase = phase;
}
void measure_freqtrack(struct freqtrack *ft,float complex const *buffer,int count){
  ft->unfiltered = lag_one(buffer,count);
  ft->unfiltered_pending = true;
}
bool freqtrack_residual(struct freqtrack const *ft,float complex const *buffer,int count,float *residual){
  if(count <= 1)
    return false;
  struct lagone const filtered = lag_one(buffer,count);
  struct lagone const unfiltered = ft->unfiltered_pending ? ft->unfiltered : filtered;
  if(!lagone_valid(&filtered) || !lagone_valid(&unfiltered))
    return false;
  double r = lagone_hz(&filtered,ft->samprate);
  if(fabs(r) > Wide_residual){
    double const wide = lagone_hz(&unfiltered,ft->samprate);
    if(wide * r > 0 && fabs(wide) > fabs(r))
      r = wide;
  }
  *residual = (float)r;
  return true;
}
void update_freqtrack(struct freqtrack *ft,bool valid,float residual,int count){
  if(count <= 0)
    return;
  bool const measured = ft->unfiltered_pending;
  struct lagone const unfiltered = ft->unfiltered;
  ft->unfiltered_pending = false;
  if(ft->seed_pending){
    ft->seed_pending = false; // this block was corrected with the pre-seed value
  } else if(valid){
    double const total = (double)ft->applied + residual;
    double weight = 1;
    if(measured && unfiltered.power > 0){
      ft->coherence = (float)(sqrt(unfiltered.re * unfiltered.re + unfiltered.im * unfiltered.im) / unfiltered.power);
      weight = (ft->coherence - Coherence_floor) / Coherence_span;
      weight = weight < 0 ? 0 : weight > 1 ? 1 : weight;
    }
    double const a = weight * (1 - pow(1 - ft->sample_factor,(double)count));
    double next = ft->estimate + a * (total - ft->estimate);
    if(next > ft->max_offset)
      next = ft->max_offset;
    else if(next < -ft->max_offset)
      next = -ft->max_offset;
    ft->estimate = (float)next;
  }
  ft->applied = ft->estimate;
}

// ---------------- symbol timing ----------------

// Solve the n x n system a x = b in place (Gaussian elimination, partial pivoting); n is small
static int solve(int n,double a[n][n],double b[n]){
  for(int col=0; col < n; col++){
    int pivot = col;
    for(int r=col+1; r < n; r++)
      if(fabs(a[r][col]) > fabs(a[pivot][col]))
	pivot = r;
    if(fabs(a[pivot][col]) < 1e-300)
      return -1;
    if(pivot != col){
      for(int c=0; c < n; c++){
	double const t = a[col][c];
	a[col][c] = a[pivot][c];
	a[pivot][c] = t;
      }
      double const t = b[col];
      b[col] = b[pivot];
      b[pivot] = t;
    }
    for(int r=col+1; r < n; r++){
      double const m = a[r][col] / a[col][col];
      for(int c=col; c < n; c++)
	a[r][c] -= m * a[col][c];
      b[r] -= m * b[col];
    }
  }
  for(int r=n-1; r >= 0; r--){
    for(int c=r+1; c < n; c++)
      b[r] -= a[r][c] * b[c];
    b[r] /= a[r][r];
  }
  return 0;
}
static double dsinc(double x){
  return fabs(x) < 1e-12 ? 1.0 : sin(M_PI * x) / (M_PI * x);
}
// Interpolator arm k: the least-squares (MMSE) 8-tap filter whose output is the signal k/nphases
// of a sample before window[4], for a signal band-limited to a quarter of the sample rate.
// Minimizing the integral over |f| < B of |sum h[i] e^(-j 2 pi f i) - e^(-j 2 pi f p)|^2 gives
// R h = r with R[i][j] = sinc(2B(i-j)) and r[i] = sinc(2B(i-p))
static int design_interpolator(float *taps,int nphases){
  double const b2 = 2 * 0.25;
  for(int k=0; k < nphases; k++){
    double const p = SYMSYNC_TAPS / 2 - (double)k / nphases;
    double a[SYMSYNC_TAPS][SYMSYNC_TAPS];
    double h[SYMSYNC_TAPS];
    for(int i=0; i < SYMSYNC_TAPS; i++){
      for(int j=0; j < SYMSYNC_TAPS; j++)
	a[i][j] = dsinc(b2 * (i - j));
      h[i] = dsinc(b2 * (i - p));
    }
    if(solve(SYMSYNC_TAPS,a,h) != 0)
      return -1;
    for(int i=0; i < SYMSYNC_TAPS; i++)
      taps[k * SYMSYNC_TAPS + i] = (float)h[i];
  }
  return 0;
}
// Loop gains for a natural frequency 'bw' (radians per update) and damping, the usual
// second-order digital loop. The loop's output is the resampling ratio r, held for the next
// 2/r input samples, so a ratio step moves the next symbol by 2 dr / r^2 samples; scaling by
// r^2 / 2 makes 'bw' the bandwidth of the timing itself
static void set_gains(struct symsync *s,float bw){
  float const zeta = s->damping;
  float const k0 = 2.0f / s->error_gain;
  float cos_wd = 1;
  if(zeta > 1)
    cos_wd = coshf(bw * sqrtf(zeta * zeta - 1));
  else if(zeta < 1)
    cos_wd = cosf(bw * sqrtf(1 - zeta * zeta));
  float const scale = s->base_ratio * s->base_ratio / 2;
  s->kp = scale * k0 * expf(-zeta * bw) * sinhf(zeta * bw);
  s->ki = scale * k0 * (1 - expf(-zeta * bw) * (sinhf(zeta * bw) + cos_wd));
}
int init_symsync(struct symsync *s,double samprate,double symrate,int nphases,
		 float acquire_bw,float track_bw,float damping,float error_gain,float rate_limit){
  assert(s != NULL);
  if(s == NULL || nphases < 1 || samprate <= 0 || symrate <= 0 || 2 * symrate > samprate)
    return -1;
  memset(s,0,sizeof *s);
  s->taps = calloc((size_t)nphases * SYMSYNC_TAPS,sizeof *s->taps);
  if(s->taps == NULL || design_interpolator(s->taps,nphases) != 0){
    free_symsync(s);
    return -1;
  }
  s->nphases = nphases;
  s->base_ratio = (float)(2 * symrate / samprate);
  s->ratio = s->base_ratio;
  s->integral = s->base_ratio;
  s->out_min = 0.9f * s->base_ratio;
  s->out_max = 1.1f * s->base_ratio;
  // The integral is the loop's estimate of the symbol rate error; without signal it random
  // walks, and a narrow loop cannot pull in a rate error of a few percent once a signal returns
  s->int_min = (1 - rate_limit) * s->base_ratio;
  s->int_max = (1 + rate_limit) * s->base_ratio;
  s->acquire_bw = acquire_bw;
  s->track_bw = track_bw;
  s->damping = damping;
  s->error_gain = error_gain;
  set_gains(s,acquire_bw);
  return 0;
}
void free_symsync(struct symsync *s){
  if(s == NULL)
    return;
  free(s->taps);
  s->taps = NULL;
}
void lock_symsync(struct symsync *s,bool locked){
  if(locked == s->locked)
    return;
  s->locked = locked;
  set_gains(s,locked ? s->track_bw : s->acquire_bw);
}
void set_symsync_bandwidth(struct symsync *s,float bw){
  set_gains(s,bw);
}
void reset_symsync_rate(struct symsync *s){
  s->ratio = s->base_ratio;
  s->integral = s->base_ratio;
}
void run_symsync(struct symsync *s,float complex const *buffer,int count,symsync_output out,void *arg){
  assert(s != NULL && s->taps != NULL);
  for(int k=0; k < count; k++){
    float complex const x = buffer[k];
    size_t const at = (size_t)s->samples_in & (SYMSYNC_HISTORY - 1);
    s->history[at] = s->history[at + SYMSYNC_HISTORY] = x;
    s->samples_in++;
    s->window[s->wpos] = s->window[s->wpos + SYMSYNC_TAPS] = x;
    if(++s->wpos == SYMSYNC_TAPS)
      s->wpos = 0;
    // The accumulator crossed an integer (acc - 1) / ratio input samples before the sample
    // just taken; arm k delays by k / nphases samples, so that fraction picks the arm.
    // The loop may change the ratio below, so use the one this step added
    float const ratio = s->ratio;
    s->accumulator += ratio;
    while(s->accumulator >= 1){
      float const delay = (s->accumulator - 1) / ratio;
      int arm = (int)(delay * (float)s->nphases);
      if(arm > s->nphases - 1)
	arm = s->nphases - 1;
      if(arm < 0)
	arm = 0;
      float const * restrict const h = s->taps + arm * SYMSYNC_TAPS;
      float complex const * restrict const w = s->window + s->wpos;
      float complex y = 0;
      for(int i=0; i < SYMSYNC_TAPS; i++)
	y += h[i] * w[i];

      bool is_symbol;
      if(s->expect_midpoint){
	s->mid = y;
	s->expect_midpoint = false;
	is_symbol = false;
      } else {
	// Gardner: the midpoint times the difference of the symbols either side of it
	float e = crealf(s->mid) * (crealf(y) - crealf(s->prev)) + cimagf(s->mid) * (cimagf(y) - cimagf(s->prev));
	float const energy = cnrmf(s->mid) + cnrmf(y);
	if(energy > 1e-20f)
	  s->error_ema += 0.01f * (fabsf(e) / energy - s->error_ema);
	s->prev = y;
	s->expect_midpoint = true;
	is_symbol = true;
	// An error straddling a nudge, from samples on both sides of it, is not used
	if(s->ignore_next_error)
	  e = 0;
	s->ignore_next_error = false;
	e = e > 0.15f ? 0.15f : e < -0.15f ? -0.15f : e;
	s->integral += s->ki * e;
	s->integral = s->integral > s->int_max ? s->int_max : s->integral < s->int_min ? s->int_min : s->integral;
	float r = s->kp * e + s->integral;
	r = r > s->out_max ? s->out_max : r < s->out_min ? s->out_min : r;
	s->ratio = r;
      }
      size_t const o = (size_t)s->outputs_out & (SYMSYNC_OUTPUTS - 1);
      s->outputs[o].newest = s->samples_in - 1;
      s->outputs[o].arm = (uint16_t)arm;
      s->outputs_out++;
      out(arg,y,is_symbol);
      s->accumulator -= 1;
    }
  }
}
bool symsync_near(struct symsync const *s,uint64_t output,int arms,float complex *result){
  if(output >= s->outputs_out || s->outputs_out - output > SYMSYNC_OUTPUTS)
    return false;
  size_t const o = (size_t)output & (SYMSYNC_OUTPUTS - 1);
  // Arm a delays by a / nphases samples before the newest sample of the window: later = less delay
  int64_t newest = (int64_t)s->outputs[o].newest;
  int arm = (int)s->outputs[o].arm - arms;
  while(arm < 0){
    arm += s->nphases;
    newest++;
  }
  while(arm >= s->nphases){
    arm -= s->nphases;
    newest--;
  }
  int64_t const oldest = newest - SYMSYNC_TAPS + 1;
  if(newest >= (int64_t)s->samples_in || oldest < 0 || (int64_t)s->samples_in - oldest > SYMSYNC_HISTORY)
    return false;
  float const * restrict const h = s->taps + arm * SYMSYNC_TAPS;
  float complex const * restrict const w = s->history + ((size_t)oldest & (SYMSYNC_HISTORY - 1));
  float complex y = 0;
  for(int i=0; i < SYMSYNC_TAPS; i++)
    y += h[i] * w[i];
  *result = y;
  return true;
}
// Move the sampling instant through the resampler's phase only: the loop's ratio and integral
// are untouched. The resampler can only move an output within the current input sample
void nudge_symsync(struct symsync *s,float symbols){
  symbols = symbols > 0.49f ? 0.49f : symbols < -0.49f ? -0.49f : symbols;
  s->accumulator += -symbols * 2;
  s->ignore_next_error = true;
}
// The sampling instant moves half a symbol with no symbol added or lost: the next error is
// computed from samples one symbol apart with their own midpoint, as if the loop had always
// run on the other half
void slip_symsync(struct symsync *s){
  if(s->expect_midpoint){
    float complex const t = s->prev;
    s->prev = s->mid;
    s->mid = t;
    s->expect_midpoint = false;
  } else {
    s->prev = s->mid;
    s->expect_midpoint = true;
  }
}

// ---------------- soft symbols ----------------

struct softdibit make_softdibit(float complex z){
  struct softdibit sd;
  float const re = crealf(z);
  float const im = cimagf(z);
  if(re >= 0)
    sd.dibit = im >= 0 ? 0 : 2;
  else
    sd.dibit = im >= 0 ? 1 : 3;
  sd.phase = atan2f(im,re);
  // Distance from the nearest decision boundary (the axes), normalized so an ideal point is 1
  float const mag = sqrtf(re * re + im * im);
  float c = 0;
  if(mag > 1e-10f){
    float const di = fabsf(re) / mag;
    float const dq = fabsf(im) / mag;
    c = (di < dq ? di : dq) * M_SQRT2f;
  }
  sd.confidence = c > 1 ? 1 : c;
  return sd;
}
