// P25 receiver for a complex baseband (IQ) stream
// Phase 1 (FDMA): C4FM and the linear simulcast modulations (CQPSK/LSM) through one chain
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _P25_H
#define _P25_H 1

#include <complex.h>
#include <stdbool.h>
#include <stdint.h>

#include "digital.h"

enum {
  P25_SYMRATE = 4800,
  P25_SYNC_DIBITS = 24,
  P25_NID_DIBITS = 32,
};

struct p25p1;

// Every soft dibit, before framing (tests and diagnostics)
typedef void (*p25_dibit_tap)(void *arg,struct softdibit const *sd);

struct p25p1 *create_p25p1(double samprate);
void delete_p25p1(struct p25p1 *p);
void p25p1_set_dibit_tap(struct p25p1 *p,p25_dibit_tap tap,void *arg);
// Feed 'count' samples at the rate given to create_p25p1(); any block size
void p25p1_samples(struct p25p1 *p,float complex const *iq,int count);
// Force the timing and frequency loops to their tracking (true) or acquisition (false) settings
void p25p1_set_locked(struct p25p1 *p,bool locked);
float p25p1_frequency_offset(struct p25p1 const *p); // Hz, estimated carrier offset
// Frequency from the decided symbols while locked (default) or always from the mean frequency
void p25p1_set_decision_directed(struct p25p1 *p,bool enable);
#endif
