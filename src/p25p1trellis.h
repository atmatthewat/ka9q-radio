// P25 Phase 1 trellis codes (rate 1/2 and 3/4) with hard and soft Viterbi decoders, and
// the data deinterleave of the trellis coded blocks (TSBK, PDU header, data block)
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _P25P1TRELLIS_H
#define _P25P1TRELLIS_H 1

#include <stdint.h>

// Bits are one per uint8_t (0 or 1), in transmitted order, msb of each field first.

// P25 Phase 1 data deinterleave (196 bits = 98 dibits of a TSBK, PDU header or data block)
// out[p25_data_deinterleave[i]] = in[i]
extern uint8_t const p25_data_deinterleave[196];
void p25_deinterleave_bits(uint8_t out[196],uint8_t const in[196]);
void p25_deinterleave_bit_floats(float out[196],float const in[196]); // per-bit confidences
void p25_deinterleave_dibit_floats(float out[98],float const in[98]); // per-dibit phases or confidences

// P25 trellis codes (rate 1/2: 2 bits per 4-bit symbol; rate 3/4: 3 bits), Viterbi decoded.
// nsyms 4-bit symbols (49 for P25), the last flushing the encoder to state 0;
// produces (nsyms - 1) * 2 or * 3 bits in out[].
// Hard: in[] is 4 * nsyms deinterleaved bits; returns the path's Hamming distance from them.
// Ties go to the lowest-numbered predecessor state.
enum { TRELLIS_MAX_SYMS = 128 };
int trellis_12_decode(uint8_t *out,uint8_t const *in,int nsyms);
int trellis_34_decode(uint8_t *out,uint8_t const *in,int nsyms);
// Soft: phase[] is 2 * nsyms deinterleaved dibit phases (radians, the differential phase of
// each pi/4 DQPSK dibit: 00 +45, 01 +135, 10 -45, 11 -135 degrees).
// The branch metric is the squared phase distance to the two ideal dibit phases, unweighted.
// Returns the path metric (FLT_MAX, out[] zeroed, if no path has a finite metric)
float trellis_12_decode_soft(uint8_t *out,float const *phase,int nsyms);
float trellis_34_decode_soft(uint8_t *out,float const *phase,int nsyms);

#endif
