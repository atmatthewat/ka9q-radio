// Forward error correction for the P25 digital voice and data decoders
// Reed-Solomon and BCH over GF(64), Golay, Hamming, trellis (Viterbi), CRC, Phase 2 ISCH
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DFEC_H
#define _DFEC_H 1

#include <stdbool.h>
#include <stdint.h>

// Conventions, unless stated otherwise:
// Bits are one per uint8_t (0 or 1), in transmitted order, msb of each field first.
// A decoder corrects in place and returns the number of bits (or symbols) it changed,
// 0 for a clean word, or -1 if the word is uncorrectable, in which case it is left as received.

// Reed-Solomon over GF(64), primitive polynomial x^6 + x + 1, roots alpha^1 .. alpha^parity.
// sym[i] (0-63) is the coefficient of x^i; all P25 codes are (63,k) codes shortened by
// zeroing the top positions, and the caller passes the whole 63-symbol word with them zero.
// parity: n - k (1-28). length: the shortened length (63 for none); a correction at
// position >= length is a decoding failure. erasures: positions (0-62) known to be
// unreliable, nerasures of them (erasures may be NULL when nerasures is 0); distinct.
// Corrects e errors and f erasures when 2e + f <= parity.
// Returns the number of symbols changed, or -1 (sym untouched). A "correction" that does
// not produce a codeword of the (shortened) code is rejected as uncorrectable.
int rs63_decode(uint8_t sym[63],int parity,int length,int const *erasures,int nerasures);
bool rs63_is_codeword(uint8_t const sym[63],int parity);

// The P25 codes. Phase 1 places parity at positions 0 .. parity-1 and data above it
// (the transmitted hexbits in reverse order); Phase 2 MAC and ESS likewise
static inline int rs_24_12_13_decode(uint8_t sym[63],int const *erasures,int nerasures){ // LDU1, TDULC LC
  return rs63_decode(sym,12,24,erasures,nerasures);
}
static inline int rs_24_16_9_decode(uint8_t sym[63],int const *erasures,int nerasures){ // LDU2 ESS
  return rs63_decode(sym,8,24,erasures,nerasures);
}
static inline int rs_36_20_17_decode(uint8_t sym[63],int const *erasures,int nerasures){ // HDU
  return rs63_decode(sym,16,36,erasures,nerasures);
}
static inline int rs_63_35_29_decode(uint8_t sym[63],int const *erasures,int nerasures){ // Phase 2 FACCH/SACCH
  return rs63_decode(sym,28,63,erasures,nerasures);
}
static inline int rs_44_16_29_decode(uint8_t sym[63],int const *erasures,int nerasures){ // Phase 2 ESS
  return rs63_decode(sym,28,44,erasures,nerasures);
}

// P25 NID: BCH(63,16,23), decoded as the binary subcode of RS(63,41) over GF(64)
// bits[k], k = 0..62, in transmitted order: bits 0-11 NAC, 12-15 DUID, 16-62 parity
// (bit k is the coefficient of x^(62-k)); the NID's 64th (parity) bit is not part of the code.
// erasures: bit indices (0-62, entries outside are ignored) known to be unreliable.
// Accepts only a BCH codeword with 2 * errors + erasures <= 22.
// Returns the number of bits changed (erased bits included), or -1 (bits untouched).
int bch_63_16_decode(uint8_t bits[63],int const *erasures,int nerasures);
// Soft NID decode: errors-only first; if that fails, erase the one ambiguous bit of each dibit
// whose confidence is below threshold (weakest first, at most 22) and decode again.
// Near a quadrant boundary only one bit of a dibit is in doubt: the lsb near +-90 degrees
// (00|01 and 10|11), the msb near 0 / 180 degrees (00|10 and 01|11).
// confidence[j], lsb_ambiguous[j]: NID dibit j (bits 2j, 2j+1), j = 0..31. Same return as above.
int bch_63_16_decode_soft(uint8_t bits[63],float const confidence[32],bool const lsb_ambiguous[32],float threshold);
#define BCH_NID_ERASURE_THRESHOLD 0.3f

// Golay(24,12,8): bits 0-11 data, 12-22 Golay(23,12) parity, 23 overall even parity.
// Corrects up to 3 errors, detects 4. Returns bits changed (0-3) or -1
int golay24_decode(uint8_t bits[24]);
// Golay(23,12): bits 0-11 data, 12-22 parity. Perfect: every word is within three bits of one codeword,
// so this always corrects. Returns the bits changed (0-3); *data_fixed (may be NULL) those among bits 0-11
int golay23_decode(uint8_t bits[23],int *data_fixed);
// Golay(18,6,8): Golay(24,12,8) shortened by six leading zero data bits (HDU). bits 0-5 data
int golay18_decode(uint8_t bits[18]);

// Hamming(10,6,3): bits 0-5 data, 6-9 parity (8s bit first). Returns 0, 1 (one bit fixed) or -1
int hamming10_decode(uint8_t bits[10]);
// Same, but a correction of a bit whose confidence[] (one per bit of the word) exceeds
// threshold is taken as a double error elsewhere: -1. confidence may be NULL (hard decode)
int hamming10_decode_soft(uint8_t bits[10],float const confidence[10],float threshold);
#define HAMMING10_HIGH_CONFIDENCE 0.7f

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

// CRC-CCITT as P25 uses it (TSBK, PDU header): x^16+x^12+x^5+1, zero preset, msb first, inverted
uint16_t crc_ccitt(uint8_t const *bits,int n);
// 80 data bits followed by their 16-bit CRC. Returns 0 if the CRC checks (also when
// correct_one is set and the single bit error was in the CRC itself), 1 if a single data bit
// error was found and fixed (only with correct_one), -1 otherwise
int crc_ccitt80_check(uint8_t bits[96],bool correct_one);
// Phase 2 MAC CRC-12: x^12+x^11+x^3+x^2+x+1, zero preset, msb first, inverted
uint16_t crc12(uint8_t const *bits,int n);
// n data bits (144 FACCH, 168 SACCH) followed by their 12-bit CRC
bool crc12_check(uint8_t const *bits,int n);

// Phase 2 ISCH (I-ISCH): (40,9) code, minimum distance 8, nearest codeword up to 7 errors
// Only codewords whose channel field is this timeslot (0 or 1) and whose ISCH location is
// not the reserved value 3 are candidates; a tie goes to the lowest info value.
// *info gets the 9 info bits, msb first: LCH type (2), channel (2), ISCH location (2),
// LCH flag (1), superframe sequence (2). Returns bits corrected (0-7) or -1
int isch_decode(uint8_t const bits[40],int timeslot,int *info);
int isch_decode_word(uint64_t word,int timeslot,int *info); // word bit 39 = first bit sent

#endif
