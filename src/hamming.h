// Hamming(10,6,3), hard and soft decision
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _HAMMING_H
#define _HAMMING_H 1

#include <stdint.h>

// Bits are one per uint8_t (0 or 1), in transmitted order, msb of each field first.
// A decoder corrects in place and returns the number of bits it changed,
// 0 for a clean word, or -1 if the word is uncorrectable, in which case it is left as received.

// Hamming(10,6,3): bits 0-5 data, 6-9 parity (8s bit first). Returns 0, 1 (one bit fixed) or -1
int hamming10_decode(uint8_t bits[10]);
// Same, but a correction of a bit whose confidence[] (one per bit of the word) exceeds
// threshold is taken as a double error elsewhere: -1. confidence may be NULL (hard decode)
int hamming10_decode_soft(uint8_t bits[10],float const confidence[10],float threshold);
#define HAMMING10_HIGH_CONFIDENCE 0.7f

#endif
