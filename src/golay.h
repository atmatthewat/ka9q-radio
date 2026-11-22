// Golay codes: Golay(24,12,8), the perfect Golay(23,12) and Golay(18,6,8) (shortened),
// decoded by a syndrome table
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _GOLAY_H
#define _GOLAY_H 1

#include <stdint.h>

// Bits are one per uint8_t (0 or 1), in transmitted order, msb of each field first.
// A decoder corrects in place and returns the number of bits it changed,
// 0 for a clean word, or -1 if the word is uncorrectable, in which case it is left as received.

// Golay(24,12,8): bits 0-11 data, 12-22 Golay(23,12) parity, 23 overall even parity.
// Corrects up to 3 errors, detects 4. Returns bits changed (0-3) or -1
int golay24_decode(uint8_t bits[24]);
// Golay(23,12): bits 0-11 data, 12-22 parity. Perfect: every word is within three bits of one codeword,
// so this always corrects. Returns the bits changed (0-3); *data_fixed (may be NULL) those among bits 0-11
int golay23_decode(uint8_t bits[23],int *data_fixed);
// Golay(18,6,8): Golay(24,12,8) shortened by six leading zero data bits (HDU). bits 0-5 data
int golay18_decode(uint8_t bits[18]);

#endif
