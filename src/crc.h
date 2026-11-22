// Cyclic redundancy checks over bit arrays: CRC-CCITT (with an 80-bit check that can
// correct one bit) and CRC-12
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _CRC_H
#define _CRC_H 1

#include <stdbool.h>
#include <stdint.h>

// Bits are one per uint8_t (0 or 1), in transmitted order, msb of each field first.

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

#endif
