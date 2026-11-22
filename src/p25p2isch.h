// P25 Phase 2 ISCH (I-ISCH): the (40,9) code, decoded by nearest codeword
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _P25P2ISCH_H
#define _P25P2ISCH_H 1

#include <stdint.h>

// Phase 2 ISCH (I-ISCH): (40,9) code, minimum distance 8, nearest codeword up to 7 errors
// Only codewords whose channel field is this timeslot (0 or 1) and whose ISCH location is
// not the reserved value 3 are candidates; a tie goes to the lowest info value.
// *info gets the 9 info bits, msb first: LCH type (2), channel (2), ISCH location (2),
// LCH flag (1), superframe sequence (2). Returns bits corrected (0-7) or -1
int isch_decode(uint8_t const bits[40],int timeslot,int *info);
int isch_decode_word(uint64_t word,int timeslot,int *info); // word bit 39 = first bit sent

#endif
