// Hamming(10,6,3), hard and soft decision
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "hamming.h"

// Hamming(10,6,3), the LDU1 / LDU2 hexbit code
// The four parity bits are sent 8s bit first (bit 6) to 1s bit (bit 9)

static int const Hamming10_checksums[6] = {0xE, 0xD, 0xB, 0x7, 0x3, 0xC};
// Syndrome -> bit of the word to flip, or -1 for a multiple error
static int const Hamming10_position[16] = {
  -1, 9, 8, 4, 7, -1, -1, 3, 6, -1, -1, 2, 5, 1, 0, -1
};

static int hamming10_syndrome(uint8_t const bits[10]){
  int s = 0;
  for(int i = 0; i < 6; i++){
    if(bits[i])
      s ^= Hamming10_checksums[i];
  }
  for(int i = 0; i < 4; i++){
    if(bits[6+i])
      s ^= 8 >> i;
  }
  return s;
}
int hamming10_decode(uint8_t bits[10]){
  return hamming10_decode_soft(bits,NULL,0);
}
int hamming10_decode_soft(uint8_t bits[10],float const confidence[10],float threshold){
  assert(bits != NULL);
  int const s = hamming10_syndrome(bits);
  if(s == 0)
    return 0;
  int const p = Hamming10_position[s];
  if(p < 0)
    return -1;
  // A syndrome pointing at a confident bit more likely means a double error elsewhere
  if(confidence != NULL && confidence[p] > threshold)
    return -1;
  bits[p] ^= 1;
  return 1;
}
