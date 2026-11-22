// Cyclic redundancy checks over bit arrays: CRC-CCITT (with an 80-bit check that can
// correct one bit) and CRC-12
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crc.h"

// CRCs: msb first, zero preset, the remainder of M(x) x^width inverted

static unsigned crc_bits(uint8_t const *bits,int n,unsigned poly,int width){
  unsigned const mask = (1u << width) - 1;
  unsigned reg = 0;
  for(int i = 0; i < n; i++){
    unsigned const fb = ((reg >> (width - 1)) ^ bits[i]) & 1;
    reg = (reg << 1) & mask;
    if(fb)
      reg ^= poly;
  }
  return reg ^ mask;
}
static unsigned get_field(uint8_t const *bits,int n){
  unsigned v = 0;
  for(int i = 0; i < n; i++)
    v = (v << 1) | (bits[i] & 1);
  return v;
}

uint16_t crc_ccitt(uint8_t const *bits,int n){
  assert(bits != NULL && n >= 0);
  return crc_bits(bits,n,0x1021,16);
}

int crc_ccitt80_check(uint8_t bits[96],bool correct_one){
  assert(bits != NULL);
  unsigned const residual = crc_ccitt(bits,80) ^ get_field(bits + 80,16);
  if(residual == 0)
    return 0;
  if(!correct_one)
    return -1;
  // A single error in data bit i leaves the residual x^(16 + 79 - i) mod g(x)
  unsigned s = 0x1021; // bit 79: x^16 mod g(x)
  for(int i = 79; i >= 0; i--){
    if(s == residual){
      bits[i] ^= 1;
      return 1;
    }
    s = (s & 0x8000) ? ((s << 1) ^ 0x1021) & 0xffff : s << 1;
  }
  // A single error in CRC bit i leaves the residual 2^(15-i): the data is good
  if(__builtin_popcount(residual) == 1)
    return 0;
  return -1;
}

uint16_t crc12(uint8_t const *bits,int n){
  assert(bits != NULL && n >= 0);
  return crc_bits(bits,n,0x897,12);
}
bool crc12_check(uint8_t const *bits,int n){
  assert(bits != NULL && n >= 0);
  return crc12(bits,n) == get_field(bits + n,12);
}
