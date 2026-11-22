// Golay codes: Golay(24,12,8), the perfect Golay(23,12) and Golay(18,6,8) (shortened),
// decoded by a syndrome table
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "golay.h"

static uint32_t Golay_pattern[2048];     // Golay(23,12) syndrome -> error pattern

static pthread_once_t Once = PTHREAD_ONCE_INIT;
static void golay_init(void);
static inline void init(void){
  pthread_once(&Once,golay_init);
}

// Golay(24,12,8) and Golay(18,6,8)
// Golay(23,12) is perfect: each of its 2048 syndromes is exactly one error pattern of at
// most three bits, so a syndrome table corrects any 1-3 errors in bits 0-22; the overall
// parity bit then catches a fourth error (or locates a lone error in bit 23)

// Syndrome contribution of each of bits 0-22 (data 0-11, parity 12-22)
static int const Golay_checksums[23] = {
  0x63A, 0x31D, 0x7B4, 0x3DA, 0x1ED, 0x6CC, 0x366, 0x1B3,
  0x6E3, 0x54B, 0x49F, 0x475, 0x400, 0x200, 0x100, 0x080,
  0x040, 0x020, 0x010, 0x008, 0x004, 0x002, 0x001
};

// w23: bit 22 = codeword bit 0
static uint32_t golay_syndrome(uint32_t w23){
  uint32_t s = 0;
  for(int i = 0; i < 23; i++){
    if((w23 >> (22 - i)) & 1)
      s ^= Golay_checksums[i];
  }
  return s;
}
static void golay_init(void){
  for(int a = 0; a < 23; a++){
    uint32_t const ea = 1u << (22 - a);
    Golay_pattern[Golay_checksums[a]] = ea;
    for(int b = a + 1; b < 23; b++){
      uint32_t const eb = 1u << (22 - b);
      Golay_pattern[Golay_checksums[a] ^ Golay_checksums[b]] = ea | eb;
      for(int c = b + 1; c < 23; c++)
        Golay_pattern[Golay_checksums[a] ^ Golay_checksums[b] ^ Golay_checksums[c]] = ea | eb | (1u << (22 - c));
    }
  }
}
// word: bit 23 = codeword bit 0. Returns -1 for four errors, else the corrected word
static int64_t golay_correct(uint32_t word){
  uint32_t const w23 = word >> 1;
  uint32_t const pattern = Golay_pattern[golay_syndrome(w23)];
  uint32_t c = ((w23 ^ pattern) << 1) | (word & 1);
  if(__builtin_popcount(c) & 1){
    if(__builtin_popcount(pattern) == 3)
      return -1; // four errors
    c ^= 1; // the overall parity bit was one of the errors
  }
  return c;
}

int golay24_decode(uint8_t bits[24]){
  assert(bits != NULL);
  init();
  uint32_t word = 0;
  for(int i = 0; i < 24; i++){
    if(bits[i])
      word |= 1u << (23 - i);
  }
  int64_t const c = golay_correct(word);
  if(c < 0)
    return -1;
  for(int i = 0; i < 24; i++)
    bits[i] = (c >> (23 - i)) & 1;
  return __builtin_popcount((uint32_t)c ^ word);
}

int golay23_decode(uint8_t bits[23],int *data_fixed){
  assert(bits != NULL);
  init();
  uint32_t w = 0;
  for(int i = 0; i < 23; i++){
    if(bits[i])
      w |= 1u << (22 - i);
  }
  uint32_t const pattern = Golay_pattern[golay_syndrome(w)];
  for(int i = 0; i < 23; i++)
    bits[i] ^= (pattern >> (22 - i)) & 1;
  if(data_fixed != NULL)
    *data_fixed = __builtin_popcount(pattern >> 11);
  return __builtin_popcount(pattern);
}

int golay18_decode(uint8_t bits[18]){
  assert(bits != NULL);
  init();
  uint32_t word = 0; // 24-bit form, the six shortened positions (bits 23-18) zero
  for(int i = 0; i < 18; i++){
    if(bits[i])
      word |= 1u << (17 - i);
  }
  int64_t const c = golay_correct(word);
  if(c < 0 || (c >> 18) != 0)
    return -1; // a correction in the shortened positions is not a codeword of this code
  for(int i = 0; i < 18; i++)
    bits[i] = (c >> (17 - i)) & 1;
  return __builtin_popcount((uint32_t)c ^ word);
}
