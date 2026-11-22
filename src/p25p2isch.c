// P25 Phase 2 ISCH (I-ISCH): the (40,9) code, decoded by nearest codeword
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "p25p2isch.h"

static uint64_t Isch_codeword[512];      // ISCH info -> codeword

static pthread_once_t Once = PTHREAD_ONCE_INIT;
static void isch_init(void);
static inline void init(void){
  pthread_once(&Once,isch_init);
}

// Phase 2 ISCH (40,9) code

static uint64_t const Isch_generator[9] = {
  0x8816CE36D7ULL, 0x201DFD4F64ULL, 0x100F4B1758ULL,
  0x0C00DED18EULL, 0x020807F7FFULL, 0x09048D9B72ULL,
  0x009DA3A171ULL, 0x0058CBAA4EULL, 0x00343D8597ULL
};
static uint64_t const Isch_offset = 0x184229D461ULL;

static void isch_init(void){
  for(int x = 0; x < 512; x++){
    uint64_t c = 0;
    for(int i = 0; i < 9; i++){
      if(x & (1 << (8 - i)))
        c ^= Isch_generator[i];
    }
    Isch_codeword[x] = c ^ Isch_offset;
  }
}

int isch_decode_word(uint64_t word,int timeslot,int *info){
  assert(timeslot == 0 || timeslot == 1);
  init();
  word &= 0xFFFFFFFFFFULL;
  int best = 8; // corrects up to 7
  int best_info = -1;
  for(int x = 0; x < 512; x++){
    if(((x >> 5) & 3) != timeslot || ((x >> 3) & 3) == 3)
      continue; // other channel, or the reserved ISCH location
    int const e = __builtin_popcountll(word ^ Isch_codeword[x]);
    if(e < best){
      best = e;
      best_info = x;
      if(e == 0)
        break;
    }
  }
  if(best_info < 0)
    return -1;
  if(info != NULL)
    *info = best_info;
  return best;
}
int isch_decode(uint8_t const bits[40],int timeslot,int *info){
  assert(bits != NULL);
  uint64_t w = 0;
  for(int i = 0; i < 40; i++)
    w = (w << 1) | (bits[i] & 1);
  return isch_decode_word(w,timeslot,info);
}
