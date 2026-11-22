// P25 Phase 1 trellis codes (rate 1/2 and 3/4) with hard and soft Viterbi decoders, and
// the data deinterleave of the trellis coded blocks (TSBK, PDU header, data block)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "p25p1trellis.h"

// P25 Phase 1 data deinterleave

uint8_t const p25_data_deinterleave[196] = {
  0, 1, 2, 3, 16, 17, 18, 19, 32, 33, 34, 35, 48, 49, 50, 51,
  64, 65, 66, 67, 80, 81, 82, 83, 96, 97, 98, 99, 112, 113, 114, 115,
  128, 129, 130, 131, 144, 145, 146, 147, 160, 161, 162, 163, 176, 177, 178, 179,
  192, 193, 194, 195, 4, 5, 6, 7, 20, 21, 22, 23, 36, 37, 38, 39,
  52, 53, 54, 55, 68, 69, 70, 71, 84, 85, 86, 87, 100, 101, 102, 103,
  116, 117, 118, 119, 132, 133, 134, 135, 148, 149, 150, 151, 164, 165, 166, 167,
  180, 181, 182, 183, 8, 9, 10, 11, 24, 25, 26, 27, 40, 41, 42, 43,
  56, 57, 58, 59, 72, 73, 74, 75, 88, 89, 90, 91, 104, 105, 106, 107,
  120, 121, 122, 123, 136, 137, 138, 139, 152, 153, 154, 155, 168, 169, 170, 171,
  184, 185, 186, 187, 12, 13, 14, 15, 28, 29, 30, 31, 44, 45, 46, 47,
  60, 61, 62, 63, 76, 77, 78, 79, 92, 93, 94, 95, 108, 109, 110, 111,
  124, 125, 126, 127, 140, 141, 142, 143, 156, 157, 158, 159, 172, 173, 174, 175,
  188, 189, 190, 191
};

void p25_deinterleave_bits(uint8_t out[196],uint8_t const in[196]){
  assert(out != NULL && in != NULL && out != in);
  for(int i = 0; i < 196; i++)
    out[p25_data_deinterleave[i]] = in[i];
}
void p25_deinterleave_bit_floats(float out[196],float const in[196]){
  assert(out != NULL && in != NULL && out != in);
  for(int i = 0; i < 196; i++)
    out[p25_data_deinterleave[i]] = in[i];
}
// The table moves dibits whole (entries 2i and 2i+1 are an aligned pair)
void p25_deinterleave_dibit_floats(float out[98],float const in[98]){
  assert(out != NULL && in != NULL && out != in);
  for(int i = 0; i < 98; i++)
    out[p25_data_deinterleave[2*i] / 2] = in[i];
}

// ---------------------------------------------------------------------------
// P25 trellis codes: output symbol = table[previous input][current input], the state being
// the previous input. Survivors are kept as a traceback table. A state takes the first
// predecessor (lowest state number) with the strictly smallest metric, and the flush the
// first final state with the strictly smallest metric

static uint8_t const Trellis_12[4][4] = {
  {0x2, 0xC, 0x1, 0xF},
  {0xE, 0x0, 0xD, 0x3},
  {0x9, 0x7, 0xA, 0x4},
  {0x5, 0xB, 0x6, 0x8}
};
static uint8_t const Trellis_34[8][8] = {
  {2, 13, 14, 1, 7, 8, 11, 4},
  {14, 1, 7, 8, 11, 4, 2, 13},
  {10, 5, 6, 9, 15, 0, 3, 12},
  {6, 9, 15, 0, 3, 12, 10, 5},
  {15, 0, 3, 12, 10, 5, 6, 9},
  {3, 12, 10, 5, 6, 9, 15, 0},
  {7, 8, 11, 4, 2, 13, 14, 1},
  {11, 4, 2, 13, 14, 1, 7, 8}
};

static void traceback(uint8_t *out,uint8_t pred[][8],int steps,int k,int state){
  for(int i = steps-1; i >= 0; i--){
    for(int b = 0; b < k; b++)
      out[i*k + b] = (state >> (k - 1 - b)) & 1;
    state = pred[i][state];
  }
}

static int viterbi_hard(uint8_t *out,uint8_t const *in,int nsyms,int k,uint8_t const *table){
  assert(out != NULL && in != NULL);
  assert(nsyms >= 1 && nsyms <= TRELLIS_MAX_SYMS);
  int const nstates = 1 << k;
  int const steps = nsyms - 1;
  uint8_t pred[TRELLIS_MAX_SYMS][8];
  unsigned metric[8];
  bool valid[8] = {false};
  metric[0] = 0;
  valid[0] = true;
  for(int t = 0; t <= steps; t++){
    int sym = 0;
    for(int b = 0; b < 4; b++)
      sym = (sym << 1) | (in[4*t + b] ? 1 : 0);
    if(t == steps){
      // Flush to state 0
      bool found = false;
      unsigned best = 0;
      int best_state = 0;
      for(int p = 0; p < nstates; p++){
        if(!valid[p])
          continue;
        unsigned const m = metric[p] + __builtin_popcount(table[p * nstates] ^ sym);
        if(!found || m < best){
          best = m;
          best_state = p;
          found = true;
        }
      }
      traceback(out,pred,steps,k,best_state);
      return (int)best;
    }
    unsigned next[8] = {0};
    bool next_valid[8] = {false};
    for(int p = 0; p < nstates; p++){
      if(!valid[p])
        continue;
      for(int x = 0; x < nstates; x++){
        unsigned const m = metric[p] + __builtin_popcount(table[p * nstates + x] ^ sym);
        if(!next_valid[x] || m < next[x]){
          next[x] = m;
          pred[t][x] = p;
          next_valid[x] = true;
        }
      }
    }
    for(int s = 0; s < nstates; s++){
      metric[s] = next[s];
      valid[s] = next_valid[s];
    }
  }
  return 0; // not reached
}
int trellis_12_decode(uint8_t *out,uint8_t const *in,int nsyms){
  return viterbi_hard(out,in,nsyms,2,&Trellis_12[0][0]);
}
int trellis_34_decode(uint8_t *out,uint8_t const *in,int nsyms){
  return viterbi_hard(out,in,nsyms,3,&Trellis_34[0][0]);
}

// Circular phase difference
static float phase_diff(float a,float b){
  float d = a - b;
  if(!isfinite(d))
    return (float)M_PI; // garbage in: as far as possible from everything
  if(fabsf(d) > 64.0f)
    d = remainderf(d,(float)(2 * M_PI));
  while(d > M_PI)
    d -= 2.0f * M_PI;
  while(d < -M_PI)
    d += 2.0f * M_PI;
  return d;
}

// Squared phase distance of a received symbol (two dibit phases) to an expected output.
// Not weighted by dibit confidence: confidence is the distance to the nearest decision
// boundary, so weighting by it shrinks exactly the distances that separate competing paths
// (measured TSBK CRC pass rates on DQPSK in AWGN were better unweighted at 4, 6 and 8 dB Es/N0)
static float branch_metric(float phase0,float phase1,int expected){
  static float const ideal[4] = {
    0.7854f,   // 00: +45 degrees
    2.3562f,   // 01: +135
    -0.7854f,  // 10: -45
    -2.3562f,  // 11: -135
  };
  float const d0 = phase_diff(phase0,ideal[(expected >> 2) & 3]);
  float const d1 = phase_diff(phase1,ideal[expected & 3]);
  return d0 * d0 + d1 * d1;
}

static float viterbi_soft(uint8_t *out,float const *phase,int nsyms,int k,uint8_t const *table){
  assert(out != NULL && phase != NULL);
  assert(nsyms >= 1 && nsyms <= TRELLIS_MAX_SYMS);
  int const nstates = 1 << k;
  int const steps = nsyms - 1;
  uint8_t pred[TRELLIS_MAX_SYMS][8];
  float metric[8];
  bool valid[8];
  for(int s = 0; s < nstates; s++){
    metric[s] = FLT_MAX;
    valid[s] = false;
  }
  metric[0] = 0;
  valid[0] = true;

  float bm[16];
  for(int t = 0; t < steps; t++){
    for(int o = 0; o < 16; o++)
      bm[o] = branch_metric(phase[2*t],phase[2*t+1],o);
    float next[8] = {0};
    bool next_valid[8] = {false};
    for(int p = 0; p < nstates; p++){
      if(!valid[p])
        continue;
      for(int x = 0; x < nstates; x++){
        float const m = metric[p] + bm[table[p * nstates + x]];
        if(!next_valid[x] || m < next[x]){
          next[x] = m;
          pred[t][x] = p;
          next_valid[x] = true;
        }
      }
    }
    for(int s = 0; s < nstates; s++){
      metric[s] = next_valid[s] ? next[s] : FLT_MAX;
      valid[s] = next_valid[s];
    }
  }
  // Flush to state 0
  float best = FLT_MAX;
  bool found = false;
  int best_state = 0;
  for(int p = 0; p < nstates; p++){
    if(!valid[p])
      continue;
    float const m = metric[p] + branch_metric(phase[2*steps],phase[2*steps+1],table[p * nstates]);
    if(m < best){
      best = m;
      best_state = p;
      found = true;
    }
  }
  if(!found)
    memset(out,0,steps * k);
  else
    traceback(out,pred,steps,k,best_state);
  return best;
}
float trellis_12_decode_soft(uint8_t *out,float const *phase,int nsyms){
  return viterbi_soft(out,phase,nsyms,2,&Trellis_12[0][0]);
}
float trellis_34_decode_soft(uint8_t *out,float const *phase,int nsyms){
  return viterbi_soft(out,phase,nsyms,3,&Trellis_34[0][0]);
}
