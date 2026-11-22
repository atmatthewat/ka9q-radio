// Error correction and field extraction for one assembled P25 Phase 1 data unit,
// and IMBE voice frame decoding to vocoder input (see p25p1unit.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "dfec.h"
#include "p25p1unit.h"

// ---------------------------------------------------------------------------
// Hexbit words (TIA-102.BAAA)

static int get_hex(uint8_t const *bits){
  int v = 0;
  for(int i = 0; i < 6; i++)
    v = (v << 1) | (bits[i] & 1);
  return v;
}
static void put_hex(uint8_t *bits,int v){
  for(int i = 0; i < 6; i++)
    bits[i] = (v >> (5 - i)) & 1;
}

// Reed-Solomon over a word's nhex hexbits, hex[0] sent first: data hexbits 0 .. ndata-1,
// then the parity. The Phase 1 codes take the last hexbit sent as the coefficient of x^0,
// so the parity sits at positions 0 .. nhex-ndata-1 and the data above it.
// Corrects hex[] in place; returns the hexbits changed or -1 (hex[] untouched)
static int rs_hexbits(int hex[],int nhex,int ndata,bool const erased[]){
  uint8_t sym[63];
  int eras[36];
  int nerased = 0;
  memset(sym,0,sizeof sym);
  for(int i = 0; i < nhex; i++){
    sym[nhex-1-i] = (uint8_t)hex[i];
    if(erased[i])
      eras[nerased++] = nhex-1-i;
  }
  int const r = rs63_decode(sym,nhex-ndata,nhex,nerased > 0 ? eras : NULL,nerased);
  if(r < 0)
    return -1;
  for(int i = 0; i < nhex; i++)
    hex[i] = sym[nhex-1-i];
  return r;
}

static void word_init(struct p25_word *w,int nbits){
  memset(w,0,sizeof *w);
  w->nbits = nbits;
}
// RS-decode and deliver the data hexbits
static bool word_finish(struct p25_word *w,int hex[],int nhex,int ndata,bool const erased[]){
  int const r = rs_hexbits(hex,nhex,ndata,erased);
  if(r < 0)
    return false;
  w->rs_fixed = r;
  for(int i = 0; i < ndata; i++)
    put_hex(w->bits + 6*i,hex[i]);
  w->ok = true;
  return true;
}

// HDU: hexbit i is the data of the Golay(18,6,8) word at bit 18 i; 20 data hexbits
// (MI, MFID, ALGID, KID, TGID), 16 RS(36,20,17) parity
bool p25_hdu_decode(struct p25_word *w,uint8_t const bits[P25_HDU_BITS]){
  assert(w != NULL && bits != NULL);
  word_init(w,120);
  uint8_t work[36 * 18];
  memcpy(work,bits,sizeof work);
  int hex[36];
  bool erased[36];
  for(int i = 0; i < 36; i++){
    int const r = golay18_decode(work + 18*i);
    erased[i] = r < 0;
    if(r < 0)
      w->erasures++;
    else
      w->inner_fixed += r;
    hex[i] = get_hex(work + 18*i);
  }
  return word_finish(w,hex,36,20,erased);
}

// TDULC: Golay(24,12,8) word i at bit 24 i carries hexbits 2i and 2i+1; 12 link control
// hexbits, 12 RS(24,12,13) parity. A failed Golay word erases both its hexbits
bool p25_tdulc_decode(struct p25_word *w,uint8_t const bits[P25_TDULC_BITS]){
  assert(w != NULL && bits != NULL);
  word_init(w,72);
  uint8_t work[12 * 24];
  memcpy(work,bits,sizeof work);
  int hex[24];
  bool erased[24];
  for(int i = 0; i < 12; i++){
    int const r = golay24_decode(work + 24*i);
    erased[2*i] = erased[2*i+1] = r < 0;
    if(r < 0)
      w->erasures++;
    else
      w->inner_fixed += r;
    hex[2*i] = get_hex(work + 24*i);
    hex[2*i+1] = get_hex(work + 24*i + 6);
  }
  return word_finish(w,hex,24,12,erased);
}

// ---------------------------------------------------------------------------
// LDU1 and LDU2

// The LDU payload: IMBE frames 1 and 2, then six groups of four Hamming(10,6,3) words
// (40 bits) each followed by an IMBE frame, except that the sixth group is followed by
// the 32 low speed data bits before frame 9
static int const Imbe_offset[P25_IMBE_FRAMES] = {0, 144, 328, 512, 696, 880, 1064, 1248, 1424};
enum { LSD_OFFSET = 1392 };

// Hamming word i (0-23), hexbit i of the link control or encryption sync
static inline int ldu_word(int i){
  return 288 + 184 * (i / 4) + 10 * (i % 4);
}

bool p25_ldu_decode(struct p25_ldu *ldu,int duid,uint8_t bits[P25_LDU_BITS],float const conf[P25_LDU_BITS]){
  assert(ldu != NULL && bits != NULL);
  memset(ldu,0,sizeof *ldu);
  ldu->duid = duid;
  // LDU1: RS(24,12,13) link control. LDU2: RS(24,16,9) encryption sync
  int const ndata = duid == 10 ? 16 : 12;
  int hex[24];
  bool erased[24];

  if(conf != NULL){
    // Soft stage, in place
    ldu->soft = true;
    for(int i = 0; i < 24; i++){
      int const s = ldu_word(i);
      int const r = hamming10_decode_soft(bits + s,conf + s,HAMMING10_HIGH_CONFIDENCE);
      erased[i] = r < 0;
      if(r < 0)
        ldu->soft_erasures++;
      else if(r > 0)
        ldu->soft_fixed++;
    }
    if(ldu->soft_erasures > 0){
      for(int i = 0; i < 24; i++)
        hex[i] = get_hex(bits + ldu_word(i));
      int const r = rs_hexbits(hex,24,ndata,erased);
      if(r < 0){
        ldu->soft_rs = -1; // the Hamming corrections stay
      } else {
        ldu->soft_rs = 1;
        ldu->soft_rs_fixed = r;
        for(int i = 0; i < 24; i++)
          put_hex(bits + ldu_word(i),hex[i]); // the Hamming parity bits are left as they are
      }
    }
  }
  // Hard decode of the link control or encryption sync, on a copy
  struct p25_word *w = &ldu->word;
  word_init(w,6 * ndata);
  for(int i = 0; i < 24; i++){
    uint8_t cw[10];
    memcpy(cw,bits + ldu_word(i),sizeof cw);
    int const r = hamming10_decode(cw);
    erased[i] = r < 0;
    if(r < 0)
      w->erasures++;
    else
      w->inner_fixed += r;
    hex[i] = get_hex(cw);
  }
  word_finish(w,hex,24,ndata,erased);

  for(int f = 0; f < P25_IMBE_FRAMES; f++)
    p25_imbe_decode(&ldu->voice[f],bits + Imbe_offset[f]);
  memcpy(ldu->lsd,bits + LSD_OFFSET,sizeof ldu->lsd);
  return w->ok;
}

// ---------------------------------------------------------------------------
// IMBE voice frames (TIA-102.BABA). New: beyond extracting the 144 bits of each frame

// Golay(23,12): bits 0-11 data, 12-22 parity; the Golay(24,12,8) code less its overall parity
// bit. A 23-bit word within three errors of a codeword is within three of the 24-bit
// codeword for one of the two values of the missing bit, so try both. Returns bits changed
static int golay23_decode(uint8_t bits[23]){
  uint8_t w[24];
  memcpy(w,bits,23);
  for(int p = 0; p < 2; p++){
    w[23] = (uint8_t)p;
    if(golay24_decode(w) < 0)
      continue;
    int n = 0;
    for(int i = 0; i < 23; i++){
      n += w[i] != bits[i];
      bits[i] = w[i];
    }
    return n;
  }
  return -1; // not reached: the code is perfect
}

// Hamming(15,11,3): bits 0-10 data, 11-14 parity (8s bit first). The parity checks of data
// bit i are the bits of the i-th of the 4-bit values of weight two or more, largest first
static uint8_t const Hamming15_checksums[11] = {0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x7, 0x6, 0x5, 0x3};

// Returns bits changed (0 or 1): every syndrome of a perfect code is a single error
static int hamming15_decode(uint8_t bits[15]){
  int s = 0;
  for(int i = 0; i < 11; i++){
    if(bits[i])
      s ^= Hamming15_checksums[i];
  }
  for(int i = 0; i < 4; i++){
    if(bits[11+i])
      s ^= 8 >> i;
  }
  if(s == 0)
    return 0;
  int p = -1;
  if((s & (s - 1)) == 0){
    p = s == 8 ? 11 : s == 4 ? 12 : s == 2 ? 13 : 14;
  } else {
    for(int i = 0; i < 11; i++){
      if(Hamming15_checksums[i] == s)
        p = i;
    }
  }
  bits[p] ^= 1;
  return 1;
}

// Codeword layout after deinterleaving: c0 at 0, c1 23, c2 46, c3 69 (23 bits each),
// c4 92, c5 107, c6 122 (15 each), c7 137 (7)
static int const Imbe_cw_start[8] = {0, 23, 46, 69, 92, 107, 122, 137};
static int const Imbe_info_bits[8] = {12, 12, 12, 12, 11, 11, 11, 7};

void p25_imbe_decode(struct p25_imbe *f,uint8_t const raw[P25_IMBE_BITS]){
  assert(f != NULL && raw != NULL);
  memset(f,0,sizeof *f);
  memcpy(f->raw,raw,sizeof f->raw);
  // Deinterleave: the codeword bits, c0 msb first through c7 lsb, read as six rows of 24
  // are sent column by column, six bits (three dibits) per column; in the odd columns the
  // two bits of each dibit are exchanged
  uint8_t v[144];
  for(int j = 0; j < 144; j++){
    int const col = j / 6;
    int const row = (j % 6) ^ (col & 1);
    v[24 * row + col] = raw[j] & 1;
  }
  f->errors[0] = golay23_decode(v);
  // c1-c6 (vector bits 23-136) are masked by the msb of p(n) = 173 p(n-1) + 13849 mod 65536,
  // n = 1 .. 114, p(0) = 16 u0
  uint32_t const u0 = (uint32_t)(get_hex(v) << 6 | get_hex(v + 6));
  uint32_t pr = 16 * u0;
  for(int n = 0; n < 114; n++){
    pr = (173 * pr + 13849) & 0xffff;
    v[23 + n] ^= (uint8_t)(pr >> 15);
  }
  for(int c = 1; c < 4; c++)
    f->errors[c] = golay23_decode(v + Imbe_cw_start[c]);
  for(int c = 4; c < 7; c++)
    f->errors[c] = hamming15_decode(v + Imbe_cw_start[c]);
  int k = 0;
  for(int c = 0; c < 8; c++){
    memcpy(f->u + k,v + Imbe_cw_start[c],Imbe_info_bits[c]);
    k += Imbe_info_bits[c];
  }
  assert(k == P25_IMBE_INFO_BITS);
  f->e0 = f->errors[0];
  f->e4 = f->errors[4];
  for(int c = 0; c < 7; c++)
    f->total += f->errors[c];
}

// ---------------------------------------------------------------------------
// Trunking signalling blocks and packet data

// Deinterleave and Viterbi-decode one 196-bit block (TIA-102.BAAA trellis codes)
static void trellis_block(struct p25_block *b,uint8_t const bits[P25_BLOCK_BITS],float const phase[P25_BLOCK_BITS/2],
                          bool three_quarter){
  memset(b,0,sizeof *b);
  b->nbits = three_quarter ? 144 : 96;
  if(phase != NULL){
    float ph[98];
    p25_deinterleave_dibit_floats(ph,phase);
    b->soft = true;
    b->metric = three_quarter ? trellis_34_decode_soft(b->bits,ph,49) : trellis_12_decode_soft(b->bits,ph,49);
  } else {
    uint8_t d[196];
    p25_deinterleave_bits(d,bits);
    b->metric = (float)(three_quarter ? trellis_34_decode(b->bits,d,49) : trellis_12_decode(b->bits,d,49));
  }
}

int p25_tsbk_decode(struct p25_block *b,uint8_t const bits[P25_BLOCK_BITS],float const phase[P25_BLOCK_BITS/2],
                    bool correct_one){
  assert(b != NULL && bits != NULL);
  trellis_block(b,bits,phase,false);
  b->crc = crc_ccitt80_check(b->bits,correct_one);
  // A block failing its CRC has an untrustworthy last-block bit: assume more may follow
  b->last = b->crc >= 0 && b->bits[0];
  return b->crc;
}

void p25_pdu_reset(struct p25_pdu *p){
  assert(p != NULL);
  p->pending = false;
}

static int get_field(uint8_t const *bits,int offset,int len){
  int v = 0;
  for(int i = 0; i < len; i++)
    v = (v << 1) | bits[offset + i];
  return v;
}

int p25_pdu_header(struct p25_pdu *p,struct p25_block *b,uint8_t const bits[P25_BLOCK_BITS],
                   float const phase[P25_BLOCK_BITS/2],bool correct_one){
  assert(p != NULL && b != NULL && bits != NULL);
  trellis_block(b,bits,phase,false);
  b->crc = crc_ccitt80_check(b->bits,correct_one);
  p25_pdu_reset(p);
  if(b->crc < 0)
    return -1; // blocks to follow is trusted only from a header that passes
  p->confirmed = b->bits[1];
  p->outbound = b->bits[2];
  p->format = get_field(b->bits,3,5);
  p->vendor = (uint8_t)get_field(b->bits,16,8);
  p->blocks_to_follow = get_field(b->bits,49,7);
  p->kind = p->format == 23 ? P25_PDUKIND_AMBTC : p->format == 21 ? P25_PDUKIND_UMBTC : P25_PDUKIND_DATA;
  p->nblocks = 0;
  p->block_bits = p->confirmed ? 144 : 96;
  memcpy(p->payload,b->bits,96);
  p->nbits = 96;
  if(p->blocks_to_follow == 0)
    return 1;
  p->pending = true;
  return 0;
}

int p25_pdu_block(struct p25_pdu *p,struct p25_block *b,uint8_t const bits[P25_BLOCK_BITS],
                  float const phase[P25_BLOCK_BITS/2]){
  assert(p != NULL && b != NULL && bits != NULL);
  trellis_block(b,bits,phase,p->pending && p->confirmed);
  if(!p->pending)
    return -1;
  memcpy(p->payload + 96 + p->nblocks * p->block_bits,b->bits,(size_t)p->block_bits);
  p->nblocks++;
  p->nbits = 96 + p->nblocks * p->block_bits;
  if(p->nblocks < p->blocks_to_follow)
    return 0;
  p->pending = false;
  return 1;
}

void p25_pack_bits(uint8_t *octets,uint8_t const *bits,int nbits){
  assert(octets != NULL && bits != NULL);
  for(int i = 0; i < (nbits + 7) / 8; i++){
    uint8_t o = 0;
    for(int j = 0; j < 8; j++){
      int const k = 8*i + j;
      o = (uint8_t)((o << 1) | (k < nbits ? (bits[k] & 1) : 0));
    }
    octets[i] = o;
  }
}
