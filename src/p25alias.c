// P25 talker alias reassembly: Motorola header and data blocks (Phase 1 link control,
// Phase 2 MAC), its de-obfuscation and CRC, and L3Harris link control blocks 1-4
// Copyright 2026, Matthew Kaufman, KA6SQG

#include <string.h>
#include "p25alias.h"

static int get_bit(uint8_t const *p, int i){
  return (p[i >> 3] >> (7 - (i & 7))) & 1;
}
static uint32_t get_field(uint8_t const *p, int off, int len){
  uint32_t v = 0;
  for(int i = off; i < off + len; i++)
    v = (v << 1) | get_bit(p, i);
  return v;
}
static void put_bits(uint8_t *dst, int at, uint8_t const *src, int from, int n){
  for(int i = 0; i < n; i++)
    if(get_bit(src, from + i))
      dst[(at + i) >> 3] |= 0x80 >> ((at + i) & 7);
}

// Motorola's substitution table, indexed by the encoded octet.
// After sdrtrunk (phase1/message/lc/motorola/MotorolaTalkerAliasComplete.java LOOKUP_TABLE,
// there indexed by the signed octet + 128), Dennis Sheirer, GPL-3; the same table as OP25's
// (gr-op25_repeater/apps/tk_p25.py mot_talker_alias), Graham J. Norbury, GPL-3, whose
// unsigned indexing this is.
static const uint8_t Mot_lut[256] = {
  0xd2, 0xf6, 0xd4, 0x2b, 0x63, 0x49, 0x94, 0x5e, 0xa7, 0x5c, 0x70, 0x69, 0xf7, 0x08, 0xb1, 0x7d,
  0x38, 0xcf, 0xcc, 0xd8, 0x51, 0x8f, 0xd5, 0x93, 0x6a, 0xf3, 0xef, 0x7e, 0xfb, 0x64, 0xf4, 0x35,
  0x27, 0x07, 0x31, 0x14, 0x87, 0x98, 0x76, 0x34, 0xca, 0x92, 0x33, 0x1b, 0x4f, 0x8c, 0x09, 0x40,
  0x32, 0x36, 0x77, 0x12, 0xd3, 0xc3, 0x01, 0xab, 0x72, 0x81, 0x95, 0xc9, 0xc0, 0xe9, 0x65, 0x52,
  0x24, 0x30, 0x1c, 0xdb, 0x88, 0xe8, 0x97, 0x9d, 0x58, 0x26, 0x04, 0x39, 0xac, 0x2a, 0x9e, 0xaa,
  0x25, 0xd7, 0xce, 0xeb, 0x96, 0xf5, 0x0e, 0x8d, 0xdc, 0xa9, 0x2f, 0xdd, 0x1f, 0xea, 0x91, 0xb7,
  0xd6, 0x89, 0x8b, 0xd1, 0xb0, 0x99, 0x13, 0x7a, 0xe7, 0x9a, 0xb5, 0x86, 0xff, 0x46, 0x85, 0xb2,
  0x73, 0xda, 0xbf, 0xd0, 0x71, 0xcb, 0x4d, 0x80, 0x15, 0x67, 0x16, 0x1a, 0x20, 0x8e, 0x45, 0x3e,
  0xf2, 0x2e, 0x66, 0x90, 0x74, 0x8a, 0x6f, 0x78, 0xbb, 0x53, 0x03, 0x11, 0x68, 0xcd, 0x44, 0x17,
  0x28, 0x5f, 0x1e, 0x84, 0x75, 0x79, 0x6e, 0x9b, 0x2c, 0xbe, 0x62, 0x2d, 0xf1, 0x7c, 0xb8, 0x83,
  0xd9, 0x4e, 0x6d, 0x02, 0x61, 0x3d, 0xa8, 0x06, 0xb9, 0xf8, 0x9c, 0x37, 0x3a, 0x23, 0xc1, 0x50,
  0xed, 0x9f, 0xaf, 0x3b, 0xbd, 0x82, 0xba, 0xa0, 0xdf, 0xc2, 0x47, 0x22, 0xf0, 0xee, 0xa1, 0xfe,
  0xa2, 0x10, 0x5b, 0x48, 0x57, 0xa3, 0x05, 0x60, 0x7b, 0x0d, 0xf9, 0x6c, 0xb3, 0x56, 0x4c, 0xbc,
  0x29, 0xa4, 0x0f, 0xec, 0xb6, 0xa5, 0xa6, 0x3c, 0x7f, 0x6b, 0xb4, 0x21, 0xad, 0xae, 0xc4, 0xc8,
  0xc5, 0x5d, 0xde, 0xe0, 0x1d, 0x19, 0x4b, 0xc6, 0x0c, 0x3f, 0x5a, 0xc7, 0xe1, 0x59, 0x55, 0x54,
  0x4a, 0x43, 0x42, 0xe2, 0xe3, 0xfa, 0x00, 0xe4, 0xe5, 0x18, 0x41, 0x0b, 0x0a, 0xe6, 0xfc, 0xfd,
};

// CRC-16/GSM: x^16+x^12+x^5+1, zero preset, msb first, inverted
static uint16_t crc16_gsm(uint8_t const *bits, int n){
  uint16_t crc = 0;
  for(int i = 0; i < n; i++){
    bool const b = get_bit(bits, i) != ((crc & 0x8000) != 0);
    crc <<= 1;
    if(b)
      crc ^= 0x1021;
  }
  return crc ^ 0xffff;
}

// Inverse of an odd number mod 256 (Newton: each step doubles the bits that are right)
static uint8_t inverse(uint8_t s){
  uint8_t x = s;
  for(int i = 0; i < 3; i++)
    x *= 2 - s * x;
  return x;
}

static void put_utf8(struct p25_alias_result *out, uint32_t cp){
  uint8_t u[3];
  int n;
  if(cp < 0x80){
    u[0] = cp;
    n = 1;
  } else if(cp < 0x800){
    u[0] = 0xc0 | (cp >> 6);
    u[1] = 0x80 | (cp & 0x3f);
    n = 2;
  } else {
    u[0] = 0xe0 | (cp >> 12);
    u[1] = 0x80 | ((cp >> 6) & 0x3f);
    u[2] = 0x80 | (cp & 0x3f);
    n = 3;
  }
  if(out->len + n < P25_ALIAS_MAX){
    memcpy(out->text + out->len, u, n);
    out->len += n;
  }
}

// Strip NULs and blanks from both ends
static int trim(char *s, int n){
  while(n > 0 && (s[n - 1] == '\0' || s[n - 1] == ' '))
    n--;
  int start = 0;
  while(start < n && (s[start] == '\0' || s[start] == ' '))
    start++;
  memmove(s, s + start, n - start);
  return n - start;
}

bool p25_alias_motorola(uint8_t const *bits, int nbits, struct p25_alias_result *out){
  memset(out, 0, sizeof *out);
  out->mfid = P25_MFID_MOTOROLA;
  if(nbits < 72)
    return false;
  // Zero padding off the end, in whole octets after the first 72 bits
  int size = 72;
  for(int i = nbits; i > 72; i--){
    if(get_bit(bits, i - 1)){
      size = 72 + ((i - 72 + 7) / 8) * 8;
      break;
    }
  }
  if(size > nbits)
    size = nbits;
  bool const crc_ok = crc16_gsm(bits, size - 16) == get_field(bits, size - 16, 16);
  out->has_suid = true;
  out->wacn = get_field(bits, 0, 20);
  out->sysid = get_field(bits, 20, 12);
  out->unit = get_field(bits, 32, 24);

  // Up to 16 chunks of 16 bits from bit 56, through the last nonzero one; its last
  // two octets are the CRC
  int chunks = 1;
  for(int x = 16; x > 1; x--){
    if(size >= 56 + x * 16 - 1 && 56 + x * 16 <= nbits && get_field(bits, 56 + (x - 1) * 16, 16) != 0){
      chunks = x;
      break;
    }
  }
  uint8_t enc[32];
  int n = 0;
  for(int i = 0; i < chunks * 2 && 56 + i * 8 + 8 <= nbits; i++)
    enc[n++] = get_field(bits, 56 + i * 8, 8);
  if(n >= 3){
    int const len = n - 2;
    uint8_t dec[32];
    uint16_t acc = len;
    for(int i = 0; i < len; i++){
      uint16_t const mult = acc * 293 + 0x72e9;
      uint8_t const m1 = Mot_lut[enc[i]] - (mult >> 8);
      dec[i] = m1 * inverse(mult | 1);
      acc += enc[i] + 1;
    }
    for(int c = 0; c * 2 + 1 < len; c++)
      put_utf8(out, (uint32_t)dec[2 * c] << 8 | dec[2 * c + 1]);
  }
  out->len = trim(out->text, out->len);
  out->text[out->len] = '\0';
  return crc_ok && out->len > 0;
}

void p25_alias_init(struct p25_alias *a){
  memset(a, 0, sizeof *a);
  a->lc.sequence = -1;
  a->mac.sequence = -1;
}

static void mot_clear(struct p25_mot_alias *m){
  m->have_header = false;
  m->have = 0;
}

// A header or data block of one sequence; a block of another sequence starts over
static void mot_header(struct p25_mot_alias *m, int sequence, int count, uint8_t const *frag){
  if(sequence != m->sequence){
    m->have = 0;
    m->sequence = sequence;
  }
  m->have_header = true;
  m->count = count;
  if(frag)
    memcpy(m->header, frag, sizeof m->header);
}
static void mot_block(struct p25_mot_alias *m, int sequence, int number, uint8_t const *frag, int nbits){
  if(sequence != m->sequence){
    mot_clear(m);
    m->sequence = sequence;
  }
  if(number < 1 || number > P25_ALIAS_MAX_BLOCKS)
    return;
  memset(m->block[number - 1], 0, sizeof m->block[0]);
  put_bits(m->block[number - 1], 0, frag, 0, nbits);
  m->have |= 1u << (number - 1);
}
// header_bits 0 (link control: the header carries no text) or 64 (MAC)
static bool mot_assemble(struct p25_alias *a, struct p25_mot_alias *m, int header_bits, int block_bits,
                         struct p25_alias_result *out){
  if(!m->have_header || m->count == 0 || m->count > P25_ALIAS_MAX_BLOCKS)
    return false;
  uint32_t const need = (1u << m->count) - 1;
  if((m->have & need) != need)
    return false;
  uint8_t bits[(64 + P25_ALIAS_MAX_BLOCKS * 100 + 7) / 8];
  memset(bits, 0, sizeof bits);
  put_bits(bits, 0, m->header, 0, header_bits);
  for(int b = 0; b < m->count; b++)
    put_bits(bits, header_bits + b * block_bits, m->block[b], 0, block_bits);
  int const nbits = header_bits + m->count * block_bits;
  mot_clear(m);
  if(!p25_alias_motorola(bits, nbits, out)){
    a->crc_failures++;
    return false;
  }
  return true;
}

// L3Harris: blocks 1 and 2, then 3 and 4 unless they repeat what is there (on the air
// blocks 3-4 often repeat 1-2)
static bool harris_assemble(struct p25_alias const *a, struct p25_alias_result *out){
  if(a->harris_len[0] == 0 || a->harris_len[1] == 0)
    return false;
  memset(out, 0, sizeof *out);
  out->mfid = P25_MFID_HARRIS;
  memcpy(out->text, a->harris[0], a->harris_len[0]);
  out->len = a->harris_len[0];
  for(int i = 1; i < 4; i++){
    int const k = a->harris_len[i];
    if(k == 0)
      break;
    bool found = false;
    for(int j = 0; j + k <= out->len && !found; j++)
      found = memcmp(out->text + j, a->harris[i], k) == 0;
    if(found)
      break;
    memcpy(out->text + out->len, a->harris[i], k);
    out->len += k;
  }
  out->text[out->len] = '\0';
  return true;
}

bool p25_alias_lc(struct p25_alias *a, struct p25_msg const *lc, struct p25_alias_result *out){
  if(lc->protect || lc->raw_len < 9)
    return false;
  switch(lc->kind){
  case P25_LC_MOT_ALIAS_HDR:
    mot_header(&a->lc, lc->sequence, lc->block_count, NULL);
    return mot_assemble(a, &a->lc, 0, 44, out);
  case P25_LC_MOT_ALIAS_DATA:
    {
      uint8_t frag[6] = { 0 };
      put_bits(frag, 0, lc->raw, 28, 44);  // link control bits 28-71
      mot_block(&a->lc, lc->sequence, lc->block, frag, 44);
    }
    return mot_assemble(a, &a->lc, 0, 44, out);
  case P25_LC_HARRIS_ALIAS: // octets 2-8 of blocks 1-4
    if(lc->block < 1 || lc->block > 4)
      return false;
    {
      char t[7];
      memcpy(t, lc->raw + 2, 7);
      a->harris_len[lc->block - 1] = trim(t, 7);
      memcpy(a->harris[lc->block - 1], t, a->harris_len[lc->block - 1]);
    }
    return harris_assemble(a, out);
  default:
    return false;
  }
}

bool p25_alias_mac(struct p25_alias *a, struct p25_mac_struct const *s, struct p25_alias_result *out){
  if(s->vendor == P25_MFID_HARRIS && s->mac_kind == P25_MAC_HARRIS_ALIAS){
    memset(out, 0, sizeof *out);
    out->mfid = P25_MFID_HARRIS;
    out->len = strlen(s->alias);
    memcpy(out->text, s->alias, out->len + 1);
    return out->len > 0;
  }
  if(s->vendor != P25_MFID_MOTOROLA)
    return false;
  if(s->msg.kind == P25_LC_MOT_ALIAS_HDR)
    mot_header(&a->mac, s->msg.sequence, s->msg.block_count, s->frag);
  else if(s->msg.kind == P25_LC_MOT_ALIAS_DATA)
    mot_block(&a->mac, s->msg.sequence, s->msg.block, s->frag, 100);
  else
    return false;
  return mot_assemble(a, &a->mac, 64, 100, out);
}
