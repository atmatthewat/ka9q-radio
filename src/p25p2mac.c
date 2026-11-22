// P25 Phase 2 MAC PDU parsing (TIA-102.BBAC, BBAD): walks a SACCH, FACCH or LCCH PDU into
// its structures and decodes them into struct p25_msg, with one-line log formatting
// Copyright 2026, Matthew Kaufman, KA6SQG

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "p25p1msg.h"
#include "p25p2mac.h"

// The PDU: octets MSB first, nbits of them valid. Bits past nbits read as zero.
struct pdu_bits {
  uint8_t const *p;
  int n;
};
static int get_bit(struct pdu_bits const *b, int i){
  if(i < 0 || i >= b->n)
    return 0;
  return (b->p[i >> 3] >> (7 - (i & 7))) & 1;
}
// A whole field, or zero if any of it lies past the PDU
static uint32_t get_field(struct pdu_bits const *b, int off, int len){
  if(off < 0 || off + len > b->n)
    return 0;
  uint32_t v = 0;
  for(int i = off; i < off + len; i++)
    v = (v << 1) | ((b->p[i >> 3] >> (7 - (i & 7))) & 1);
  return v;
}

// Structure lengths in octets, opcode included. 0: not listed (standard: the rest of the PDU;
// vendor: the vendor length field). VAR: variable, from the structure's own length field.
// REST: the rest of the PDU.
//
// Opcode lengths after sdrtrunk (MacOpcode.java, MacMessageFactory.java and the structure
// classes in module/decode/p25/phase2/message/mac), Dennis Sheirer, GPL-3; cross-checked
// against OP25 (gr-op25_repeater/lib/p25p2_tdma.cc mac_msg_len), Max H. Parke KA1RBI and
// Graham J. Norbury, GPL-3. Where they differ the length that the structure's fields need
// is taken: 0x45, 0x4a and 0xc5 are OP25's, as sdrtrunk's own field layouts for them end at
// 8, 9 and 12 octets. 0xe3, 0xed, 0xf6 and 0xf8 are OP25's alone. The Motorola regroup
// extended function command is 0x84, as OP25 has it and sdrtrunk names it (its value, 0x85,
// disagrees with its name). Multi-fragment base structures (0x71, 0xc7 ...) are 18 octets,
// the fragment an LCCH PDU holds; OP25 lists the whole message's length there instead.
#define VAR 0xff
#define REST 0xfe
static const uint8_t Std_len[256] = {
  [0x00] = REST, [0x01] = 7, [0x02] = 8, [0x03] = 7, [0x05] = 16, [0x08] = VAR,
  [0x10] = VAR, [0x11] = VAR, [0x12] = VAR, [0x21] = 14, [0x22] = 15, [0x25] = 15,
  [0x30] = 5, [0x31] = 7,
  [0x40] = 9, [0x41] = 7, [0x42] = 9, [0x44] = 9, [0x45] = 8, [0x46] = 9, [0x48] = 10,
  [0x49] = 10, [0x4a] = 9, [0x4c] = 10, [0x52] = 8, [0x53] = 9, [0x54] = 9, [0x55] = 7,
  [0x58] = 10, [0x5a] = 7, [0x5c] = 10, [0x5d] = 8, [0x5e] = 14, [0x5f] = 7, [0x60] = 9,
  [0x61] = 9, [0x64] = 9, [0x67] = 9, [0x68] = 10, [0x6a] = 7, [0x6b] = 10, [0x6c] = 10,
  [0x6d] = 7, [0x6f] = 9, [0x70] = 9, [0x71] = 18, [0x72] = 9, [0x73] = 9, [0x74] = 9,
  [0x75] = 9, [0x76] = 10, [0x77] = 13, [0x78] = 9, [0x79] = 9, [0x7a] = 9, [0x7b] = 11,
  [0x7c] = 9, [0x7d] = 9,
  [0x88] = 5, [0x90] = 7,  // standard-vendor opcodes in the vendor partition
  [0xc0] = 11, [0xc3] = 8, [0xc4] = 15, [0xc5] = 12, [0xc6] = 15, [0xc7] = 18, [0xc8] = 12,
  [0xc9] = 12, [0xcb] = 18, [0xcc] = 14, [0xcd] = 18, [0xce] = 18, [0xcf] = 18, [0xd6] = 9,
  [0xd8] = 14, [0xd9] = 18, [0xda] = 11, [0xdb] = 18, [0xdc] = 14, [0xde] = 18, [0xdf] = 11,
  [0xe0] = 18, [0xe3] = 14, [0xe4] = 17, [0xe5] = 14, [0xe8] = 16, [0xe9] = 8, [0xea] = 11,
  [0xec] = 13, [0xed] = 19, [0xf2] = 16, [0xf3] = 14, [0xf6] = 12, [0xf8] = 22, [0xfa] = 11,
  [0xfb] = 13, [0xfc] = 11, [0xfe] = 15,
};
// Vendor partition (0x80-0xbf), indexed by opcode - 0x80
static const uint8_t Motorola_len[64] = {
  [0x00] = 8, [0x01] = 17, [0x03] = 7, [0x04] = 11, [0x09] = 17, [0x11] = 17, [0x15] = 17,
  [0x20] = 16, [0x23] = 11, [0x24] = 13, [0x25] = 11, [0x26] = 11, [0x27] = 11, [0x28] = 10,
};
static const uint8_t Harris_len[64] = {
  [0x20] = 9, [0x28] = REST, [0x2a] = 17, [0x2c] = 12,
};

static bool vendor_partition(uint8_t op){
  return op >= 0x80 && op <= 0xbf && op != 0x88 && op != 0x90;
}

// Bits before the CRC: where structures may lie
static int max_index(enum p25_mac_chan chan){
  return chan == P25_MAC_FACCH ? 144 : chan == P25_MAC_LCCH ? 152 : 168;
}

// A manufacturer-specific structure carries its own length (octets, bits 18-23), but not
// every one sets it: the field is taken when it is plausible (3 or more octets, inside the
// PDU), else the vendor table's length
static int struct_len(struct pdu_bits const *b, int maxidx, int offset, uint8_t op, uint8_t *vendor){
  int const remaining = (maxidx - offset + 7) / 8;
  int len;
  *vendor = 0;
  if(vendor_partition(op)){
    *vendor = get_field(b, offset + 8, 8);
    int const lf = get_field(b, offset + 18, 6);
    uint8_t const *tbl = *vendor == P25_MFID_MOTOROLA ? Motorola_len : *vendor == P25_MFID_HARRIS ? Harris_len : NULL;
    int fixed = 0;
    if(tbl != NULL && tbl[op - 0x80] != 0 && tbl[op - 0x80] != VAR)
      fixed = tbl[op - 0x80] == REST ? -1 : tbl[op - 0x80];
    if(lf >= 3 && lf <= remaining)
      len = lf;
    else
      len = fixed != 0 ? fixed : lf;
  } else {
    uint8_t const t = Std_len[op];
    if(t == 0 || t == REST)
      len = -1;
    else if(t == VAR){
      int const count = get_field(b, offset + 14, 2);
      // paging: 2-octet groups or 3-octet units; a count of 0 is four of them
      static const uint8_t group_paging[4] = { 10, 4, 6, 8 };
      static const uint8_t unit_paging[4] = { 14, 5, 8, 11 };
      if(op == 0x11)
        len = group_paging[count];
      else if(op == 0x12)
        len = unit_paging[count];
      else
        len = get_field(b, offset + 10, 6);
    } else
      len = t;
  }
  if(len < 0)
    len = remaining;
  return len;
}

int p25_mac_struct_len(uint8_t const *octets, int nbits, enum p25_mac_chan chan, int offset){
  struct pdu_bits b = { octets, nbits };
  if(octets == NULL || offset + 8 > nbits)
    return 0;
  uint8_t vendor;
  return struct_len(&b, max_index(chan), offset, get_field(&b, offset, 8), &vendor);
}

// Field readers relative to the structure being decoded
struct ctx {
  struct pdu_bits const *b;
  struct p25_mac_struct *s;
};
static uint32_t F(struct ctx const *c, int off, int len){
  return get_field(c->b, c->s->offset + off, len);
}
static bool B(struct ctx const *c, int off){
  return get_field(c->b, c->s->offset + off, 1);
}
static struct p25_chan CH(struct ctx const *c, int off){
  struct p25_chan ch = { .iden = F(c, off, 4), .num = F(c, off + 4, 12) };
  return ch;
}
static void suid(struct ctx const *c, int off){
  c->s->msg.wacn = F(c, off, 20);
  c->s->msg.sysid = F(c, off + 20, 12);
  c->s->suid = F(c, off + 32, 24);
  c->s->has_suid = true;
}

// A structure laid out as a TSBK: TSBK bits 16-79 (after opcode and MFID) are structure bits
// at-(at+63), each bit copied that lies inside the structure and the PDU. Then the Phase 1
// decoder reads it. Most abbreviated (partition 1) structures are the TSBK without its MFID
// octet (at 8); the 10-octet ones keep the TSBK's positions (at 16) and the 7-octet ones drop
// its two reserved octets after the opcode (at -8); vendor structures put it after the
// vendor and length octets (at 24).
static void as_tsbk(struct ctx const *c, int at, uint8_t tsbk_opcode, uint8_t mfid){
  uint8_t t[12] = { 0x80 | (tsbk_opcode & 0x3f), mfid };
  int const end = c->s->len * 8;
  for(int i = 16; i < 80; i++){
    int const k = at + i - 16;
    if(k >= 0 && k < end && get_bit(c->b, c->s->offset + k))
      t[i >> 3] |= 0x80 >> (i & 7);
  }
  p25_decode_tsbk(&c->s->msg, t);
  c->s->msg.last_block = false;
}

// Partition 1 (0x40-0x7f): where TSBK bit 16 lies in the structure; 0 means decoded here
static const int8_t P1_at[64] = {
  [0x00] = 8, [0x02] = 8, [0x04] = 8, [0x06] = 8, [0x0c] = 16, [0x14] = 8, [0x18] = 16,
  [0x1a] = -8, [0x1c] = 16, [0x1f] = -8, [0x20] = 8, [0x21] = 8, [0x24] = 8, [0x27] = 8,
  [0x28] = 16, [0x2a] = -8, [0x2b] = 16, [0x2c] = 16, [0x2d] = 8, [0x2f] = 8, [0x30] = 8,
  [0x31] = 8, [0x32] = 8, [0x33] = 8, [0x34] = 8, [0x37] = 8, [0x38] = 8, [0x39] = 8,
  [0x3a] = 8, [0x3b] = 8, [0x3c] = 8, [0x3d] = 8,
};

static void grant(struct ctx const *c, int svc, int ch, int ch_ul, int group, bool distinct_all){
  struct p25_mac_struct *s = c->s;
  struct p25_mac_grant g = {
    .svc = svc >= 0 ? F(c, svc, 8) : 0,
    .ch = CH(c, ch),
    .group = F(c, group, 16),
  };
  if(ch_ul >= 0)
    g.ch_ul = CH(c, ch_ul);
  // the first always; a later one only if it names another, nonzero group
  if(s->ngrants > 0){
    if(g.group == 0)
      return;
    for(int i = 0; i < (distinct_all ? s->ngrants : 1); i++)
      if(s->grant[i].group == g.group)
        return;
  }
  s->grant[s->ngrants++] = g;
}
// The grants into the flat fields too: the first, and the second as the "b" call
static void grants_to_msg(struct p25_mac_struct *s){
  s->msg.svc = s->grant[0].svc;
  s->msg.ch = s->grant[0].ch;
  s->msg.group = s->grant[0].group;
  if(s->ngrants > 1){
    s->msg.ch_b = s->grant[1].ch;
    s->msg.group_b = s->grant[1].group;
    s->msg.has_b = true;
  }
}

static void harris_alias(struct ctx const *c){
  // From octet 3 to the end of the structure, up to a zero octet, blanks trimmed
  struct p25_mac_struct *s = c->s;
  int n = 0;
  for(int i = 24; i + 8 <= s->len * 8 && n < (int)sizeof s->alias - 1; i += 8){
    if(s->offset + i + 8 > c->b->n)
      break;
    uint8_t ch = F(c, i, 8);
    if(ch == 0)
      break;
    s->alias[n++] = ch;
  }
  while(n > 0 && (uint8_t)s->alias[n - 1] <= ' ')
    n--;
  int start = 0;
  while(start < n && (uint8_t)s->alias[start] <= ' ')
    start++;
  memmove(s->alias, s->alias + start, n - start);
  s->alias[n - start] = '\0';
}

static void decode_standard(struct ctx const *c){
  struct p25_mac_struct *s = c->s;
  struct p25_msg *m = &s->msg;
  uint8_t const op = s->opcode;
  if(op >= 0x40 && op <= 0x7f && P1_at[op - 0x40] != 0){
    as_tsbk(c, P1_at[op - 0x40], op & 0x3f, P25_MFID_STD);
    if(op == 0x7b){
      s->nac = F(c, 76, 12);
      s->has_nac = true;
    }
    if(op == 0x42){ // the grant list as the other updates have it
      grant(c, -1, 8, -1, 24, false);
      grant(c, -1, 40, -1, 56, false);
    }
    return;
  }
  if(op >= 0x40 && op <= 0x7f && Std_len[op] == 0){
    // Not in either table: read as the TSBK it abbreviates; its length is unknown
    as_tsbk(c, 8, op & 0x3f, P25_MFID_STD);
    return;
  }
  switch(op){
  case 0x00:
    s->mac_kind = P25_MAC_NULL;
    break;
  case 0x01:
  case 0x21:
    m->kind = P25_LC_GRP_V_CH_USR;
    m->svc = F(c, 8, 8);
    m->group = F(c, 16, 16);
    m->src = F(c, 32, 24);
    if(op == 0x21)
      suid(c, 56);
    break;
  case 0x02:
  case 0x22:
    m->kind = P25_LC_UU_V_CH_USR;
    m->svc = F(c, 8, 8);
    m->tgt = F(c, 16, 24);
    m->src = F(c, 40, 24);
    if(op == 0x22)
      suid(c, 64);
    break;
  case 0x03:
    m->kind = P25_LC_TEL_INT_V_CH_USR;
    m->svc = F(c, 8, 8);
    m->call_timer_ms = F(c, 16, 16) * 100;
    m->tgt = F(c, 32, 24);
    break;
  case 0x05: // three of: service options, channel, group
    s->mac_kind = P25_MAC_GRP_V_CH_GRANT_UPDT_MULT;
    for(int i = 0; i < 3; i++)
      grant(c, 8 + 40 * i, 16 + 40 * i, -1, 32 + 40 * i, true);
    grants_to_msg(s);
    break;
  case 0x25: // two of: service options, downlink, uplink, group
    s->mac_kind = P25_MAC_GRP_V_CH_GRANT_UPDT_MULT_EXP;
    for(int i = 0; i < 2; i++)
      grant(c, 8 + 56 * i, 16 + 56 * i, 32 + 56 * i, 48 + 56 * i, false);
    grants_to_msg(s);
    break;
  case 0x08:
    s->mac_kind = P25_MAC_NULL_AZB;
    break;
  case 0x10:
    s->mac_kind = P25_MAC_MULTI_FRAG;
    break;
  case 0x11:
  case 0x12: // count 14-15, then 16-bit groups or 24-bit units
    {
      s->mac_kind = op == 0x11 ? P25_MAC_GRP_PAGING : P25_MAC_IND_PAGING;
      int const w = op == 0x11 ? 16 : 24;
      for(int i = 0; i < 4 && 16 + w * (i + 1) <= s->len * 8; i++)
        s->paged[s->npaged++] = F(c, 16 + w * i, w);
    }
    break;
  case 0x30:
    s->mac_kind = P25_MAC_PWR_CTL;
    m->tgt = F(c, 8, 24);
    s->rf_level = F(c, 32, 4);
    s->ber = F(c, 36, 4);
    break;
  case 0x31:
    s->mac_kind = P25_MAC_RELEASE;
    s->forced = B(c, 8);
    s->audio = B(c, 9);
    m->tgt = F(c, 16, 24);
    s->nac = F(c, 44, 12);
    s->has_nac = true;
    break;
  // Partition 1, where the TSBK layout does not carry over
  case 0x45: // no reserved octet: service options, target, source
    m->kind = P25_UU_ANS_REQ;
    m->svc = F(c, 8, 8);
    m->tgt = F(c, 16, 24);
    m->src = F(c, 40, 24);
    break;
  case 0x48:
  case 0x49:
    m->kind = op == 0x48 ? P25_TELE_INT_CH_GRANT : P25_TELE_INT_CH_GRANT_UPDT;
    m->svc = F(c, 8, 8);
    m->ch = CH(c, 24);
    m->timer = F(c, 40, 16);
    m->tgt = F(c, 56, 24);
    break;
  case 0x4a: // ten 4-bit digits, then the target
    m->kind = P25_TELE_INT_ANS_REQ;
    for(int i = 0; i < 10; i++)
      s->digits[i] = "0123456789abcdef"[F(c, 8 + 4 * i, 4)];
    m->tgt = F(c, 48, 24);
    break;
  case 0x55:
    m->kind = P25_SN_DATA_PAGE_REQ;
    m->svc = F(c, 8, 8);
    m->data_access = F(c, 16, 16);
    m->tgt = F(c, 32, 24);
    break;
  case 0x75: // validity flags 8-10, local time offset 11-23, date 24-45, time 48-64
    m->kind = P25_TIME_DATE_ANN;
    m->month = F(c, 24, 4);
    m->day = F(c, 28, 5);
    m->year = F(c, 33, 13);
    m->hour = F(c, 48, 5);
    m->minute = F(c, 53, 6);
    s->second = F(c, 59, 6);
    break;
  case 0x76:
    m->kind = P25_ROAM_ADDR_CMD;
    m->wacn = F(c, 24, 20);
    m->sysid = F(c, 44, 12);
    m->tgt = F(c, 56, 24);
    break;
  case 0x41: case 0x52: case 0x53: case 0x5d: case 0x5e: case 0x88:
    s->mac_kind = P25_MAC_OTHER;
    break;
  case 0x90:
    s->mac_kind = P25_MAC_GRG_V_CH_USR;
    m->group = F(c, 16, 16);
    m->src = F(c, 32, 24);
    break;
  // Extended partition: explicit channels, extended addresses
  case 0xc0:
    m->kind = P25_GRP_V_CH_GRANT;
    m->svc = F(c, 8, 8);
    m->ch = CH(c, 16);
    m->ch_b = CH(c, 32);
    m->has_b = true;
    m->group = F(c, 48, 16);
    m->src = F(c, 64, 24);
    break;
  case 0xc3:
    m->kind = P25_GRP_V_CH_GRANT_UPDT_EXP;
    grant(c, 8, 16, 32, 48, false);
    m->svc = s->grant[0].svc;
    m->ch = s->grant[0].ch;
    m->ch_b = s->grant[0].ch_ul;
    m->has_b = true;
    m->group = s->grant[0].group;
    break;
  case 0xc4:
  case 0xc6:
    m->kind = op == 0xc4 ? P25_UU_V_CH_GRANT : P25_UU_V_CH_GRANT_UPDT;
    m->ch = CH(c, 8);
    m->ch_b = CH(c, 24);
    m->has_b = true;
    suid(c, 40);
    m->src = s->suid;
    m->tgt = F(c, 96, 24);
    break;
  case 0xc8:
  case 0xc9:
    m->kind = op == 0xc8 ? P25_TELE_INT_CH_GRANT : P25_TELE_INT_CH_GRANT_UPDT;
    m->svc = F(c, 8, 8);
    m->ch = CH(c, 24);
    m->ch_b = CH(c, 40);
    m->has_b = true;
    m->timer = F(c, 56, 16);
    m->tgt = F(c, 72, 24);
    break;
  case 0xd6:
    m->kind = P25_SN_DATA_CH_ANN_EXP;
    m->svc = F(c, 8, 8);
    m->autonomous = B(c, 16);
    m->requested = B(c, 17);
    m->ch = CH(c, 24);
    m->ch_b = CH(c, 40);
    m->has_b = true;
    m->data_access = F(c, 56, 16);
    break;
  case 0xd8:
    m->kind = P25_STS_UPDT;
    m->unit_status = F(c, 16, 8);
    m->user_status = F(c, 24, 8);
    m->tgt = F(c, 32, 24);
    suid(c, 56);
    m->src = s->suid;
    break;
  case 0xda:
  case 0xdf:
  case 0xea:
    m->kind = op == 0xda ? P25_STS_Q : op == 0xdf ? P25_CALL_ALRT : P25_GRP_AFF_Q;
    m->tgt = F(c, 8, 24);
    suid(c, 32);
    m->src = s->suid;
    break;
  case 0xdc:
    m->kind = P25_MSG_UPDT;
    m->message = F(c, 16, 16);
    m->tgt = F(c, 32, 24);
    suid(c, 56);
    m->src = s->suid;
    break;
  case 0xe8: // group ID: WACN, system, group 56-103
    m->kind = P25_GRP_AFF_RSP;
    m->local_global = B(c, 16);
    m->response = F(c, 22, 2);
    m->group_b = F(c, 24, 16);
    m->group = F(c, 40, 16);
    m->wacn = F(c, 56, 20);
    m->sysid = F(c, 76, 12);
    m->tgt = F(c, 104, 24);
    break;
  case 0xe9:
    m->kind = P25_SCCB_EXP;
    m->rfss = F(c, 8, 8);
    m->site = F(c, 16, 8);
    m->ch = CH(c, 24);
    m->ch_b = CH(c, 40);
    m->has_b = m->ch_b.num != 0;
    m->svc_class = F(c, 56, 8);
    break;
  case 0xec:
    m->kind = P25_U_REG_RSP;
    m->response = F(c, 22, 2);
    suid(c, 24);
    m->info = s->suid;
    m->src = F(c, 80, 24);
    break;
  case 0xf3: // the TDMA identifier update at TSBK positions, then WACN and system
    as_tsbk(c, 16, 0x33, P25_MFID_STD);
    m->wacn = F(c, 80, 20);
    m->sysid = F(c, 100, 12);
    break;
  case 0xfa:
  case 0xfb:
  case 0xfc:
  case 0xfe:
    m->lra = F(c, 8, 8);
    m->ch = CH(c, 48);
    m->ch_b = CH(c, 64);
    m->has_b = true;
    m->svc_class = F(c, 80, 8);
    if(op == 0xfb){
      m->kind = P25_NET_STS_BCST_EXP;
      m->wacn = F(c, 16, 20);
      m->sysid = F(c, 36, 12);
      s->nac = F(c, 92, 12);
      s->has_nac = true;
      break;
    }
    m->kind = op == 0xfa ? P25_RFSS_STS_BCST_EXP : P25_ADJ_STS_BCST_EXP;
    m->site_flags = op == 0xfa ? B(c, 19) : F(c, 16, 4);
    m->sysid = F(c, 20, 12);
    m->rfss = F(c, 32, 8);
    m->site = F(c, 40, 8);
    if(op == 0xfe)
      m->wacn = F(c, 96, 20);
    break;
  case 0x71: case 0xc5: case 0xc7: case 0xcb: case 0xcc: case 0xcd: case 0xce: case 0xcf:
  case 0xd9: case 0xdb: case 0xde: case 0xe0: case 0xe3: case 0xe4: case 0xe5: case 0xed:
  case 0xf2: case 0xf6: case 0xf8:
    s->mac_kind = P25_MAC_OTHER;
    break;
  default:
    break;
  }
}

// Bits [off, off+n) of the PDU from the structure, past the structure's end if need be
static void fragment(struct ctx const *c, int off, int n){
  struct p25_mac_struct *s = c->s;
  memset(s->frag, 0, sizeof s->frag);
  for(int i = 0; i < n; i++)
    if(get_bit(c->b, s->offset + off + i))
      s->frag[i >> 3] |= 0x80 >> (i & 7);
  s->frag_bits = n;
}

static void decode_motorola(struct ctx const *c){
  struct p25_mac_struct *s = c->s;
  struct p25_msg *m = &s->msg;
  switch(s->opcode){
  case 0x80: // octet 2 is the vendor length: no service options
    m->kind = P25_LC_MOT_GRG_V_CH_USR;
    m->group = F(c, 24, 16);
    m->src = F(c, 40, 24);
    break;
  case 0xa0:
    m->kind = P25_LC_MOT_GRG_V_CH_USR;
    m->svc = F(c, 24, 8);
    m->group = F(c, 32, 16);
    m->src = F(c, 48, 24);
    suid(c, 72);
    break;
  case 0x81:
  case 0x89: // supergroup, then as many talkgroups as the length holds, up to six
    {
      m->kind = s->opcode == 0x81 ? P25_MOT_GRG_ADD : P25_MOT_GRG_DEL;
      m->group = F(c, 24, 16);
      int n = (s->len - 5) / 2;
      n = n < 0 ? 0 : n > 6 ? 6 : n;
      for(int i = 0; i < n; i++)
        s->members[i] = F(c, 40 + 16 * i, 16);
      s->nmembers = n;
      m->nmembers = n < 3 ? n : 3;
      memcpy(m->members, s->members, m->nmembers * sizeof m->members[0]);
    }
    break;
  case 0x83:
    m->kind = P25_LC_MOT_GRG_V_CH_UPDT;
    m->group = F(c, 24, 16);
    m->ch = CH(c, 40);
    break;
  case 0x84:
    as_tsbk(c, 24, 0x04, P25_MFID_MOTOROLA);
    break;
  case 0x91: // talkgroup, blocks, format, sequence; the 64-bit fragment from 72 starts with the SUID
    m->kind = P25_LC_MOT_ALIAS_HDR;
    m->group = F(c, 24, 16);
    m->block_count = F(c, 40, 8);
    m->alias_format = F(c, 48, 8);
    m->sequence = F(c, 64, 4);
    suid(c, 72);
    fragment(c, 72, 64);
    break;
  case 0x95: // block, sequence; a 100-bit fragment from 36
    m->kind = P25_LC_MOT_ALIAS_DATA;
    m->block = F(c, 24, 8);
    m->sequence = F(c, 32, 4);
    fragment(c, 36, 100);
    break;
  case 0xa3:
    as_tsbk(c, 24, 0x02, P25_MFID_MOTOROLA);
    break;
  case 0xa4:
    m->kind = P25_MOT_GRG_CH_GRANT;
    m->svc = F(c, 24, 8);
    m->ch = CH(c, 32);
    m->ch_b = CH(c, 48);
    m->has_b = true;
    m->group = F(c, 64, 16);
    m->src = F(c, 80, 24);
    break;
  case 0xa5:
    as_tsbk(c, 24, 0x03, P25_MFID_MOTOROLA);
    break;
  case 0xa6:
  case 0xa7:
    as_tsbk(c, 24, s->opcode == 0xa6 ? 0x06 : 0x07, P25_MFID_MOTOROLA);
    break;
  case 0xa8:
    m->kind = P25_MOT_ACK_RSP;
    m->aiv = B(c, 24);
    m->ex = B(c, 25);
    m->svc_type = F(c, 26, 6);
    m->src = F(c, 32, 24);
    m->tgt = F(c, 56, 24);
    break;
  case 0x82: case 0x87: case 0x8b: case 0x8f: case 0xbf:
    s->mac_kind = P25_MAC_OTHER;
    break;
  default:
    break;
  }
}

static void decode_harris(struct ctx const *c){
  struct p25_mac_struct *s = c->s;
  struct p25_msg *m = &s->msg;
  switch(s->opcode){
  case 0xa0:
  case 0xac:
    s->mac_kind = P25_MAC_HARRIS_DATA_GRANT;
    m->ch = CH(c, 32);
    m->tgt = F(c, 48, 24);
    if(s->opcode == 0xac)
      m->src = F(c, 72, 24);
    break;
  case 0xa8:
    s->mac_kind = P25_MAC_HARRIS_ALIAS;
    harris_alias(c);
    break;
  case 0xb0: // the TSBK layout after the vendor octets; a talkgroup target may list more
    as_tsbk(c, 24, 0x30, P25_MFID_HARRIS);
    if(m->regroup_opts & 0x40)
      for(int i = 0; i < 4 && 88 + 16 * i <= s->len * 8; i++)
        s->members[s->nmembers++] = F(c, 72 + 16 * i, 16);
    break;
  case 0x81: case 0x8f: case 0xaa:
    s->mac_kind = P25_MAC_OTHER;
    break;
  default:
    break;
  }
}

static void decode_struct(struct pdu_bits const *b, struct p25_mac_struct *s){
  struct ctx c = { b, s };
  struct p25_msg *m = &s->msg;
  memset(m, 0, sizeof *m);
  if(s->vendor == P25_MFID_MOTOROLA)
    decode_motorola(&c);
  else if(s->vendor == P25_MFID_HARRIS)
    decode_harris(&c);
  else if(!vendor_partition(s->opcode))
    decode_standard(&c);
  // else another manufacturer's: unknown
  m->family = P25_FAMILY_MAC;
  m->opcode = s->opcode;
  m->mfid = s->vendor;
  m->raw_len = s->raw_len < (int)sizeof m->raw ? s->raw_len : (int)sizeof m->raw;
  memcpy(m->raw, s->raw, m->raw_len);
}

int p25_mac_decode(struct p25_mac_pdu *pdu, enum p25_mac_chan chan, uint8_t const *octets, int nbits){
  if(pdu == NULL)
    return -1;
  memset(pdu, 0, sizeof *pdu);
  pdu->chan = chan;
  pdu->algid = P25_ALGID_CLEAR;
  if(octets == NULL || nbits < 8)
    return -1;
  struct pdu_bits b = { octets, nbits };
  pdu->type = get_field(&b, 0, 3);
  pdu->offset_4v = get_field(&b, 3, 3);
  if(chan == P25_MAC_LCCH)
    pdu->lcch_nac = get_field(&b, 152, 12);

  switch(pdu->type){
  case P25_MAC_PTT:
    for(int i = 0; i < 9; i++)
      pdu->mi[i] = get_field(&b, 8 + 8 * i, 8);
    pdu->algid = get_field(&b, 80, 8);
    pdu->kid = get_field(&b, 88, 16);
    pdu->src = get_field(&b, 104, 24);
    pdu->group = get_field(&b, 128, 16);
    return 0;
  case P25_MAC_END_PTT:
    pdu->nac = get_field(&b, 12, 12);
    pdu->src = get_field(&b, 104, 24);
    pdu->group = get_field(&b, 128, 16);
    return 0;
  case P25_MAC_SIGNAL:
  case P25_MAC_IDLE:
  case P25_MAC_ACTIVE:
  case P25_MAC_HANGTIME:
    break;
  default:
    return 0;
  }

  // Up to three structures from bit 8; a NULL INFORMATION opcode ends the list
  int const maxidx = max_index(chan);
  int offset = 8;
  for(int n = 0; n < 3 && offset + 8 <= maxidx && offset + 8 <= nbits; n++){
    uint8_t const op = get_field(&b, offset, 8);
    if(n > 0 && op == 0x00)
      break;
    struct p25_mac_struct *s = &pdu->s[pdu->nstruct++];
    s->opcode = op;
    s->offset = offset;
    s->len = struct_len(&b, maxidx, offset, op, &s->vendor);
    int k = s->len < P25_MAC_MAX_RAW ? s->len : P25_MAC_MAX_RAW;
    if(k > (nbits - offset) / 8)
      k = (nbits - offset) / 8;
    for(int i = 0; i < k; i++)
      s->raw[i] = get_field(&b, offset + 8 * i, 8);
    s->raw_len = k;
    decode_struct(&b, s);
    if(op == 0x00 || s->len <= 0)
      break;
    offset += s->len * 8;
  }
  return pdu->nstruct;
}

// Names

static char const *const Mac_kind_names[P25_MAC_KIND_COUNT] = {
  [P25_MAC_NULL] = "NULL",
  [P25_MAC_NULL_AZB] = "NULL_AZB",
  [P25_MAC_MULTI_FRAG] = "MULTI_FRAG",
  [P25_MAC_GRP_PAGING] = "GRP_PAGING",
  [P25_MAC_IND_PAGING] = "IND_PAGING",
  [P25_MAC_GRP_V_CH_GRANT_UPDT_MULT] = "GRP_V_CH_GRANT_UPDT_MULT",
  [P25_MAC_GRP_V_CH_GRANT_UPDT_MULT_EXP] = "GRP_V_CH_GRANT_UPDT_MULT_EXP",
  [P25_MAC_PWR_CTL] = "PWR_CTL",
  [P25_MAC_RELEASE] = "MAC_RELEASE",
  [P25_MAC_GRG_V_CH_USR] = "GRG_V_CH_USR",
  [P25_MAC_HARRIS_DATA_GRANT] = "HARRIS_DATA_GRANT",
  [P25_MAC_HARRIS_ALIAS] = "HARRIS_ALIAS",
  [P25_MAC_OTHER] = "OTHER",
};

char const *p25_mac_kind_name(struct p25_mac_struct const *s){
  if(s->mac_kind == P25_MAC_MSG)
    return p25_kind_name(s->msg.kind);
  if(s->mac_kind < 0 || s->mac_kind >= P25_MAC_KIND_COUNT)
    return "?";
  return Mac_kind_names[s->mac_kind];
}

char const *p25_mac_pdu_name(uint8_t type){
  static char const *const names[8] = {
    "signal", "ptt", "end_ptt", "idle", "active", "reserved5", "hangtime", "reserved7"
  };
  return names[type & 7];
}

char const *p25_mac_chan_name(enum p25_mac_chan chan){
  return chan == P25_MAC_FACCH ? "facch" : chan == P25_MAC_LCCH ? "lcch" : "sacch";
}

// Formatting

struct out {
  char *p;
  size_t left;
  int n;
};

static void put(struct out *o, char const *fmt, ...){
  va_list ap;
  va_start(ap, fmt);
  int k = vsnprintf(o->p, o->left, fmt, ap);
  va_end(ap);
  if(k < 0)
    return;
  o->n += k;
  size_t const used = (size_t)k < o->left ? (size_t)k : (o->left ? o->left - 1 : 0);
  o->p += used;
  o->left -= used;
}

static void put_hex(struct out *o, char const *key, uint8_t const *p, int len){
  put(o, " %s=", key);
  for(int i = 0; i < len; i++)
    put(o, "%02x", p[i]);
}

// A channel as p25_format() writes it: number, and frequency (and slot) when the plan knows it
static void put_chan(struct out *o, char const *suffix, struct p25_chan ch, struct p25_bandplan const *plan){
  put(o, " ch%s=%u-%u", suffix, ch.iden, ch.num);
  uint64_t dl;
  int slot;
  if(!p25_chan_freq(plan, ch, &dl, NULL, &slot))
    return;
  put(o, " freq%s=%llu.%06llu", suffix, (unsigned long long)(dl / 1000000), (unsigned long long)(dl % 1000000));
  struct p25_band const *b = &plan->band[ch.iden];
  if(b->tdma && b->slots > 1)
    put(o, " slot%s=%d", suffix, slot);
}

// Text that came off the air: printable ASCII, anything else as '?'
static void put_text(struct out *o, char const *key, char const *s){
  put(o, " %s=\"", key);
  for(; *s; s++)
    put(o, "%c", ((uint8_t)*s >= 0x20 && (uint8_t)*s < 0x7f && *s != '"') ? *s : '?');
  put(o, "\"");
}

// A kind p25msg knows: its own formatter writes the fields
static void put_msg(struct out *o, struct p25_mac_struct const *s, struct p25_bandplan const *plan){
  struct p25_msg const *m = &s->msg;
  switch(m->kind){
  case P25_LC_MOT_ALIAS_HDR:
    put(o, " mfid=0x%02x opcode=0x%02x", m->mfid, m->opcode);
    put(o, " tg=%u blocks=%u seq=%u format=%u", m->group, m->block_count, m->sequence, m->alias_format);
    return;
  case P25_LC_MOT_ALIAS_DATA:
    put(o, " mfid=0x%02x opcode=0x%02x", m->mfid, m->opcode);
    put(o, " block=%u seq=%u", m->block, m->sequence);
    put_hex(o, "data", s->raw + 4, s->raw_len > 4 ? s->raw_len - 4 : 0);
    return;
  case P25_MOT_GRG_ADD:
  case P25_MOT_GRG_DEL:
    put(o, " mfid=0x%02x opcode=0x%02x sg=%u tgs=", m->mfid, m->opcode, m->group);
    for(int i = 0; i < s->nmembers; i++)
      put(o, i ? ",%u" : "%u", s->members[i]);
    return;
  case P25_TELE_INT_ANS_REQ:
    put(o, " unit=%u digits=%s", m->tgt, s->digits);
    return;
  case P25_UNKNOWN:
    put(o, " mfid=0x%02x opcode=0x%02x len=%d", m->mfid, m->opcode, s->len);
    put_hex(o, "raw", s->raw, s->raw_len);
    return;
  default:
    break;
  }
  // p25_format() reads a TSBK the same way; drop its "TSBK <kind>"
  struct p25_msg t = *m;
  t.family = P25_FAMILY_TSBK;
  char line[512];
  p25_format(line, sizeof line, &t, plan);
  size_t const skip = 5 + strlen(p25_kind_name(m->kind));
  put(o, "%s", strlen(line) >= skip ? line + skip : "");
  if(m->has_b && (m->kind == P25_GRP_V_CH_GRANT || m->kind == P25_UU_V_CH_GRANT || m->kind == P25_UU_V_CH_GRANT_UPDT
                  || m->kind == P25_TELE_INT_CH_GRANT || m->kind == P25_TELE_INT_CH_GRANT_UPDT
                  || m->kind == P25_MOT_GRG_CH_GRANT))
    put_chan(o, "_ul", m->ch_b, plan);
  if(m->kind == P25_TIME_DATE_ANN)
    put(o, " sec=%u", s->second);
  if(m->kind == P25_HARRIS_GRG_EXENC_CMD && s->nmembers > 1){
    put(o, " tgs=");
    for(int i = 0; i < s->nmembers; i++)
      put(o, i ? ",%u" : "%u", s->members[i]);
  }
  // WACN and system p25_format() has no place for
  if(s->has_suid)
    put(o, " suid=%05x.%03x.%u", m->wacn, m->sysid, s->suid);
  else if(s->opcode == 0xfe)
    put(o, " wacn=0x%05x", m->wacn);
  else if(s->opcode == 0xf3 || s->opcode == 0xe8 || s->opcode == 0x76)
    put(o, " wacn=0x%05x sys=0x%03x", m->wacn, m->sysid);
}

int p25_mac_format(char *buf, size_t size, struct p25_mac_pdu const *pdu, int index,
                   struct p25_bandplan const *plan){
  struct out o = { .p = buf, .left = size, .n = 0 };
  if(size > 0)
    buf[0] = '\0';
  char const *chan = p25_mac_chan_name(pdu->chan);
  if(index < 0 || index >= pdu->nstruct || pdu->type == P25_MAC_PTT || pdu->type == P25_MAC_END_PTT){
    switch(pdu->type){
    case P25_MAC_PTT:
      put(&o, "MAC PTT chan=%s tg=%u src=%u algid=0x%02x kid=0x%04x", chan, pdu->group, pdu->src, pdu->algid, pdu->kid);
      if(pdu->algid != P25_ALGID_CLEAR)
        put(&o, " enc=1");
      put_hex(&o, "mi", pdu->mi, 9);
      break;
    case P25_MAC_END_PTT:
      put(&o, "MAC END_PTT chan=%s tg=%u src=%u nac=0x%03x", chan, pdu->group, pdu->src, pdu->nac);
      break;
    default:
      put(&o, "MAC PDU chan=%s pdu=%s offset=%u structures=%d", chan, p25_mac_pdu_name(pdu->type), pdu->offset_4v,
          pdu->nstruct);
      break;
    }
    if(pdu->chan == P25_MAC_LCCH)
      put(&o, " nac=0x%03x", pdu->lcch_nac);
    return o.n;
  }

  struct p25_mac_struct const *s = &pdu->s[index];
  struct p25_msg const *m = &s->msg;
  put(&o, "MAC %s chan=%s pdu=%s", p25_mac_kind_name(s), chan, p25_mac_pdu_name(pdu->type));
  switch(s->mac_kind){
  case P25_MAC_MSG:
    put_msg(&o, s, plan);
    break;
  case P25_MAC_NULL:
  case P25_MAC_NULL_AZB:
    break;
  case P25_MAC_GRP_V_CH_GRANT_UPDT_MULT:
  case P25_MAC_GRP_V_CH_GRANT_UPDT_MULT_EXP:
    for(int i = 0; i < s->ngrants; i++){
      char sfx[4] = "";
      if(i)
        snprintf(sfx, sizeof sfx, "_%c", 'a' + i);
      put(&o, " tg%s=%u svc%s=0x%02x", sfx, s->grant[i].group, sfx, s->grant[i].svc);
      put_chan(&o, sfx, s->grant[i].ch, plan);
      if(s->mac_kind == P25_MAC_GRP_V_CH_GRANT_UPDT_MULT_EXP){
        char ul[8];
        snprintf(ul, sizeof ul, "%s_ul", sfx);
        put_chan(&o, ul, s->grant[i].ch_ul, plan);
      }
    }
    break;
  case P25_MAC_GRP_PAGING:
  case P25_MAC_IND_PAGING:
    put(&o, " %s=", s->mac_kind == P25_MAC_GRP_PAGING ? "tgs" : "units");
    for(int i = 0; i < s->npaged; i++)
      put(&o, i ? ",%u" : "%u", s->paged[i]);
    break;
  case P25_MAC_PWR_CTL:
    put(&o, " tgt=%u rf_level=%u ber=%u", m->tgt, s->rf_level, s->ber);
    break;
  case P25_MAC_RELEASE:
    put(&o, " tgt=%u forced=%d audio=%d nac=0x%03x", m->tgt, s->forced, s->audio, s->nac);
    break;
  case P25_MAC_GRG_V_CH_USR:
    put(&o, " sg=%u src=%u", m->group, m->src);
    break;
  case P25_MAC_HARRIS_DATA_GRANT:
    put(&o, " mfid=0x%02x opcode=0x%02x tgt=%u", s->vendor, s->opcode, m->tgt);
    if(s->opcode == 0xac)
      put(&o, " src=%u", m->src);
    put_chan(&o, "", m->ch, plan);
    break;
  case P25_MAC_HARRIS_ALIAS:
    put(&o, " mfid=0x%02x opcode=0x%02x", s->vendor, s->opcode);
    put_text(&o, "alias", s->alias);
    break;
  case P25_MAC_MULTI_FRAG:
  case P25_MAC_OTHER:
  default:
    put(&o, " mfid=0x%02x opcode=0x%02x len=%d", s->vendor, s->opcode, s->len);
    put_hex(&o, "raw", s->raw, s->raw_len);
    break;
  }
  if(s->has_nac && s->mac_kind == P25_MAC_MSG)
    put(&o, " nac=0x%03x", s->nac);
  return o.n;
}
