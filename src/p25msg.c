// P25 Phase 1 message decoding: TSBKs (TIA-102.AABC), link control (TIA-102.AABF),
// alternate multi-block trunking and packet data headers (TIA-102.BAAA), HDU and LDU2
// encryption sync, the identifier (band plan) table, and one-line log formatting
// Copyright 2026, Matthew Kaufman, KA6SQG

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "p25msg.h"

// Bits [off, off+len) of an MSB-first octet string, len <= 32
static uint32_t field(uint8_t const *p, int off, int len){
  uint32_t v = 0;
  for(int i = off; i < off + len; i++)
    v = (v << 1) | ((p[i >> 3] >> (7 - (i & 7))) & 1);
  return v;
}
static bool bit(uint8_t const *p, int off){
  return (p[off >> 3] >> (7 - (off & 7))) & 1;
}
static struct p25_chan chan(uint8_t const *p, int off){
  struct p25_chan c = { .iden = field(p, off, 4), .num = field(p, off + 4, 12) };
  return c;
}
static void keep_raw(struct p25_msg *msg, uint8_t const *p, int len){
  if(len > (int)sizeof msg->raw)
    len = sizeof msg->raw;
  memcpy(msg->raw, p, len);
  msg->raw_len = len;
}

// Identifier updates (TIA-102.AABC IDEN_UP, IDEN_UP_TDMA, IDEN_UP_VU)
static void iden_fdma(struct p25_msg *msg, uint8_t const *p){
  msg->iden = field(p, 16, 4);
  msg->bw_hz = field(p, 20, 9) * 125;
  int64_t off = (int64_t)field(p, 30, 8) * 250000;  // sign bit 29: 1 positive
  msg->tx_offset_hz = bit(p, 29) ? off : -off;
  msg->spacing_hz = field(p, 38, 10) * 125;
  msg->base_hz = (uint64_t)field(p, 48, 32) * 5;
  msg->iden_slots = 1;
}
// TDMA and VHF/UHF share a layout: 4-bit type, 13-bit offset in channel spacings
static void iden_13bit(struct p25_msg *msg, uint8_t const *p){
  msg->iden = field(p, 16, 4);
  msg->iden_type = field(p, 20, 4);
  msg->spacing_hz = field(p, 38, 10) * 125;
  int64_t off = (int64_t)field(p, 25, 13) * msg->spacing_hz;
  msg->tx_offset_hz = bit(p, 24) ? off : -off;
  msg->base_hz = (uint64_t)field(p, 48, 32) * 5;
}
// TDMA channel types: slots per channel and bandwidth
static const struct { uint8_t slots; uint16_t bw; } Tdma_type[16] = {
  [0] = { 1, 12500 }, [1] = { 1, 12500 }, [2] = { 1, 6250 }, [3] = { 2, 12500 },
  [4] = { 4, 25000 }, [5] = { 2, 12500 },
};
static void iden_tdma(struct p25_msg *msg, uint8_t const *p){
  iden_13bit(msg, p);
  int t = msg->iden_type;
  msg->iden_slots = Tdma_type[t].slots ? Tdma_type[t].slots : 1;
  msg->bw_hz = Tdma_type[t].bw;
  msg->iden_tdma = (t == 3 || t == 4 || t == 5);
}
static void iden_vu(struct p25_msg *msg, uint8_t const *p){
  iden_13bit(msg, p);
  msg->bw_hz = msg->iden_type == 4 ? 6250 : msg->iden_type == 5 ? 12500 : 0;
  msg->iden_slots = 1;
}

// Two talkgroup/channel pairs; the second only if it names another group
static void two_grants(struct p25_msg *msg, uint8_t const *p){
  msg->ch = chan(p, 16);
  msg->group = field(p, 32, 16);
  msg->ch_b = chan(p, 48);
  msg->group_b = field(p, 64, 16);
  msg->has_b = msg->group_b != 0 && msg->group_b != msg->group;
}
// Response layout: AIV, EX, service type, reason, additional info, target
static void response(struct p25_msg *msg, uint8_t const *p){
  msg->aiv = bit(p, 16);
  msg->ex = bit(p, 17);
  msg->svc_type = field(p, 18, 6);
  msg->reason = field(p, 24, 8);
  msg->info = field(p, 32, 24);
  msg->tgt = field(p, 56, 24);
}

static void tsbk_standard(struct p25_msg *msg, uint8_t const *p){
  switch(msg->opcode){
  case 0x00:
    msg->kind = P25_GRP_V_CH_GRANT;
    msg->svc = field(p, 16, 8);
    msg->ch = chan(p, 24);
    msg->group = field(p, 40, 16);
    msg->src = field(p, 56, 24);
    break;
  case 0x02:
    msg->kind = P25_GRP_V_CH_GRANT_UPDT;
    two_grants(msg, p);
    break;
  case 0x03:
    msg->kind = P25_GRP_V_CH_GRANT_UPDT_EXP;
    msg->svc = field(p, 16, 8);
    msg->ch = chan(p, 32);
    msg->ch_b = chan(p, 48);
    msg->has_b = true;
    msg->group = field(p, 64, 16);
    break;
  case 0x04:
  case 0x06: // the update has the grant's layout
    msg->kind = msg->opcode == 0x04 ? P25_UU_V_CH_GRANT : P25_UU_V_CH_GRANT_UPDT;
    msg->ch = chan(p, 16);
    msg->tgt = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x05:
    msg->kind = P25_UU_ANS_REQ;
    msg->svc = field(p, 16, 8);
    msg->tgt = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x08:
  case 0x09:
    msg->kind = msg->opcode == 0x08 ? P25_TELE_INT_CH_GRANT : P25_TELE_INT_CH_GRANT_UPDT;
    msg->svc = field(p, 16, 8);
    msg->ch = chan(p, 24);
    msg->timer = field(p, 40, 16);
    msg->tgt = field(p, 56, 24);
    break;
  case 0x0a:
    msg->kind = P25_TELE_INT_ANS_REQ;
    msg->tgt = field(p, 16, 24);
    msg->timer = field(p, 40, 16);
    break;
  case 0x10:
    msg->kind = P25_IND_DATA_CH_GRANT;
    msg->ch = chan(p, 16);
    msg->tgt = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x11:
    msg->kind = P25_GRP_DATA_CH_GRANT;
    msg->svc = field(p, 16, 8);
    msg->ch = chan(p, 24);
    msg->group = field(p, 40, 16);
    msg->src = field(p, 56, 24);
    break;
  case 0x12:
    msg->kind = P25_GRP_DATA_CH_ANN;
    break;
  case 0x13:
    msg->kind = P25_GRP_DATA_CH_ANN_EXP;
    break;
  case 0x14:
    msg->kind = P25_SN_DATA_CH_GRANT;
    msg->svc = field(p, 16, 8);
    msg->ch = chan(p, 24);
    msg->ch_b = chan(p, 40);
    msg->has_b = msg->ch_b.num != 4095; // channel 4095: no uplink
    msg->tgt = field(p, 56, 24);
    break;
  case 0x15:
    msg->kind = P25_SN_DATA_PAGE_REQ;
    break;
  case 0x16:
    msg->kind = P25_SN_DATA_CH_ANN_EXP;
    msg->svc = field(p, 16, 8);
    msg->autonomous = bit(p, 24);
    msg->requested = bit(p, 25);
    msg->ch = chan(p, 32);
    msg->ch_b = chan(p, 48);
    msg->has_b = true;
    msg->data_access = field(p, 64, 16);
    break;
  case 0x18:
    msg->kind = P25_STS_UPDT;
    msg->unit_status = field(p, 16, 8);
    msg->user_status = field(p, 24, 8);
    msg->tgt = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x1a:
    msg->kind = P25_STS_Q;
    msg->tgt = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x1c:
    msg->kind = P25_MSG_UPDT;
    msg->message = field(p, 16, 16);
    msg->tgt = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x1d: // source before target, unlike most
    msg->kind = P25_RAD_MON_CMD;
    msg->tx_mult = field(p, 30, 2);
    msg->src = field(p, 32, 24);
    msg->tgt = field(p, 56, 24);
    break;
  case 0x1f:
    msg->kind = P25_CALL_ALRT;
    msg->tgt = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x20: // additional information (32-55) is the source address
    msg->kind = P25_ACK_RSP_FNE;
    msg->aiv = bit(p, 16);
    msg->ex = bit(p, 17);
    msg->svc_type = field(p, 18, 6);
    msg->src = field(p, 32, 24);
    msg->tgt = field(p, 56, 24);
    break;
  case 0x21:
    msg->kind = P25_QUE_RSP;
    response(msg, p);
    break;
  case 0x24:
    msg->kind = P25_EXT_FNCT_CMD;
    msg->function = field(p, 16, 16);
    msg->args = field(p, 32, 24);
    msg->tgt = field(p, 56, 24);
    break;
  case 0x27:
    msg->kind = P25_DENY_RSP;
    response(msg, p);
    break;
  case 0x28: // LG, response, announcement group, group, target
    msg->kind = P25_GRP_AFF_RSP;
    msg->local_global = bit(p, 16);
    msg->response = field(p, 22, 2);
    msg->group_b = field(p, 24, 16);
    msg->group = field(p, 40, 16);
    msg->tgt = field(p, 56, 24);
    break;
  case 0x29:
    msg->kind = P25_SCCB_EXP;
    msg->rfss = field(p, 16, 8);
    msg->site = field(p, 24, 8);
    msg->ch = chan(p, 32);
    msg->ch_b = chan(p, 56);
    msg->has_b = true;
    msg->svc_class = field(p, 72, 8);
    break;
  case 0x2a:
    msg->kind = P25_GRP_AFF_Q;
    msg->tgt = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x2b:
    msg->kind = P25_LOC_REG_RSP;
    msg->response = field(p, 22, 2);
    msg->group = field(p, 24, 16);
    msg->rfss = field(p, 40, 8);
    msg->site = field(p, 48, 8);
    msg->tgt = field(p, 56, 24);
    break;
  case 0x2c: // source ID in info, source address in src
    msg->kind = P25_U_REG_RSP;
    msg->response = field(p, 18, 2);
    msg->sysid = field(p, 20, 12);
    msg->info = field(p, 32, 24);
    msg->src = field(p, 56, 24);
    break;
  case 0x2d:
    msg->kind = P25_U_REG_CMD;
    msg->tgt = field(p, 16, 24);
    break;
  case 0x2e:
    msg->kind = P25_AUTH_CMD;
    msg->tgt = field(p, 16, 24);
    break;
  case 0x2f: // WACN, system, source
    msg->kind = P25_U_DE_REG_ACK;
    msg->wacn = field(p, 24, 20);
    msg->sysid = field(p, 44, 12);
    msg->src = field(p, 56, 24);
    break;
  case 0x30: // TIA-102.AABB time synchronisation
    msg->kind = P25_SYNC_BCST;
    msg->time_unlocked = bit(p, 29);
    msg->uslot_unlocked = bit(p, 30);
    msg->leap = field(p, 31, 2);
    msg->lto_valid_bit = bit(p, 33);
    msg->lto_negative = bit(p, 34);
    msg->lto_hours = field(p, 35, 4);
    msg->lto_half = bit(p, 39);
    msg->year = 2000 + field(p, 40, 7);
    msg->month = field(p, 47, 4);
    msg->day = field(p, 51, 5);
    msg->hour = field(p, 56, 5);
    msg->minute = field(p, 61, 6);
    msg->microslots = field(p, 67, 13);
    break;
  case 0x31:
    msg->kind = P25_AUTH_DMAND;
    break;
  case 0x32:
    msg->kind = P25_AUTH_FNE_RESP;
    break;
  case 0x33:
    msg->kind = P25_IDEN_UP_TDMA;
    iden_tdma(msg, p);
    break;
  case 0x34:
    msg->kind = P25_IDEN_UP_VU;
    iden_vu(msg, p);
    break;
  case 0x35:
    msg->kind = P25_TIME_DATE_ANN;
    msg->year = 2000 + field(p, 16, 7);
    msg->month = field(p, 23, 4);
    msg->day = field(p, 27, 5);
    msg->hour = field(p, 32, 5);
    msg->minute = field(p, 37, 6);
    break;
  case 0x36:
    msg->kind = P25_ROAM_ADDR_CMD;
    msg->tgt = field(p, 16, 24);
    break;
  case 0x37:
    msg->kind = P25_ROAM_ADDR_UPDT;
    break;
  case 0x38:
    msg->kind = P25_SYS_SRV_BCST;
    msg->avail_svc = field(p, 24, 24);
    msg->supp_svc = field(p, 48, 24);
    msg->req_priority = field(p, 72, 8);
    break;
  case 0x39:
    msg->kind = P25_SCCB;
    msg->rfss = field(p, 16, 8);
    msg->site = field(p, 24, 8);
    msg->ch = chan(p, 32);
    msg->svc_class = field(p, 48, 8);
    msg->ch_b = chan(p, 56);
    msg->svc_class_b = field(p, 72, 8);
    msg->has_b = msg->ch_b.num != 0 && msg->ch_b.num != msg->ch.num;
    break;
  case 0x3a:
    msg->kind = P25_RFSS_STS_BCST;
    msg->lra = field(p, 16, 8);
    msg->site_flags = bit(p, 27);
    msg->sysid = field(p, 28, 12);
    msg->rfss = field(p, 40, 8);
    msg->site = field(p, 48, 8);
    msg->ch = chan(p, 56);
    msg->svc_class = field(p, 72, 8);
    break;
  case 0x3b:
    msg->kind = P25_NET_STS_BCST;
    msg->lra = field(p, 16, 8);
    msg->wacn = field(p, 24, 20);
    msg->sysid = field(p, 44, 12);
    msg->ch = chan(p, 56);
    msg->svc_class = field(p, 72, 8);
    break;
  case 0x3c:
    msg->kind = P25_ADJ_STS_BCST;
    msg->lra = field(p, 16, 8);
    msg->site_flags = field(p, 24, 4);
    msg->sysid = field(p, 28, 12);
    msg->rfss = field(p, 40, 8);
    msg->site = field(p, 48, 8);
    msg->ch = chan(p, 56);
    msg->svc_class = field(p, 72, 8);
    break;
  case 0x3d:
    msg->kind = P25_IDEN_UP;
    iden_fdma(msg, p);
    break;
  case 0x3e:
    msg->kind = P25_ADJ_STS_BCST_UNCOORD;
    break;
  default: // reserved
    break;
  }
}

// Motorola base station ID: six-bit characters, A-Z 1-26, 0-9 27-36, '-' 37, '/' 38, 0 ends
static void cwid(char *out, uint8_t const *p){
  int n = 0;
  for(int i = 0; i < 8; i++){
    int c = field(p, 16 + 6 * i, 6);
    if(c == 0)
      break;
    out[n++] = c <= 26 ? 'A' + c - 1 : c <= 36 ? '0' + c - 27 : c == 37 ? '-' : c == 38 ? '/' : '?';
  }
  out[n] = '\0';
}

static void tsbk_motorola(struct p25_msg *msg, uint8_t const *p){
  switch(msg->opcode){
  case 0x00:
  case 0x01: // supergroup and up to three members, each new, nonzero and not the supergroup
    msg->kind = msg->opcode == 0x00 ? P25_MOT_GRG_ADD : P25_MOT_GRG_DEL;
    msg->group = field(p, 16, 16);
    for(int i = 0; i < 3; i++){
      uint16_t g = field(p, 32 + 16 * i, 16);
      if(g == 0 || g == msg->group)
        continue;
      bool dup = false;
      for(int j = 0; j < msg->nmembers; j++)
        dup |= msg->members[j] == g;
      if(!dup)
        msg->members[msg->nmembers++] = g;
    }
    break;
  case 0x02:
    msg->kind = P25_MOT_GRG_CH_GRANT;
    msg->svc = field(p, 16, 8);
    msg->ch = chan(p, 24);
    msg->group = field(p, 40, 16);
    msg->src = field(p, 56, 24);
    break;
  case 0x03:
    msg->kind = P25_MOT_GRG_CH_UPDT;
    two_grants(msg, p);
    break;
  case 0x04:
    msg->kind = P25_MOT_EXT_FNCT_CMD;
    msg->ext_class = field(p, 16, 8);
    msg->ext_operand = field(p, 24, 8);
    msg->args = field(p, 32, 24);
    msg->tgt = field(p, 56, 24);
    break;
  case 0x05:
    msg->kind = P25_MOT_TRAFFIC_CH_ID;
    msg->tch1 = field(p, 16, 12);
    msg->tch2 = field(p, 28, 12);
    break;
  case 0x06:
  case 0x07: // the standard response layout
    msg->kind = msg->opcode == 0x06 ? P25_MOT_QUE_RSP : P25_MOT_DENY_RSP;
    response(msg, p);
    break;
  case 0x08:
    msg->kind = P25_MOT_ACK_RSP;
    msg->aiv = bit(p, 16);
    msg->ex = bit(p, 17);
    msg->svc_type = field(p, 18, 6);
    msg->src = field(p, 32, 24);
    msg->tgt = field(p, 56, 24);
    break;
  case 0x09:
    msg->kind = P25_MOT_SYS_LOADING;
    msg->load = field(p, 16, 8);
    msg->capacity = field(p, 24, 8);
    break;
  case 0x0a:
    msg->kind = P25_MOT_EMERG_ALRM;
    msg->group = field(p, 40, 16);
    msg->src = field(p, 56, 24);
    break;
  case 0x0b:
    msg->kind = P25_MOT_BSI;
    cwid(msg->cwid, p);
    msg->ch = chan(p, 64);
    break;
  case 0x0e:
    msg->kind = P25_MOT_CC_SHUTDOWN;
    msg->shutdown_min = field(p, 16, 16);
    break;
  case 0x16:
    msg->kind = P25_MOT_TDMA_DATA_CH;
    msg->ch = chan(p, 32);
    msg->ch_b = chan(p, 48);
    msg->has_b = true;
    break;
  default:
    break;
  }
}

static void tsbk_harris(struct p25_msg *msg, uint8_t const *p){
  if(msg->opcode != 0x30)
    return;
  // Group regroup explicit encryption command. Options: 0x80 simulselect (else patch),
  // 0x40 talkgroup target (else a radio), 0x20 activate, 0x1f supergroup sequence number
  msg->kind = P25_HARRIS_GRG_EXENC_CMD;
  msg->regroup_opts = field(p, 16, 8);
  msg->group = field(p, 24, 16);
  msg->key_id = field(p, 40, 16);
  msg->tgt = field(p, 56, 24);
  if(msg->regroup_opts & 0x40){ // a talkgroup target: algorithm, then the talkgroup
    msg->alg_id = field(p, 56, 8);
    msg->group_b = field(p, 64, 16);
  }
}

int p25_decode_tsbk(struct p25_msg *msg, uint8_t const tsbk[12]){
  memset(msg, 0, sizeof *msg);
  if(tsbk == NULL)
    return -1;
  msg->family = P25_FAMILY_TSBK;
  msg->last_block = bit(tsbk, 0);
  msg->protect = bit(tsbk, 1);
  msg->opcode = field(tsbk, 2, 6);
  msg->mfid = tsbk[1];
  keep_raw(msg, tsbk, 12);
  switch(msg->mfid){
  case P25_MFID_STD:
  case P25_MFID_STD1:
    tsbk_standard(msg, tsbk);
    break;
  case P25_MFID_MOTOROLA:
    tsbk_motorola(msg, tsbk);
    break;
  case P25_MFID_HARRIS:
    tsbk_harris(msg, tsbk);
    break;
  default: // another manufacturer's opcodes
    break;
  }
  return 0;
}

// Link control (TIA-102.AABF): bit 0 protected, bit 1 standard format (implicit MFID),
// opcode 2-7, MFID 8-15 when bit 1 is clear
static enum p25_kind lc_standard_kind(int opcode){
  switch(opcode){
  case 0x00: return P25_LC_GRP_V_CH_USR;
  case 0x02: return P25_GRP_V_CH_GRANT_UPDT;
  case 0x03: return P25_LC_UU_V_CH_USR;
  case 0x04: return P25_GRP_V_CH_GRANT_UPDT_EXP;
  case 0x05: return P25_UU_ANS_REQ;
  case 0x06: return P25_LC_TEL_INT_V_CH_USR;
  case 0x07: return P25_TELE_INT_ANS_REQ;
  case 0x09: return P25_LC_SRC_ID_EXT;
  case 0x0a: return P25_LC_UU_V_CH_USR_EXT;
  case 0x0f: return P25_LC_CALL_TRM;
  case 0x10: return P25_GRP_AFF_Q;
  case 0x11: return P25_U_REG_CMD;
  case 0x13: return P25_STS_Q;
  case 0x14: return P25_STS_UPDT;
  case 0x15: return P25_MSG_UPDT;
  case 0x16: return P25_CALL_ALRT;
  case 0x17: return P25_EXT_FNCT_CMD;
  case 0x20: return P25_SYS_SRV_BCST;
  case 0x21: return P25_SCCB;
  case 0x22: return P25_ADJ_STS_BCST;
  case 0x23: return P25_RFSS_STS_BCST;
  case 0x24: return P25_NET_STS_BCST;
  case 0x26: return P25_SCCB_EXP;
  case 0x27: return P25_ADJ_STS_BCST_EXP;
  case 0x28: return P25_RFSS_STS_BCST_EXP;
  case 0x29: return P25_NET_STS_BCST_EXP;
  // authentication, channel identifier updates, extended-source forms, protection parameters
  case 0x12: case 0x18: case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x25: case 0x2a:
    return P25_LC_OTHER;
  default: return P25_UNKNOWN;
  }
}
static enum p25_kind lc_motorola_kind(int opcode){
  switch(opcode){
  case 0x00: return P25_LC_MOT_GRG_V_CH_USR;
  case 0x01: return P25_LC_MOT_GRG_V_CH_UPDT;
  case 0x02: return P25_LC_MOT_FAILSOFT;
  case 0x03: return P25_MOT_GRG_ADD;
  case 0x04: return P25_MOT_GRG_DEL;
  case 0x06: return P25_LC_MOT_UNIT_GPS;
  case 0x0a: return P25_MOT_EMERG_ALRM;
  case 0x0f: return P25_LC_MOT_TALK_COMPLETE;
  case 0x15: return P25_LC_MOT_ALIAS_HDR;
  case 0x17: return P25_LC_MOT_ALIAS_DATA;
  default: return P25_UNKNOWN;
  }
}
static enum p25_kind lc_harris_kind(int opcode){
  switch(opcode){
  case 0x0a: return P25_LC_HARRIS_RETURN_CC;
  case 0x2a: return P25_LC_HARRIS_GPS1;
  case 0x2b: return P25_LC_HARRIS_GPS2;
  case 0x32: case 0x33: case 0x34: case 0x35: return P25_LC_HARRIS_ALIAS;
  default: return P25_UNKNOWN;
  }
}

int p25_decode_lc(struct p25_msg *msg, uint8_t const lc[9], bool terminator){
  memset(msg, 0, sizeof *msg);
  if(lc == NULL)
    return -1;
  uint8_t const *p = lc;
  msg->family = terminator ? P25_FAMILY_TDULC : P25_FAMILY_LC;
  msg->protect = bit(p, 0);
  msg->sf = bit(p, 1);
  msg->opcode = field(p, 2, 6);
  msg->mfid = msg->sf ? P25_MFID_STD : p[1];
  keep_raw(msg, p, 9);
  switch(msg->mfid){
  case P25_MFID_MOTOROLA:
    msg->kind = lc_motorola_kind(msg->opcode);
    break;
  case P25_MFID_HARRIS:
    msg->kind = lc_harris_kind(msg->opcode);
    break;
  case P25_MFID_STD:
  case P25_MFID_STD1:
    msg->kind = lc_standard_kind(msg->opcode);
    break;
  default:
    msg->kind = P25_UNKNOWN;
    break;
  }
  if(msg->protect)
    return 0; // the rest is encrypted

  switch(msg->kind){
  case P25_LC_GRP_V_CH_USR:
  case P25_LC_MOT_GRG_V_CH_USR:
    msg->svc = field(p, 16, 8);
    msg->group = field(p, 32, 16);
    msg->src = field(p, 48, 24);
    break;
  case P25_GRP_V_CH_GRANT_UPDT:
    msg->ch = chan(p, 8);
    msg->group = field(p, 24, 16);
    msg->ch_b = chan(p, 40);
    msg->group_b = field(p, 56, 16);
    msg->has_b = msg->ch_b.num != 0 && msg->group != msg->group_b;
    break;
  case P25_LC_UU_V_CH_USR:
    msg->svc = field(p, 16, 8);
    msg->tgt = field(p, 24, 24);
    msg->src = field(p, 48, 24);
    break;
  case P25_GRP_V_CH_GRANT_UPDT_EXP:
    msg->svc = field(p, 16, 8);
    msg->group = field(p, 24, 16);
    msg->ch = chan(p, 40);   // downlink
    msg->ch_b = chan(p, 56); // uplink
    msg->has_b = true;
    break;
  case P25_LC_TEL_INT_V_CH_USR:
    msg->svc = field(p, 16, 8);
    msg->call_timer_ms = field(p, 32, 16) * 100;
    msg->tgt = field(p, 48, 24);
    break;
  case P25_LC_UU_V_CH_USR_EXT: // service options in octet 1; the source is in an extension LC
    msg->svc = field(p, 8, 8);
    msg->tgt = field(p, 24, 24);
    break;
  case P25_LC_CALL_TRM:
  case P25_LC_MOT_TALK_COMPLETE:
    msg->address = field(p, 48, 24);
    break;
  case P25_UU_ANS_REQ:
  case P25_GRP_AFF_Q:
  case P25_CALL_ALRT:
    msg->tgt = field(p, 24, 24);
    msg->src = field(p, 48, 24);
    break;
  case P25_STS_UPDT:
    msg->unit_status = field(p, 8, 8);
    msg->user_status = field(p, 16, 8);
    msg->tgt = field(p, 24, 24);
    msg->src = field(p, 48, 24);
    break;
  case P25_MSG_UPDT:
    msg->message = field(p, 8, 16);
    msg->tgt = field(p, 24, 24);
    msg->src = field(p, 48, 24);
    break;
  case P25_LC_MOT_GRG_V_CH_UPDT:
    msg->svc = field(p, 16, 8);
    msg->group = field(p, 24, 16);
    msg->ch = chan(p, 56);
    break;
  case P25_SYS_SRV_BCST:
    msg->avail_svc = field(p, 24, 24);
    msg->supp_svc = field(p, 48, 24);
    break;
  case P25_SCCB:
    msg->rfss = field(p, 8, 8);
    msg->site = field(p, 16, 8);
    msg->ch = chan(p, 24);
    msg->svc_class = field(p, 40, 8);
    msg->ch_b = chan(p, 48);
    msg->svc_class_b = field(p, 64, 8);
    msg->has_b = msg->ch_b.num != 0;
    break;
  case P25_ADJ_STS_BCST:
  case P25_RFSS_STS_BCST:
    msg->lra = field(p, 8, 8);
    msg->sysid = field(p, 20, 12);
    msg->rfss = field(p, 32, 8);
    msg->site = field(p, 40, 8);
    msg->ch = chan(p, 48);
    msg->svc_class = field(p, 64, 8);
    break;
  case P25_NET_STS_BCST:
    msg->wacn = field(p, 16, 20);
    msg->sysid = field(p, 36, 12);
    msg->ch = chan(p, 48);
    msg->svc_class = field(p, 64, 8);
    break;
  case P25_SCCB_EXP:
    msg->rfss = field(p, 8, 8);
    msg->site = field(p, 16, 8);
    msg->ch = chan(p, 24);
    msg->ch_b = chan(p, 40);
    msg->has_b = msg->ch_b.num != 0;
    msg->svc_class = field(p, 56, 8);
    break;
  case P25_ADJ_STS_BCST_EXP:
    msg->lra = field(p, 8, 8);
    msg->ch = chan(p, 16);
    msg->rfss = field(p, 32, 8);
    msg->site = field(p, 40, 8);
    msg->ch_b = chan(p, 48);
    msg->has_b = msg->ch_b.num != 0;
    msg->svc_class = field(p, 64, 8);
    break;
  case P25_RFSS_STS_BCST_EXP: // uplink first
    msg->lra = field(p, 8, 8);
    msg->ch_b = chan(p, 16);
    msg->has_b = msg->ch_b.num != 0;
    msg->rfss = field(p, 32, 8);
    msg->site = field(p, 40, 8);
    msg->ch = chan(p, 48);
    msg->svc_class = field(p, 64, 8);
    break;
  case P25_NET_STS_BCST_EXP:
    msg->wacn = field(p, 8, 20);
    msg->sysid = field(p, 28, 12);
    msg->ch = chan(p, 40);
    msg->ch_b = chan(p, 56);
    msg->has_b = msg->ch_b.num != 0;
    break;
  case P25_MOT_GRG_ADD:
  case P25_MOT_GRG_DEL:
    msg->group = field(p, 16, 16);
    msg->members[0] = field(p, 32, 16);
    msg->members[1] = field(p, 48, 16);
    msg->nmembers = 2;
    break;
  case P25_LC_MOT_UNIT_GPS:
    {
      double const scale = 1.0 / 0x7fffff;
      msg->latitude = field(p, 25, 23) * 90.0 * scale * (bit(p, 24) ? -1.0 : 1.0);
      msg->longitude = field(p, 49, 23) * 180.0 * scale + (bit(p, 48) ? -180.0 : 0.0);
    }
    break;
  case P25_MOT_EMERG_ALRM:
    msg->group = field(p, 16, 16);
    msg->src = field(p, 48, 24);
    break;
  case P25_LC_MOT_ALIAS_HDR:
    msg->group = field(p, 16, 16);
    msg->block_count = field(p, 32, 8);
    msg->alias_format = field(p, 40, 8);
    msg->sequence = field(p, 56, 4);
    break;
  case P25_LC_MOT_ALIAS_DATA:
    msg->block = field(p, 16, 8);
    msg->sequence = field(p, 24, 4);
    break;
  case P25_LC_HARRIS_RETURN_CC:
    msg->src = field(p, 24, 24);
    msg->tgt = field(p, 48, 24);
    break;
  case P25_LC_HARRIS_ALIAS: // block 1-4, octets 2-8 are text
    msg->block = msg->opcode - 0x31;
    for(int i = 0; i < 7; i++){
      uint8_t c = p[2 + i];
      msg->text[i] = (c >= 0x20 && c < 0x7f) ? c : (c == 0 ? '\0' : '?');
    }
    msg->text[7] = '\0';
    break;
  default:
    break;
  }
  return 0;
}

// L3Harris talker GPS: octets 2-8 of block 1 then of block 2, 112 bits
void p25_harris_gps(uint8_t const block1[9], uint8_t const block2[9], double *latitude,
                    double *longitude, uint32_t *seconds_of_day, uint16_t *heading){
  uint8_t m[14];
  memcpy(m, block1 + 2, 7);
  memcpy(m + 7, block2 + 2, 7);
  double lat = field(m, 24, 8) + (field(m, 17, 7) + field(m, 0, 16) / 10000.0) / 60.0;
  double lon = field(m, 56, 8) + (field(m, 49, 7) + field(m, 32, 16) / 10000.0) / 60.0;
  if(latitude)
    *latitude = bit(m, 16) ? -lat : lat;
  if(longitude)
    *longitude = bit(m, 48) ? -lon : lon;
  if(seconds_of_day)
    *seconds_of_day = field(m, 64, 16) * (bit(m, 80) ? 2u : 1u);
  if(heading)
    *heading = field(m, 95, 9);
}

// Packet data (TIA-102.BAAA). Header: confirmed 1, outbound 2, format 3-7, SAP 10-15,
// MFID 16-23, LLID 24-47, blocks to follow 49-55, pad octets 59-63, data header offset 74-79
#define PDU_FMT_RESPONSE 0x03
#define PDU_FMT_UNCONFIRMED 0x15
#define PDU_FMT_CONFIRMED 0x16
#define PDU_FMT_AMBTC 0x17
#define SAP_SNDCP_DATA 4
#define SAP_SNDCP_CONTROL 6
#define SAP_TRUNKING 61
#define SAP_TRUNKING_ENC 63

// User octets of a packet: data block octets (a confirmed block's serial number and
// CRC-9 dropped) without the pad octets and the CRC-32; -1 if blocks are missing
static int user_data(uint8_t const *pdu, int len, struct p25_msg const *msg, uint8_t *out, int max){
  int const block = msg->confirmed ? 18 : 12;
  int const skip = msg->confirmed ? 2 : 0;
  if(msg->blocks == 0 || len < 12 + msg->blocks * block)
    return -1;
  int n = (block - skip) * msg->blocks - msg->pad_octets - 4;
  if(n <= 0)
    return -1;
  int k = 0;
  for(int b = 0; b < msg->blocks; b++)
    for(int o = skip; o < block && k < max && k < n; o++)
      out[k++] = pdu[12 + b * block + o];
  return n;
}

// SNDCP context control (TIA-102.BAEB), the first octets of the user data
static void sndcp_control(struct p25_msg *msg, uint8_t const *d, int n){
  if(n <= 0)
    return;
  msg->sndcp_type = d[0] >> 4;
  msg->sndcp_nsapi = d[0] & 0x0f;
  if(n > 1){
    msg->sndcp_has_arg = true;
    msg->sndcp_arg = d[1];
  }
  // the IPv4 address: an outbound accept at octet 3, an inbound request at octet 2
  int at = -1;
  if(msg->outbound && msg->sndcp_type == 0)
    at = 3;
  else if(!msg->outbound && msg->sndcp_type == 0 && n > 1)
    at = 2;
  if(at >= 0 && n >= at + 4){
    msg->sndcp_has_ip = true;
    memcpy(msg->sndcp_ip, d + at, 4);
  }
}

// Alternate multi-block trunking control (TIA-102.AABC): opcode 58-63 and service options
// 64-71 of the header; LLID is the source (or the unit); data block 0 from octet 12
static void mbt(struct p25_msg *msg, uint8_t const *h){
  uint8_t const *b0 = h + 12;
  msg->opcode = field(h, 58, 6);
  msg->svc = field(h, 64, 8);
  if(msg->mfid == P25_MFID_MOTOROLA){
    if(msg->opcode == 0x02){
      msg->kind = P25_MOT_GRG_CH_GRANT;
      msg->ch = chan(b0, 0);
      msg->group = field(b0, 32, 16);
      msg->src = msg->llid;
    }
    return;
  }
  if(msg->mfid != P25_MFID_STD && msg->mfid != P25_MFID_STD1)
    return;
  switch(msg->opcode){
  case 0x00:
    msg->kind = P25_GRP_V_CH_GRANT;
    msg->ch = chan(b0, 16);
    msg->group = field(b0, 48, 16);
    msg->src = msg->llid;
    break;
  case 0x04:
  case 0x06:
    msg->kind = msg->opcode == 0x04 ? P25_UU_V_CH_GRANT : P25_UU_V_CH_GRANT_UPDT;
    msg->src = field(b0, 32, 24);
    msg->tgt = field(b0, 56, 24);
    msg->ch = chan(b0, 80);
    break;
  case 0x08:
  case 0x09:
    msg->kind = msg->opcode == 0x08 ? P25_TELE_INT_CH_GRANT : P25_TELE_INT_CH_GRANT_UPDT;
    msg->ch = chan(b0, 0);
    msg->timer = field(b0, 32, 16);
    msg->tgt = msg->llid;
    break;
  case 0x10:
    msg->kind = P25_IND_DATA_CH_GRANT;
    msg->ch = chan(b0, 80);
    msg->tgt = field(b0, 56, 24);
    break;
  case 0x11:
    msg->kind = P25_GRP_DATA_CH_GRANT;
    msg->ch = chan(b0, 16);
    msg->group = field(b0, 48, 16);
    break;
  case 0x3a:
    msg->kind = P25_RFSS_STS_BCST;
    msg->sysid = field(h, 36, 12);
    msg->rfss = field(b0, 0, 8);
    msg->site = field(b0, 8, 8);
    msg->ch = chan(b0, 16);
    break;
  case 0x3b:
    msg->kind = P25_NET_STS_BCST;
    msg->sysid = field(h, 36, 12);
    msg->wacn = field(b0, 0, 20);
    msg->ch = chan(b0, 24);
    break;
  case 0x3c:
    msg->kind = P25_ADJ_STS_BCST;
    msg->sysid = field(h, 36, 12);
    msg->rfss = field(h, 64, 8);
    msg->site = field(h, 72, 8);
    msg->ch = chan(b0, 0);
    break;
  default:
    break;
  }
}

int p25_decode_pdu(struct p25_msg *msg, uint8_t const *pdu, int len){
  memset(msg, 0, sizeof *msg);
  if(pdu == NULL || len < 12)
    return -1;
  msg->family = P25_FAMILY_PDU;
  msg->kind = P25_PDU_OTHER;
  keep_raw(msg, pdu, 12);
  msg->confirmed = bit(pdu, 1);
  msg->outbound = bit(pdu, 2);
  msg->format = field(pdu, 3, 5);
  msg->sap = field(pdu, 10, 6);
  msg->mfid = pdu[2];
  msg->llid = field(pdu, 24, 24);
  msg->blocks = field(pdu, 49, 7);
  msg->pad_octets = field(pdu, 59, 5);
  msg->header_offset = field(pdu, 74, 6);
  msg->user_octets = -1;

  switch(msg->format){
  case PDU_FMT_AMBTC:
    msg->family = P25_FAMILY_MBT;
    msg->kind = P25_UNKNOWN;
    msg->opcode = field(pdu, 58, 6);
    if(len >= 24 && msg->sap == SAP_TRUNKING)
      mbt(msg, pdu);
    break;
  case PDU_FMT_RESPONSE:
    msg->kind = P25_PDU_RESPONSE;
    msg->pdu_response = pdu[1];
    msg->has_src_llid = !bit(pdu, 48);
    msg->src_llid = field(pdu, 56, 24);
    break;
  case PDU_FMT_CONFIRMED:
  case PDU_FMT_UNCONFIRMED:
    {
      if(msg->sap == SAP_TRUNKING || msg->sap == SAP_TRUNKING_ENC)
        break; // UMBTC: trunking control, header only
      uint8_t d[16];
      msg->user_octets = user_data(pdu, len, msg, d, sizeof d);
      if(msg->sap == SAP_SNDCP_CONTROL && msg->mfid == P25_MFID_STD){
        msg->kind = P25_PDU_SNDCP;
        sndcp_control(msg, d, msg->user_octets);
      } else
        msg->kind = msg->sap == SAP_SNDCP_DATA ? P25_PDU_SNDCP_DATA : P25_PDU_DATA;
    }
    break;
  default:
    break;
  }
  return 0;
}

// HDU header word: MI 0-71, MFID 72-79, ALGID 80-87, KID 88-103, TGID 104-119
int p25_decode_hdu(struct p25_msg *msg, uint8_t const hdu[15]){
  memset(msg, 0, sizeof *msg);
  if(hdu == NULL)
    return -1;
  msg->family = P25_FAMILY_HDU;
  msg->kind = P25_HDU;
  keep_raw(msg, hdu, 15);
  memcpy(msg->mi, hdu, 9);
  msg->mfid = hdu[9];
  msg->algid = hdu[10];
  msg->kid = field(hdu, 88, 16);
  msg->group = field(hdu, 104, 16);
  return 0;
}

// LDU2 encryption sync: MI 0-71, ALGID 72-79, KID 80-95
int p25_decode_es(struct p25_msg *msg, uint8_t const es[12]){
  memset(msg, 0, sizeof *msg);
  if(es == NULL)
    return -1;
  msg->family = P25_FAMILY_ES;
  msg->kind = P25_ENC_SYNC;
  keep_raw(msg, es, 12);
  memcpy(msg->mi, es, 9);
  msg->algid = es[9];
  msg->kid = field(es, 80, 16);
  return 0;
}

// Band plan

void p25_bandplan_init(struct p25_bandplan *plan){
  memset(plan, 0, sizeof *plan);
}

bool p25_bandplan_update(struct p25_bandplan *plan, struct p25_msg const *msg){
  if(msg->kind != P25_IDEN_UP && msg->kind != P25_IDEN_UP_TDMA && msg->kind != P25_IDEN_UP_VU)
    return false;
  int64_t const off = msg->tx_offset_hz < 0 ? -msg->tx_offset_hz : msg->tx_offset_hz;
  if(msg->base_hz < 100000000 || msg->base_hz > 1000000000 || msg->spacing_hz == 0
     || msg->spacing_hz > 1000000 || off > 100000000)
    return false;
  struct p25_band b = {
    .valid = true,
    .tdma = msg->kind == P25_IDEN_UP_TDMA && msg->iden_tdma,
    .slots = msg->kind == P25_IDEN_UP_TDMA ? msg->iden_slots : 1,
    .type = msg->kind == P25_IDEN_UP ? 0 : msg->iden_type,
    .base_hz = msg->base_hz,
    .spacing_hz = msg->spacing_hz,
    .tx_offset_hz = msg->tx_offset_hz,
    .bw_hz = msg->bw_hz,
  };
  struct p25_band *old = &plan->band[msg->iden & 15];
  bool const changed = memcmp(old, &b, sizeof b) != 0;
  *old = b;
  return changed;
}

bool p25_chan_freq(struct p25_bandplan const *plan, struct p25_chan ch, uint64_t *downlink_hz,
                   uint64_t *uplink_hz, int *slot){
  if(plan == NULL || ch.iden > 15 || !plan->band[ch.iden].valid)
    return false;
  struct p25_band const *b = &plan->band[ch.iden];
  // A TDMA channel number counts slots: channel / slots is the carrier, the remainder the slot
  int const slots = (b->tdma && b->slots > 1) ? b->slots : 1;
  uint64_t const dl = b->base_hz + (uint64_t)b->spacing_hz * (ch.num / slots);
  if(downlink_hz)
    *downlink_hz = dl;
  if(uplink_hz)
    *uplink_hz = b->tx_offset_hz == 0 ? 0 : dl + (uint64_t)b->tx_offset_hz;
  if(slot)
    *slot = ch.num % slots;
  return true;
}

// Names

static char const *const Kind_names[P25_KIND_COUNT] = {
  [P25_UNKNOWN] = "UNKNOWN",
  [P25_GRP_V_CH_GRANT] = "GRP_V_CH_GRANT",
  [P25_GRP_V_CH_GRANT_UPDT] = "GRP_V_CH_GRANT_UPDT",
  [P25_GRP_V_CH_GRANT_UPDT_EXP] = "GRP_V_CH_GRANT_UPDT_EXP",
  [P25_UU_V_CH_GRANT] = "UU_V_CH_GRANT",
  [P25_UU_ANS_REQ] = "UU_ANS_REQ",
  [P25_UU_V_CH_GRANT_UPDT] = "UU_V_CH_GRANT_UPDT",
  [P25_TELE_INT_CH_GRANT] = "TELE_INT_CH_GRANT",
  [P25_TELE_INT_CH_GRANT_UPDT] = "TELE_INT_CH_GRANT_UPDT",
  [P25_TELE_INT_ANS_REQ] = "TELE_INT_ANS_REQ",
  [P25_IND_DATA_CH_GRANT] = "IND_DATA_CH_GRANT",
  [P25_GRP_DATA_CH_GRANT] = "GRP_DATA_CH_GRANT",
  [P25_GRP_DATA_CH_ANN] = "GRP_DATA_CH_ANN",
  [P25_GRP_DATA_CH_ANN_EXP] = "GRP_DATA_CH_ANN_EXP",
  [P25_SN_DATA_CH_GRANT] = "SN_DATA_CH_GRANT",
  [P25_SN_DATA_PAGE_REQ] = "SN_DATA_PAGE_REQ",
  [P25_SN_DATA_CH_ANN_EXP] = "SN_DATA_CH_ANN_EXP",
  [P25_STS_UPDT] = "STS_UPDT",
  [P25_STS_Q] = "STS_Q",
  [P25_MSG_UPDT] = "MSG_UPDT",
  [P25_RAD_MON_CMD] = "RAD_MON_CMD",
  [P25_CALL_ALRT] = "CALL_ALRT",
  [P25_ACK_RSP_FNE] = "ACK_RSP_FNE",
  [P25_QUE_RSP] = "QUE_RSP",
  [P25_EXT_FNCT_CMD] = "EXT_FNCT_CMD",
  [P25_DENY_RSP] = "DENY_RSP",
  [P25_GRP_AFF_RSP] = "GRP_AFF_RSP",
  [P25_GRP_AFF_Q] = "GRP_AFF_Q",
  [P25_LOC_REG_RSP] = "LOC_REG_RSP",
  [P25_U_REG_RSP] = "U_REG_RSP",
  [P25_U_REG_CMD] = "U_REG_CMD",
  [P25_AUTH_CMD] = "AUTH_CMD",
  [P25_U_DE_REG_ACK] = "U_DE_REG_ACK",
  [P25_SYNC_BCST] = "SYNC_BCST",
  [P25_AUTH_DMAND] = "AUTH_DMAND",
  [P25_AUTH_FNE_RESP] = "AUTH_FNE_RESP",
  [P25_TIME_DATE_ANN] = "TIME_DATE_ANN",
  [P25_ROAM_ADDR_CMD] = "ROAM_ADDR_CMD",
  [P25_ROAM_ADDR_UPDT] = "ROAM_ADDR_UPDT",
  [P25_IDEN_UP] = "IDEN_UP",
  [P25_IDEN_UP_TDMA] = "IDEN_UP_TDMA",
  [P25_IDEN_UP_VU] = "IDEN_UP_VU",
  [P25_SYS_SRV_BCST] = "SYS_SRV_BCST",
  [P25_SCCB] = "SCCB",
  [P25_SCCB_EXP] = "SCCB_EXP",
  [P25_RFSS_STS_BCST] = "RFSS_STS_BCST",
  [P25_RFSS_STS_BCST_EXP] = "RFSS_STS_BCST_EXP",
  [P25_NET_STS_BCST] = "NET_STS_BCST",
  [P25_NET_STS_BCST_EXP] = "NET_STS_BCST_EXP",
  [P25_ADJ_STS_BCST] = "ADJ_STS_BCST",
  [P25_ADJ_STS_BCST_EXP] = "ADJ_STS_BCST_EXP",
  [P25_ADJ_STS_BCST_UNCOORD] = "ADJ_STS_BCST_UNCOORD",
  [P25_MOT_GRG_ADD] = "MOT_GRG_ADD",
  [P25_MOT_GRG_DEL] = "MOT_GRG_DEL",
  [P25_MOT_GRG_CH_GRANT] = "MOT_GRG_CH_GRANT",
  [P25_MOT_GRG_CH_UPDT] = "MOT_GRG_CH_UPDT",
  [P25_MOT_EXT_FNCT_CMD] = "MOT_EXT_FNCT_CMD",
  [P25_MOT_TRAFFIC_CH_ID] = "MOT_TRAFFIC_CH_ID",
  [P25_MOT_QUE_RSP] = "MOT_QUE_RSP",
  [P25_MOT_DENY_RSP] = "MOT_DENY_RSP",
  [P25_MOT_ACK_RSP] = "MOT_ACK_RSP",
  [P25_MOT_SYS_LOADING] = "MOT_SYS_LOADING",
  [P25_MOT_EMERG_ALRM] = "MOT_EMERG_ALRM",
  [P25_MOT_BSI] = "MOT_BSI",
  [P25_MOT_CC_SHUTDOWN] = "MOT_CC_SHUTDOWN",
  [P25_MOT_TDMA_DATA_CH] = "MOT_TDMA_DATA_CH",
  [P25_HARRIS_GRG_EXENC_CMD] = "HARRIS_GRG_EXENC_CMD",
  [P25_LC_GRP_V_CH_USR] = "GRP_V_CH_USR",
  [P25_LC_UU_V_CH_USR] = "UU_V_CH_USR",
  [P25_LC_TEL_INT_V_CH_USR] = "TEL_INT_V_CH_USR",
  [P25_LC_SRC_ID_EXT] = "SRC_ID_EXT",
  [P25_LC_UU_V_CH_USR_EXT] = "UU_V_CH_USR_EXT",
  [P25_LC_CALL_TRM] = "CALL_TRM",
  [P25_LC_OTHER] = "LC_OTHER",
  [P25_LC_MOT_GRG_V_CH_USR] = "MOT_GRG_V_CH_USR",
  [P25_LC_MOT_GRG_V_CH_UPDT] = "MOT_GRG_V_CH_UPDT",
  [P25_LC_MOT_FAILSOFT] = "MOT_FAILSOFT",
  [P25_LC_MOT_UNIT_GPS] = "MOT_UNIT_GPS",
  [P25_LC_MOT_TALK_COMPLETE] = "MOT_TALK_COMPLETE",
  [P25_LC_MOT_ALIAS_HDR] = "MOT_ALIAS_HDR",
  [P25_LC_MOT_ALIAS_DATA] = "MOT_ALIAS_DATA",
  [P25_LC_HARRIS_RETURN_CC] = "HARRIS_RETURN_CC",
  [P25_LC_HARRIS_GPS1] = "HARRIS_GPS1",
  [P25_LC_HARRIS_GPS2] = "HARRIS_GPS2",
  [P25_LC_HARRIS_ALIAS] = "HARRIS_ALIAS",
  [P25_PDU_RESPONSE] = "PDU_RESPONSE",
  [P25_PDU_SNDCP] = "SNDCP_CONTROL",
  [P25_PDU_SNDCP_DATA] = "SNDCP_DATA",
  [P25_PDU_DATA] = "PACKET_DATA",
  [P25_PDU_OTHER] = "PDU",
  [P25_HDU] = "VOICE_HDR",
  [P25_ENC_SYNC] = "ENC_SYNC",
};

char const *p25_kind_name(enum p25_kind kind){
  if(kind < 0 || kind >= P25_KIND_COUNT || Kind_names[kind] == NULL)
    return "?";
  return Kind_names[kind];
}

char const *p25_family_name(enum p25_family family){
  static char const *const names[] = { "TSBK", "LC", "TDULC", "MBT", "PDU", "HDU", "ES", "MAC" };
  if(family < 0 || family >= (int)(sizeof names / sizeof names[0]))
    return "?";
  return names[family];
}

// TIA-102.AABC deny and queued response reasons
char const *p25_deny_reason_name(uint8_t reason){
  switch(reason){
  case 0x10: return "requester_invalid";
  case 0x11: return "requester_unauthorized";
  case 0x20: return "target_invalid";
  case 0x21: return "target_unauthorized";
  case 0x2f: return "target_refused";
  case 0x30: return "group_invalid";
  case 0x31: return "group_unauthorized";
  case 0x40: return "invalid_dialing";
  case 0x41: return "number_unauthorized";
  case 0x42: return "pstn_invalid";
  case 0x50: return "call_timeout";
  case 0x51: return "landline_terminated";
  case 0x52: return "unit_terminated";
  case 0x5f: return "call_preempted";
  case 0x60: return "site_access_denied";
  case 0x67: return "ptt_collide";
  case 0x77: return "ptt_bonk";
  case 0xf0: return "call_options_invalid";
  case 0xf1: return "protection_invalid";
  case 0xf2: return "duplex_invalid";
  case 0xf3: return "mode_invalid";
  case 0xff: return "service_unsupported";
  default: return "";
  }
}

// TIA-102.AABC extended functions
char const *p25_ext_function_name(uint16_t function){
  switch(function){
  case 0x0000: return "radio_check";
  case 0x007d: return "radio_detach";
  case 0x007e: return "radio_uninhibit";
  case 0x007f: return "radio_inhibit";
  case 0x0080: return "radio_check_ack";
  case 0x00fd: return "radio_detach_ack";
  case 0x00fe: return "radio_uninhibit_ack";
  case 0x00ff: return "radio_inhibit_ack";
  case 0x0200: return "regroup_create";
  case 0x0201: return "regroup_cancel";
  case 0x0280: return "regroup_create_ack";
  case 0x0281: return "regroup_cancel_ack";
  default: return "";
  }
}

// TIA-102.BAAA service access points
char const *p25_sap_name(uint8_t sap){
  switch(sap){
  case 0: return "user_data";
  case 1: return "encrypted_user_data";
  case 2: return "circuit_data";
  case 3: return "circuit_data_control";
  case 4: return "packet_data";
  case 5: return "arp";
  case 6: return "sndcp_control";
  case 15: return "scan_preamble";
  case 29: return "encryption_support";
  case 31: return "extended_address";
  case 32: return "registration";
  case 33: return "channel_reassignment";
  case 34: return "system_configuration";
  case 35: return "loopback";
  case 36: return "statistics";
  case 37: return "out_of_service";
  case 38: return "paging";
  case 39: return "configuration";
  case 40: return "key_management";
  case 41: return "encrypted_key_management";
  case 48: return "location_service";
  case 61: return "trunking_control";
  case 63: return "encrypted_trunking_control";
  default: return "";
  }
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

static void put_mhz(struct out *o, char const *key, uint64_t hz){
  put(o, " %s=%llu.%06llu", key, (unsigned long long)(hz / 1000000), (unsigned long long)(hz % 1000000));
}

// " ch=1-291 freq=851.637500" (and " slot=1" on TDMA); suffix names the second channel.
// An explicit uplink channel names the uplink frequency itself: no transmit offset is added.
static void put_chan(struct out *o, char const *suffix, struct p25_chan ch, struct p25_bandplan const *plan){
  put(o, " ch%s=%u-%u", suffix, ch.iden, ch.num);
  uint64_t dl;
  int slot;
  if(!p25_chan_freq(plan, ch, &dl, NULL, &slot))
    return;
  char key[16];
  snprintf(key, sizeof key, "freq%s", suffix);
  put_mhz(o, key, dl);
  struct p25_band const *b = &plan->band[ch.iden];
  if(b->tdma && b->slots > 1)
    put(o, " slot%s=%d", suffix, slot);
}

static void put_svc(struct out *o, uint8_t svc){
  put(o, " svc=0x%02x", svc);
  if(svc & P25_SVC_EMERGENCY)
    put(o, " emerg=1");
  if(svc & P25_SVC_ENCRYPTED)
    put(o, " enc=1");
  if(svc & P25_SVC_DUPLEX)
    put(o, " duplex=1");
  if(svc & P25_SVC_PACKET)
    put(o, " packet=1");
  put(o, " prio=%d", svc & P25_SVC_PRIORITY);
}

static void put_hex(struct out *o, char const *key, uint8_t const *p, int len){
  put(o, " %s=", key);
  for(int i = 0; i < len; i++)
    put(o, "%02x", p[i]);
}

static void put_reason(struct out *o, uint8_t reason){
  put(o, " reason=0x%02x", reason);
  char const *name = p25_deny_reason_name(reason);
  if(*name)
    put(o, " reason_name=%s", name);
}

static void put_iden(struct out *o, struct p25_msg const *m){
  put(o, " iden=%u", m->iden);
  if(m->kind == P25_IDEN_UP_TDMA)
    put(o, " type=%u tdma=%d slots=%u", m->iden_type, m->iden_tdma, m->iden_slots);
  else if(m->kind == P25_IDEN_UP_VU)
    put(o, " bw_code=%u", m->iden_type);
  put_mhz(o, "base", m->base_hz);
  put(o, " spacing=%u bw=%u tx_offset=%lld", m->spacing_hz, m->bw_hz, (long long)m->tx_offset_hz);
}

static void put_site(struct out *o, struct p25_msg const *m){
  if(m->family != P25_FAMILY_MBT)
    put(o, " lra=0x%02x", m->lra);
  put(o, " sys=0x%03x rfss=%u site=%u", m->sysid, m->rfss, m->site);
}

static void put_flags(struct out *o, struct p25_msg const *m){
  if(m->kind == P25_ADJ_STS_BCST && m->family == P25_FAMILY_TSBK)
    put(o, " conv=%d fail=%d valid=%d", (m->site_flags >> 3) & 1, (m->site_flags >> 2) & 1,
        (m->site_flags >> 1) & 1);
  if(m->family == P25_FAMILY_TSBK)
    put(o, " net=%d", m->site_flags & 1);
}

int p25_format(char *buf, size_t size, struct p25_msg const *m, struct p25_bandplan const *plan){
  struct out o = { .p = buf, .left = size, .n = 0 };
  if(size > 0)
    buf[0] = '\0';
  put(&o, "%s %s", p25_family_name(m->family), p25_kind_name(m->kind));
  bool const lc = m->family == P25_FAMILY_LC || m->family == P25_FAMILY_TDULC;
  if(m->family == P25_FAMILY_TSBK || m->family == P25_FAMILY_MBT || lc){
    if(m->kind == P25_UNKNOWN || m->kind == P25_LC_OTHER || m->mfid != P25_MFID_STD)
      put(&o, " mfid=0x%02x opcode=0x%02x", m->mfid, m->opcode);
    if(m->protect)
      put(&o, " protected=1");
  }
  if(lc && m->protect){
    put_hex(&o, "lc", m->raw, 9);
    return o.n;
  }

  switch(m->kind){
  case P25_UNKNOWN:
  case P25_LC_OTHER:
  case P25_GRP_DATA_CH_ANN:
  case P25_GRP_DATA_CH_ANN_EXP:
  case P25_SN_DATA_PAGE_REQ:
  case P25_AUTH_DMAND:
  case P25_AUTH_FNE_RESP:
  case P25_ROAM_ADDR_UPDT:
  case P25_ADJ_STS_BCST_UNCOORD:
  case P25_LC_SRC_ID_EXT:
  case P25_LC_MOT_FAILSOFT:
  case P25_LC_HARRIS_GPS1:
  case P25_LC_HARRIS_GPS2:
    if(m->family == P25_FAMILY_MBT){
      put(&o, " sap=%u llid=%u blocks=%u", m->sap, m->llid, m->blocks);
      put_hex(&o, "hdr", m->raw, 12);
    } else
      put_hex(&o, "raw", m->raw, m->raw_len);
    break;
  case P25_GRP_V_CH_GRANT:
  case P25_GRP_DATA_CH_GRANT:
  case P25_MOT_GRG_CH_GRANT:
    put(&o, " tg=%u", m->group);
    if(m->kind != P25_GRP_DATA_CH_GRANT || m->family == P25_FAMILY_TSBK)
      put(&o, " src=%u", m->src);
    if(m->kind != P25_GRP_DATA_CH_GRANT || m->family == P25_FAMILY_TSBK)
      put_svc(&o, m->svc);
    put_chan(&o, "", m->ch, plan);
    break;
  case P25_GRP_V_CH_GRANT_UPDT:
  case P25_MOT_GRG_CH_UPDT:
    put(&o, " tg=%u", m->group);
    put_chan(&o, "", m->ch, plan);
    if(m->has_b){
      put(&o, " tg_b=%u", m->group_b);
      put_chan(&o, "_b", m->ch_b, plan);
    }
    break;
  case P25_GRP_V_CH_GRANT_UPDT_EXP:
    put(&o, " tg=%u", m->group);
    put_svc(&o, m->svc);
    put_chan(&o, "", m->ch, plan);
    put_chan(&o, "_ul", m->ch_b, plan);
    break;
  case P25_UU_V_CH_GRANT:
  case P25_UU_V_CH_GRANT_UPDT:
  case P25_IND_DATA_CH_GRANT:
    if(m->family != P25_FAMILY_MBT || m->kind != P25_IND_DATA_CH_GRANT)
      put(&o, " src=%u", m->src);
    put(&o, " tgt=%u", m->tgt);
    if(m->family == P25_FAMILY_MBT && m->kind != P25_IND_DATA_CH_GRANT)
      put_svc(&o, m->svc);
    put_chan(&o, "", m->ch, plan);
    break;
  case P25_UU_ANS_REQ:
  case P25_STS_Q:
  case P25_CALL_ALRT:
  case P25_GRP_AFF_Q:
  case P25_RAD_MON_CMD:
  case P25_LC_HARRIS_RETURN_CC:
    put(&o, " src=%u tgt=%u", m->src, m->tgt);
    if(m->kind == P25_UU_ANS_REQ && !lc)
      put_svc(&o, m->svc);
    if(m->kind == P25_RAD_MON_CMD)
      put(&o, " tx_mult=%u", m->tx_mult);
    break;
  case P25_TELE_INT_CH_GRANT:
  case P25_TELE_INT_CH_GRANT_UPDT:
    put(&o, " unit=%u timer_ms=%u", m->tgt, m->timer * 100);
    put_svc(&o, m->svc);
    put_chan(&o, "", m->ch, plan);
    break;
  case P25_TELE_INT_ANS_REQ:
    if(!lc)
      put(&o, " unit=%u timer=%u", m->tgt, m->timer);
    else
      put_hex(&o, "lc", m->raw, 9);
    break;
  case P25_SN_DATA_CH_GRANT:
    put(&o, " tgt=%u", m->tgt);
    put_svc(&o, m->svc);
    put_chan(&o, "", m->ch, plan);
    if(m->has_b)
      put_chan(&o, "_ul", m->ch_b, plan);
    break;
  case P25_SN_DATA_CH_ANN_EXP:
    put_svc(&o, m->svc);
    put(&o, " autonomous=%d requested=%d dac=0x%04x", m->autonomous, m->requested, m->data_access);
    put_chan(&o, "", m->ch, plan);
    put_chan(&o, "_ul", m->ch_b, plan);
    break;
  case P25_STS_UPDT:
    put(&o, " src=%u tgt=%u unit_status=%u user_status=%u", m->src, m->tgt, m->unit_status, m->user_status);
    break;
  case P25_MSG_UPDT:
    put(&o, " src=%u tgt=%u msg=0x%04x", m->src, m->tgt, m->message);
    break;
  case P25_ACK_RSP_FNE:
  case P25_MOT_ACK_RSP:
    put(&o, " tgt=%u src=%u svc_type=0x%02x aiv=%d ex=%d", m->tgt, m->src, m->svc_type, m->aiv, m->ex);
    break;
  case P25_QUE_RSP:
  case P25_DENY_RSP:
  case P25_MOT_QUE_RSP:
  case P25_MOT_DENY_RSP:
    put(&o, " tgt=%u svc_type=0x%02x", m->tgt, m->svc_type);
    put_reason(&o, m->reason);
    put(&o, " aiv=%d info=%u", m->aiv, m->info);
    break;
  case P25_EXT_FNCT_CMD:
    if(lc){
      put_hex(&o, "lc", m->raw, 9);
      break;
    }
    put(&o, " tgt=%u function=0x%04x", m->tgt, m->function);
    if(*p25_ext_function_name(m->function))
      put(&o, " function_name=%s", p25_ext_function_name(m->function));
    put(&o, " args=0x%06x", m->args);
    break;
  case P25_GRP_AFF_RSP:
    put(&o, " tgt=%u tg=%u ann_tg=%u response=%u lg=%d", m->tgt, m->group, m->group_b, m->response,
        m->local_global);
    break;
  case P25_LOC_REG_RSP:
    put(&o, " tgt=%u tg=%u rfss=%u site=%u response=%u", m->tgt, m->group, m->rfss, m->site, m->response);
    break;
  case P25_U_REG_RSP:
    put(&o, " src=%u src_id=%u sys=0x%03x response=%u", m->src, m->info, m->sysid, m->response);
    break;
  case P25_U_REG_CMD:
  case P25_AUTH_CMD:
  case P25_ROAM_ADDR_CMD:
    if(lc)
      put_hex(&o, "lc", m->raw, 9);
    else
      put(&o, " tgt=%u", m->tgt);
    break;
  case P25_U_DE_REG_ACK:
    put(&o, " src=%u wacn=0x%05x sys=0x%03x", m->src, m->wacn, m->sysid);
    break;
  case P25_SYNC_BCST:
    put(&o, " date=%04u-%02u-%02u time=%02u:%02u microslots=%u", m->year, m->month, m->day, m->hour,
        m->minute, m->microslots);
    if(!m->lto_valid_bit)
      put(&o, " utc_offset=%c%u:%02u", m->lto_negative ? '-' : '+', m->lto_hours, m->lto_half ? 30 : 0);
    put(&o, " unlocked=%d uslot_unlocked=%d leap=%u", m->time_unlocked, m->uslot_unlocked, m->leap);
    break;
  case P25_TIME_DATE_ANN:
    put(&o, " date=%04u-%02u-%02u time=%02u:%02u", m->year, m->month, m->day, m->hour, m->minute);
    break;
  case P25_IDEN_UP:
  case P25_IDEN_UP_TDMA:
  case P25_IDEN_UP_VU:
    put_iden(&o, m);
    break;
  case P25_SYS_SRV_BCST:
    put(&o, " avail=0x%06x supp=0x%06x", m->avail_svc, m->supp_svc);
    if(!lc)
      put(&o, " req_prio=%u", m->req_priority);
    break;
  case P25_SCCB:
    put(&o, " rfss=%u site=%u", m->rfss, m->site);
    put_chan(&o, "", m->ch, plan);
    put(&o, " class=0x%02x", m->svc_class);
    if(m->has_b){
      put_chan(&o, "_b", m->ch_b, plan);
      put(&o, " class_b=0x%02x", m->svc_class_b);
    }
    break;
  case P25_SCCB_EXP:
    put(&o, " rfss=%u site=%u", m->rfss, m->site);
    put_chan(&o, "", m->ch, plan);
    if(m->has_b)
      put_chan(&o, "_ul", m->ch_b, plan);
    put(&o, " class=0x%02x", m->svc_class);
    break;
  case P25_RFSS_STS_BCST:
  case P25_RFSS_STS_BCST_EXP:
  case P25_ADJ_STS_BCST:
  case P25_ADJ_STS_BCST_EXP:
    put_site(&o, m);
    put_chan(&o, "", m->ch, plan);
    if(m->has_b)
      put_chan(&o, "_ul", m->ch_b, plan);
    if(m->family != P25_FAMILY_MBT)
      put(&o, " class=0x%02x", m->svc_class);
    if(m->kind == P25_RFSS_STS_BCST || m->kind == P25_ADJ_STS_BCST)
      put_flags(&o, m);
    break;
  case P25_NET_STS_BCST:
  case P25_NET_STS_BCST_EXP:
    if(m->family == P25_FAMILY_TSBK)
      put(&o, " lra=0x%02x", m->lra);
    put(&o, " wacn=0x%05x sys=0x%03x", m->wacn, m->sysid);
    put_chan(&o, "", m->ch, plan);
    if(m->has_b)
      put_chan(&o, "_ul", m->ch_b, plan);
    if(m->family != P25_FAMILY_MBT && m->kind == P25_NET_STS_BCST)
      put(&o, " class=0x%02x", m->svc_class);
    break;
  case P25_MOT_GRG_ADD:
  case P25_MOT_GRG_DEL:
    put(&o, " sg=%u tgs=", m->group);
    for(int i = 0; i < m->nmembers; i++)
      put(&o, i ? ",%u" : "%u", m->members[i]);
    break;
  case P25_MOT_EXT_FNCT_CMD:
    put(&o, " tgt=%u class=0x%02x operand=0x%02x args=0x%06x", m->tgt, m->ext_class, m->ext_operand, m->args);
    break;
  case P25_MOT_TRAFFIC_CH_ID:
    put(&o, " tch1=%u tch2=%u", m->tch1, m->tch2);
    break;
  case P25_MOT_SYS_LOADING:
    put(&o, " load=%u capacity=%u", m->load, m->capacity);
    break;
  case P25_MOT_EMERG_ALRM:
    put(&o, " tg=%u src=%u", m->group, m->src);
    break;
  case P25_MOT_BSI:
    put(&o, " cwid=\"%s\"", m->cwid);
    put_chan(&o, "", m->ch, plan);
    break;
  case P25_MOT_CC_SHUTDOWN:
    put(&o, " minutes=%u", m->shutdown_min);
    break;
  case P25_MOT_TDMA_DATA_CH:
    put_chan(&o, "", m->ch, plan);
    put_chan(&o, "_ul", m->ch_b, plan);
    break;
  case P25_HARRIS_GRG_EXENC_CMD:
    put(&o, " sg=%u %s %s seq=%u key=0x%04x opts=0x%02x", m->group,
        (m->regroup_opts & 0x20) ? "activate=1" : "activate=0",
        (m->regroup_opts & 0x80) ? "simulselect=1" : "simulselect=0", m->regroup_opts & 0x1f, m->key_id,
        m->regroup_opts);
    if(m->regroup_opts & 0x40)
      put(&o, " tg=%u alg=0x%02x", m->group_b, m->alg_id);
    else
      put(&o, " radio=%u", m->tgt);
    break;
  case P25_LC_GRP_V_CH_USR:
  case P25_LC_MOT_GRG_V_CH_USR:
    put(&o, " tg=%u src=%u", m->group, m->src);
    put_svc(&o, m->svc);
    break;
  case P25_LC_UU_V_CH_USR:
    put(&o, " tgt=%u src=%u", m->tgt, m->src);
    put_svc(&o, m->svc);
    break;
  case P25_LC_TEL_INT_V_CH_USR:
    put(&o, " unit=%u timer_ms=%u", m->tgt, m->call_timer_ms);
    put_svc(&o, m->svc);
    break;
  case P25_LC_UU_V_CH_USR_EXT:
    put(&o, " tgt=%u", m->tgt);
    put_svc(&o, m->svc);
    break;
  case P25_LC_CALL_TRM:
  case P25_LC_MOT_TALK_COMPLETE:
    put(&o, " addr=%u", m->address);
    // the system controller's address: the network tore the channel down
    if(m->kind == P25_LC_CALL_TRM && (m->address == 0xfffffd || m->address == 0xffffff || m->address == 0))
      put(&o, " network=1");
    break;
  case P25_LC_MOT_GRG_V_CH_UPDT:
    put(&o, " tg=%u", m->group);
    put_svc(&o, m->svc);
    put_chan(&o, "", m->ch, plan);
    break;
  case P25_LC_MOT_UNIT_GPS:
    put(&o, " lat=%.6f lon=%.6f", m->latitude, m->longitude);
    break;
  case P25_LC_MOT_ALIAS_HDR:
    put(&o, " tg=%u blocks=%u seq=%u format=%u", m->group, m->block_count, m->sequence, m->alias_format);
    break;
  case P25_LC_MOT_ALIAS_DATA:
    put(&o, " block=%u seq=%u", m->block, m->sequence);
    put_hex(&o, "data", m->raw + 3, 6);
    break;
  case P25_LC_HARRIS_ALIAS:
    put(&o, " block=%u text=\"%s\"", m->block, m->text);
    break;
  case P25_PDU_RESPONSE:
    put(&o, " llid=%u response=0x%02x", m->llid, m->pdu_response);
    if(m->has_src_llid)
      put(&o, " src=%u", m->src_llid);
    put(&o, " dir=%s", m->outbound ? "out" : "in");
    break;
  case P25_PDU_SNDCP:
  case P25_PDU_SNDCP_DATA:
  case P25_PDU_DATA:
    put(&o, " llid=%u sap=%u", m->llid, m->sap);
    if(*p25_sap_name(m->sap))
      put(&o, " sap_name=%s", p25_sap_name(m->sap));
    put(&o, " confirmed=%d dir=%s octets=%d", m->confirmed, m->outbound ? "out" : "in", m->user_octets);
    if(m->kind == P25_PDU_SNDCP && m->user_octets > 0){
      put(&o, " sndcp_type=%u nsapi=%u", m->sndcp_type, m->sndcp_nsapi);
      if(m->sndcp_has_arg)
        put(&o, " arg=%u", m->sndcp_arg);
      if(m->sndcp_has_ip)
        put(&o, " ip=%u.%u.%u.%u", m->sndcp_ip[0], m->sndcp_ip[1], m->sndcp_ip[2], m->sndcp_ip[3]);
    }
    break;
  case P25_PDU_OTHER:
    put(&o, " format=0x%02x sap=%u mfid=0x%02x llid=%u blocks=%u confirmed=%d dir=%s", m->format, m->sap,
        m->mfid, m->llid, m->blocks, m->confirmed, m->outbound ? "out" : "in");
    put_hex(&o, "hdr", m->raw, 12);
    break;
  case P25_HDU:
    put(&o, " mfid=0x%02x", m->mfid);
    if(m->mfid == P25_MFID_STD){
      put(&o, " tg=%u algid=0x%02x kid=0x%04x", m->group, m->algid, m->kid);
      put_hex(&o, "mi", m->mi, 9);
    }
    break;
  case P25_ENC_SYNC:
    put(&o, " algid=0x%02x kid=0x%04x", m->algid, m->kid);
    put_hex(&o, "mi", m->mi, 9);
    break;
  case P25_KIND_COUNT:
    break;
  }
  return o.n;
}
