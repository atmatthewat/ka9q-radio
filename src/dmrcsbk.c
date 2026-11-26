// DMR control signalling blocks (see dmrcsbk.h): the CSBK and its CRC, every flavour's messages and
// their log lines, multi-block assembly, channel numbering, grants and the channel map
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dmrfec.h"
#include "dmrcsbk.h"

// Theory of operation
//
// Input. The 96 information bits of a burst whose slot type says CSBK, MBC header or MBC continuation,
// as BPTC(196,96) delivered them (dmrmsg.c hands them on unchecked: the CRC is this file's). Every bit
// number below is the bit of that 96-bit block, which is also how sdrtrunk numbers its fields, so the
// two can be read side by side.
//
// The common block (TS 102 361-2; sdrtrunk CSBKMessage.java:38-45, and OP25's dmr_slot.cc:274-278, which
// reads the same five fields and checks the same CRC): LB (0), PF (1), CSBKO (2-7), FID (8-15), 64
// payload bits (16-79), and a CRC-CCITT of bits 0-79, inverted and XORed with 0xA5A5 (0xAAAA for a
// multi-block header). The CRC rule: a block that fails is never parsed and never acted on. Some
// systems use another mask (Motorola's "RAS" among them); sdrtrunk learns such a mask after two
// sightings and from then on accepts it unasked (DMRCrcMaskManager.java). That is not done here. The
// mask that would have made the block pass is computed for every block (observed_mask), a counter keeps
// how often each (CSBKO, FID, mask) has come, and accepting anything but 0xA5A5 is the caller's
// explicit choice, by passing that mask. A bit error also produces an "observed mask", a different one
// each time, which is why a count and a deliberate decision come before anything is believed. The
// counter holds 256 entries; when it is full the entries seen once (bit errors, mostly) are dropped,
// and if it is still full the new one is not recorded.
//
// What is parsed, by (FID, CSBKO). The table and the field layouts are sdrtrunk's (GPL-3, Dennis
// Sheirer, github.com/DSheirer/sdrtrunk, commit 1945b835: message/data/csbk/Opcode.java,
// CSBKMessageFactory.java and the classes under csbk/standard, csbk/motorola and csbk/hytera, with
// message/type/SystemIdentityCode, Reason, ServiceKind, ProtectKind, Tier3Gateway, AbsoluteChannelParameters
// and channel/DMRLsn, DMRTier3Channel, DMRAbsoluteChannel). A pair with no parser comes back as
// DMR_CSBK_UNKNOWN with its 64 bits and, where sdrtrunk's table has one, its name: nothing is dropped.
// Unless a message says otherwise its layout rests on sdrtrunk alone. The exceptions with a second
// source: the common block above; Connect Plus neighbours (CSBKO 1) and voice channel user (CSBKO 3),
// also parsed by OP25 (GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al., dmr_slot.cc:282-304); and
// the rest LSN, beacon flag and site of the Capacity Plus neighbours CSBK (59), read the same way by
// trunk-recorder's dmr_parser.cc. One real message is known: the test word in the main() of sdrtrunk's
// BPTC_196_96.java decodes to a Capacity Plus Site Status, single segment, rest LSN 5, idle, standard
// mask, and agrees with the segment and rest LSN positions.
//
// Where this differs from sdrtrunk, on purpose (its versions are faults, not copied):
//   - Local time month and mass registration window: sdrtrunk's bit lists are {26, 27, 28, 39}, a typo
//     for 29 (LocalTime.java:37, MassRegistration.java:37) that takes the last bit from the backoff
//     field. Here they are bits 26-29.
//   - Ahoy stun and revive: sdrtrunk's isStunCommand and isReviveCommand are the same expression
//     (StunReviveKill.java:118-131). Here the service kind flag (bit 23) tells them apart, clear = stun,
//     set = revive, as getCommand() in the same class has it.
//   - Acknowledgement class: sdrtrunk's AcknowledgeType (0 acknowledged, 1 refused) contradicts its own
//     Reason table, where every refusal is 0x00-0x3F and every acceptance 0x44-0x65. Here the class is
//     the reason's top two bits: 00 NACK, 01 ACK, 10 queued, 11 wait.
//   - Capacity Max open mode, timeslot 2: sdrtrunk's bit list is {56..61, 63, 64, 64, 65..79}
//     (CapacityMaxOpenModeVoiceChannelUpdate.java:48), which skips bit 62 and reads 64 twice. Here the
//     talkgroup is the 24 bits 56-79, as timeslot 1's is 32-55; dmr_cap_max_ts2_as_sdrtrunk() gives
//     sdrtrunk's reading for comparing logs.
//   - Connect Plus neighbours: sdrtrunk reads six 8-bit sites from bit 16, the sixth overlapping 24
//     "unknown" bits at 56-79; OP25 reads five, and only the low 6 bits of each. Here the five octets
//     both agree on are sites, as 8 bits (the Connect Plus site of the Short LC has 8), the last 24 bits
//     are kept raw, and the sixth is available from them.
//   - Connect Plus data grants say they are data. sdrtrunk's ignore_data_calls misses them: the opcode
//     is not in its data grant set (Opcode.java:170-172).
//   Checked against TS 102 361-2 V2.5.1 and -4 V1.12.1 (an audit of 2026-11-23):
//   - Data grants: HI_RATE is bit 29; bit 31 is offset timing (sdrtrunk reads 31 as "high rate").
//     TV_GRANT and BTV_GRANT carry Late_Entry at bit 29 (tables 7.9-7.15).
//   - Ann_WD_TSCC: AW_FLAG 0 = add the channel, 1 = withdraw it (table 7.69; sdrtrunk inverts it).
//   - Local_Time: the UTC offset is 4 bits (30-33, 15 = not sent) and a sign (34), not 5 bits (table 7.73).
//   - Queued for busy radio is reason 0xA1, not 0xAA (table 7.44).
//   - CSBKO 38 is the Tier II NACK_Rsp, with its own layout (TS 102 361-2 table 7.6: reason 24-31,
//     source before target), not an acknowledgement. CSBKO 30 is C_ACKVIT.
//   - C_ALOHA bit 17 is TSCCAS (table 7.19; sdrtrunk: reserved).
//   - The multi-item data grants (55, 56) carry a CG_AP block like the other grants (tables 7.13, 7.15).
// Layouts neither sdrtrunk nor OP25 parses, written from TS 102 361-2 / -4: unit-to-unit request and
// answer (CSBKO 4, 5), BS outbound activation (56 from a mobile), random access (31), the multi-item
// data grants (55, 56, with the single-item grant layout). FID 0 CSBKO 56 is both a multi-item
// talkgroup data grant (from a Tier III base station) and BS_Dwn_Act (from a mobile), so the caller
// says which by mobile_sourced. trunk-recorder reads FID 0 grants with the Connect Plus
// layout (addresses first, a 4-bit LCN at 64); that contradicts sdrtrunk and is not used.
//
// The Connect Plus channel field. sdrtrunk reads a 5-bit "logical slot number" at bits 64-68 of the
// voice channel user and subtracts 1 ("Always leave as minus 1", ConnectPlusVoiceChannelUser.java:
// 129-132); OP25 reads the same bits as a 4-bit repeater number and a timeslot bit, 0 = TS1
// (dmr_slot.cc:297-298). They are one reading: with air = 2 * repeater + slot bit,
// air - 1 = 2 * (repeater - 1) + (slot bit + 1), the LSN of that repeater's timeslot. So the field is
// {repeater from 1, timeslot from 0}, not an LSN off by one. Both readings are kept with the five bits;
// they agree for every repeater from 1, and the channel is NONE for repeater 0, where sdrtrunk's
// arithmetic goes negative. The data channel grant (40-44) and OTA announcement (63-67) have the same
// field (sdrtrunk only). It is still to be checked on a capture before a channel is tuned from it.
//
// Channels. Three ways a message names a traffic channel: an LSN (Capacity Plus, Connect Plus), one per
// timeslot of a repeater, LSN 1 = repeater 1 TS1, LSN 2 = repeater 1 TS2, LSN 3 = repeater 2 TS1 (the
// configuration maps the repeater, never the LSN); a Tier III 12-bit logical physical channel number
// with a timeslot bit (the map's key); or absolute frequencies from a CG_AP block, which override the
// map. CG_AP (sdrtrunk AbsoluteChannelParameters.java:32-43; one source, OP25 passes multi-block control
// up unparsed): colour code 12-15, CDEF type 16-19 (only 0 is defined), LCN 22-33, uplink MHz 34-43 and
// 125 Hz steps 44-56, downlink MHz 57-66 and steps 67-79. "Uplink first" is sdrtrunk's order and is not
// confirmed by a second source (a base station is heard on the downlink, so a swapped pair would show at
// once). 8,000 steps are 1 MHz, so a count of 8,000 or more is no frequency a sender would write: such a
// block, or one with another CDEF type or no downlink, is not plausible and not used for tuning.
//
// Multi-block control. A CSBK that needs more than 64 bits is a header burst (slot type MBC header, the
// CSBK layout, mask 0xAAAA) and up to three continuation bursts (MBC continuation) on the same
// timeslot; each continuation block starts with its own LB, and the last (LB = 1) ends with a
// CRC-CCITT with no mask. Both CRCs are checked: sdrtrunk never checks the header's (MBCHeader's
// getCRCMask() has no caller), holds every continuation block valid, and checks the pair only when a few
// message classes are built, so an unknown multi-block message is "valid" unconditionally. What the
// continuation CRC covers: OP25 (dmr_slot.cc:349-386) computes it over every continuation block together,
// sdrtrunk (CSBKMessage.java:93-107) over the first block's 80 bits. With one block, the CG_AP case,
// those are the same computation, so that case has two sources; with more only OP25's reading makes
// sense (sdrtrunk never looks at blocks 2 and 3), and it is used: TS 102 361-1 7.4.0 (figures 7.11-7.13)
// confirms it, the last block's CRC over all but the header, no mask. Three blocks as the limit: 7.4.0
// describes a header, up to two intermediate blocks and a last block without stating a maximum; OP25
// takes any number, sdrtrunk reads one. The two CRCs are separate, so
// a header and a block of two different messages would pass together; three things prevent it: any
// other burst on the timeslot abandons the message (as sdrtrunk, DMRMessageProcessor.java:218-230), a
// block more than 90 ms after the one before is refused (the bursts of a timeslot are 60 ms apart; 90
// allows half as much again), and a message that completed or failed is forgotten, so a repeated last
// block finds no header. Only the first continuation block is parsed, as CG_AP, and only for the
// messages sdrtrunk parses it for (CSBKMessageFactory.java:351-446): Tier III grants 48-54, P_CLEAR,
// C_MOVE, C_BCAST types 0, 2, 5 and 6, and the Hytera adjacent site announcement. Every continuation bit
// is kept for anything else.
//
// Grants, whatever the flavour: Tier III PV / TV / BTV / PD / TD grants and their duplex and multi-item
// forms (one message at call start; with a CG_AP block the channel is absolute, and an implausible one
// falls back to the logical channel); Connect Plus voice channel user (3) and data channel grant (6);
// Capacity Max voice channel updates, open mode (33, up to two talkgroups) and advantage mode (34, up to
// four). The voice channel user and the updates repeat while the call lasts: activity_update says so.
// Capacity Plus has no grants (its Site Status is an activity map) and Hytera Tier III uses the standard
// ones. protect_flag is the CSBK's PF bit, which sdrtrunk reads as encryption; it never labels voice.
//
// The channel map: LCN -> frequency for one site, from the configuration (what the user says is true)
// and from the air (a C_BCAST "announce channel frequency" with its CG_AP block; sdrtrunk parses it and
// never fills its map from it). The configuration wins: an air value never replaces a configured one.
// A disagreement is returned as a conflict for the caller to log, since a wrong LCN table sends every
// grant to the wrong frequency and this is where it can be noticed. Two air values that disagree are a
// conflict too, and the newer is kept (a site can be re-planned). Two frequencies within tolerance_hz
// are the same (CG_AP has 125 Hz steps, so a configuration typed off that grid needs one).

static uint32_t bits_to_uint(uint8_t const *bits,int n){
  uint32_t v = 0;
  for(int i=0; i < n; i++)
    v = (v << 1) | (bits[i] & 1u);
  return v;
}

static void append(char *buf,size_t size,size_t *len,char const *fmt,...) __attribute__((format(printf,4,5)));
static void append(char *buf,size_t size,size_t *len,char const *fmt,...){
  if(*len >= size)
    return;
  va_list ap;
  va_start(ap,fmt);
  int const n = vsnprintf(buf + *len,size - *len,fmt,ap);
  va_end(ap);
  if(n > 0)
    *len += (size_t)n < size - *len ? (size_t)n : size - *len - 1;
}
static int finish(char *buf,size_t size,size_t len){
  if(size > 0 && len == 0)
    buf[0] = '\0';
  return (int)len;
}

// ---------------- Channels ----------------

struct dmr_channel_ref dmr_chref_none(void){
  struct dmr_channel_ref c;
  memset(&c,0,sizeof c);
  return c;
}
struct dmr_channel_ref dmr_chref_from_lsn(int lsn){
  struct dmr_channel_ref c = dmr_chref_none();
  if(lsn < 1 || lsn > 255)
    return c;
  c.kind = DMR_CHREF_LSN;
  c.lsn = (uint8_t)lsn;
  c.lcn = (uint16_t)dmr_lsn_to_lcn(lsn);
  c.timeslot = (uint8_t)dmr_lsn_to_timeslot(lsn);
  return c;
}
struct dmr_channel_ref dmr_chref_from_tier3(int lcn,int timeslot){
  struct dmr_channel_ref c = dmr_chref_none();
  c.kind = DMR_CHREF_TIER3;
  c.lcn = (uint16_t)(lcn & 0xFFF);
  c.timeslot = (uint8_t)(timeslot == 1 || timeslot == 2 ? timeslot : 0);
  return c;
}
struct dmr_channel_ref dmr_chref_from_absolute(int lcn,int timeslot,uint64_t downlink_hz,uint64_t uplink_hz){
  struct dmr_channel_ref c = dmr_chref_from_tier3(lcn,timeslot);
  c.kind = DMR_CHREF_ABSOLUTE;
  c.downlink_hz = downlink_hz;
  c.uplink_hz = uplink_hz;
  return c;
}
int dmr_format_mhz(char *buf,size_t size,uint64_t hz){
  return snprintf(buf,size,"%llu.%06llu",(unsigned long long)(hz / 1000000ull),(unsigned long long)(hz % 1000000ull));
}
int dmr_chref_describe(char *buf,size_t size,struct dmr_channel_ref const *c){
  char mhz[40];
  switch(c->kind){
  case DMR_CHREF_LSN:
    return snprintf(buf,size,"LSN %u (LCN %u TS%u)",c->lsn,c->lcn,c->timeslot);
  case DMR_CHREF_TIER3:
    return snprintf(buf,size,"LCN %u TS%u",c->lcn,c->timeslot);
  case DMR_CHREF_ABSOLUTE:
    dmr_format_mhz(mhz,sizeof mhz,c->downlink_hz);
    return snprintf(buf,size,"LCN %u TS%u %s MHz",c->lcn,c->timeslot,mhz);
  case DMR_CHREF_NONE:
    break;
  }
  return snprintf(buf,size,"no channel");
}

void dmr_cgap_parse(struct dmr_cgap *p,uint8_t const bits80[80]){
  assert(p != NULL && bits80 != NULL);
  memset(p,0,sizeof *p);
  p->last_block = (bits80[0] & 1u) != 0;
  p->protect = (bits80[1] & 1u) != 0;
  p->opcode = (uint8_t)bits_to_uint(bits80 + 2,6);
  p->color_code = (uint8_t)bits_to_uint(bits80 + 12,4);
  p->cdef_type = (uint8_t)bits_to_uint(bits80 + 16,4);
  p->lcn = (uint16_t)bits_to_uint(bits80 + 22,12);
  p->uplink_mhz = (uint16_t)bits_to_uint(bits80 + 34,10);
  p->uplink_steps = (uint16_t)bits_to_uint(bits80 + 44,13);
  p->downlink_mhz = (uint16_t)bits_to_uint(bits80 + 57,10);
  p->downlink_steps = (uint16_t)bits_to_uint(bits80 + 67,13);
}
struct dmr_channel_ref dmr_cgap_channel(struct dmr_cgap const *p,int timeslot){
  return dmr_chref_from_absolute(p->lcn,timeslot,dmr_cgap_downlink_hz(p),dmr_cgap_uplink_hz(p));
}
int dmr_cgap_describe(char *buf,size_t size,struct dmr_cgap const *p){
  char down[40],up[40];
  dmr_format_mhz(down,sizeof down,dmr_cgap_downlink_hz(p));
  dmr_format_mhz(up,sizeof up,dmr_cgap_uplink_hz(p));
  return snprintf(buf,size,"CG_AP LCN %u cc=%u down=%s up=%s MHz",p->lcn,p->color_code,down,up);
}

// ---------------- The common block ----------------

uint32_t dmr_csbk_bits(struct dmr_csbk_block const *k,int first,int count){
  return bits_to_uint(k->bits + first,count);
}
static bool bit(struct dmr_csbk_block const *k,int index){
  return k->bits[index] != 0;
}

void dmr_csbk_read_block(struct dmr_csbk_block *k,uint8_t const info96[96],uint8_t slot,uint8_t color_code,
                         uint64_t timestamp_us,uint16_t crc_mask){
  assert(k != NULL && info96 != NULL);
  memset(k,0,sizeof *k);
  k->timestamp_us = timestamp_us;
  k->slot = slot;
  k->color_code = color_code;
  for(int i=0; i < 96; i++)
    k->bits[i] = info96[i] & 1u;
  k->crc_mask = crc_mask;
  k->observed_mask = dmr_crc_ccitt_observed_mask(k->bits,96);
  k->crc_ok = k->observed_mask == crc_mask;
  k->last_block = bit(k,0);
  k->protect = bit(k,1);
  k->opcode = (uint8_t)dmr_csbk_bits(k,2,6);
  k->fid = (uint8_t)dmr_csbk_bits(k,8,8);
  k->payload = ((uint64_t)dmr_csbk_bits(k,16,32) << 32) | dmr_csbk_bits(k,48,32);
}

void dmr_csbk_mask_counter_init(struct dmr_csbk_mask_counter *c,size_t max_entries){
  assert(c != NULL);
  memset(c,0,sizeof *c);
  c->max_entries = (max_entries == 0 || max_entries > DMR_CSBK_MASK_COUNTER_MAX) ? DMR_CSBK_MASK_COUNTER_MAX : max_entries;
}
uint32_t dmr_csbk_mask_note_block(struct dmr_csbk_mask_counter *c,struct dmr_csbk_block const *k){
  if(k->crc_ok)
    return 0;
  return dmr_csbk_mask_note(c,k->opcode,k->fid,k->observed_mask);
}
uint32_t dmr_csbk_mask_note(struct dmr_csbk_mask_counter *c,uint8_t opcode,uint8_t fid,uint16_t mask){
  for(size_t i=0; i < c->count; i++){
    struct dmr_csbk_mask_entry *e = &c->entries[i];
    if(e->opcode == opcode && e->fid == fid && e->mask == mask)
      return ++e->count;
  }
  if(c->count >= c->max_entries){
    // Full: keep the entries seen more than once, in order
    size_t kept = 0;
    for(size_t i=0; i < c->count; i++){
      if(c->entries[i].count > 1)
        c->entries[kept++] = c->entries[i];
    }
    c->count = kept;
    if(c->count >= c->max_entries)
      return 0;
  }
  struct dmr_csbk_mask_entry *e = &c->entries[c->count++];
  e->opcode = opcode;
  e->fid = fid;
  e->mask = mask;
  e->count = 1;
  return 1;
}
uint32_t dmr_csbk_mask_count(struct dmr_csbk_mask_counter const *c,uint8_t opcode,uint8_t fid,uint16_t mask){
  for(size_t i=0; i < c->count; i++){
    struct dmr_csbk_mask_entry const *e = &c->entries[i];
    if(e->opcode == opcode && e->fid == fid && e->mask == mask)
      return e->count;
  }
  return 0;
}
bool dmr_csbk_mask_most_seen(struct dmr_csbk_mask_counter const *c,uint8_t opcode,uint8_t fid,uint32_t min_count,
                             uint16_t *mask){
  struct dmr_csbk_mask_entry const *best = NULL;
  for(size_t i=0; i < c->count; i++){
    struct dmr_csbk_mask_entry const *e = &c->entries[i];
    if(e->opcode == opcode && e->fid == fid && (best == NULL || e->count > best->count))
      best = e;
  }
  if(best == NULL || best->count < min_count)
    return false;
  if(mask != NULL)
    *mask = best->mask;
  return true;
}
void dmr_csbk_mask_clear(struct dmr_csbk_mask_counter *c){
  c->count = 0;
}

// ---------------- Names ----------------

char const *dmr_csbk_name(uint8_t fid,uint8_t opcode){
  // sdrtrunk Opcode.java (GPL-3, Dennis Sheirer)
  switch(fid){
  case DMR_FID_STANDARD:
    switch(opcode){
    case 3: return "FEATURE NOT SUPPORTED";
    case 4: return "UU_V_REQ";
    case 5: return "UU_ANS_RSP";
    case 7: return "CHANNEL TIMING";
    case 25: return "ALOHA";
    case 26: return "UDT OUTBOUND HEADER";
    case 27: return "UDT INBOUND HEADER";
    case 28: return "AHOY";
    case 30: return "C_ACKVIT";
    case 31: return "C_RAND";
    case 32: return "C_ACKD";
    case 33: return "C_ACKU";
    case 34: return "P_ACKD";
    case 35: return "P_ACKU";
    case 36: return "UDT DGNA OUTBOUND HEADER";
    case 37: return "UDT DGNA INBOUND HEADER";
    case 38: return "NACK_RSP";
    case 40: return "C_BCAST";
    case 42: return "P_MAINT";
    case 46: return "P_CLEAR";
    case 47: return "P_PROTECT";
    case 48: return "PV_GRANT";
    case 49: return "TV_GRANT";
    case 50: return "BTV_GRANT";
    case 51: return "PD_GRANT";
    case 52: return "TD_GRANT";
    case 53: return "PV_GRANT_DX";
    case 54: return "PD_GRANT_DX";
    case 55: return "PD_GRANT_MI";
    case 56: return "TD_GRANT_MI";
    case 57: return "C_MOVE";
    case 61: return "PREAMBLE";
    default: return NULL;
    }
  case DMR_FID_CONNECT_PLUS:
    switch(opcode){
    case 1: return "CON+ NEIGHBORS";
    case 3: return "CON+ VOICE CHANNEL USER";
    case 6: return "CON+ DATA CHANNEL GRANT";
    case 10: return "CON+ OTA ANNOUNCEMENT";
    case 12: return "CON+ TERMINATE CHANNEL GRANT";
    case 16: return "CON+ CSBKO 16";
    case 17: return "CON+ REGISTRATION REQUEST";
    case 18: return "CON+ REGISTRATION RESPONSE";
    case 24: return "CON+ AFFILIATION";
    case 28: return "CON+ DATA REVERT WINDOW ANNOUNCEMENT";
    case 29: return "CON+ DATA REVERT WINDOW GRANT";
    default: return NULL;
    }
  case DMR_FID_MOTOROLA:
    switch(opcode){
    case 25: return "CAPMAX ALOHA";
    case 31: return "CAP+ CALL ALERT";
    case 32: return "CAP+ CALL ALERT ACK";
    case 33: return "CAPMAX CHANNEL UPDATE OPEN MODE";
    case 34: return "CAPMAX CHANNEL UPDATE ADVANTAGE MODE";
    case 41: return "CAP+ DATA REVERT WINDOW ANNOUNCEMENT";
    case 42: return "CAP+ DATA REVERT WINDOW GRANT";
    case 59: return "CAP+ NEIGHBORS";
    case 60: return "CAP+ CSBKO 60";
    case 61: return "CAP+ PREAMBLE";
    case 62: return "CAP+ SITE STATUS";
    default: return NULL;
    }
  case DMR_FID_HYTERA_08:
    switch(opcode){
    case 32: return "HYTERA 08 ACK";
    case 40: return "HYTERA 08 ANNOUNCEMENT";
    case 44: return "HYTERA 08 CSBKO 44";
    case 47: return "HYTERA TALKER STATUS";
    default: return NULL;
    }
  case DMR_FID_HYTERA_68:
    switch(opcode){
    case 10: return "XPT SITE STATE";
    case 11: return "XPT ADJACENT SITES";
    case 25: return "HYTERA ALOHA";
    case 32: return "HYTERA 68 ACK";
    case 40: return "HYTERA 68 ANNOUNCEMENT";
    case 61: return "XPT PREAMBLE";
    case 62: return "HYTERA SMS AVAILABLE";
    default: return NULL;
    }
  default:
    return NULL;
  }
}

char const *dmr_system_model_name(enum dmr_system_model m){
  switch(m){
  case DMR_MODEL_TINY: return "tiny";
  case DMR_MODEL_SMALL: return "small";
  case DMR_MODEL_LARGE: return "large";
  case DMR_MODEL_HUGE: return "huge";
  }
  return "?";
}

char const *dmr_tier3_gateway_name(uint32_t address){
  // sdrtrunk Tier3Gateway.java (GPL-3, Dennis Sheirer)
  switch(address){
  case 0xFFFEC0: return "PSTNI";
  case 0xFFFEC1: return "PABXI";
  case 0xFFFEC2: return "LINEI";
  case 0xFFFEC3: return "IPI";
  case 0xFFFEC4: return "SUPLI";
  case 0xFFFEC5: return "SDMI";
  case 0xFFFEC6: return "REGI";
  case 0xFFFEC7: return "MSI";
  case 0xFFFEC9: return "DIVERTI";
  case 0xFFFECA: return "TSI";
  case 0xFFFECB: return "DISPATI";
  case 0xFFFECC: return "STUNI";
  case 0xFFFECD: return "AUTHI";
  case 0xFFFECE: return "GPI";
  case 0xFFFECF: return "KILLI";
  case 0xFFFED0: return "PSTNDI";
  case 0xFFFED1: return "PABXDI";
  case 0xFFFED2: return "LINEDI";
  case 0xFFFED3: return "DISPATDI";
  case 0xFFFED4: return "ALLMSI";
  case 0xFFFED5: return "IPDI";
  case 0xFFFED6: return "DGNAI";
  case 0xFFFED7: return "TATTSI";
  case 0xFFFFFD: return "ALLMSIDL";
  case 0xFFFFFE: return "ALLMSIDZ";
  case 0xFFFFFF: return "ALLMSID";
  default: return NULL;
  }
}
// "1234" or "TSI(16776906)"
static void append_address(char *buf,size_t size,size_t *len,uint32_t address){
  char const *gateway = dmr_tier3_gateway_name(address);
  if(gateway != NULL)
    append(buf,size,len,"%s(%u)",gateway,address);
  else
    append(buf,size,len,"%u",address);
}

char const *dmr_service_kind_name(uint8_t kind){
  // TS 102 361-4 service kinds, as sdrtrunk's ServiceKind.java (GPL-3, Dennis Sheirer)
  static char const * const names[16] = {
    "individual voice", "talkgroup voice", "individual packet", "talkgroup packet",
    "individual short data", "talkgroup short data", "short data polling", "status transport",
    "call diversion", "call answer", "duplex voice", "duplex packet",
    "reserved 12", "supplementary", "register / authenticate / radio check", "cancel call"};
  return names[kind & 0xFu];
}

char const *dmr_ack_reason_name(uint8_t reason){
  // sdrtrunk Reason.java (GPL-3, Dennis Sheirer)
  switch(reason){
  case 0x00: return "MS: service not supported";
  case 0x11: return "MS: line not supported";
  case 0x12: return "MS refused: stack full";
  case 0x13: return "MS refused: equipment busy";
  case 0x14: return "MS: refused by recipient";
  case 0x15: return "MS refused: custom";
  case 0x16: return "MS: duplex not supported";
  case 0x1F: return "MS refused: reason unknown";
  case 0x20: return "service not supported";
  case 0x21: return "refused: not permitted";
  case 0x22: return "refused: service temporarily unavailable";
  case 0x23: return "refused: service unavailable";
  case 0x24: return "refused: called radio not registered";
  case 0x25: return "refused: called radio offline";
  case 0x26: return "refused: called radio has call diversion";
  case 0x27: return "refused: network congestion";
  case 0x28: return "refused: network not ready";
  case 0x29: return "refused: cannot cancel call";
  case 0x2A: return "registration refused";
  case 0x2B: return "registration denied";
  case 0x2C: return "IP connection failed";
  case 0x2D: return "refused: radio not registered";
  case 0x2E: return "called party busy";
  case 0x2F: return "called talkgroup not allowed";
  case 0x30: return "CRC error in UDT upload";
  case 0x31: return "refused: duplex call, network congestion";
  case 0x3F: return "refused: reason unknown";
  case 0x44: return "MS: message accepted";
  case 0x45: return "MS: callback";
  case 0x46: return "MS: alerting but not ready";
  case 0x47: return "MS: accepted for status polling";
  case 0x48: return "MS: authentication response";
  case 0x60: return "message accepted";
  case 0x61: return "store and forward";
  case 0x62: return "registration accepted";
  case 0x63: return "accepted for status polling";
  case 0x64: return "authentication response";
  case 0x65: return "subscription service registration accepted";
  case 0xA0: return "queued for resource";
  case 0xA1: return "queued for busy radio";
  case 0xE0: return "wait";
  default: return NULL;
  }
}

char const *dmr_protect_kind_name(uint8_t kind){
  switch(kind){
  case 0: return "disable PTT";
  case 1: return "enable PTT";
  case 2: return "illegally parked";
  case 3: return "enable target PTT only";
  default: return "reserved";
  }
}

char const *dmr_tier3_grant_name(enum dmr_tier3_grant_kind kind){
  switch(kind){
  case DMR_T3G_PRIVATE_VOICE: return "PV_GRANT";
  case DMR_T3G_TALKGROUP_VOICE: return "TV_GRANT";
  case DMR_T3G_BROADCAST_TALKGROUP_VOICE: return "BTV_GRANT";
  case DMR_T3G_PRIVATE_DATA: return "PD_GRANT";
  case DMR_T3G_TALKGROUP_DATA: return "TD_GRANT";
  case DMR_T3G_DUPLEX_PRIVATE_VOICE: return "PV_GRANT_DX";
  case DMR_T3G_DUPLEX_PRIVATE_DATA: return "PD_GRANT_DX";
  case DMR_T3G_PRIVATE_DATA_MULTI: return "PD_GRANT_MI";
  case DMR_T3G_TALKGROUP_DATA_MULTI: return "TD_GRANT_MI";
  }
  return "GRANT";
}

// ---------------- Standard (FID 0x00) messages ----------------
// Layouts: sdrtrunk (GPL-3, Dennis Sheirer, commit 1945b835) message/data/csbk/standard/*.java, with
// the corrections the theory of operation lists; the ones sdrtrunk lacks from TS 102 361-2 / -4

void dmr_system_code_parse(struct dmr_system_code *s,struct dmr_csbk_block const *k,int first,bool has_par){
  // sdrtrunk SystemIdentityCode.java:34-43
  memset(s,0,sizeof *s);
  s->raw = (uint16_t)dmr_csbk_bits(k,first,14);
  s->model = (enum dmr_system_model)dmr_csbk_bits(k,first,2);
  switch(s->model){
  case DMR_MODEL_TINY:
    s->network = (uint16_t)dmr_csbk_bits(k,first + 2,9);
    s->site = (uint16_t)dmr_csbk_bits(k,first + 11,3);
    break;
  case DMR_MODEL_SMALL:
    s->network = (uint16_t)dmr_csbk_bits(k,first + 2,7);
    s->site = (uint16_t)dmr_csbk_bits(k,first + 9,5);
    break;
  case DMR_MODEL_LARGE:
    s->network = (uint16_t)dmr_csbk_bits(k,first + 2,4);
    s->site = (uint16_t)dmr_csbk_bits(k,first + 6,8);
    break;
  case DMR_MODEL_HUGE:
    s->network = (uint16_t)dmr_csbk_bits(k,first + 2,2);
    s->site = (uint16_t)dmr_csbk_bits(k,first + 4,10);
    break;
  }
  s->has_par = has_par;
  if(has_par)
    s->par = (uint8_t)dmr_csbk_bits(k,first + 14,2);
}
static void append_system_code(char *buf,size_t size,size_t *len,struct dmr_system_code const *s){
  append(buf,size,len,"net=%u site=%u (%s)",s->network,s->site,dmr_system_model_name(s->model));
}

// Aloha (sdrtrunk Aloha.java:41-52; CapacityMaxAloha and HyteraAloha are copies, the latter marking its
// bits 16-31 unverified)
static void parse_aloha(struct dmr_csbk_aloha *a,struct dmr_csbk_block const *k,enum dmr_aloha_flavor flavor){
  memset(a,0,sizeof *a);
  a->flavor = flavor;
  a->tsccas = bit(k,17);
  a->site_timeslot_sync = bit(k,18);
  a->version = (uint8_t)dmr_csbk_bits(k,19,3);
  a->timing_offset = bit(k,22);
  a->active_network_connection = bit(k,23);
  a->mask = (uint8_t)dmr_csbk_bits(k,24,5);
  a->service_function = (uint8_t)dmr_csbk_bits(k,29,2);
  a->nrand_wait = (uint8_t)dmr_csbk_bits(k,31,4);
  a->registration_required = bit(k,35);
  a->backoff = (uint8_t)dmr_csbk_bits(k,36,4);
  dmr_system_code_parse(&a->system,k,40,true);
  a->radio = dmr_csbk_bits(k,56,24);
}
static void describe_aloha(char *buf,size_t size,size_t *len,struct dmr_csbk_aloha const *a){
  append(buf,size,len,"%s",a->flavor == DMR_ALOHA_CAPACITY_MAX ? "CAPMAX ALOHA " : a->flavor == DMR_ALOHA_HYTERA ? "HYTERA ALOHA " : "ALOHA ");
  append_system_code(buf,size,len,&a->system);
  if(a->registration_required)
    append(buf,size,len," reg-required");
  append(buf,size,len,"%s",a->active_network_connection ? " net-connected" : " net-disconnected");
  append(buf,size,len," services=%u mask=%u backoff=%u",a->service_function,a->mask,a->backoff);
  if(dmr_system_code_multiple_cc(&a->system))
    append(buf,size,len," multi-cc");
  if(a->flavor == DMR_ALOHA_STANDARD && a->tsccas)
    append(buf,size,len," tsccas");
  if(a->radio != 0){
    append(buf,size,len," to=");
    append_address(buf,size,len,a->radio);
  }
}

// Ahoy (sdrtrunk ahoy/Ahoy.java:37-46 and its subclasses)
static void parse_ahoy(struct dmr_csbk_ahoy *a,struct dmr_csbk_block const *k){
  memset(a,0,sizeof *a);
  a->service_options_mirror = (uint8_t)dmr_csbk_bits(k,16,7);
  a->service_kind_flag = bit(k,23);
  a->ambient_listening = bit(k,24);
  a->target_is_talkgroup = bit(k,25);
  a->appended_blocks = (uint8_t)dmr_csbk_bits(k,26,2);
  a->service_kind = (uint8_t)dmr_csbk_bits(k,28,4);
  a->target = dmr_csbk_bits(k,32,24);
  a->source = dmr_csbk_bits(k,56,24);
}
enum dmr_ahoy_kind dmr_ahoy_kind(struct dmr_csbk_ahoy const *a){
  switch(a->service_kind){
  case 0: case 1: case 2: case 3: case 4: case 5: case 10: case 11:
    return DMR_AHOY_SERVICE_RADIO_CHECK;
  case 13:
    if(a->source == DMR_GATEWAY_KILL)
      return DMR_AHOY_KILL;
    if(a->source == DMR_GATEWAY_STUN)
      return a->service_kind_flag ? DMR_AHOY_REVIVE : DMR_AHOY_STUN;
    return DMR_AHOY_OTHER;
  case 14:
    return a->source == DMR_GATEWAY_TSI ? DMR_AHOY_RADIO_CHECK : DMR_AHOY_AUTHENTICATE;
  case 15:
    return DMR_AHOY_CANCEL_CALL;
  default:
    return DMR_AHOY_OTHER;
  }
}
static void describe_ahoy(char *buf,size_t size,size_t *len,struct dmr_csbk_ahoy const *a){
  append(buf,size,len,"AHOY ");
  enum dmr_ahoy_kind const kind = dmr_ahoy_kind(a);
  switch(kind){
  case DMR_AHOY_SERVICE_RADIO_CHECK: append(buf,size,len,"service check (%s)",dmr_service_kind_name(a->service_kind)); break;
  case DMR_AHOY_RADIO_CHECK: append(buf,size,len,"radio check"); break;
  case DMR_AHOY_AUTHENTICATE: append(buf,size,len,"authenticate challenge=%06X",a->source); break;
  case DMR_AHOY_CANCEL_CALL: append(buf,size,len,"cancel call"); break;
  case DMR_AHOY_STUN: append(buf,size,len,"STUN"); break;
  case DMR_AHOY_REVIVE: append(buf,size,len,"REVIVE"); break;
  case DMR_AHOY_KILL: append(buf,size,len,"KILL"); break;
  case DMR_AHOY_OTHER: append(buf,size,len,"service=%u (%s)",a->service_kind,dmr_service_kind_name(a->service_kind)); break;
  }
  append(buf,size,len,"%s",a->target_is_talkgroup ? " to=tg " : " to=");
  append_address(buf,size,len,a->target);
  if(kind != DMR_AHOY_AUTHENTICATE){
    append(buf,size,len," from=");
    append_address(buf,size,len,a->source);
  }
}

// Acknowledgements, CSBKO 32-35 (38 is NACK_Rsp, parsed apart) and the Hytera copies (sdrtrunk
// acknowledge/Acknowledge.java:42-50, hytera/Hytera08Acknowledge.java, Hytera68Acknowledge.java)
static void parse_ack(struct dmr_csbk_ack *a,struct dmr_csbk_block const *k){
  memset(a,0,sizeof *a);
  a->opcode = k->opcode;
  a->fid = k->fid;
  a->response_info = (uint8_t)dmr_csbk_bits(k,16,7);
  a->reason = (uint8_t)dmr_csbk_bits(k,23,8);
  a->group_flag = bit(k,16);
  a->target = dmr_csbk_bits(k,32,24);
  a->source = dmr_csbk_bits(k,56,24);
}
static void describe_ack(char *buf,size_t size,size_t *len,struct dmr_csbk_ack const *a){
  static char const * const classes[4] = {"NACK", "ACK", "QACK", "WACK"};
  if(a->fid != DMR_FID_STANDARD)
    append(buf,size,len,"HYTERA %02X ",a->fid);
  append(buf,size,len,"%s",classes[(int)dmr_ack_class(a)]);
  char const *reason = dmr_ack_reason_name(a->reason);
  if(reason != NULL)
    append(buf,size,len," reason=0x%02X (%s)",a->reason,reason);
  else
    append(buf,size,len," reason=0x%02X",a->reason);
  append(buf,size,len," to=");
  append_address(buf,size,len,a->target);
  append(buf,size,len," from=");
  append_address(buf,size,len,a->source);
  if(a->response_info != 0)
    append(buf,size,len," info=%u",a->response_info);
}

// Channel grants, CSBKO 48-56 (sdrtrunk grant/ChannelGrant.java:41-45 and its subclasses; 55 and 56 with
// the single-item layout, as TS 102 361-4 tables 7.13 and 7.15 have them)
static void parse_grant(struct dmr_csbk_grant *g,struct dmr_csbk_block const *k){
  memset(g,0,sizeof *g);
  g->opcode = k->opcode;
  g->kind = (enum dmr_tier3_grant_kind)(dmr_csbk_is_grant_opcode(k->opcode) ? k->opcode - DMR_CSBKO_PV_GRANT : 1);
  g->lcn = (uint16_t)dmr_csbk_bits(k,16,12);
  g->timeslot = (uint8_t)(dmr_csbk_bits(k,28,1) + 1);
  g->flag29 = bit(k,29);
  g->emergency = bit(k,30);
  g->flag31 = bit(k,31);
  g->destination = dmr_csbk_bits(k,32,24);
  g->source = dmr_csbk_bits(k,56,24);
}
bool dmr_csbk_grant_is_data(struct dmr_csbk_grant const *g){
  return g->kind == DMR_T3G_PRIVATE_DATA || g->kind == DMR_T3G_TALKGROUP_DATA || g->kind == DMR_T3G_DUPLEX_PRIVATE_DATA
    || g->kind == DMR_T3G_PRIVATE_DATA_MULTI || g->kind == DMR_T3G_TALKGROUP_DATA_MULTI;
}
bool dmr_csbk_grant_is_duplex(struct dmr_csbk_grant const *g){
  return g->kind == DMR_T3G_DUPLEX_PRIVATE_VOICE || g->kind == DMR_T3G_DUPLEX_PRIVATE_DATA;
}
bool dmr_csbk_grant_to_talkgroup(struct dmr_csbk_grant const *g){
  return g->kind == DMR_T3G_TALKGROUP_VOICE || g->kind == DMR_T3G_BROADCAST_TALKGROUP_VOICE
    || g->kind == DMR_T3G_TALKGROUP_DATA || g->kind == DMR_T3G_TALKGROUP_DATA_MULTI;
}
// Bits 29-31 by grant (TS 102 361-4 tables 7.9-7.15):
//                          bit 29        bit 30      bit 31
//   PV_GRANT (48)          reserved      emergency   offset timing
//   PV_GRANT_DX (53)       reserved      emergency   call direction
//   TV / BTV_GRANT (49/50) late entry    emergency   offset timing
//   data grants            HI_RATE       emergency   offset timing (duplex: call direction)
// sdrtrunk reads bit 31 as the data grants' "high rate"
static bool grant_high_rate(struct dmr_csbk_grant const *g){
  return dmr_csbk_grant_is_data(g) && g->flag29;
}
static bool grant_late_entry(struct dmr_csbk_grant const *g){
  return (g->kind == DMR_T3G_TALKGROUP_VOICE || g->kind == DMR_T3G_BROADCAST_TALKGROUP_VOICE) && g->flag29;
}
static bool grant_offset_timing(struct dmr_csbk_grant const *g){
  return !dmr_csbk_grant_is_duplex(g) && g->flag31;
}
static bool grant_target_is_source(struct dmr_csbk_grant const *g){
  return dmr_csbk_grant_is_duplex(g) && g->flag31;
}
uint32_t dmr_csbk_grant_called(struct dmr_csbk_grant const *g){
  return grant_target_is_source(g) ? g->source : g->destination;
}
uint32_t dmr_csbk_grant_caller(struct dmr_csbk_grant const *g){
  return grant_target_is_source(g) ? g->destination : g->source;
}
struct dmr_channel_ref dmr_csbk_grant_channel(struct dmr_csbk_grant const *g){
  return dmr_chref_from_tier3(g->lcn,g->timeslot);
}
static void append_chref(char *buf,size_t size,size_t *len,struct dmr_channel_ref const *c){
  char text[96];
  dmr_chref_describe(text,sizeof text,c);
  append(buf,size,len,"%s",text);
}
static void describe_grant(char *buf,size_t size,size_t *len,struct dmr_csbk_grant const *g){
  append(buf,size,len,"%s",dmr_tier3_grant_name(g->kind));
  append(buf,size,len,"%s",dmr_csbk_grant_to_talkgroup(g) ? " tg=" : " to=");
  append_address(buf,size,len,dmr_csbk_grant_called(g));
  append(buf,size,len," from=");
  append_address(buf,size,len,dmr_csbk_grant_caller(g));
  append(buf,size,len," ");
  struct dmr_channel_ref const c = dmr_csbk_grant_channel(g);
  append_chref(buf,size,len,&c);
  if(g->emergency)
    append(buf,size,len," EMERGENCY");
  if(grant_high_rate(g))
    append(buf,size,len," hi-rate");
  if(grant_late_entry(g))
    append(buf,size,len," late-entry");
  if(grant_offset_timing(g))
    append(buf,size,len," offset");
}

static void parse_nack_response(struct dmr_csbk_nack_response *n,struct dmr_csbk_block const *k){
  memset(n,0,sizeof *n);
  n->additional_info = bit(k,16);
  n->ms_sourced = bit(k,17);
  n->service_type = (uint8_t)dmr_csbk_bits(k,18,6);
  n->reason = (uint8_t)dmr_csbk_bits(k,24,8);
  n->source = dmr_csbk_bits(k,32,24);
  n->target = dmr_csbk_bits(k,56,24);
}
static void describe_nack_response(char *buf,size_t size,size_t *len,struct dmr_csbk_nack_response const *n){
  append(buf,size,len,"NACK_RSP reason=0x%02X",n->reason);
  if(n->reason == 0x21)
    append(buf,size,len," (MS does not support this service)");
  append(buf,size,len," service=%u %s to=",n->service_type,n->ms_sourced ? "ms-sourced" : "bs-sourced");
  append_address(buf,size,len,n->target);
  append(buf,size,len," from=");
  append_address(buf,size,len,n->source);
}

// P_CLEAR (sdrtrunk Clear.java:47-51), P_PROTECT (Protect.java:41-45), C_MOVE (MoveTSCC.java:43-50,
// which only displays it), preamble (Preamble.java:40-45)
static void parse_clear(struct dmr_csbk_clear *c,struct dmr_csbk_block const *k){
  memset(c,0,sizeof *c);
  c->lcn = (uint16_t)dmr_csbk_bits(k,16,12);
  c->target_is_talkgroup = bit(k,31);
  c->destination = dmr_csbk_bits(k,32,24);
  c->source = dmr_csbk_bits(k,56,24);
}
static void describe_clear(char *buf,size_t size,size_t *len,struct dmr_csbk_clear const *c){
  append(buf,size,len,"P_CLEAR return to ");
  struct dmr_channel_ref const ch = dmr_chref_from_tier3(c->lcn,1);
  append_chref(buf,size,len,&ch);
  append(buf,size,len,"%s",c->target_is_talkgroup ? " tg=" : " to=");
  append_address(buf,size,len,c->destination);
  append(buf,size,len," from=");
  append_address(buf,size,len,c->source);
}
static void parse_protect(struct dmr_csbk_protect *p,struct dmr_csbk_block const *k){
  memset(p,0,sizeof *p);
  p->kind = (uint8_t)dmr_csbk_bits(k,28,3);
  p->target_is_talkgroup = bit(k,31);
  p->destination = dmr_csbk_bits(k,32,24);
  p->source = dmr_csbk_bits(k,56,24);
}
static void describe_protect(char *buf,size_t size,size_t *len,struct dmr_csbk_protect const *p){
  append(buf,size,len,"P_PROTECT %s",dmr_protect_kind_name(p->kind));
  append(buf,size,len,"%s",p->target_is_talkgroup ? " tg=" : " to=");
  append_address(buf,size,len,p->destination);
  append(buf,size,len," from=");
  append_address(buf,size,len,p->source);
}
static void parse_move_tscc(struct dmr_csbk_move_tscc *m,struct dmr_csbk_block const *k){
  memset(m,0,sizeof *m);
  m->mask = (uint8_t)dmr_csbk_bits(k,25,5);
  m->registration_required = bit(k,35);
  m->backoff = (uint8_t)dmr_csbk_bits(k,36,4);
  m->lcn = (uint16_t)dmr_csbk_bits(k,44,12);
  m->radio = dmr_csbk_bits(k,56,24);
}
static void describe_move_tscc(char *buf,size_t size,size_t *len,struct dmr_csbk_move_tscc const *m){
  append(buf,size,len,"C_MOVE control channel to ");
  struct dmr_channel_ref const ch = dmr_chref_from_tier3(m->lcn,1);
  append_chref(buf,size,len,&ch);
  if(m->radio != 0){
    append(buf,size,len," to=");
    append_address(buf,size,len,m->radio);
  }
}
static void parse_preamble(struct dmr_csbk_preamble *p,struct dmr_csbk_block const *k){
  memset(p,0,sizeof *p);
  p->data_follows = bit(k,16);
  p->target_is_talkgroup = bit(k,17);
  p->blocks_to_follow = (uint8_t)dmr_csbk_bits(k,24,8);
  p->target = dmr_csbk_bits(k,32,24);
  p->source = dmr_csbk_bits(k,56,24);
}
static void describe_preamble(char *buf,size_t size,size_t *len,struct dmr_csbk_preamble const *p){
  append(buf,size,len,"PREAMBLE %s blocks=%u",p->data_follows ? "data" : "csbk",p->blocks_to_follow);
  append(buf,size,len,"%s",p->target_is_talkgroup ? " tg=" : " to=");
  append_address(buf,size,len,p->target);
  append(buf,size,len," from=");
  append_address(buf,size,len,p->source);
}

// Announcements, C_BCAST (sdrtrunk announcement/Announcement.java:38-43 and AnnouncementType.java; the
// type classes AnnounceWithdrawTSCC, CallTimerParameters, VoteNowAdvice, LocalTime, MassRegistration,
// AnnounceChannelFrequency, AdjacentSiteInformation; Hytera: HyteraAnnouncement,
// HyteraAdjacentSiteInformation)
static void parse_bcast_common(struct dmr_bcast_common *c,struct dmr_csbk_block const *k){
  memset(c,0,sizeof *c);
  c->fid = k->fid;
  c->type = dmr_bcast_type(k);
  c->parameters1 = (uint16_t)dmr_csbk_bits(k,21,14);
  c->registration_required = bit(k,35);
  c->backoff = (uint8_t)dmr_csbk_bits(k,36,4);
  dmr_system_code_parse(&c->system,k,40,true);
  c->parameters2 = dmr_csbk_bits(k,56,24);
}
static char const *bcast_prefix(struct dmr_bcast_common const *c){
  return c->fid == DMR_FID_STANDARD ? "C_BCAST " : "HYTERA C_BCAST ";
}
static void describe_broadcast(char *buf,size_t size,size_t *len,struct dmr_bcast_common const *c){
  append(buf,size,len,"%s",bcast_prefix(c));
  append(buf,size,len,"type=%u p1=%04X p2=%06X ",c->type,c->parameters1,c->parameters2);
  append_system_code(buf,size,len,&c->system);
}
static void parse_announce_withdraw_tscc(struct dmr_csbk_announce_withdraw_tscc *a,struct dmr_csbk_block const *k){
  memset(a,0,sizeof *a);
  parse_bcast_common(&a->common,k);
  a->color_code1 = (uint8_t)dmr_csbk_bits(k,25,4);
  a->color_code2 = (uint8_t)dmr_csbk_bits(k,29,4);
  a->add1 = !bit(k,33);  // AW_FLAG 0 = add to the hunt list, 1 = withdraw (TS 102 361-4 table 7.69;
  a->add2 = !bit(k,34);  // sdrtrunk has them the other way round)
  a->lcn1 = (uint16_t)dmr_csbk_bits(k,56,12);
  a->lcn2 = (uint16_t)dmr_csbk_bits(k,68,12);
}
static void describe_announce_withdraw_tscc(char *buf,size_t size,size_t *len,struct dmr_csbk_announce_withdraw_tscc const *a){
  append(buf,size,len,"%sTSCC",bcast_prefix(&a->common));
  if(a->lcn1 != 0)
    append(buf,size,len," %s LCN %u cc=%u",a->add1 ? "add" : "withdraw",a->lcn1,a->color_code1);
  if(a->lcn2 != 0)
    append(buf,size,len," %s LCN %u cc=%u",a->add2 ? "add" : "withdraw",a->lcn2,a->color_code2);
  append(buf,size,len," ");
  append_system_code(buf,size,len,&a->common.system);
}
int dmr_call_timer_emergency_seconds(int v){
  return v == 0 ? 0 : v <= 10 ? v : v <= 20 ? (v - 8) * 5 : v <= 28 ? (v - 16) * 15 : v <= 40 ? (v - 22) * 30
    : v <= 51 ? (v - 31) * 60 : v <= 510 ? (v - 47) * 300 : DMR_CALL_TIMER_INFINITE;
}
int dmr_call_timer_packet_seconds(int v){
  return v == 0 ? 0 : v <= 5 ? v : v <= 10 ? (v - 4) * 5 : v <= 12 ? (v - 8) * 15 : v <= 20 ? (v - 10) * 30
    : v <= 25 ? (v - 15) * 60 : v <= 30 ? (v - 23) * 300 : DMR_CALL_TIMER_INFINITE;
}
int dmr_call_timer_voice_seconds(int v){
  return v == 0 ? 0 : v <= 59 ? v : v <= 107 ? (v - 48) * 5 : v <= 138 ? (v - 98) * 30
    : v <= 4094 ? (v - 118) * 60 : DMR_CALL_TIMER_INFINITE;
}
static void parse_call_timers(struct dmr_csbk_call_timers *t,struct dmr_csbk_block const *k){
  memset(t,0,sizeof *t);
  parse_bcast_common(&t->common,k);
  t->emergency = (uint16_t)dmr_csbk_bits(k,21,9);
  t->packet = (uint8_t)dmr_csbk_bits(k,30,5);
  t->ms_to_ms = (uint16_t)dmr_csbk_bits(k,56,12);
  t->ms_to_line = (uint16_t)dmr_csbk_bits(k,68,12);
}
static void describe_call_timers(char *buf,size_t size,size_t *len,struct dmr_csbk_call_timers const *t){
  append(buf,size,len,"%s",bcast_prefix(&t->common));
  append(buf,size,len,"call timers emergency=%ds packet=%ds ms-ms=%ds ms-line=%ds ",dmr_call_timer_emergency_seconds(t->emergency),
         dmr_call_timer_packet_seconds(t->packet),dmr_call_timer_voice_seconds(t->ms_to_ms),dmr_call_timer_voice_seconds(t->ms_to_line));
  append_system_code(buf,size,len,&t->common.system);
}
static void parse_other_site(struct dmr_csbk_other_site *s,struct dmr_csbk_block const *k){
  memset(s,0,sizeof *s);
  parse_bcast_common(&s->common,k);
  dmr_system_code_parse(&s->other,k,21,false);
  s->network_status_available = bit(k,56);
  s->active_network_connection = bit(k,57);
  s->confirmed_priority = (uint8_t)dmr_csbk_bits(k,58,3);
  s->adjacent_priority = (uint8_t)dmr_csbk_bits(k,61,3);
  s->lcn = (uint16_t)dmr_csbk_bits(k,68,12);
}
static void describe_other_site(char *buf,size_t size,size_t *len,struct dmr_csbk_other_site const *s,char const *what){
  append(buf,size,len,"%s%s",bcast_prefix(&s->common),what);
  append_system_code(buf,size,len,&s->other);
  append(buf,size,len," LCN %u; this ",s->lcn);
  append_system_code(buf,size,len,&s->common.system);
}
static void parse_local_time(struct dmr_csbk_local_time *t,struct dmr_csbk_block const *k){
  memset(t,0,sizeof *t);
  parse_bcast_common(&t->common,k);
  t->day = (uint8_t)dmr_csbk_bits(k,21,5);
  t->month = (uint8_t)dmr_csbk_bits(k,26,4);   // 26-29, not sdrtrunk's 26, 27, 28, 39
  t->utc_offset_hours = (uint8_t)dmr_csbk_bits(k,30,4);  // not sdrtrunk's five bits without a sign
  t->utc_offset_negative = bit(k,34);
  t->hour = (uint8_t)dmr_csbk_bits(k,56,5);
  t->minute = (uint8_t)dmr_csbk_bits(k,61,6);
  t->second = (uint8_t)dmr_csbk_bits(k,67,6);
  t->day_of_week = (uint8_t)dmr_csbk_bits(k,73,3);
  t->utc_offset_fraction = (uint8_t)dmr_csbk_bits(k,76,2);
}
static void describe_local_time(char *buf,size_t size,size_t *len,struct dmr_csbk_local_time const *t){
  append(buf,size,len,"%s",bcast_prefix(&t->common));
  append(buf,size,len,"local time month=%u day=%u %02u:%02u:%02u ",t->month,t->day,t->hour,t->minute,t->second);
  if(t->utc_offset_hours == 15)
    append(buf,size,len,"utc-offset=none ");
  else
    append(buf,size,len,"utc-offset=%c%u:%02u ",t->utc_offset_negative ? '-' : '+',t->utc_offset_hours,15u * t->utc_offset_fraction);
  append_system_code(buf,size,len,&t->common.system);
}
static void parse_mass_registration(struct dmr_csbk_mass_registration *m,struct dmr_csbk_block const *k){
  memset(m,0,sizeof *m);
  parse_bcast_common(&m->common,k);
  m->window = (uint8_t)dmr_csbk_bits(k,26,4);  // 26-29, as the month above
  m->aloha_mask = (uint8_t)dmr_csbk_bits(k,30,5);
  m->radio = dmr_csbk_bits(k,56,24);
}
static void describe_mass_registration(char *buf,size_t size,size_t *len,struct dmr_csbk_mass_registration const *m){
  append(buf,size,len,"%s",bcast_prefix(&m->common));
  append(buf,size,len,"mass registration window=%u mask=%u",m->window,m->aloha_mask);
  if(m->radio != 0){
    append(buf,size,len," to=");
    append_address(buf,size,len,m->radio);
  }
  append(buf,size,len," ");
  append_system_code(buf,size,len,&m->common.system);
}

// TS 102 361-2 7.1.2.2 / 7.1.2.3 (tables 7.5b, 7.5c), 7.1.2.1 (table 7.5a) and TS 102 361-4 table 7.25
static void parse_unit_to_unit(struct dmr_csbk_unit_to_unit *u,struct dmr_csbk_block const *k){
  memset(u,0,sizeof *u);
  u->is_answer = k->opcode == DMR_CSBKO_UU_ANS_RSP;
  u->service_options = (uint8_t)dmr_csbk_bits(k,16,8);
  u->answer_response = (uint8_t)dmr_csbk_bits(k,24,8);
  u->target = dmr_csbk_bits(k,32,24);
  u->source = dmr_csbk_bits(k,56,24);
}
static void describe_unit_to_unit(char *buf,size_t size,size_t *len,struct dmr_csbk_unit_to_unit const *u){
  if(u->is_answer)
    append(buf,size,len,"UU_ANS_RSP %s (0x%02X)",u->answer_response == 0x20 ? "proceed" : u->answer_response == 0x21 ? "deny" : "?",
           u->answer_response);
  else
    append(buf,size,len,"UU_V_REQ");
  append(buf,size,len," to=%u from=%u options=%02X",u->target,u->source,u->service_options);
}
static void parse_bs_downlink_activation(struct dmr_csbk_bs_downlink_activation *a,struct dmr_csbk_block const *k){
  memset(a,0,sizeof *a);
  a->bs_address = dmr_csbk_bits(k,32,24);
  a->source = dmr_csbk_bits(k,56,24);
}
static void parse_random_access(struct dmr_csbk_random_access *r,struct dmr_csbk_block const *k){
  memset(r,0,sizeof *r);
  r->service_options = (uint8_t)dmr_csbk_bits(k,16,7);
  r->proxy_flag = bit(k,23);
  r->appended_supplementary_data = (uint8_t)dmr_csbk_bits(k,24,2);
  r->appended_short_data = (uint8_t)dmr_csbk_bits(k,26,2);
  r->service_kind = (uint8_t)dmr_csbk_bits(k,28,4);
  r->target = dmr_csbk_bits(k,32,24);
  r->source = dmr_csbk_bits(k,56,24);
}
static void describe_random_access(char *buf,size_t size,size_t *len,struct dmr_csbk_random_access const *r){
  append(buf,size,len,"C_RAND service=%u (%s) to=",r->service_kind,dmr_service_kind_name(r->service_kind));
  append_address(buf,size,len,r->target);
  append(buf,size,len," from=");
  append_address(buf,size,len,r->source);
}

// ---------------- Motorola ----------------
// Layouts: sdrtrunk (GPL-3, Dennis Sheirer, commit 1945b835) message/data/csbk/motorola/*.java; the
// Connect Plus neighbours and voice channel user also OP25 (GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al.), dmr_slot.cc:282-304

// Capacity Plus neighbours (CapacityPlusNeighbors.java:40-57)
static void parse_cap_plus_neighbors(struct dmr_csbk_cap_plus_neighbors *n,struct dmr_csbk_block const *k){
  memset(n,0,sizeof *n);
  n->lcss = (uint8_t)dmr_csbk_bits(k,16,2);
  n->rest_lsn = (uint8_t)dmr_csbk_bits(k,19,5);
  n->async_beacon = bit(k,24);
  n->site = (uint8_t)dmr_csbk_bits(k,25,4);
  n->neighbor_count = (uint8_t)dmr_csbk_bits(k,29,3);
  for(int i=0; i < 6; i++){
    n->neighbors[i].site = (uint8_t)dmr_csbk_bits(k,32 + 8 * i,4);
    n->neighbors[i].rest_lsn = (uint8_t)dmr_csbk_bits(k,36 + 8 * i,4);
  }
}
static void describe_cap_plus_neighbors(char *buf,size_t size,size_t *len,struct dmr_csbk_cap_plus_neighbors const *n){
  append(buf,size,len,"CAP+ NEIGHBORS site=%u rest LSN %u",n->site,n->rest_lsn);
  for(int i=0; i < dmr_cap_plus_neighbors_present(n); i++)
    append(buf,size,len," [site %u rest %u]",n->neighbors[i].site,n->neighbors[i].rest_lsn);
}

// Capacity Plus site status (CapacityPlusSiteStatus.java:47-306). From bit 24 a byte-wise list: a bitmap
// of LSN 1-8 in voice (first bit LSN 1), then one 8-bit talkgroup per set bit if it is not zero; the
// same for LSN 9-16; an options byte whose first bit announces a bitmap of LSN 1-8 in data revert use,
// then one 16-bit radio per set bit. A zero bitmap takes one byte. What does not fit the 56 bits goes in
// a continuation segment, which is not joined here (as sdrtrunk): an LSN whose identifier fell off the
// end has id_known false, and a continuation keeps its 56 bits
static void add_activity(struct dmr_csbk_cap_plus_site_status *s,int lsn,bool data,bool known,uint32_t id){
  struct dmr_cap_plus_activity *a = &s->activity[s->activity_count++];
  a->lsn = (uint8_t)lsn;
  a->data = data;
  a->id_known = known;
  a->id = (uint16_t)id;
}
static void parse_cap_plus_site_status(struct dmr_csbk_cap_plus_site_status *s,struct dmr_csbk_block const *k){
  memset(s,0,sizeof *s);
  s->segment = (uint8_t)dmr_csbk_bits(k,16,2);
  s->rest_lsn = (uint8_t)dmr_csbk_bits(k,19,5);
  if(!dmr_cap_plus_first_segment(s)){
    s->continuation = k->payload & 0x00FFFFFFFFFFFFFFull;
    return;
  }
  int pointer = 24;
  for(int half=0; half < 2; half++){
    if(pointer <= 72 && dmr_csbk_bits(k,pointer,8) != 0){
      int const bitmap = pointer;
      pointer += 8;
      for(int i=0; i < 8; i++){
        if(!bit(k,bitmap + i))
          continue;
        if(pointer <= 72){
          add_activity(s,half * 8 + i + 1,false,true,dmr_csbk_bits(k,pointer,8));
          pointer += 8;
        } else
          add_activity(s,half * 8 + i + 1,false,false,0);
      }
    } else
      pointer += 8;
  }
  if(pointer <= 72 && bit(k,pointer)){
    pointer += 8;
    if(pointer <= 72 && dmr_csbk_bits(k,pointer,8) != 0){
      int const bitmap = pointer;
      pointer += 8;
      for(int i=0; i < 8; i++){
        if(!bit(k,bitmap + i))
          continue;
        if(pointer <= 64){
          add_activity(s,i + 1,true,true,dmr_csbk_bits(k,pointer,16));
          pointer += 16;
        } else
          add_activity(s,i + 1,true,false,0);
      }
    }
  }
}
struct dmr_cap_plus_activity const *dmr_cap_plus_find(struct dmr_csbk_cap_plus_site_status const *s,int lsn,bool data){
  for(int i=0; i < s->activity_count; i++){
    struct dmr_cap_plus_activity const *a = &s->activity[i];
    if(a->lsn == lsn && a->data == data)
      return a;
  }
  return NULL;
}
static void describe_cap_plus_site_status(char *buf,size_t size,size_t *len,struct dmr_csbk_cap_plus_site_status const *s){
  append(buf,size,len,"CAP+ SITE STATUS rest LSN %u",s->rest_lsn);
  if(!dmr_cap_plus_first_segment(s)){
    append(buf,size,len," continuation %014llX",(unsigned long long)s->continuation);
    return;
  }
  if(s->activity_count == 0)
    append(buf,size,len," idle");
  for(int i=0; i < s->activity_count; i++){
    struct dmr_cap_plus_activity const *a = &s->activity[i];
    append(buf,size,len," LSN%u:%s",a->lsn,a->data ? "radio " : "tg ");
    if(a->id_known)
      append(buf,size,len,"%u",a->id);
    else
      append(buf,size,len,"?");
  }
}

// Capacity Plus preamble (CapacityPlusPreamble.java:40-46)
static void parse_cap_plus_preamble(struct dmr_csbk_cap_plus_preamble *p,struct dmr_csbk_block const *k){
  memset(p,0,sizeof *p);
  p->data_follows = bit(k,16);
  p->target_is_talkgroup = bit(k,17);
  p->blocks_to_follow = (uint8_t)dmr_csbk_bits(k,18,5);
  p->unknown1 = (uint8_t)dmr_csbk_bits(k,24,8);
  p->unknown2 = (uint8_t)dmr_csbk_bits(k,32,8);
  p->target = (uint16_t)dmr_csbk_bits(k,40,16);
  p->unknown3 = (uint8_t)dmr_csbk_bits(k,56,8);
  p->source = (uint16_t)dmr_csbk_bits(k,64,16);
}
// Capacity Plus data revert window announcement (41) and grant (42)
static void parse_cap_plus_data_window(struct dmr_csbk_cap_plus_data_window *w,struct dmr_csbk_block const *k){
  memset(w,0,sizeof *w);
  w->is_grant = k->opcode == DMR_CSBKO_CAP_PLUS_DATA_WINDOW_GRANT;
  w->radio = (uint16_t)dmr_csbk_bits(k,24,16);
  w->window = (uint8_t)dmr_csbk_bits(k,40,8);
  w->super_frame = (uint8_t)dmr_csbk_bits(k,48,8);
}

static void parse_con_plus_slot(struct dmr_con_plus_slot *s,struct dmr_csbk_block const *k,int first){
  memset(s,0,sizeof *s);
  s->air = (uint8_t)dmr_csbk_bits(k,first,5);
  s->lsn_minus_one = (int)s->air - 1;
  s->repeater = (uint8_t)dmr_csbk_bits(k,first,4);
  s->timeslot = (uint8_t)(dmr_csbk_bits(k,first + 4,1) + 1);
}
struct dmr_channel_ref dmr_con_plus_slot_channel(struct dmr_con_plus_slot const *s){
  return s->repeater >= 1 ? dmr_chref_from_lsn(dmr_lsn_from_lcn(s->repeater,s->timeslot)) : dmr_chref_none();
}
static void append_con_plus_slot(char *buf,size_t size,size_t *len,struct dmr_con_plus_slot const *s){
  append(buf,size,len,"repeater %u TS%u (air %u, LSN-1 %d)",s->repeater,s->timeslot,s->air,s->lsn_minus_one);
}
// Connect Plus neighbours (sdrtrunk ConnectPlusNeighborReport.java; OP25 (GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al.) dmr_slot.cc:283-287)
static void parse_con_plus_neighbors(struct dmr_csbk_con_plus_neighbors *n,struct dmr_csbk_block const *k){
  memset(n,0,sizeof *n);
  for(int i=0; i < 5; i++)
    n->sites[i] = (uint8_t)dmr_csbk_bits(k,16 + 8 * i,8);
  n->trailing = dmr_csbk_bits(k,56,24);
}
static void describe_con_plus_neighbors(char *buf,size_t size,size_t *len,struct dmr_csbk_con_plus_neighbors const *n){
  append(buf,size,len,"CON+ NEIGHBORS");
  int count = 0;
  for(int i=0; i < 5; i++)
    count += n->sites[i] != 0 ? 1 : 0;
  if(count == 0)
    append(buf,size,len," none");
  for(int i=0; i < 5; i++){
    if(n->sites[i] != 0)
      append(buf,size,len," %u",n->sites[i]);
  }
  append(buf,size,len," trailing=%06X",n->trailing);
}
// Connect Plus voice channel user (sdrtrunk ConnectPlusVoiceChannelUser.java:43-47; OP25 (GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al.) dmr_slot.cc:294-298)
static void parse_con_plus_voice_channel_user(struct dmr_csbk_con_plus_voice_channel_user *v,struct dmr_csbk_block const *k){
  memset(v,0,sizeof *v);
  v->source = dmr_csbk_bits(k,16,24);
  v->group = dmr_csbk_bits(k,40,24);
  parse_con_plus_slot(&v->slot,k,64);
  v->unknown = (uint8_t)dmr_csbk_bits(k,72,8);
}
// Connect Plus data channel grant (ConnectPlusDataChannelGrant.java:41-46)
static void parse_con_plus_data_channel_grant(struct dmr_csbk_con_plus_data_channel_grant *g,struct dmr_csbk_block const *k){
  memset(g,0,sizeof *g);
  g->target = dmr_csbk_bits(k,16,24);
  parse_con_plus_slot(&g->slot,k,40);
  g->unknown = (uint8_t)dmr_csbk_bits(k,48,8);
}
// Connect Plus OTA announcement (ConnectPlusOTAAnnouncement.java:38-42)
static void parse_con_plus_ota_announcement(struct dmr_csbk_con_plus_ota_announcement *a,struct dmr_csbk_block const *k){
  memset(a,0,sizeof *a);
  a->message_type = (uint8_t)dmr_csbk_bits(k,16,8);
  a->version = (uint16_t)dmr_csbk_bits(k,24,16);
  parse_con_plus_slot(&a->slot,k,63);
}
// Connect Plus terminate channel grant (ConnectPlusTerminateChannelGrant.java)
static void parse_con_plus_terminate_channel_grant(struct dmr_csbk_con_plus_terminate_channel_grant *t,struct dmr_csbk_block const *k){
  memset(t,0,sizeof *t);
  t->target = dmr_csbk_bits(k,16,24);
  for(int i=0; i < 5; i++)
    t->unknown[i] = (uint8_t)dmr_csbk_bits(k,40 + 8 * i,8);
}
// Connect Plus CSBKO 16, registration request (17) and response (18), affiliation (24): one layout
// (ConnectPlusCSBKO_16, RegistrationRequest, RegistrationResponse, TalkgroupAffiliation.java)
static void parse_con_plus_radio_event(struct dmr_csbk_con_plus_radio_event *e,struct dmr_csbk_block const *k){
  memset(e,0,sizeof *e);
  e->kind = k->opcode == DMR_CSBKO_CON_PLUS_REGISTRATION_REQUEST ? DMR_CPRE_REGISTRATION_REQUEST
    : k->opcode == DMR_CSBKO_CON_PLUS_REGISTRATION_RESPONSE ? DMR_CPRE_REGISTRATION_RESPONSE
    : k->opcode == DMR_CSBKO_CON_PLUS_TALKGROUP_AFFILIATION ? DMR_CPRE_TALKGROUP_AFFILIATION
    : DMR_CPRE_CSBKO_16;
  e->source = dmr_csbk_bits(k,16,24);
  e->target = dmr_csbk_bits(k,40,24);
  e->unknown = (uint16_t)dmr_csbk_bits(k,64,16);
}
static void describe_con_plus_radio_event(char *buf,size_t size,size_t *len,struct dmr_csbk_con_plus_radio_event const *e){
  switch(e->kind){
  case DMR_CPRE_REGISTRATION_REQUEST: append(buf,size,len,"CON+ REGISTRATION REQUEST from=%u to=%u",e->source,e->target); break;
  case DMR_CPRE_REGISTRATION_RESPONSE: append(buf,size,len,"CON+ REGISTRATION RESPONSE from=%u to=%u",e->source,e->target); break;
  case DMR_CPRE_TALKGROUP_AFFILIATION: append(buf,size,len,"CON+ AFFILIATION radio=%u tg=%u",e->source,e->target); break;
  case DMR_CPRE_CSBKO_16: append(buf,size,len,"CON+ CSBKO 16 from=%u to=%u",e->source,e->target); break;
  }
  append(buf,size,len," unknown=%04X",e->unknown);
}
// Connect Plus data revert window announcement (28) and grant (29); the grant's layout carries
// sdrtrunk's own "TODO: this may not be correct"
static void parse_con_plus_data_window(struct dmr_csbk_con_plus_data_window *w,struct dmr_csbk_block const *k){
  memset(w,0,sizeof *w);
  w->is_grant = k->opcode == DMR_CSBKO_CON_PLUS_DATA_WINDOW_GRANT;
  if(w->is_grant){
    w->radio = dmr_csbk_bits(k,16,24);
    w->super_frame = (uint8_t)dmr_csbk_bits(k,48,4);
    w->window = (uint8_t)dmr_csbk_bits(k,70,5);
  } else {
    w->window = (uint8_t)dmr_csbk_bits(k,16,7);
    w->super_frame = (uint8_t)dmr_csbk_bits(k,24,4);
    w->repeater = (uint8_t)dmr_csbk_bits(k,28,4);
    w->radio = dmr_csbk_bits(k,32,24);
  }
}
// Capacity Max voice channel update, open mode (CapacityMaxOpenModeVoiceChannelUpdate.java, "likely
// incomplete implementation"; timeslot 2 fixed) and advantage mode (...AdvantageModeVoiceChannelUpdate.java:42-47)
static void parse_cap_max_open_mode_update(struct dmr_csbk_cap_max_open_mode_update *u,struct dmr_csbk_block const *k){
  memset(u,0,sizeof *u);
  u->lcn = (uint16_t)dmr_csbk_bits(k,16,12);
  u->unknown = (uint8_t)dmr_csbk_bits(k,28,4);
  u->talkgroup_ts1 = dmr_csbk_bits(k,32,24);
  u->talkgroup_ts2 = dmr_csbk_bits(k,56,24);
}
uint32_t dmr_cap_max_ts2_as_sdrtrunk(struct dmr_csbk_block const *k){
  static int const bits[24] = {56, 57, 58, 59, 60, 61, 63, 64, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79};
  uint32_t v = 0;
  for(int i=0; i < 24; i++)
    v = (v << 1) | (bit(k,bits[i]) ? 1u : 0u);
  return v;
}
static void parse_cap_max_advantage_mode_update(struct dmr_csbk_cap_max_advantage_mode_update *u,struct dmr_csbk_block const *k){
  memset(u,0,sizeof *u);
  for(int i=0; i < 2; i++){
    u->repeaters[i].lcn = (uint16_t)dmr_csbk_bits(k,16 + 32 * i,12);
    u->repeaters[i].talkgroup_ts1 = (uint16_t)dmr_csbk_bits(k,28 + 32 * i,10);
    u->repeaters[i].talkgroup_ts2 = (uint16_t)dmr_csbk_bits(k,38 + 32 * i,10);
  }
}

// ---------------- Hytera ----------------
// Layouts: sdrtrunk alone (GPL-3, Dennis Sheirer, commit 1945b835) message/data/csbk/hytera/*.java:
// HyteraTrafficChannelTalkerStatus.java:41-47, HyteraXPTSiteState.java:38-49 (seen only in a patent,
// it says), HyteraXPTAdjacentSites.java:36-45, HyteraXPTPreamble.java:39-43,
// HyteraSmsAvailableNotification.java; identifier/DMRTalkgroup.getCompressed

static void parse_hytera_talker_status(struct dmr_csbk_hytera_talker_status *t,struct dmr_csbk_block const *k){
  memset(t,0,sizeof *t);
  t->unknown1 = (uint8_t)dmr_csbk_bits(k,16,8);
  t->unknown2 = (uint8_t)dmr_csbk_bits(k,24,8);
  t->talker_inactive = bit(k,30);
  t->talker = dmr_csbk_bits(k,32,24);
  t->source = dmr_csbk_bits(k,56,24);
}
// Bits 0-1, where a standard CSBK has LB and PF, are a sequence number
static void parse_hytera_xpt_site_state(struct dmr_csbk_hytera_xpt_site_state *s,struct dmr_csbk_block const *k){
  memset(s,0,sizeof *s);
  s->sequence = (uint8_t)dmr_csbk_bits(k,0,2);
  s->free_repeater = (uint8_t)dmr_csbk_bits(k,16,4);
  for(int i=0; i < 3; i++)
    s->state[i] = (uint8_t)dmr_csbk_bits(k,20 + 4 * i,4);
  for(int i=0; i < 6; i++)
    s->hashed_address[i] = (uint8_t)dmr_csbk_bits(k,32 + 8 * i,8);
}
static void describe_hytera_xpt_site_state(char *buf,size_t size,size_t *len,struct dmr_csbk_hytera_xpt_site_state const *s){
  append(buf,size,len,"XPT SITE STATE");
  if(s->free_repeater == 0)
    append(buf,size,len," all busy");
  else
    append(buf,size,len," free=%u",s->free_repeater);
  for(int i=0; i < 3; i++)
    append(buf,size,len," R%d:%u(%02X/%02X)",dmr_xpt_repeater_number(s,i),s->state[i],s->hashed_address[2 * i],
           s->hashed_address[2 * i + 1]);
}
static void parse_hytera_xpt_adjacent_sites(struct dmr_csbk_hytera_xpt_adjacent_sites *a,struct dmr_csbk_block const *k){
  memset(a,0,sizeof *a);
  a->sequence = (uint8_t)dmr_csbk_bits(k,0,2);
  for(int i=0; i < 4; i++){
    a->sites[i].site = (uint8_t)dmr_csbk_bits(k,16 + 16 * i,5);
    a->sites[i].free_repeater = (uint8_t)dmr_csbk_bits(k,24 + 16 * i,4);
  }
}
static void parse_hytera_xpt_preamble(struct dmr_csbk_hytera_xpt_preamble *p,struct dmr_csbk_block const *k){
  memset(p,0,sizeof *p);
  p->data_follows = bit(k,16);
  p->target_is_talkgroup = bit(k,17);
  p->blocks_to_follow = (uint8_t)dmr_csbk_bits(k,24,8);
  p->free_repeater = (uint8_t)dmr_csbk_bits(k,32,4);
  p->priority_repeater = (uint8_t)dmr_csbk_bits(k,36,4);
  p->target = (uint16_t)dmr_csbk_bits(k,40,16);
  p->priority_hashed_address = (uint8_t)dmr_csbk_bits(k,56,8);
  p->source = (uint16_t)dmr_csbk_bits(k,64,16);
}
static void parse_hytera_sms_available(struct dmr_csbk_hytera_sms_available *s,struct dmr_csbk_block const *k){
  memset(s,0,sizeof *s);
  s->unknown = (uint16_t)dmr_csbk_bits(k,16,16);
  s->destination = dmr_csbk_bits(k,32,24);
  s->source = dmr_csbk_bits(k,56,24);
}
// "Compressed" talkgroups, TS 102 361-2 annex C.2.1.2.6 (ETSI's; sdrtrunk's use_compressed_talkgroups,
// seen on Hytera Tier III). By the air address (figure C.4):
//   0 .. 0xDF6767         B2 (table C.5): K1 x 1464100 + K2 x 146410 + K3 x 14641 + K4 x 1331 + K5 x 121 +
//                         K6 x 11 + K7, K1-K3 decimal and K4-K7 base 11 (the digit 10 is written "*")
//   0xDF6768 .. 0xE02AB7  B4 (table C.7): the prefixes 10-14, eight digits K1 K2 0 0 K5 K6 K7 K8, the air
//                         address 14541000 + K1K2 x 10000 + K5..K8 ("12005678" is 0xDFCBB6, table C.8)
//   above                 reserved and special addresses: no user form, returned unchanged
// sdrtrunk applies B2 to every address, mangling B4 and the special ones. A "*" has no number: as in
// sdrtrunk, the digit 10 carries into the next decimal place, so that a configuration written for it
// still matches (at the cost that such a talkgroup shares its number with an all-digit one)
uint32_t dmr_hytera_dialable_talkgroup(uint32_t address){
  uint8_t digit[8] = {0};
  int n;
  if(address <= 0xDF6767u){
    static uint32_t const weights[7] = {1464100u, 146410u, 14641u, 1331u, 121u, 11u, 1u};
    n = 7;
    for(int i=0; i < 7; i++){
      digit[i] = (uint8_t)(address / weights[i]);
      address -= digit[i] * weights[i];
    }
  } else if(address <= 0xE02AB7u){
    uint32_t const v = address - 14541000u;
    uint32_t const prefix = v / 10000u;
    uint32_t low = v % 10000u;
    n = 8;
    digit[0] = (uint8_t)(prefix / 10u);
    digit[1] = (uint8_t)(prefix % 10u);
    for(int i=7; i >= 4; i--){
      digit[i] = (uint8_t)(low % 10u);
      low /= 10u;
    }
  } else
    return address;
  uint32_t dialable = 0;
  for(int i=0; i < n; i++)
    dialable = dialable * 10u + digit[i];  // a 10 carries
  return dialable;
}

// ---------------- The message ----------------

static void parse_broadcast_body(struct dmr_csbk_message *m,struct dmr_csbk_block const *k){
  if(k->fid != DMR_FID_STANDARD){
    // Hytera: only the adjacent site announcement has a known layout
    if(dmr_bcast_type(k) == DMR_BCAST_ADJACENT_SITE){
      m->kind = DMR_CSBK_ADJACENT_SITE;
      parse_other_site(&m->u.other_site,k);
    } else {
      m->kind = DMR_CSBK_BROADCAST;
      parse_bcast_common(&m->u.broadcast,k);
    }
    return;
  }
  switch(dmr_bcast_type(k)){
  case DMR_BCAST_ANNOUNCE_WITHDRAW_TSCC:
    m->kind = DMR_CSBK_ANNOUNCE_WITHDRAW_TSCC;
    parse_announce_withdraw_tscc(&m->u.announce_withdraw_tscc,k);
    break;
  case DMR_BCAST_CALL_TIMERS:
    m->kind = DMR_CSBK_CALL_TIMERS;
    parse_call_timers(&m->u.call_timers,k);
    break;
  case DMR_BCAST_VOTE_NOW:
    m->kind = DMR_CSBK_VOTE_NOW;
    parse_other_site(&m->u.other_site,k);
    break;
  case DMR_BCAST_LOCAL_TIME:
    m->kind = DMR_CSBK_LOCAL_TIME;
    parse_local_time(&m->u.local_time,k);
    break;
  case DMR_BCAST_MASS_REGISTRATION:
    m->kind = DMR_CSBK_MASS_REGISTRATION;
    parse_mass_registration(&m->u.mass_registration,k);
    break;
  case DMR_BCAST_CHANNEL_FREQUENCY:
    m->kind = DMR_CSBK_CHANNEL_FREQUENCY;
    parse_bcast_common(&m->u.broadcast,k);
    break;
  case DMR_BCAST_ADJACENT_SITE:
    m->kind = DMR_CSBK_ADJACENT_SITE;
    parse_other_site(&m->u.other_site,k);
    break;
  default:
    m->kind = DMR_CSBK_BROADCAST;
    parse_bcast_common(&m->u.broadcast,k);
    break;
  }
}

static void set_unknown(struct dmr_csbk_message *m,struct dmr_csbk_block const *k){
  m->kind = DMR_CSBK_UNKNOWN;
  m->u.unknown.opcode = k->opcode;
  m->u.unknown.fid = k->fid;
  m->u.unknown.payload = k->payload;
}

void dmr_csbk_parse_body(struct dmr_csbk_message *m,struct dmr_csbk_block const *k,bool mobile_sourced){
  assert(m != NULL && k != NULL);
  memset(&m->u,0,sizeof m->u);
  switch(k->fid){
  case DMR_FID_STANDARD:
    switch(k->opcode){
    case DMR_CSBKO_UU_V_REQ:
    case DMR_CSBKO_UU_ANS_RSP:
      m->kind = DMR_CSBK_UNIT_TO_UNIT;
      parse_unit_to_unit(&m->u.unit_to_unit,k);
      return;
    case DMR_CSBKO_ALOHA:
      m->kind = DMR_CSBK_ALOHA;
      parse_aloha(&m->u.aloha,k,DMR_ALOHA_STANDARD);
      return;
    case DMR_CSBKO_AHOY:
      m->kind = DMR_CSBK_AHOY;
      parse_ahoy(&m->u.ahoy,k);
      return;
    case DMR_CSBKO_RANDOM_ACCESS:
      m->kind = DMR_CSBK_RANDOM_ACCESS;
      parse_random_access(&m->u.random_access,k);
      return;
    case DMR_CSBKO_ACK_OUTBOUND_TSCC:
    case DMR_CSBKO_ACK_INBOUND_TSCC:
    case DMR_CSBKO_ACK_OUTBOUND_PAYLOAD:
    case DMR_CSBKO_ACK_INBOUND_PAYLOAD:
      m->kind = DMR_CSBK_ACK;
      parse_ack(&m->u.ack,k);
      return;
    case DMR_CSBKO_NACK:
      m->kind = DMR_CSBK_NACK_RESPONSE;
      parse_nack_response(&m->u.nack_response,k);
      return;
    case DMR_CSBKO_BROADCAST:
      parse_broadcast_body(m,k);
      return;
    case DMR_CSBKO_CLEAR:
      m->kind = DMR_CSBK_CLEAR;
      parse_clear(&m->u.clear,k);
      return;
    case DMR_CSBKO_PROTECT:
      m->kind = DMR_CSBK_PROTECT;
      parse_protect(&m->u.protect,k);
      return;
    case DMR_CSBKO_TD_GRANT_MI:
      if(mobile_sourced){
        m->kind = DMR_CSBK_BS_DOWNLINK_ACTIVATION;
        parse_bs_downlink_activation(&m->u.bs_downlink_activation,k);
        return;
      }
      m->kind = DMR_CSBK_GRANT;
      parse_grant(&m->u.grant,k);
      return;
    case DMR_CSBKO_PV_GRANT:
    case DMR_CSBKO_TV_GRANT:
    case DMR_CSBKO_BTV_GRANT:
    case DMR_CSBKO_PD_GRANT:
    case DMR_CSBKO_TD_GRANT:
    case DMR_CSBKO_PV_GRANT_DX:
    case DMR_CSBKO_PD_GRANT_DX:
    case DMR_CSBKO_PD_GRANT_MI:
      m->kind = DMR_CSBK_GRANT;
      parse_grant(&m->u.grant,k);
      return;
    case DMR_CSBKO_MOVE_TSCC:
      m->kind = DMR_CSBK_MOVE_TSCC;
      parse_move_tscc(&m->u.move_tscc,k);
      return;
    case DMR_CSBKO_PREAMBLE:
      m->kind = DMR_CSBK_PREAMBLE;
      parse_preamble(&m->u.preamble,k);
      return;
    default:
      break;
    }
    break;
  case DMR_FID_CONNECT_PLUS:
    switch(k->opcode){
    case DMR_CSBKO_CON_PLUS_NEIGHBORS:
      m->kind = DMR_CSBK_CON_PLUS_NEIGHBORS;
      parse_con_plus_neighbors(&m->u.con_plus_neighbors,k);
      return;
    case DMR_CSBKO_CON_PLUS_VOICE_CHANNEL_USER:
      m->kind = DMR_CSBK_CON_PLUS_VOICE_CHANNEL_USER;
      parse_con_plus_voice_channel_user(&m->u.con_plus_voice_channel_user,k);
      return;
    case DMR_CSBKO_CON_PLUS_DATA_CHANNEL_GRANT:
      m->kind = DMR_CSBK_CON_PLUS_DATA_CHANNEL_GRANT;
      parse_con_plus_data_channel_grant(&m->u.con_plus_data_channel_grant,k);
      return;
    case DMR_CSBKO_CON_PLUS_OTA_ANNOUNCEMENT:
      m->kind = DMR_CSBK_CON_PLUS_OTA_ANNOUNCEMENT;
      parse_con_plus_ota_announcement(&m->u.con_plus_ota_announcement,k);
      return;
    case DMR_CSBKO_CON_PLUS_TERMINATE_CHANNEL_GRANT:
      m->kind = DMR_CSBK_CON_PLUS_TERMINATE_CHANNEL_GRANT;
      parse_con_plus_terminate_channel_grant(&m->u.con_plus_terminate_channel_grant,k);
      return;
    case DMR_CSBKO_CON_PLUS_CSBKO_16:
    case DMR_CSBKO_CON_PLUS_REGISTRATION_REQUEST:
    case DMR_CSBKO_CON_PLUS_REGISTRATION_RESPONSE:
    case DMR_CSBKO_CON_PLUS_TALKGROUP_AFFILIATION:
      m->kind = DMR_CSBK_CON_PLUS_RADIO_EVENT;
      parse_con_plus_radio_event(&m->u.con_plus_radio_event,k);
      return;
    case DMR_CSBKO_CON_PLUS_DATA_WINDOW_ANNOUNCEMENT:
    case DMR_CSBKO_CON_PLUS_DATA_WINDOW_GRANT:
      m->kind = DMR_CSBK_CON_PLUS_DATA_WINDOW;
      parse_con_plus_data_window(&m->u.con_plus_data_window,k);
      return;
    default:
      break;
    }
    break;
  case DMR_FID_MOTOROLA:
    switch(k->opcode){
    case DMR_CSBKO_CAP_MAX_ALOHA:
      m->kind = DMR_CSBK_ALOHA;
      parse_aloha(&m->u.aloha,k,DMR_ALOHA_CAPACITY_MAX);
      return;
    case DMR_CSBKO_CAP_MAX_OPEN_MODE_UPDATE:
      m->kind = DMR_CSBK_CAP_MAX_OPEN_MODE_UPDATE;
      parse_cap_max_open_mode_update(&m->u.cap_max_open_mode_update,k);
      return;
    case DMR_CSBKO_CAP_MAX_ADVANTAGE_MODE_UPDATE:
      m->kind = DMR_CSBK_CAP_MAX_ADVANTAGE_MODE_UPDATE;
      parse_cap_max_advantage_mode_update(&m->u.cap_max_advantage_mode_update,k);
      return;
    case DMR_CSBKO_CAP_PLUS_DATA_WINDOW_ANNOUNCEMENT:
    case DMR_CSBKO_CAP_PLUS_DATA_WINDOW_GRANT:
      m->kind = DMR_CSBK_CAP_PLUS_DATA_WINDOW;
      parse_cap_plus_data_window(&m->u.cap_plus_data_window,k);
      return;
    case DMR_CSBKO_CAP_PLUS_NEIGHBORS:
      m->kind = DMR_CSBK_CAP_PLUS_NEIGHBORS;
      parse_cap_plus_neighbors(&m->u.cap_plus_neighbors,k);
      return;
    case DMR_CSBKO_CAP_PLUS_PREAMBLE:
      m->kind = DMR_CSBK_CAP_PLUS_PREAMBLE;
      parse_cap_plus_preamble(&m->u.cap_plus_preamble,k);
      return;
    case DMR_CSBKO_CAP_PLUS_SITE_STATUS:
      m->kind = DMR_CSBK_CAP_PLUS_SITE_STATUS;
      parse_cap_plus_site_status(&m->u.cap_plus_site_status,k);
      return;
    default:
      break;  // 31, 32 (call alert) and 60: named, no layout
    }
    break;
  case DMR_FID_HYTERA_08:
    switch(k->opcode){
    case DMR_CSBKO_HYTERA_ACK:
      m->kind = DMR_CSBK_ACK;
      parse_ack(&m->u.ack,k);
      return;
    case DMR_CSBKO_HYTERA_ANNOUNCEMENT:
      parse_broadcast_body(m,k);
      return;
    case DMR_CSBKO_HYTERA_08_TALKER_STATUS:
      m->kind = DMR_CSBK_HYTERA_TALKER_STATUS;
      parse_hytera_talker_status(&m->u.hytera_talker_status,k);
      return;
    default:
      break;  // 44: named, no layout
    }
    break;
  case DMR_FID_HYTERA_68:
    switch(k->opcode){
    case DMR_CSBKO_HYTERA_XPT_SITE_STATE:
      m->kind = DMR_CSBK_HYTERA_XPT_SITE_STATE;
      parse_hytera_xpt_site_state(&m->u.hytera_xpt_site_state,k);
      return;
    case DMR_CSBKO_HYTERA_XPT_ADJACENT_SITES:
      m->kind = DMR_CSBK_HYTERA_XPT_ADJACENT_SITES;
      parse_hytera_xpt_adjacent_sites(&m->u.hytera_xpt_adjacent_sites,k);
      return;
    case DMR_CSBKO_HYTERA_68_ALOHA:
      m->kind = DMR_CSBK_ALOHA;
      parse_aloha(&m->u.aloha,k,DMR_ALOHA_HYTERA);
      return;
    case DMR_CSBKO_HYTERA_ACK:
      m->kind = DMR_CSBK_ACK;
      parse_ack(&m->u.ack,k);
      return;
    case DMR_CSBKO_HYTERA_ANNOUNCEMENT:
      parse_broadcast_body(m,k);
      return;
    case DMR_CSBKO_HYTERA_XPT_PREAMBLE:
      m->kind = DMR_CSBK_HYTERA_XPT_PREAMBLE;
      parse_hytera_xpt_preamble(&m->u.hytera_xpt_preamble,k);
      return;
    case DMR_CSBKO_HYTERA_68_SMS_AVAILABLE:
      m->kind = DMR_CSBK_HYTERA_SMS_AVAILABLE;
      parse_hytera_sms_available(&m->u.hytera_sms_available,k);
      return;
    default:
      break;
    }
    break;
  default:
    break;
  }
  set_unknown(m,k);
}

void dmr_csbk_parse(struct dmr_csbk_message *m,uint8_t const info96[96],uint8_t slot,uint8_t color_code,
                    uint64_t timestamp_us,uint16_t crc_mask,bool mobile_sourced){
  assert(m != NULL && info96 != NULL);
  memset(m,0,sizeof *m);
  dmr_csbk_read_block(&m->block,info96,slot,color_code,timestamp_us,crc_mask);
  m->kind = DMR_CSBK_NONE;
  if(m->block.crc_ok)
    dmr_csbk_parse_body(m,&m->block,mobile_sourced);
}

struct dmr_bcast_common const *dmr_csbk_broadcast_common(struct dmr_csbk_message const *m){
  switch(m->kind){
  case DMR_CSBK_BROADCAST:
  case DMR_CSBK_CHANNEL_FREQUENCY:
    return &m->u.broadcast;
  case DMR_CSBK_ANNOUNCE_WITHDRAW_TSCC:
    return &m->u.announce_withdraw_tscc.common;
  case DMR_CSBK_CALL_TIMERS:
    return &m->u.call_timers.common;
  case DMR_CSBK_VOTE_NOW:
  case DMR_CSBK_ADJACENT_SITE:
    return &m->u.other_site.common;
  case DMR_CSBK_LOCAL_TIME:
    return &m->u.local_time.common;
  case DMR_CSBK_MASS_REGISTRATION:
    return &m->u.mass_registration.common;
  default:
    return NULL;
  }
}

// Only an announcement of channel frequencies: whether another message's CG_AP LCN (a grant's, say)
// is a reusable map key is not established
bool dmr_csbk_channel_frequency(struct dmr_csbk_message const *m,struct dmr_cgap *p){
  if(m->kind != DMR_CSBK_CHANNEL_FREQUENCY || !m->has_absolute || !dmr_cgap_plausible(&m->absolute))
    return false;
  if(p != NULL)
    *p = m->absolute;
  return true;
}

static void describe_body(char *buf,size_t size,size_t *len,struct dmr_csbk_message const *m){
  switch(m->kind){
  case DMR_CSBK_NONE:
    break;
  case DMR_CSBK_UNKNOWN: {
    char const *name = dmr_csbk_name(m->u.unknown.fid,m->u.unknown.opcode);
    append(buf,size,len,"CSBK %s csbko=%u fid=0x%02X data=%016llX",name != NULL ? name : "UNKNOWN",m->u.unknown.opcode,
           m->u.unknown.fid,(unsigned long long)m->u.unknown.payload);
    break;
  }
  case DMR_CSBK_ALOHA:
    describe_aloha(buf,size,len,&m->u.aloha);
    break;
  case DMR_CSBK_AHOY:
    describe_ahoy(buf,size,len,&m->u.ahoy);
    break;
  case DMR_CSBK_ACK:
    describe_ack(buf,size,len,&m->u.ack);
    break;
  case DMR_CSBK_NACK_RESPONSE:
    describe_nack_response(buf,size,len,&m->u.nack_response);
    break;
  case DMR_CSBK_GRANT:
    describe_grant(buf,size,len,&m->u.grant);
    break;
  case DMR_CSBK_CLEAR:
    describe_clear(buf,size,len,&m->u.clear);
    break;
  case DMR_CSBK_PROTECT:
    describe_protect(buf,size,len,&m->u.protect);
    break;
  case DMR_CSBK_MOVE_TSCC:
    describe_move_tscc(buf,size,len,&m->u.move_tscc);
    break;
  case DMR_CSBK_PREAMBLE:
    describe_preamble(buf,size,len,&m->u.preamble);
    break;
  case DMR_CSBK_BROADCAST:
    describe_broadcast(buf,size,len,&m->u.broadcast);
    break;
  case DMR_CSBK_ANNOUNCE_WITHDRAW_TSCC:
    describe_announce_withdraw_tscc(buf,size,len,&m->u.announce_withdraw_tscc);
    break;
  case DMR_CSBK_CALL_TIMERS:
    describe_call_timers(buf,size,len,&m->u.call_timers);
    break;
  case DMR_CSBK_VOTE_NOW:
    describe_other_site(buf,size,len,&m->u.other_site,"vote now ");
    break;
  case DMR_CSBK_LOCAL_TIME:
    describe_local_time(buf,size,len,&m->u.local_time);
    break;
  case DMR_CSBK_MASS_REGISTRATION:
    describe_mass_registration(buf,size,len,&m->u.mass_registration);
    break;
  case DMR_CSBK_CHANNEL_FREQUENCY:
    append(buf,size,len,"%schannel frequency ",bcast_prefix(&m->u.broadcast));
    append_system_code(buf,size,len,&m->u.broadcast.system);
    break;
  case DMR_CSBK_ADJACENT_SITE:
    describe_other_site(buf,size,len,&m->u.other_site,"adjacent site ");
    break;
  case DMR_CSBK_UNIT_TO_UNIT:
    describe_unit_to_unit(buf,size,len,&m->u.unit_to_unit);
    break;
  case DMR_CSBK_BS_DOWNLINK_ACTIVATION:
    append(buf,size,len,"BS_DWN_ACT bs=%u from=%u",m->u.bs_downlink_activation.bs_address,m->u.bs_downlink_activation.source);
    break;
  case DMR_CSBK_RANDOM_ACCESS:
    describe_random_access(buf,size,len,&m->u.random_access);
    break;
  case DMR_CSBK_CAP_PLUS_NEIGHBORS:
    describe_cap_plus_neighbors(buf,size,len,&m->u.cap_plus_neighbors);
    break;
  case DMR_CSBK_CAP_PLUS_SITE_STATUS:
    describe_cap_plus_site_status(buf,size,len,&m->u.cap_plus_site_status);
    break;
  case DMR_CSBK_CAP_PLUS_PREAMBLE: {
    struct dmr_csbk_cap_plus_preamble const *p = &m->u.cap_plus_preamble;
    append(buf,size,len,"CAP+ PREAMBLE %s blocks=%u %s%u from=%u",p->data_follows ? "data" : "csbk",p->blocks_to_follow,
           p->target_is_talkgroup ? "tg=" : "to=",p->target,p->source);
    break;
  }
  case DMR_CSBK_CAP_PLUS_DATA_WINDOW: {
    struct dmr_csbk_cap_plus_data_window const *w = &m->u.cap_plus_data_window;
    append(buf,size,len,"CAP+ DATA REVERT WINDOW %s %u.%u",w->is_grant ? "grant" : "announce",w->super_frame,w->window);
    if(w->radio != 0)
      append(buf,size,len," radio=%u",w->radio);
    break;
  }
  case DMR_CSBK_CON_PLUS_NEIGHBORS:
    describe_con_plus_neighbors(buf,size,len,&m->u.con_plus_neighbors);
    break;
  case DMR_CSBK_CON_PLUS_VOICE_CHANNEL_USER: {
    struct dmr_csbk_con_plus_voice_channel_user const *v = &m->u.con_plus_voice_channel_user;
    append(buf,size,len,"CON+ VOICE CHANNEL USER tg=%u from=%u ",v->group,v->source);
    append_con_plus_slot(buf,size,len,&v->slot);
    break;
  }
  case DMR_CSBK_CON_PLUS_DATA_CHANNEL_GRANT:
    append(buf,size,len,"CON+ DATA CHANNEL GRANT to=%u ",m->u.con_plus_data_channel_grant.target);
    append_con_plus_slot(buf,size,len,&m->u.con_plus_data_channel_grant.slot);
    break;
  case DMR_CSBK_CON_PLUS_OTA_ANNOUNCEMENT: {
    struct dmr_csbk_con_plus_ota_announcement const *a = &m->u.con_plus_ota_announcement;
    append(buf,size,len,"CON+ OTA ANNOUNCEMENT type=%u version=%u on ",a->message_type,a->version);
    append_con_plus_slot(buf,size,len,&a->slot);
    break;
  }
  case DMR_CSBK_CON_PLUS_TERMINATE_CHANNEL_GRANT: {
    struct dmr_csbk_con_plus_terminate_channel_grant const *t = &m->u.con_plus_terminate_channel_grant;
    append(buf,size,len,"CON+ TERMINATE CHANNEL GRANT to=%u unknown=%02X%02X%02X%02X%02X",t->target,t->unknown[0],
           t->unknown[1],t->unknown[2],t->unknown[3],t->unknown[4]);
    break;
  }
  case DMR_CSBK_CON_PLUS_RADIO_EVENT:
    describe_con_plus_radio_event(buf,size,len,&m->u.con_plus_radio_event);
    break;
  case DMR_CSBK_CON_PLUS_DATA_WINDOW: {
    struct dmr_csbk_con_plus_data_window const *w = &m->u.con_plus_data_window;
    append(buf,size,len,"CON+ DATA REVERT WINDOW %s %u.%u",w->is_grant ? "grant" : "announce",w->super_frame,w->window);
    if(w->radio != 0)
      append(buf,size,len," radio=%u",w->radio);
    break;
  }
  case DMR_CSBK_CAP_MAX_OPEN_MODE_UPDATE: {
    struct dmr_csbk_cap_max_open_mode_update const *u = &m->u.cap_max_open_mode_update;
    append(buf,size,len,"CAPMAX CHANNEL UPDATE (open) LCN %u",u->lcn);
    if(u->talkgroup_ts1 != 0)
      append(buf,size,len," TS1 tg=%u",u->talkgroup_ts1);
    if(u->talkgroup_ts2 != 0)
      append(buf,size,len," TS2 tg=%u",u->talkgroup_ts2);
    break;
  }
  case DMR_CSBK_CAP_MAX_ADVANTAGE_MODE_UPDATE:
    append(buf,size,len,"CAPMAX CHANNEL UPDATE (advantage)");
    for(int i=0; i < 2; i++){
      if(m->u.cap_max_advantage_mode_update.repeaters[i].talkgroup_ts1 != 0)
        append(buf,size,len," LCN %u TS1 tg=%u",m->u.cap_max_advantage_mode_update.repeaters[i].lcn,
               m->u.cap_max_advantage_mode_update.repeaters[i].talkgroup_ts1);
      if(m->u.cap_max_advantage_mode_update.repeaters[i].talkgroup_ts2 != 0)
        append(buf,size,len," LCN %u TS2 tg=%u",m->u.cap_max_advantage_mode_update.repeaters[i].lcn,
               m->u.cap_max_advantage_mode_update.repeaters[i].talkgroup_ts2);
    }
    break;
  case DMR_CSBK_HYTERA_TALKER_STATUS: {
    struct dmr_csbk_hytera_talker_status const *t = &m->u.hytera_talker_status;
    append(buf,size,len,"HYTERA TALKER STATUS %s talker=%u from=%u",t->talker_inactive ? "ended" : "talking",t->talker,t->source);
    break;
  }
  case DMR_CSBK_HYTERA_XPT_SITE_STATE:
    describe_hytera_xpt_site_state(buf,size,len,&m->u.hytera_xpt_site_state);
    break;
  case DMR_CSBK_HYTERA_XPT_ADJACENT_SITES:
    append(buf,size,len,"XPT ADJACENT SITES");
    for(int i=0; i < 4; i++){
      if(m->u.hytera_xpt_adjacent_sites.sites[i].site != 0)
        append(buf,size,len," [site %u free %u]",m->u.hytera_xpt_adjacent_sites.sites[i].site,
               m->u.hytera_xpt_adjacent_sites.sites[i].free_repeater);
    }
    break;
  case DMR_CSBK_HYTERA_XPT_PREAMBLE: {
    struct dmr_csbk_hytera_xpt_preamble const *p = &m->u.hytera_xpt_preamble;
    append(buf,size,len,"XPT PREAMBLE %s blocks=%u %s%u from=%u free=%u",p->data_follows ? "data" : "csbk",p->blocks_to_follow,
           p->target_is_talkgroup ? "tg=" : "to=",p->target,p->source,p->free_repeater);
    if(p->priority_repeater != 0)
      append(buf,size,len," priority call %02X on repeater %u",p->priority_hashed_address,p->priority_repeater);
    break;
  }
  case DMR_CSBK_HYTERA_SMS_AVAILABLE: {
    struct dmr_csbk_hytera_sms_available const *s = &m->u.hytera_sms_available;
    append(buf,size,len,"HYTERA SMS AVAILABLE to=%u from=%u unknown=%04X",s->destination,s->source,s->unknown);
    break;
  }
  }
}

int dmr_csbk_describe(char *buf,size_t size,struct dmr_csbk_message const *m){
  assert(buf != NULL && m != NULL);
  size_t len = 0;
  if(!dmr_csbk_parsed(m)){
    append(buf,size,&len,"CSBK CRC FAIL csbko=%u fid=0x%02X observed-mask=0x%04X",m->block.opcode,m->block.fid,
           m->block.observed_mask);
    return finish(buf,size,len);
  }
  if(m->from_mbc)
    append(buf,size,&len,"MBC ");
  describe_body(buf,size,&len,m);
  if(m->block.protect)
    append(buf,size,&len," PF");
  if(m->has_absolute){
    char text[160];
    dmr_cgap_describe(text,sizeof text,&m->absolute);
    append(buf,size,&len," %s",text);
  }
  return finish(buf,size,len);
}

// ---------------- Multi-block control ----------------
// After sdrtrunk (GPL-3, Dennis Sheirer, commit 1945b835) message/data/mbc/MBCAssembler,
// MBCContinuationBlock, MultiCSBK, header/MBCHeader and CSBKMessageFactory.create(MBCHeader, List),
// with both CRCs checked; the continuation CRC's span is OP25 (GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al.)'s, dmr_slot.cc:349-386

void dmr_mbc_init(struct dmr_mbc_assembler *a,uint64_t max_block_gap_us){
  assert(a != NULL);
  memset(a,0,sizeof *a);
  a->max_block_gap_us = max_block_gap_us;
}

bool dmr_mbc_carries_absolute(struct dmr_csbk_block const *header,bool mobile_sourced){
  if(header->fid == DMR_FID_STANDARD){
    // Every grant, the multi-item data grants (55, 56) included (TS 102 361-4 tables 7.13, 7.15)
    if(header->opcode == DMR_CSBKO_TD_GRANT_MI)
      return !mobile_sourced;
    if(header->opcode >= DMR_CSBKO_PV_GRANT && header->opcode <= DMR_CSBKO_PD_GRANT_MI)
      return true;
    if(header->opcode == DMR_CSBKO_CLEAR || header->opcode == DMR_CSBKO_MOVE_TSCC)
      return true;
    if(header->opcode == DMR_CSBKO_BROADCAST){
      uint8_t const type = dmr_bcast_type(header);
      return type == DMR_BCAST_ANNOUNCE_WITHDRAW_TSCC || type == DMR_BCAST_VOTE_NOW || type == DMR_BCAST_CHANNEL_FREQUENCY
        || type == DMR_BCAST_ADJACENT_SITE;
    }
    return false;
  }
  if(header->fid == DMR_FID_HYTERA_08 || header->fid == DMR_FID_HYTERA_68)
    return header->opcode == DMR_CSBKO_HYTERA_ANNOUNCEMENT && dmr_bcast_type(header) == DMR_BCAST_ADJACENT_SITE;
  return false;
}

static struct dmr_mbc_pending *pending(struct dmr_mbc_assembler *a,uint8_t slot){
  return &a->pending[slot == 2 ? 1 : 0];
}
static void abandon(struct dmr_mbc_assembler *a,struct dmr_mbc_pending *p){
  if(p->active)
    a->stats.abandoned++;
  p->active = false;
}
static void event_init(struct dmr_mbc_event *e){
  e->status = DMR_MBC_NOT_MBC;
  e->has_message = false;
  e->observed_mask = 0;
}

void dmr_mbc_on_header(struct dmr_mbc_assembler *a,struct dmr_mbc_event *e,uint8_t const info96[96],uint8_t slot,
                       uint8_t color_code,uint64_t timestamp_us,bool mobile_sourced){
  assert(a != NULL && e != NULL && info96 != NULL);
  event_init(e);
  struct dmr_mbc_pending *p = pending(a,slot);
  abandon(a,p);
  struct dmr_csbk_block header;
  dmr_csbk_read_block(&header,info96,slot,color_code,timestamp_us,DMR_CRC_MASK_MBC_HEADER);
  if(!header.crc_ok){
    a->stats.header_crc_failures++;
    e->status = DMR_MBC_HEADER_CRC_FAILED;
    e->observed_mask = header.observed_mask;
    return;
  }
  a->stats.headers++;
  p->active = true;
  p->header = header;
  p->mobile_sourced = mobile_sourced;
  p->blocks = 0;
  p->last_timestamp_us = timestamp_us;
  e->status = DMR_MBC_HEADER_ACCEPTED;
}

void dmr_mbc_on_continuation(struct dmr_mbc_assembler *a,struct dmr_mbc_event *e,uint8_t const info96[96],
                             uint8_t slot,uint64_t timestamp_us){
  assert(a != NULL && e != NULL && info96 != NULL);
  event_init(e);
  struct dmr_mbc_pending *p = pending(a,slot);
  if(!p->active){
    a->stats.orphan_blocks++;
    e->status = DMR_MBC_NO_HEADER;
    return;
  }
  uint64_t const gap = timestamp_us >= p->last_timestamp_us ? timestamp_us - p->last_timestamp_us
    : p->last_timestamp_us - timestamp_us;
  if(a->max_block_gap_us != 0 && gap > a->max_block_gap_us){
    abandon(a,p);
    e->status = DMR_MBC_STALE;
    return;
  }
  if(p->blocks >= DMR_MBC_MAX_CONTINUATION_BLOCKS){
    abandon(a,p);
    e->status = DMR_MBC_TOO_MANY_BLOCKS;
    return;
  }
  uint8_t *at = p->bits + 96 * p->blocks;
  for(int i=0; i < 96; i++)
    at[i] = info96[i] & 1u;
  p->blocks++;
  p->last_timestamp_us = timestamp_us;
  if(at[0] == 0){
    e->status = DMR_MBC_CONTINUATION_ACCEPTED;
    return;
  }
  // The last block: the CRC over every continuation block
  int const total = 96 * p->blocks;
  if(!dmr_crc_ccitt_check(p->bits,total,DMR_CRC_MASK_NONE)){
    a->stats.crc_failures++;
    e->status = DMR_MBC_CRC_FAILED;
    e->observed_mask = dmr_crc_ccitt_observed_mask(p->bits,total);
    p->active = false;
    return;
  }
  // A continuation carrying absolute parameters (CG_AP, MV_AP, BC_AP, VN_AP) has its header's CSBKO
  // in bits 2-7 (TS 102 361-4 tables 7.16, 7.18, 7.21, 7.72; dsd-neo dmr_abs_params.c checks it too):
  // one that does not is another message's block, and the pair is not a message
  if(p->header.fid == DMR_FID_STANDARD && dmr_mbc_carries_absolute(&p->header,p->mobile_sourced)){
    uint8_t opcode = 0;
    for(int i=2; i < 8; i++)
      opcode = (uint8_t)((opcode << 1) | p->bits[i]);
    if(opcode != p->header.opcode){
      a->stats.opcode_mismatches++;
      e->status = DMR_MBC_OPCODE_MISMATCH;
      p->active = false;
      return;
    }
  }
  struct dmr_csbk_message *m = &e->message;
  memset(m,0,sizeof *m);
  m->block = p->header;
  dmr_csbk_parse_body(m,&p->header,p->mobile_sourced); // a mobile's CSBKO 56 is not a data grant
  m->from_mbc = true;
  m->mbc_continuation_blocks = (uint8_t)p->blocks;
  memcpy(m->mbc_continuation_bits,p->bits,(size_t)total);
  if(dmr_mbc_carries_absolute(&p->header,p->mobile_sourced)){
    m->has_absolute = true;
    dmr_cgap_parse(&m->absolute,p->bits);
  }
  p->active = false;
  a->stats.completed++;
  e->status = DMR_MBC_COMPLETE;
  e->has_message = true;
}

void dmr_mbc_on_other_burst(struct dmr_mbc_assembler *a,uint8_t slot){
  abandon(a,pending(a,slot));
}

void dmr_mbc_on_burst(struct dmr_mbc_assembler *a,struct dmr_mbc_event *e,enum dmr_data_type type,
                      uint8_t const info96[96],uint8_t slot,uint8_t color_code,uint64_t timestamp_us,
                      bool mobile_sourced){
  if(type == DMR_DT_MBC_HEADER){
    dmr_mbc_on_header(a,e,info96,slot,color_code,timestamp_us,mobile_sourced);
    return;
  }
  if(type == DMR_DT_MBC_CONTINUATION){
    dmr_mbc_on_continuation(a,e,info96,slot,timestamp_us);
    return;
  }
  dmr_mbc_on_other_burst(a,slot);
  event_init(e);
}

void dmr_mbc_reset(struct dmr_mbc_assembler *a){
  a->pending[0].active = false;
  a->pending[1].active = false;
}

bool dmr_mbc_in_progress(struct dmr_mbc_assembler const *a,uint8_t slot){
  return a->pending[slot == 2 ? 1 : 0].active;
}

// ---------------- Grants ----------------

char const *dmr_grant_kind_name(enum dmr_grant_kind k){
  switch(k){
  case DMR_GRANT_GROUP_VOICE: return "group voice";
  case DMR_GRANT_UNIT_VOICE: return "unit voice";
  case DMR_GRANT_BROADCAST_VOICE: return "broadcast voice";
  case DMR_GRANT_GROUP_DATA: return "group data";
  case DMR_GRANT_UNIT_DATA: return "unit data";
  }
  return "?";
}
char const *dmr_grant_flavor_name(enum dmr_grant_flavor f){
  switch(f){
  case DMR_GRANT_TIER3: return "tier3";
  case DMR_GRANT_CONNECT_PLUS: return "connect+";
  case DMR_GRANT_CAPACITY_MAX: return "capmax";
  }
  return "?";
}

static struct dmr_grant *add_grant(struct dmr_grant *grants,int *count,struct dmr_csbk_message const *m,
                                   enum dmr_grant_kind kind,enum dmr_grant_flavor flavor){
  struct dmr_grant *g = &grants[(*count)++];
  memset(g,0,sizeof *g);
  g->kind = kind;
  g->flavor = flavor;
  g->channel = dmr_chref_none();
  g->protect_flag = m->block.protect;
  g->opcode = m->block.opcode;
  g->fid = m->block.fid;
  g->control_slot = m->block.slot;
  g->timestamp_us = m->block.timestamp_us;
  return g;
}

int dmr_csbk_grants(struct dmr_grant grants[DMR_MAX_GRANTS],struct dmr_csbk_message const *m){
  assert(grants != NULL && m != NULL);
  int count = 0;
  switch(m->kind){
  case DMR_CSBK_GRANT: {
    struct dmr_csbk_grant const *t = &m->u.grant;
    enum dmr_grant_kind kind = DMR_GRANT_GROUP_VOICE;
    switch(t->kind){
    case DMR_T3G_PRIVATE_VOICE:
    case DMR_T3G_DUPLEX_PRIVATE_VOICE: kind = DMR_GRANT_UNIT_VOICE; break;
    case DMR_T3G_TALKGROUP_VOICE: kind = DMR_GRANT_GROUP_VOICE; break;
    case DMR_T3G_BROADCAST_TALKGROUP_VOICE: kind = DMR_GRANT_BROADCAST_VOICE; break;
    case DMR_T3G_PRIVATE_DATA:
    case DMR_T3G_DUPLEX_PRIVATE_DATA:
    case DMR_T3G_PRIVATE_DATA_MULTI: kind = DMR_GRANT_UNIT_DATA; break;
    case DMR_T3G_TALKGROUP_DATA:
    case DMR_T3G_TALKGROUP_DATA_MULTI: kind = DMR_GRANT_GROUP_DATA; break;
    }
    struct dmr_grant *g = add_grant(grants,&count,m,kind,DMR_GRANT_TIER3);
    g->destination = dmr_csbk_grant_called(t);
    g->destination_is_group = dmr_csbk_grant_to_talkgroup(t);
    g->source = dmr_csbk_grant_caller(t);
    g->has_source = true;
    g->emergency = t->emergency;
    g->duplex = dmr_csbk_grant_is_duplex(t);
    // A multi-block grant names its channel by frequency (the 12-bit number is then no map key); an
    // implausible CG_AP is not trusted for tuning
    g->channel = (m->has_absolute && dmr_cgap_plausible(&m->absolute)) ? dmr_cgap_channel(&m->absolute,t->timeslot)
      : dmr_csbk_grant_channel(t);
    break;
  }
  case DMR_CSBK_CON_PLUS_VOICE_CHANNEL_USER: {
    struct dmr_csbk_con_plus_voice_channel_user const *v = &m->u.con_plus_voice_channel_user;
    struct dmr_grant *g = add_grant(grants,&count,m,DMR_GRANT_GROUP_VOICE,DMR_GRANT_CONNECT_PLUS);
    g->destination = v->group;
    g->destination_is_group = true;
    g->source = v->source;
    g->has_source = true;
    g->channel = dmr_con_plus_slot_channel(&v->slot);
    g->activity_update = true;
    break;
  }
  case DMR_CSBK_CON_PLUS_DATA_CHANNEL_GRANT: {
    struct dmr_csbk_con_plus_data_channel_grant const *d = &m->u.con_plus_data_channel_grant;
    struct dmr_grant *g = add_grant(grants,&count,m,DMR_GRANT_UNIT_DATA,DMR_GRANT_CONNECT_PLUS);
    g->destination = d->target;
    g->channel = dmr_con_plus_slot_channel(&d->slot);
    break;
  }
  case DMR_CSBK_CAP_MAX_OPEN_MODE_UPDATE: {
    struct dmr_csbk_cap_max_open_mode_update const *o = &m->u.cap_max_open_mode_update;
    uint32_t const talkgroups[2] = {o->talkgroup_ts1, o->talkgroup_ts2};
    for(int ts=1; ts <= 2; ts++){
      if(talkgroups[ts - 1] == 0)
        continue;
      struct dmr_grant *g = add_grant(grants,&count,m,DMR_GRANT_GROUP_VOICE,DMR_GRANT_CAPACITY_MAX);
      g->destination = talkgroups[ts - 1];
      g->destination_is_group = true;
      g->channel = dmr_chref_from_tier3(o->lcn,ts);
      g->activity_update = true;
    }
    break;
  }
  case DMR_CSBK_CAP_MAX_ADVANTAGE_MODE_UPDATE:
    for(int r=0; r < 2; r++){
      uint32_t const talkgroups[2] = {m->u.cap_max_advantage_mode_update.repeaters[r].talkgroup_ts1,
                                      m->u.cap_max_advantage_mode_update.repeaters[r].talkgroup_ts2};
      for(int ts=1; ts <= 2; ts++){
        if(talkgroups[ts - 1] == 0)
          continue;
        struct dmr_grant *g = add_grant(grants,&count,m,DMR_GRANT_GROUP_VOICE,DMR_GRANT_CAPACITY_MAX);
        g->destination = talkgroups[ts - 1];
        g->destination_is_group = true;
        g->channel = dmr_chref_from_tier3(m->u.cap_max_advantage_mode_update.repeaters[r].lcn,ts);
        g->activity_update = true;
      }
    }
    break;
  default:
    break;
  }
  return count;
}

int dmr_grant_describe(char *buf,size_t size,struct dmr_grant const *g){
  size_t len = 0;
  append(buf,size,&len,"GRANT %s %s %s%u",dmr_grant_kind_name(g->kind),dmr_grant_flavor_name(g->flavor),
         g->destination_is_group ? "tg=" : "to=",g->destination);
  if(g->has_source)
    append(buf,size,&len," from=%u",g->source);
  append(buf,size,&len," ");
  append_chref(buf,size,&len,&g->channel);
  if(g->emergency)
    append(buf,size,&len," EMERGENCY");
  if(g->protect_flag)
    append(buf,size,&len," PF");
  if(g->duplex)
    append(buf,size,&len," duplex");
  if(g->activity_update)
    append(buf,size,&len," (update)");
  return finish(buf,size,len);
}

// ---------------- The channel map ----------------

int dmr_map_conflict_describe(char *buf,size_t size,struct dmr_map_conflict const *c){
  char held[40],offered[40];
  dmr_format_mhz(held,sizeof held,c->held_hz);
  dmr_format_mhz(offered,sizeof offered,c->offered_hz);
  return snprintf(buf,size,"LCN %u: %s says %s MHz, %s says %s MHz (%s)",c->lcn,c->held_source == DMR_MAP_CONFIG ? "config" : "air",
                  held,c->offered_source == DMR_MAP_CONFIG ? "config" : "air",offered,c->replaced ? "replaced" : "kept");
}

void dmr_map_init(struct dmr_channel_map *m,uint64_t tolerance_hz){
  assert(m != NULL);
  memset(m,0,sizeof *m);
  m->tolerance_hz = tolerance_hz;
}
void dmr_map_free(struct dmr_channel_map *m){
  if(m == NULL)
    return;
  free(m->entries);
  m->entries = NULL;
  m->count = m->capacity = 0;
}
static bool same_hz(struct dmr_channel_map const *m,uint64_t a,uint64_t b){
  return (a > b ? a - b : b - a) <= m->tolerance_hz;
}
// Index of lcn, or of where it would go
static size_t lower_bound(struct dmr_channel_map const *m,uint16_t lcn){
  size_t lo = 0,hi = m->count;
  while(lo < hi){
    size_t const mid = lo + (hi - lo) / 2;
    if(m->entries[mid].lcn < lcn)
      lo = mid + 1;
    else
      hi = mid;
  }
  return lo;
}
static struct dmr_map_entry *find_entry(struct dmr_channel_map const *m,uint16_t lcn){
  size_t const i = lower_bound(m,lcn);
  return (i < m->count && m->entries[i].lcn == lcn) ? &m->entries[i] : NULL;
}
// The entry for lcn, made if need be (NULL if out of memory)
static struct dmr_map_entry *insert_entry(struct dmr_channel_map *m,uint16_t lcn){
  size_t const i = lower_bound(m,lcn);
  if(i < m->count && m->entries[i].lcn == lcn)
    return &m->entries[i];
  if(m->count == m->capacity){
    size_t const capacity = m->capacity == 0 ? 16 : 2 * m->capacity;
    struct dmr_map_entry *e = realloc(m->entries,capacity * sizeof *e);
    if(e == NULL)
      return NULL;
    m->entries = e;
    m->capacity = capacity;
  }
  memmove(&m->entries[i + 1],&m->entries[i],(m->count - i) * sizeof m->entries[0]);
  m->count++;
  memset(&m->entries[i],0,sizeof m->entries[i]);
  m->entries[i].lcn = lcn;
  return &m->entries[i];
}

bool dmr_map_set_from_config(struct dmr_channel_map *m,uint16_t lcn,uint64_t downlink_hz,uint64_t uplink_hz,
                             struct dmr_map_conflict *conflict){
  bool found = false;
  struct dmr_map_entry const *held = find_entry(m,lcn);
  if(held != NULL && !same_hz(m,held->downlink_hz,downlink_hz)){
    if(conflict != NULL){
      conflict->lcn = lcn;
      conflict->held_hz = held->downlink_hz;
      conflict->held_source = held->source;
      conflict->offered_hz = downlink_hz;
      conflict->offered_source = DMR_MAP_CONFIG;
      conflict->replaced = true;
    }
    m->conflicts++;
    found = true;
  }
  struct dmr_map_entry *e = insert_entry(m,lcn);
  if(e != NULL){
    e->downlink_hz = downlink_hz;
    e->uplink_hz = uplink_hz;
    e->source = DMR_MAP_CONFIG;
  }
  return found;
}

bool dmr_map_learn_from_air(struct dmr_channel_map *m,uint16_t lcn,uint64_t downlink_hz,uint64_t uplink_hz,
                            struct dmr_map_conflict *conflict){
  if(downlink_hz == 0)
    return false;
  struct dmr_map_entry *held = find_entry(m,lcn);
  if(held == NULL){
    struct dmr_map_entry *e = insert_entry(m,lcn);
    if(e != NULL){
      e->downlink_hz = downlink_hz;
      e->uplink_hz = uplink_hz;
      e->source = DMR_MAP_AIR;
    }
    return false;
  }
  if(same_hz(m,held->downlink_hz,downlink_hz)){
    if(held->uplink_hz == 0)
      held->uplink_hz = uplink_hz;
    return false;
  }
  struct dmr_map_conflict c = {lcn, held->downlink_hz, held->source, downlink_hz, DMR_MAP_AIR, false};
  m->conflicts++;
  if(held->source == DMR_MAP_AIR){
    held->downlink_hz = downlink_hz;
    held->uplink_hz = uplink_hz;
    held->source = DMR_MAP_AIR;
    c.replaced = true;
  }
  if(conflict != NULL)
    *conflict = c;
  return true;
}

bool dmr_map_learn_from_cgap(struct dmr_channel_map *m,struct dmr_cgap const *p,struct dmr_map_conflict *conflict){
  if(!dmr_cgap_plausible(p))
    return false;
  return dmr_map_learn_from_air(m,p->lcn,dmr_cgap_downlink_hz(p),dmr_cgap_uplink_hz(p),conflict);
}

struct dmr_map_entry const *dmr_map_find(struct dmr_channel_map const *m,uint16_t lcn){
  return find_entry(m,lcn);
}
uint64_t dmr_map_downlink_hz(struct dmr_channel_map const *m,uint16_t lcn){
  struct dmr_map_entry const *e = find_entry(m,lcn);
  return e != NULL ? e->downlink_hz : 0;
}
uint64_t dmr_map_resolve(struct dmr_channel_map const *m,struct dmr_channel_ref const *c){
  if(dmr_chref_has_frequency(c))
    return c->downlink_hz;
  if(!dmr_chref_valid(c))
    return 0;
  return dmr_map_downlink_hz(m,c->lcn);
}
