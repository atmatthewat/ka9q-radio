// DMR message layer (see dmrmsg.h): data bursts, link control, embedded LC, burst F, hidden IV,
// Short LC, talker alias, voice frames, and the per-carrier decoder that joins them
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "dfec.h"
#include "dmrfec.h"
#include "dmrmsg.h"
#include "p25p2unit.h"

// Theory of operation
//
// One decoder per carrier takes every burst of both timeslots, in the order the sink hands them on,
// and returns what that burst completed. Every message it returns has passed its own check, with one
// exception that is marked: a data burst carries a status, and only DMR_DATA_VALID means its typed
// content was checked. A BPTC decode that "succeeds" is never enough by itself: BPTC(196,96) accepts
// some codeword for a good share of random words, so each message type has a check of its own.
//
// Data bursts, by the data type in the slot type the sink decoded:
//   voice LC header, terminator   BPTC(196,96), then RS(12,9) with the data type's mask (0x96, 0x99),
//                                 then the 72-bit LC is parsed. Some Hytera Tier III systems send the
//                                 parity with no mask: an LC that fails with its mask is accepted with
//                                 none, but only if RS then has nothing to correct (a random word passes
//                                 that one time in 16.7 million). rs_corrected and lc_uncorrected say
//                                 whether RS had to repair an octet (evidence only: the call tracker
//                                 takes any checked LC, dmrcall.c).
//   PI header                     BPTC, CRC-CCITT with mask 0x6969. The 80 bits are the algorithm
//                                 octet, FID, key ID, a 32-bit MI and a 24-bit destination, as OP25
//                                 (GPL-3, op25_repeater/lib/dmr_slot.h, get_pi_*) and sdrtrunk (GPL-3,
//                                 Dennis Sheirer, lc/full/EncryptionParameters.java) read them. They
//                                 disagree on octet 0: OP25 takes the whole octet as the algorithm,
//                                 sdrtrunk its low six bits; both are kept. The algorithms known so far
//                                 are all below 0x40, where the two agree.
//   idle                          The idle message has no CRC, but its 96 bits are a fixed sequence
//                                 (TS 102 361-1 annex D: s[n] = s[n-9] ^ s[n-5] from nine ones), so the
//                                 whole 196-bit field is known. An idle burst is valid when it is within
//                                 20 bits of that field (bit 0, R(3), is outside the code and not
//                                 counted). Random bits differ in about 98 places, so this is a far
//                                 stronger test than BPTC, and it works where BPTC gives up.
//   CSBK, MBC, data header, rate 1/2 data, USBD
//                                 BPTC only: the 96 bits are handed on, DMR_DATA_UNCHECKED, for the
//                                 code that parses them and owns their CRC.
//   rate 3/4, rate 1, reserved    Not BPTC coded: the 196 bits go on as sent, DMR_DATA_NOT_BPTC.
// From sdrtrunk these are not taken: its inverted LC validity (LCMessageFactory.java:134) and its
// one-bit "correction" by CRC. Its mask learning (DMRCrcMaskManager, which marks failing LCs valid
// after two sightings) is done here only when asked for (learn_crc_masks; dmr_crc_learner below), and
// a learned LC never says clear (dmrcall.c).
//
// The link control (TS 102 361-2 7.1.1): PF (1), reserved (1), FLCO (6), FID (8), then 56 bits that
// depend on the (FID, FLCO) pair. Field positions are sdrtrunk's (lc/full/*.java, LCOpcode.java,
// ServiceOptions.java), checked for the standard voice LCs against OP25 (dmr_slot.h, get_lc_*):
//   FID 0x00   group voice 0x00, unit-to-unit voice 0x03, talker alias header and blocks 0x04-0x07,
//              GPS 0x08, terminator data 0x30
//   FID 0x10   group voice 0x00, Capacity Plus wide-area voice with the rest LSN 0x04, Capacity Max
//              group voice 0x10 and talker alias header and blocks 0x14-0x17 (the standard's layout:
//              sdrtrunk 9359f523, GPL-3, Dennis Sheirer, issue #2421), Capacity Plus voice 0x20 (privacy from its options),
//              encryption parameters 0x21
//   FID 0x68   group voice 0x00, unit-to-unit 0x03, talker alias 0x04-0x07, GPS 0x08, XPT channel
//              grant 0x09, terminator 0x30
//   FID 0x08   group voice, unit-to-unit and XPT grant read as FID 0x68's: sdrtrunk knows the FID
//              but maps no LC to it, so this is an assumption
// Anything else is DMR_LC_UNKNOWN with its nine octets. PF is not "encrypted" (sdrtrunk's
// FullLCMessage.isEncrypted reads it so); the privacy bit of the service options is.
//
// The embedded LC. Voice bursts B-E carry four 32-bit fragments, marked by their EMB's LCSS first,
// continuation, continuation, last; 128 bits in BPTC(128,77) give the 72 LC bits and a 5-bit
// checksum. A fragment is placed by when it arrived: the bursts of a slot are 288 dibits apart, so
// its place is (clock - first fragment's clock) / 288, rounded, within 24 dibits. That makes the
// assembly indifferent to a burst delivered twice or late, and lets a fragment whose EMB did not
// decode be used where the timing puts it (BPTC and the checksum decide whether its 32 bits were
// good). Without a clock fragments are taken in arrival order, and one whose EMB failed only if the
// sink's burst letter puts it next. A missing fragment loses the message; a new "first" restarts the
// collection; a continuation or last with no "first" (a late entry) is ignored. The checksum passes
// one wrong LC in 31, so it adds little: an LC is reported only when BPTC accepts the word within
// DMR_BPTC128_MAX_ERRORS and the checksum matches, and corrected says how hard BPTC worked, for a
// caller that wants to be stricter. sdrtrunk feeds its assembler without looking at the EMB
// (FLCAssembler.java), and it and OP25 place fragments by counting them.
//
// Burst F. With EMB LCSS "single fragment" the 32 bits are one self-contained (32,11) codeword. ETSI
// has two forms: the second row repeats the first (the null message, 11 zero bits) or is its
// complement (reverse channel: 4 RC bits and a CRC-7). The EMB's PI says which (TS 102 361-1 9.3.2,
// 6.4.2: an RC burst has LCSS single and PI = 1), and only that form is decoded; the other is tried
// too, but only to count (single_burst_form_mismatch) the bursts in which it alone would decode. The
// reverse channel's CRC-7 is masked with 0x7A (TS 102 361-1 table B.21, clause 6.4.2; ok-dmrlib and
// DSD-FME agree; OP25's check, compiled out, omits the mask), so residue 0 is a pass; it is reported,
// not used, since nothing acts on the RC bits. The
// vendor "short burst" layout (sdrtrunk, voice/embedded/*.java and VoiceSuperFrameProcessor.java,
// after patents EP2347540B1 and US8271009B2; one source) has the opcode in bits 8-10 of the 11:
// 0 null, valid when the 11 bits divide by x^3 + x + 1; 1, 4, 5 encryption parameters, bits 0-7 the
// key and the opcode the algorithm (ARC4, AES-128, AES-256), with no check beyond the code; 3 TXI
// delay, bits 3-7, with bits 0-2 a CRC-3 by the same division. The decoder is maximum likelihood over
// both rows (as sdrtrunk's BPTC_16_2.java now is; at a0533156 it corrected only the first row). The code has distance 8 and nothing checks
// what it delivers, so a burst with five or more errors can decode to a wrong message within three
// corrections. So a decode is accepted with at most DMR_SINGLE_BURST_MAX_CORRECTED (2) corrections,
// where the code could correct 3: a wrong message then needs six errors in the 32.
//
// The hidden IV (sdrtrunk's VoiceSuperFrameProcessor, the same patents). Each AMBE frame gives up its
// last four c3 bits (frame bits 71, 67, 63, 59, in that order); the 18 frames of a superframe carry
// 72 bits, three Golay(24,12) words, word w made of frame w of bursts A to F in turn. The 36 data bits
// are a 32-bit IV and a CRC-4 (x^4 + x + 1, the remainder XORed with 0xF at the end, as sdrtrunk and
// DSD-FME do). Checked against sdrtrunk's code
// only (VoiceMessage.java:37-42, 103-110; VoiceSuperFrameProcessor.java:46-48, 199-273), with no
// vector from a real system; sdrtrunk counts the parity over all 72 bits instead of the word's 24,
// which is not copied. On a clear call the same bits are speech, and three random words pass Golay and
// the CRC-4 about one superframe in 90; with at most 3 corrected bits in all (the default
// hidden_iv_max_golay_errors) under one in 10 million. Even so an IV says nothing about encryption:
// it is for a transmission already known to be encrypted.
//
// Short LC (TS 102 361-1 9.1.4, -2 7.1.3): the CACH of a base station carries 17 payload bits ahead
// of each burst, marked by its TACT LCSS; four of them, one slot period (144 dibits) apart, are 68
// bits of BPTC(68,36): SLCO (4), data (24) and a CRC-8. The CACH belongs to the carrier, so one
// assembler takes the bursts of both slots. A CACH whose TACT did not decode is taken as the next
// fragment of a message already begun (BPTC and the CRC then decide); anything else out of turn, a
// step in the clock other than 144 +- 24 dibits, or a burst with no CACH drops the message, and the
// next "first" starts again. sdrtrunk at a0533156 computed the CRC-8 and then overwrote the result with
// the BPTC status (SLCAssembler.java:145-149; it now ANDs the two); OP25 (dmr_cai.cc) checks it, as here. Opcodes as sdrtrunk parses
// them (lc/shorty/*.java), compared with OP25 (dmr_cai.cc decode_shortLC): for the huge network model
// of Sys_Parms sdrtrunk has network 2 bits and site 10 (as TS 102 361-4), OP25's shifts read other
// bits; for the Capacity Plus rest channel (SLCO 15) sdrtrunk reads a 5-bit rest LSN at bits 15-19
// and a site at 20-24 and wants FID 0x10 in bits 4-11, OP25 a 4-bit "LCN" at 16-19 without the FID.
// sdrtrunk's layouts are used. sdrtrunk loses an SLCO 9 whose network's upper eight bits equal a
// manufacturer's FID (ShortLCMessage.java:92-99); that is not copied. The Capacity Plus, Connect Plus
// and Hytera XPT layouts are the two programs' observations, not a standard.
//
// Talker alias (TS 102 361-2 7.1.1.4): a header LC (FLCO 0x04: format, length, 49 data bits) and up
// to three blocks (0x05-0x07, 56 bits each) in the embedded LCs of a transmission; 217 bits that run
// on. 7-bit characters start at the first bit (up to 31); in the 8-bit formats (ISO 8859-1, UTF-8)
// and UTF-16BE the first bit is unused and the rest are octets (up to 27) or 16-bit units (up to 13).
// Capacity Max sends the same header and blocks under FID 0x10 at FLCO 0x14-0x17. In UTF-8 the standard's
// length counts code units, octets (TS 102 361-2 3.1, 7.2.19), but Motorola's radios count characters:
// so every octet received is decoded, up to padding (NUL), and the text is cut at the length in
// characters, which serves both (both from sdrtrunk 9359f523, GPL-3, Dennis Sheirer, issue #2421).
// Layout and the one-bit offset as sdrtrunk (TalkerAliasHeader.java, TalkerAliasAssembler.java,
// TalkerAliasComplete.java), one source. sdrtrunk clears its assembler only on an idle or terminator
// burst, so a block from one transmission can complete the next one's header, and it reports again on
// every later fragment; here the assembler is reset for every new transmission, a header that differs
// from the one held drops the blocks, and an alias is reported once until it changes. Control
// characters become spaces and trailing spaces go, so an alias is one safe log line; invalid UTF-8
// and unpaired surrogates become U+FFFD.
//
// Voice frames (TS 102 361-1 6.1): frame 1 is burst bits 0-71, frame 2 72-107 and 156-191, frame 3
// 192-263 (sdrtrunk's 288-bit indexes less 24, VoiceMessage.java:61-92; OP25 agrees). They are kept as
// sent, msb first in 9 octets, the form a vocoder's frame decoder takes; each bit is copied singly,
// so the frame-2 octet 4 fault sdrtrunk had at a0533156 (a sign-extending shift, VoiceMessage.java:77;
// masked since) cannot happen.
// The FEC is the half-rate vocoder's, which DMR shares with P25 Phase 2: p25p2_ambe_decode() gives the
// c0 and c1 Golay corrections (fec_errors, 0 for an undamaged frame, up to 4 + 3) and the 49 bits.
//
// State per timeslot: the embedded LC being collected, the superframe's hidden-IV bits, the talker
// alias fragments. A slot's state is dropped by a data burst on it (the voice is over or not begun),
// when its voice identity changes (a new talker: the alias starts again; not the first identity of a
// transmission, whose alias may have come first on a late entry), and when nothing has come on it for
// slot_gap_dibits (4800, 1 s). Slot 0 ("not known") has state of its own. The superframe position of
// a voice burst is the sink's letter, or on a late entry the embedded fragment's place, or F for a
// single-burst message.

// ---------------- Bits ----------------

static uint32_t bits_to_uint(uint8_t const *bits,int n){
  uint32_t v = 0;
  for(int i=0; i < n; i++)
    v = (v << 1) | (bits[i] & 1u);
  return v;
}
static void uint_to_bits(uint32_t v,int n,uint8_t *bits){
  for(int i=0; i < n; i++)
    bits[i] = (uint8_t)((v >> (n - 1 - i)) & 1u);
}
static void bits_to_bytes(uint8_t const *bits,int nbytes,uint8_t *bytes){
  for(int i=0; i < nbytes; i++)
    bytes[i] = (uint8_t)bits_to_uint(bits + 8 * i,8);
}
// Bits first .. first + count - 1 of an octet array (bit 0 = top bit of octet 0), count <= 32
static uint32_t octet_field(uint8_t const *octets,int first,int count){
  uint32_t v = 0;
  for(int i=first; i < first + count; i++)
    v = (v << 1) | ((octets[i >> 3] >> (7 - (i & 7))) & 1u);
  return v;
}
static int32_t sign_extend(uint32_t v,int bits){
  uint32_t const sign = 1u << (bits - 1);
  return (int32_t)((v ^ sign) - sign);
}
// The remainder of M(x) x^width divided by the generator (poly without its x^width term), M the
// bits with bits[0] the highest power; the register preset to init
static uint32_t crc_bits(uint8_t const *bits,int n,int width,uint32_t poly,uint32_t init){
  uint32_t const top = 1u << (width - 1);
  uint32_t const mask = width == 32 ? 0xffffffffu : ((1u << width) - 1u);
  uint32_t reg = init & mask;
  for(int i=0; i < n; i++){
    bool const feedback = ((reg & top) != 0) != ((bits[i] & 1u) != 0);
    reg = (reg << 1) & mask;
    if(feedback)
      reg ^= poly;
  }
  return reg;
}
// snprintf that appends at *len, keeping *len at the string's length (never past size - 1)
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

// ---------------- Link control ----------------

char const *dmr_lc_kind_name(enum dmr_lc_kind k){
  switch(k){
  case DMR_LC_UNKNOWN: return "UNKNOWN";
  case DMR_LC_GROUP_VOICE: return "GROUP VOICE";
  case DMR_LC_UNIT_TO_UNIT_VOICE: return "UNIT-TO-UNIT VOICE";
  case DMR_LC_TALKER_ALIAS_HEADER: return "TALKER ALIAS HEADER";
  case DMR_LC_TALKER_ALIAS_BLOCK: return "TALKER ALIAS BLOCK";
  case DMR_LC_GPS_INFO: return "GPS INFO";
  case DMR_LC_TERMINATOR_DATA: return "TERMINATOR DATA";
  case DMR_LC_MOTOROLA_GROUP_VOICE: return "MOTOROLA GROUP VOICE";
  case DMR_LC_CAP_PLUS_WIDE_AREA_VOICE: return "CAP+ WIDE-AREA VOICE";
  case DMR_LC_CAP_MAX_GROUP_VOICE: return "CAPMAX GROUP VOICE";
  case DMR_LC_CAP_PLUS_ENCRYPTED_VOICE: return "CAP+ VOICE 0x20";
  case DMR_LC_MOTOROLA_ENCRYPTION_PARAMETERS: return "MOTOROLA ENCRYPTION PARAMETERS";
  case DMR_LC_HYTERA_GROUP_VOICE: return "HYTERA GROUP VOICE";
  case DMR_LC_HYTERA_UNIT_TO_UNIT_VOICE: return "HYTERA UNIT-TO-UNIT VOICE";
  case DMR_LC_HYTERA_XPT_CHANNEL_GRANT: return "HYTERA XPT CHANNEL GRANT";
  case DMR_LC_HYTERA_TERMINATOR: return "HYTERA TERMINATOR";
  }
  return "?";
}

static void lc_voice_user(struct dmr_lc *lc,uint8_t const *lc9,enum dmr_lc_kind kind,bool group){
  struct dmr_lc_voice_user *v = &lc->u.voice_user;
  v->options = lc9[2];
  v->group = group;
  v->destination = octet_field(lc9,24,24);
  v->source = octet_field(lc9,48,24);
  lc->kind = kind;
  lc->body = DMR_LCB_VOICE_USER;
}
static void lc_hytera_voice(struct dmr_lc *lc,uint8_t const *lc9,enum dmr_lc_kind kind){
  struct dmr_lc_hytera_voice *v = &lc->u.hytera_voice;
  v->options = lc9[2];
  v->free_repeater = (uint8_t)octet_field(lc9,24,4);
  v->priority_repeater = (uint8_t)octet_field(lc9,28,4);
  v->target = (uint16_t)octet_field(lc9,32,16);
  v->priority_hash = lc9[6];
  v->source = (uint16_t)octet_field(lc9,56,16);
  lc->kind = kind;
  lc->body = DMR_LCB_HYTERA_VOICE;
}
// The header at FLCO base, blocks 1-3 at base + 1 to base + 3 (standard: 0x04; Capacity Max: 0x14)
static void lc_talker_alias(struct dmr_lc *lc,uint8_t const *lc9,uint8_t base){
  if(lc->flco == base){
    struct dmr_lc_talker_alias_header *h = &lc->u.alias_header;
    h->format = (enum dmr_ta_format)octet_field(lc9,16,2);
    h->length = (uint8_t)octet_field(lc9,18,5);
    for(int i=0; i < 49; i++)
      h->data[i] = (uint8_t)octet_field(lc9,23 + i,1);
    lc->kind = DMR_LC_TALKER_ALIAS_HEADER;
    lc->body = DMR_LCB_TALKER_ALIAS_HEADER;
  } else {
    struct dmr_lc_talker_alias_block *b = &lc->u.alias_block;
    b->block = (uint8_t)(lc->flco - base);
    for(int i=0; i < 56; i++)
      b->data[i] = (uint8_t)octet_field(lc9,16 + i,1);
    lc->kind = DMR_LC_TALKER_ALIAS_BLOCK;
    lc->body = DMR_LCB_TALKER_ALIAS_BLOCK;
  }
}
static void lc_gps(struct dmr_lc *lc,uint8_t const *lc9){
  struct dmr_lc_gps_info *g = &lc->u.gps;
  g->position_error = (uint8_t)octet_field(lc9,20,3);
  g->longitude_raw = sign_extend(octet_field(lc9,23,25),25);
  g->latitude_raw = sign_extend(octet_field(lc9,48,24),24);
  g->longitude = g->longitude_raw * (360.0 / 33554432.0);
  g->latitude = g->latitude_raw * (180.0 / 16777216.0);
  lc->kind = DMR_LC_GPS_INFO;
  lc->body = DMR_LCB_GPS_INFO;
}
// Hytera XPT channel grant (FID 0x68 FLCO 0x09): DSD-FME's layout (ISC, src/dmr_flco.c:330-345; dsd-neo,
// ISC, src/protocol/dmr/dmr_flco.c:591-605, the same, with the reserved bit as group): the call's
// LCN 16-19, free repeater 24-27, handshake 28-31, a 16-bit target 32-47 and a 16-bit source 56-71, as
// XPT addresses are 8-bit groups and 16-bit units. sdrtrunk's 24-bit target at 24-47 and source at 48-71
// (HyteraXptChannelGrant.java) read its own capture, 49 68 50 10 00 34 00 2A F9 (a terminator LC that
// passes RS(12,9) with mask 0x99), as talkgroup 1048628; this layout gives LCN 5, free repeater 1,
// talkgroup 52, source 11001. sdrtrunk's own HyteraFullLC.java puts the free repeater at 24-27 and a
// 16-bit target at 32-47 too
static void lc_xpt_grant(struct dmr_lc *lc,uint8_t const *lc9){
  struct dmr_lc_hytera_xpt_grant *g = &lc->u.xpt_grant;
  g->channel = (uint8_t)octet_field(lc9,16,4);
  g->state = (uint8_t)octet_field(lc9,20,4);
  g->free_repeater = (uint8_t)octet_field(lc9,24,4);
  g->handshake = (uint8_t)octet_field(lc9,28,4);
  g->group = lc->reserved_bit;
  g->target = (uint16_t)octet_field(lc9,32,16);
  g->unknown = lc9[6];
  g->source = (uint16_t)octet_field(lc9,56,16);
  lc->kind = DMR_LC_HYTERA_XPT_CHANNEL_GRANT;
  lc->body = DMR_LCB_HYTERA_XPT_GRANT;
}

void dmr_lc_parse(struct dmr_lc *lc,uint8_t const lc9[9]){
  assert(lc != NULL && lc9 != NULL);
  memset(lc,0,sizeof *lc);
  memcpy(lc->bytes,lc9,9);
  lc->protect = (lc9[0] & 0x80) != 0;
  lc->reserved_bit = (lc9[0] & 0x40) != 0;
  lc->flco = lc9[0] & 0x3f;
  lc->fid = lc9[1];
  lc->kind = DMR_LC_UNKNOWN;
  lc->body = DMR_LCB_UNKNOWN;

  switch(lc->fid){
  case DMR_FID_STANDARD:
    switch(lc->flco){
    case 0x00: lc_voice_user(lc,lc9,DMR_LC_GROUP_VOICE,true); break;
    case 0x03: lc_voice_user(lc,lc9,DMR_LC_UNIT_TO_UNIT_VOICE,false); break;
    case 0x04: case 0x05: case 0x06: case 0x07: lc_talker_alias(lc,lc9,0x04); break;
    case 0x08: lc_gps(lc,lc9); break;
    case 0x30: {
      struct dmr_lc_terminator_data *t = &lc->u.terminator_data;
      t->destination = octet_field(lc9,16,24);
      t->source = octet_field(lc9,40,24);
      t->group = octet_field(lc9,64,1) != 0;
      t->response_requested = octet_field(lc9,65,1) != 0;
      t->full_message = octet_field(lc9,66,1) != 0;
      t->resync = octet_field(lc9,68,1) != 0;
      t->send_sequence = (uint8_t)octet_field(lc9,69,3);
      lc->kind = DMR_LC_TERMINATOR_DATA;
      lc->body = DMR_LCB_TERMINATOR_DATA;
      break;
    }
    default: break;
    }
    break;
  case DMR_FID_MOTOROLA:
    switch(lc->flco){
    case 0x00: lc_voice_user(lc,lc9,DMR_LC_MOTOROLA_GROUP_VOICE,true); break;
    case 0x04: {
      struct dmr_lc_cap_plus_wide_area_voice *v = &lc->u.wide_area;
      v->options = lc9[2];
      v->unknown = (uint16_t)octet_field(lc9,24,16);
      v->group = lc9[5];
      v->rest_lsn = (uint8_t)octet_field(lc9,51,5);
      v->source = (uint16_t)octet_field(lc9,56,16);
      lc->kind = DMR_LC_CAP_PLUS_WIDE_AREA_VOICE;
      lc->body = DMR_LCB_CAP_PLUS_WIDE_AREA_VOICE;
      break;
    }
    case 0x10: lc_voice_user(lc,lc9,DMR_LC_CAP_MAX_GROUP_VOICE,true); break;
    case 0x14: case 0x15: case 0x16: case 0x17: lc_talker_alias(lc,lc9,0x14); break;
    case 0x20: {
      struct dmr_lc_cap_plus_encrypted_voice *v = &lc->u.cap_plus_encrypted;
      v->options = lc9[2];
      v->unknown1 = lc9[3];
      v->target = (uint16_t)octet_field(lc9,32,16);
      v->unknown2 = lc9[6];
      v->source = (uint16_t)octet_field(lc9,56,16);
      lc->kind = DMR_LC_CAP_PLUS_ENCRYPTED_VOICE;
      lc->body = DMR_LCB_CAP_PLUS_ENCRYPTED_VOICE;
      break;
    }
    case 0x21: {
      struct dmr_lc_encryption_parameters *e = &lc->u.encryption;
      e->key_id = lc9[2];
      e->mi = octet_field(lc9,24,32);
      e->destination_high = (uint16_t)octet_field(lc9,56,16);
      lc->kind = DMR_LC_MOTOROLA_ENCRYPTION_PARAMETERS;
      lc->body = DMR_LCB_ENCRYPTION_PARAMETERS;
      break;
    }
    default: break;
    }
    break;
  case DMR_FID_HYTERA_68:
  case DMR_FID_HYTERA_08:
    switch(lc->flco){
    case 0x00: lc_voice_user(lc,lc9,DMR_LC_HYTERA_GROUP_VOICE,true); break;
    case 0x03: lc_hytera_voice(lc,lc9,DMR_LC_HYTERA_UNIT_TO_UNIT_VOICE); break;
    case 0x09: lc_xpt_grant(lc,lc9); break;
    default:
      if(lc->fid == DMR_FID_HYTERA_68){
        if(lc->flco >= 0x04 && lc->flco <= 0x07)
          lc_talker_alias(lc,lc9,0x04);
        else if(lc->flco == 0x08)
          lc_gps(lc,lc9);
        else if(lc->flco == 0x30)
          lc_hytera_voice(lc,lc9,DMR_LC_HYTERA_TERMINATOR);
      }
      break;
    }
    break;
  default:
    break;
  }
}

void dmr_lc_parse_bits(struct dmr_lc *lc,uint8_t const bits72[72]){
  uint8_t lc9[9];
  bits_to_bytes(bits72,9,lc9);
  dmr_lc_parse(lc,lc9);
}

bool dmr_lc_voice_identity(struct dmr_lc const *lc,struct dmr_voice_identity *id){
  assert(lc != NULL && id != NULL);
  struct dmr_voice_identity v = { .group = true, .address_bits = 24 };
  switch(lc->kind){
  case DMR_LC_GROUP_VOICE:
  case DMR_LC_UNIT_TO_UNIT_VOICE:
  case DMR_LC_MOTOROLA_GROUP_VOICE:
  case DMR_LC_CAP_MAX_GROUP_VOICE:
  case DMR_LC_HYTERA_GROUP_VOICE:
    v.group = lc->u.voice_user.group;
    v.destination = lc->u.voice_user.destination;
    v.source = lc->u.voice_user.source;
    v.options = lc->u.voice_user.options;
    break;
  case DMR_LC_CAP_PLUS_WIDE_AREA_VOICE:
    v.destination = lc->u.wide_area.group;
    v.source = lc->u.wide_area.source;
    v.options = lc->u.wide_area.options;
    v.address_bits = 16;
    break;
  case DMR_LC_CAP_PLUS_ENCRYPTED_VOICE:
    v.destination = lc->u.cap_plus_encrypted.target;
    v.source = lc->u.cap_plus_encrypted.source;
    v.options = lc->u.cap_plus_encrypted.options;
    v.address_bits = 16;
    break;
  case DMR_LC_HYTERA_UNIT_TO_UNIT_VOICE:
    v.group = false;
    v.destination = lc->u.hytera_voice.target;
    v.source = lc->u.hytera_voice.source;
    v.options = lc->u.hytera_voice.options;
    v.address_bits = 16;
    break;
  default:
    return false;
  }
  *id = v;
  return true;
}

// FID 0x10 FLCO 0x20 says what its service options say, like every voice LC: the name "encrypted
// voice" is sdrtrunk's from one observation (LCOpcode.java), and sdrtrunk itself takes the call's
// encryption from the options bit (DMRDecoderState.java); DSD-FME and dsd-neo read it as a RAS group
// call, privacy from bit 0x40 (dmr_flco.c). Read from the opcode, a clear call was taken as encrypted
enum dmr_lc_privacy dmr_lc_privacy(struct dmr_lc const *lc){
  if(lc->kind == DMR_LC_MOTOROLA_ENCRYPTION_PARAMETERS)
    return DMR_LC_ENCRYPTED;
  struct dmr_voice_identity id;
  if(!dmr_lc_voice_identity(lc,&id))
    return DMR_LC_NO_STATEMENT;
  return dmr_so_privacy(id.options) ? DMR_LC_ENCRYPTED : DMR_LC_CLEAR;
}

static void describe_options(char *buf,size_t size,size_t *len,uint8_t so){
  if(dmr_so_emergency(so))
    append(buf,size,len," emergency");
  if(dmr_so_privacy(so))
    append(buf,size,len," encrypted");
  if(dmr_so_broadcast(so))
    append(buf,size,len," broadcast");
  if(dmr_so_ovcm(so))
    append(buf,size,len," ovcm");
  if(dmr_so_priority(so) != 0)
    append(buf,size,len," priority=%u",(unsigned)dmr_so_priority(so));
}
static void hex_octets(char *buf,size_t size,size_t *len,uint8_t const *octets,int count){
  for(int i=0; i < count; i++)
    append(buf,size,len,"%02X",(unsigned)octets[i]);
}

int dmr_lc_describe(char *buf,size_t size,struct dmr_lc const *lc){
  size_t len = 0;
  append(buf,size,&len,"%s",dmr_lc_kind_name(lc->kind));
  if(lc->kind == DMR_LC_UNKNOWN)
    append(buf,size,&len," fid=0x%02X flco=0x%02X",(unsigned)lc->fid,(unsigned)lc->flco);
  switch(lc->body){
  case DMR_LCB_UNKNOWN:
    append(buf,size,&len," lc=");
    hex_octets(buf,size,&len,lc->bytes,9);
    break;
  case DMR_LCB_VOICE_USER: {
    struct dmr_lc_voice_user const *v = &lc->u.voice_user;
    append(buf,size,&len," src=%u %s=%u",(unsigned)v->source,v->group ? "tg" : "dst",(unsigned)v->destination);
    describe_options(buf,size,&len,v->options);
    break;
  }
  case DMR_LCB_CAP_PLUS_WIDE_AREA_VOICE: {
    struct dmr_lc_cap_plus_wide_area_voice const *v = &lc->u.wide_area;
    append(buf,size,&len," src=%u tg=%u",(unsigned)v->source,(unsigned)v->group);
    if(v->rest_lsn != 0)
      append(buf,size,&len," rest_lsn=%u",(unsigned)v->rest_lsn);
    describe_options(buf,size,&len,v->options);
    break;
  }
  case DMR_LCB_CAP_PLUS_ENCRYPTED_VOICE: {
    struct dmr_lc_cap_plus_encrypted_voice const *v = &lc->u.cap_plus_encrypted;
    append(buf,size,&len," src=%u tg=%u unk=%02X/%02X",(unsigned)v->source,(unsigned)v->target,
           (unsigned)v->unknown1,(unsigned)v->unknown2);
    describe_options(buf,size,&len,v->options);
    break;
  }
  case DMR_LCB_ENCRYPTION_PARAMETERS: {
    struct dmr_lc_encryption_parameters const *e = &lc->u.encryption;
    append(buf,size,&len," key=%u mi=%08X dst_hi=%04X",(unsigned)e->key_id,(unsigned)e->mi,(unsigned)e->destination_high);
    break;
  }
  case DMR_LCB_HYTERA_VOICE: {
    struct dmr_lc_hytera_voice const *v = &lc->u.hytera_voice;
    append(buf,size,&len," src=%u dst=%u free_rptr=%u pri_rptr=%u pri_hash=%02X",(unsigned)v->source,
           (unsigned)v->target,(unsigned)v->free_repeater,(unsigned)v->priority_repeater,(unsigned)v->priority_hash);
    describe_options(buf,size,&len,v->options);
    break;
  }
  case DMR_LCB_HYTERA_XPT_GRANT: {
    struct dmr_lc_hytera_xpt_grant const *g = &lc->u.xpt_grant;
    append(buf,size,&len," src=%u %s=%u lcn=%u free=%u handshake=%u",(unsigned)g->source,g->group ? "tg" : "unit",
           (unsigned)g->target,(unsigned)g->channel,(unsigned)g->free_repeater,(unsigned)g->handshake);
    break;
  }
  case DMR_LCB_TERMINATOR_DATA: {
    struct dmr_lc_terminator_data const *t = &lc->u.terminator_data;
    append(buf,size,&len," src=%u %s=%u seq=%u%s%s%s",(unsigned)t->source,t->group ? "tg" : "dst",
           (unsigned)t->destination,(unsigned)t->send_sequence,t->response_requested ? " response" : "",
           t->full_message ? " full" : "",t->resync ? " resync" : "");
    break;
  }
  case DMR_LCB_GPS_INFO: {
    struct dmr_lc_gps_info const *g = &lc->u.gps;
    append(buf,size,&len," lat=%.5f lon=%.5f error=%u",g->latitude,g->longitude,(unsigned)g->position_error);
    break;
  }
  case DMR_LCB_TALKER_ALIAS_HEADER:
    append(buf,size,&len," format=%u length=%u",(unsigned)lc->u.alias_header.format,(unsigned)lc->u.alias_header.length);
    break;
  case DMR_LCB_TALKER_ALIAS_BLOCK:
    append(buf,size,&len," block=%u",(unsigned)lc->u.alias_block.block);
    break;
  }
  if(lc->protect)
    append(buf,size,&len," pf");
  return finish(buf,size,len);
}

// ---------------- Data bursts ----------------

char const *dmr_data_type_name(enum dmr_data_type t){
  switch(t){
  case DMR_DT_PI_HEADER: return "PI HEADER";
  case DMR_DT_VOICE_LC_HEADER: return "VOICE LC HEADER";
  case DMR_DT_TERMINATOR_LC: return "TERMINATOR";
  case DMR_DT_CSBK: return "CSBK";
  case DMR_DT_MBC_HEADER: return "MBC HEADER";
  case DMR_DT_MBC_CONTINUATION: return "MBC CONTINUATION";
  case DMR_DT_DATA_HEADER: return "DATA HEADER";
  case DMR_DT_RATE12_DATA: return "RATE 1/2 DATA";
  case DMR_DT_RATE34_DATA: return "RATE 3/4 DATA";
  case DMR_DT_IDLE: return "IDLE";
  case DMR_DT_RATE1_DATA: return "RATE 1 DATA";
  case DMR_DT_USB: return "USBD";
  default: return "RESERVED";
  }
}

bool dmr_is_bptc_data_type(enum dmr_data_type t){
  switch(t){
  case DMR_DT_PI_HEADER:
  case DMR_DT_VOICE_LC_HEADER:
  case DMR_DT_TERMINATOR_LC:
  case DMR_DT_CSBK:
  case DMR_DT_MBC_HEADER:
  case DMR_DT_MBC_CONTINUATION:
  case DMR_DT_DATA_HEADER:
  case DMR_DT_RATE12_DATA:
  case DMR_DT_IDLE:
  case DMR_DT_USB:
    return true;
  default:
    return false;
  }
}

char const *dmr_algorithm_name(uint8_t algorithm_id){
  switch(algorithm_id){
  case DMR_ALG_NONE: return "none";
  case DMR_ALG_HYTERA_BP: return "Hytera BP";
  case DMR_ALG_HYTERA_EP: return "Hytera RC4/EP";
  case DMR_ALG_DMRA_RC4: return "DMRA RC4/EP";
  case DMR_ALG_DMRA_AES128: return "DMRA AES-128";
  case DMR_ALG_DMRA_AES256: return "DMRA AES-256";
  case DMR_ALG_HYTERA_EP2: return "Hytera RC4/EP";
  default: return "unknown";
  }
}

void dmr_pi_header_parse(struct dmr_pi_header *p,uint8_t const info80[80]){
  p->algorithm_octet = (uint8_t)bits_to_uint(info80,8);
  p->algorithm_id = p->algorithm_octet & 0x3f;
  p->fid = (uint8_t)bits_to_uint(info80 + 8,8);
  p->key_id = (uint8_t)bits_to_uint(info80 + 16,8);
  p->mi = bits_to_uint(info80 + 24,32);
  p->destination = bits_to_uint(info80 + 56,24);
}

int dmr_pi_header_describe(char *buf,size_t size,struct dmr_pi_header const *p){
  return snprintf(buf,size,"PI HEADER algorithm=0x%02X (%s) fid=0x%02X key=%u mi=%08X dst=%u",(unsigned)p->algorithm_id,
                  dmr_algorithm_name(p->algorithm_id),(unsigned)p->fid,(unsigned)p->key_id,(unsigned)p->mi,
                  (unsigned)p->destination);
}

// The idle message, built once for all threads
static uint8_t Idle_info[96];
static uint8_t Idle_payload[196];
static pthread_once_t Idle_once = PTHREAD_ONCE_INIT;
static void idle_init(void){
  for(int i=0; i < 96; i++)
    Idle_info[i] = i < 9 ? 1 : (Idle_info[i - 9] ^ Idle_info[i - 5]);
  dmr_bptc196_encode(Idle_info,Idle_payload,NULL);
}
uint8_t const *dmr_idle_info_bits(void){
  pthread_once(&Idle_once,idle_init);
  return Idle_info;
}
uint8_t const *dmr_idle_payload_bits(void){
  pthread_once(&Idle_once,idle_init);
  return Idle_payload;
}

void dmr_data_options_init(struct dmr_data_options *o){
  o->rs_correct = true;
  o->accept_zero_rs_mask = true;
  o->idle_max_bit_errors = 20;
  o->bptc_max_weighted_errors = DMR_BPTC196_MAX_ERRORS;
}

// ---- CRC mask learning (see dmrmsg.h) ----

char const *dmr_crc_check_name(enum dmr_crc_check k){
  switch(k){
  case DMR_CRC_CHECK_CSBK: return "csbk";
  case DMR_CRC_CHECK_RS129: return "lc";
  case DMR_CRC_CHECK_CRC5: return "emblc";
  }
  return "?";
}
void dmr_crc_learner_init(struct dmr_crc_learner *l){
  assert(l != NULL);
  memset(l,0,sizeof *l);
  l->window_us = 120000000;
  l->stale_lookups = 20;
  l->sightings = 2;
}
static void learn_remove(struct dmr_learn_key *k,int i){
  memmove(&k->residuals[i],&k->residuals[i + 1],(size_t)(k->nresiduals - i - 1) * sizeof k->residuals[0]);
  k->nresiduals--;
}
bool dmr_crc_learner_check(struct dmr_crc_learner *l,enum dmr_crc_check kind,uint8_t opcode,uint8_t fid,
                           uint32_t residual,uint64_t now_us){
  if(l == NULL || (int)kind < 0 || kind > DMR_CRC_CHECK_CRC5)
    return false;
  l->lookups[kind]++;
  struct dmr_learn_key *key = NULL;
  for(int i=0; i < l->nkeys && key == NULL; i++)
    if(l->keys[i].kind == kind && l->keys[i].opcode == opcode && l->keys[i].fid == fid)
      key = &l->keys[i];
  if(key == NULL){
    if(l->nkeys >= DMR_LEARN_MAX_KEYS){
      // The key whose newest residual is the oldest goes (one with none first)
      int stalest = 0;
      uint64_t oldest = UINT64_MAX;
      for(int i=0; i < l->nkeys; i++){
        uint64_t newest = 0;
        for(int j=0; j < l->keys[i].nresiduals; j++)
          if(l->keys[i].residuals[j].last_us > newest)
            newest = l->keys[i].residuals[j].last_us;
        if(newest < oldest){
          oldest = newest;
          stalest = i;
        }
      }
      l->evicted += (uint64_t)l->keys[stalest].nresiduals;
      memmove(&l->keys[stalest],&l->keys[stalest + 1],(size_t)(l->nkeys - stalest - 1) * sizeof l->keys[0]);
      l->nkeys--;
    }
    key = &l->keys[l->nkeys++];
    memset(key,0,sizeof *key);
    key->kind = (uint8_t)kind;
    key->opcode = opcode;
    key->fid = fid;
  }
  // Age first: older than the window, or not seen in stale_lookups lookups, is forgotten
  for(int i=0; i < key->nresiduals;){
    struct dmr_learn_residual const *r = &key->residuals[i];
    bool const old = now_us >= r->last_us ? now_us - r->last_us > l->window_us : false;
    if(old || r->staleness >= l->stale_lookups){
      learn_remove(key,i);
      l->evicted++;
    } else
      i++;
  }
  struct dmr_learn_residual *hit = NULL;
  for(int i=0; i < key->nresiduals; i++){
    if(key->residuals[i].value == residual)
      hit = &key->residuals[i];
    else
      key->residuals[i].staleness++;
  }
  if(hit == NULL){
    if(key->nresiduals >= DMR_LEARN_MAX_RESIDUALS){
      int stalest = 0;
      for(int i=1; i < key->nresiduals; i++)
        if(key->residuals[i].staleness > key->residuals[stalest].staleness)
          stalest = i;
      learn_remove(key,stalest);
      l->evicted++;
    }
    struct dmr_learn_residual *r = &key->residuals[key->nresiduals++];
    memset(r,0,sizeof *r);
    r->value = residual;
    r->sightings = 1;
    r->last_us = now_us;
    return false;
  }
  hit->sightings++;
  hit->staleness = 0;
  hit->last_us = now_us;
  if(hit->sightings < l->sightings)
    return false;
  if(hit->accepted++ == 0 && l->learned != NULL)
    l->learned(l->learned_arg,kind,opcode,fid,residual);
  l->accepted[kind]++;
  return true;
}
int dmr_crc_learner_summary(char *buf,size_t size,struct dmr_crc_learner const *l){
  size_t len = 0;
  append(buf,size,&len,"learned: csbk=%llu lc=%llu emblc=%llu",(unsigned long long)l->accepted[0],
         (unsigned long long)l->accepted[1],(unsigned long long)l->accepted[2]);
  int shown = 0;
  for(int i=0; i < l->nkeys && shown < 8; i++){
    struct dmr_learn_key const *k = &l->keys[i];
    for(int j=0; j < k->nresiduals && shown < 8; j++){
      struct dmr_learn_residual const *r = &k->residuals[j];
      if(r->accepted == 0)
        continue;
      shown++;
      append(buf,size,&len," %s %u/0x%02X:0x%0*X x%llu",dmr_crc_check_name((enum dmr_crc_check)k->kind),(unsigned)k->opcode,
             (unsigned)k->fid,k->kind == DMR_CRC_CHECK_RS129 ? 6 : k->kind == DMR_CRC_CHECK_CSBK ? 4 : 2,
             (unsigned)r->value,(unsigned long long)r->accepted);
    }
  }
  return finish(buf,size,len);
}

void dmr_data_decode(struct dmr_data_burst *d,struct dmr_burst const *b,struct dmr_data_options const *options){
  dmr_data_decode_learning(d,b,options,NULL);
}
void dmr_data_decode_learning(struct dmr_data_burst *d,struct dmr_burst const *b,struct dmr_data_options const *options,
                              struct dmr_crc_learner *learner){
  assert(d != NULL && b != NULL);
  struct dmr_data_options defaults;
  if(options == NULL){
    dmr_data_options_init(&defaults);
    options = &defaults;
  }
  memset(d,0,sizeof *d);
  d->data_type = b->data_type;
  d->color_code = b->color_code;
  d->status = DMR_DATA_REFUSED;
  d->idle_bit_errors = -1;
  dmr_bptc196_from_burst(b->bits,b->confidence,d->payload,d->payload_confidence);
  if(b->kind != DMR_KIND_DATA || !b->slot_type_valid)
    return;
  if(!dmr_is_bptc_data_type(d->data_type)){
    d->status = DMR_DATA_NOT_BPTC;
    return;
  }

  struct dmr_bptc r;
  uint8_t info[96];
  dmr_bptc196_decode(&r,info,d->reserved,d->payload,d->payload_confidence,options->bptc_max_weighted_errors);
  d->bptc_ok = r.ok;
  d->bptc_corrected = r.corrected;
  d->bptc_weighted_errors = r.weighted_errors;
  d->bptc_margin = r.margin;
  memcpy(d->info,info,sizeof d->info);

  if(d->data_type == DMR_DT_IDLE){
    uint8_t const *idle = dmr_idle_payload_bits();
    int differ = 0;
    for(int i=1; i < 196; i++) // bit 0 is R(3), outside the code and the sender's to set
      differ += (d->payload[i] ^ idle[i]) & 1;
    d->idle_bit_errors = differ;
    if(differ <= options->idle_max_bit_errors)
      d->status = DMR_DATA_VALID;
    else
      d->status = r.ok ? DMR_DATA_CHECK_FAILED : DMR_DATA_REFUSED;
    return;
  }
  if(!r.ok)
    return;

  switch(d->data_type){
  case DMR_DT_VOICE_LC_HEADER:
  case DMR_DT_TERMINATOR_LC: {
    uint8_t const mask = d->data_type == DMR_DT_VOICE_LC_HEADER ? DMR_RS_MASK_VOICE_LC_HEADER : DMR_RS_MASK_TERMINATOR;
    uint8_t octets[12];
    bits_to_bytes(info,12,octets);
    d->rs_observed_mask = dmr_rs129_observed_mask(octets);
    uint8_t bits[96];
    memcpy(bits,info,sizeof bits);
    int rs = dmr_rs129_decode_bits(bits,mask,options->rs_correct,NULL,NULL);
    d->rs_mask = mask;
    if(rs < 0 && options->accept_zero_rs_mask){
      memcpy(bits,info,sizeof bits);
      rs = dmr_rs129_decode_bits(bits,0x00,false,NULL,NULL);
      d->rs_mask = 0x00;
    }
    if(rs < 0 && learner != NULL){
      uint8_t const flco = (uint8_t)bits_to_uint(info + 2,6);
      uint8_t const fid = (uint8_t)bits_to_uint(info + 8,8);
      if(dmr_crc_learner_check(learner,DMR_CRC_CHECK_RS129,flco,fid,d->rs_observed_mask,b->timestamp_us)){
        // Accepted as received, uncorrected, and never the stricter test for "clear"
        d->rs_mask = 0;
        d->rs_corrected = 0;
        d->lc_uncorrected = false;
        d->learned_mask = true;
        dmr_lc_parse_bits(&d->lc,info);
        d->has_lc = true;
        d->status = DMR_DATA_VALID;
        return;
      }
    }
    if(rs < 0){
      d->rs_mask = 0;
      d->status = DMR_DATA_CHECK_FAILED;
      return;
    }
    memcpy(d->info,bits,sizeof d->info);
    d->rs_corrected = rs;
    d->lc_uncorrected = rs == 0;
    dmr_lc_parse_bits(&d->lc,bits);
    d->has_lc = true;
    d->status = DMR_DATA_VALID;
    return;
  }
  case DMR_DT_PI_HEADER:
    if(!dmr_crc_ccitt_check(info,96,DMR_CRC_MASK_PI_HEADER)){
      d->status = DMR_DATA_CHECK_FAILED;
      return;
    }
    dmr_pi_header_parse(&d->pi,info);
    d->has_pi = true;
    d->status = DMR_DATA_VALID;
    return;
  default:
    d->status = DMR_DATA_UNCHECKED;
    return;
  }
}

int dmr_data_describe(char *buf,size_t size,struct dmr_data_burst const *d){
  size_t len = 0;
  char const *name = dmr_data_type_name(d->data_type);
  switch(d->status){
  case DMR_DATA_REFUSED:
    return snprintf(buf,size,"%s (not decoded)",name);
  case DMR_DATA_NOT_BPTC:
    return snprintf(buf,size,"%s",name);
  case DMR_DATA_CHECK_FAILED:
    return snprintf(buf,size,"%s (check failed)",name);
  case DMR_DATA_UNCHECKED: {
    uint8_t octets[12];
    bits_to_bytes(d->info,12,octets);
    append(buf,size,&len,"%s info=",name);
    hex_octets(buf,size,&len,octets,12);
    return finish(buf,size,len);
  }
  case DMR_DATA_VALID:
    break;
  }
  if(d->has_pi)
    return dmr_pi_header_describe(buf,size,&d->pi);
  if(d->has_lc){
    char lc[DMR_DESCRIBE_MAX];
    dmr_lc_describe(lc,sizeof lc,&d->lc);
    append(buf,size,&len,"%s: %s",name,lc);
    if(d->rs_corrected > 0)
      append(buf,size,&len," (rs corrected)");
    if(d->learned_mask)
      append(buf,size,&len," (learned rs mask %06X)",(unsigned)d->rs_observed_mask);
    else if(d->rs_mask == 0x00)
      append(buf,size,&len," (zero rs mask)");
    return finish(buf,size,len);
  }
  return snprintf(buf,size,"%s",name);
}

// ---------------- Voice frames ----------------

void dmr_voice_frame_decode(struct dmr_voice_frame *f){
  uint8_t raw[P25P2_AMBE_BITS];
  for(int n=0; n < DMR_VOICE_FRAME_BITS; n++)
    raw[n] = (f->bytes[n / 8] >> (7 - n % 8)) & 1;
  struct p25p2_ambe a;
  p25p2_ambe_decode(&a,raw);
  f->errors_c0 = a.errors[0];
  f->errors_c1 = a.errors[1];
  f->fec_errors = a.errors[0] + a.errors[1];
  memcpy(f->info,a.bits,sizeof f->info);
  f->data_errors[0] = a.data_errors[0];
  f->data_errors[1] = a.data_errors[1];
}

void dmr_voice_extract(struct dmr_voice_burst *v,struct dmr_burst const *b){
  assert(v != NULL && b != NULL);
  memset(v,0,sizeof *v);
  for(int f=0; f < DMR_VOICE_FRAMES; f++){
    struct dmr_voice_frame *frame = &v->frames[f];
    for(int n=0; n < DMR_VOICE_FRAME_BITS; n++){
      if(b->bits[dmr_voice_bit_position(f,n)] & 1)
        frame->bytes[n / 8] |= (uint8_t)(0x80u >> (n % 8));
    }
    dmr_voice_frame_decode(frame);
  }
}

// ---------------- Embedded LC ----------------

enum { ELC_CLOCK_TOLERANCE = 24 }; // dibits of slack on the 288 between bursts

static void elc_clear(struct dmr_elc_assembler *a){
  a->active = false;
  a->count = 0;
  a->inferred = 0;
  memset(a->present,0,sizeof a->present);
}
static void elc_abandon(struct dmr_elc_assembler *a){
  if(a->active)
    a->abandoned++;
  elc_clear(a);
}
static void elc_store(struct dmr_elc_assembler *a,struct dmr_burst const *b,int place,bool inferred){
  a->timestamp_us = b->timestamp_us;
  dmr_embedded_from_burst(b->bits,b->confidence,a->bits + 32 * place,a->confidence + 32 * place);
  if(!a->present[place])
    a->count++;
  a->present[place] = true;
  if(inferred)
    a->inferred++;
}
// Decode once all four fragments are held
static void elc_finish(struct dmr_elc_assembler *a,struct dmr_elc_result *r){
  if(!(a->present[0] && a->present[1] && a->present[2] && a->present[3]))
    return;
  struct dmr_bptc result;
  uint8_t info[77];
  bool const ok = dmr_bptc128_decode(&result,info,a->bits,a->confidence,DMR_BPTC128_MAX_ERRORS);
  bool const checksum_ok = ok && dmr_elc_checksum_check(info);
  uint8_t const residual = (uint8_t)(dmr_elc_checksum(info) ^ bits_to_uint(info + 72,5));
  // A learned residual only for a word that arrived as a codeword (dmrmsg.h, CRC5)
  bool const learned = !checksum_ok && ok && result.corrected == 0 && a->learner != NULL
    && dmr_crc_learner_check(a->learner,DMR_CRC_CHECK_CRC5,(uint8_t)bits_to_uint(info + 2,6),(uint8_t)bits_to_uint(info + 8,8),
                             residual,a->timestamp_us);
  if(checksum_ok || learned){
    r->lc.learned_mask = learned;
    r->lc.checksum_residual = learned ? residual : 0;
    dmr_lc_parse_bits(&r->lc.lc,info);
    r->lc.corrected = result.corrected;
    r->lc.weighted_errors = result.weighted_errors;
    r->lc.inferred_fragments = a->inferred;
    r->has_lc = true;
    a->decoded++;
  } else {
    r->failed = true;
    a->failed++;
  }
  elc_clear(a);
}

void dmr_elc_init(struct dmr_elc_assembler *a){
  memset(a,0,sizeof *a);
}
void dmr_elc_reset(struct dmr_elc_assembler *a){
  elc_abandon(a);
  a->first_clock = 0;
}

void dmr_elc_on_voice_burst(struct dmr_elc_assembler *a,struct dmr_elc_result *r,struct dmr_burst const *b){
  assert(a != NULL && r != NULL && b != NULL);
  memset(r,0,sizeof *r);
  r->fragment = -1;
  if(b->kind == DMR_KIND_VOICE_A){ // the sync is where the embedded field would be
    elc_abandon(a);
    return;
  }
  // Where the burst is, counted from the first fragment: by the clock when there is one
  bool const timed = a->active && a->first_clock != 0 && b->dibit_clock != 0;
  int place = -1;
  if(timed){
    int64_t const delta = (int64_t)b->dibit_clock - (int64_t)a->first_clock;
    int64_t const n = delta >= 0 ? (delta + DMR_SLOT_BURST_SPACING_DIBITS / 2) / DMR_SLOT_BURST_SPACING_DIBITS : -1;
    int64_t const residue = delta - n * DMR_SLOT_BURST_SPACING_DIBITS;
    if(n > 3)
      elc_abandon(a); // the superframe is over
    else if(n >= 0 && residue >= -ELC_CLOCK_TOLERANCE && residue <= ELC_CLOCK_TOLERANCE)
      place = (int)n;
  } else if(a->active){
    place = a->count;
  }

  if(!b->emb_valid){
    // No LCSS. With a clock the fragment goes where the timing puts it; without, where the sink's
    // burst letter does, if that is the next place
    if(!a->active)
      return;
    if(!timed){
      int const by_letter = (int)b->kind - (int)DMR_KIND_VOICE_B;
      if(by_letter != place)
        place = -1;
    }
    if(place < 1 || place > 3 || a->present[place]){
      if(!timed)
        elc_abandon(a);
      return;
    }
    elc_store(a,b,place,true);
    r->fragment = place;
    elc_finish(a,r);
    return;
  }

  // PI = 1: the field carries reverse channel information for the other logical channel (TS 102 361-1
  // 9.3.2), not a fragment of this channel's LC; the LC being assembled cannot be completed
  if(b->emb_pi){
    elc_abandon(a);
    return;
  }
  switch(b->emb_lcss){
  case DMR_LCSS_FIRST:
    elc_abandon(a);
    a->active = true;
    a->first_clock = b->dibit_clock;
    elc_store(a,b,0,false);
    r->fragment = 0;
    break;
  case DMR_LCSS_CONTINUATION:
    if(!a->active)
      break;
    if(place != 1 && place != 2){
      elc_abandon(a);
      break;
    }
    elc_store(a,b,place,false);
    r->fragment = place;
    elc_finish(a,r);
    break;
  case DMR_LCSS_LAST:
    if(!a->active)
      break;
    if(place != 3){
      elc_abandon(a);
      break;
    }
    elc_store(a,b,3,false);
    r->fragment = 3;
    elc_finish(a,r);
    if(a->active && !timed)
      elc_abandon(a); // in arrival order nothing more can come
    break;
  case DMR_LCSS_SINGLE:
    elc_abandon(a); // burst F: not part of an LC
    break;
  }
}

// ---------------- Burst F ----------------

bool dmr_short_burst_crc3_ok(uint32_t info11){
  uint8_t bits[11];
  uint_to_bits(info11,11,bits);
  return crc_bits(bits,8,3,0x3,0) == bits_to_uint(bits + 8,3);
}

void dmr_single_burst_parse(struct dmr_single_burst *s,uint32_t info11,bool reverse_channel_form){
  memset(s,0,sizeof *s);
  s->kind = DMR_SB_UNKNOWN;
  s->info = (uint16_t)(info11 & 0x7ff);
  s->reverse_channel_form = reverse_channel_form;
  if(reverse_channel_form){
    uint8_t bits[11];
    uint_to_bits(s->info,11,bits);
    s->kind = DMR_SB_REVERSE_CHANNEL;
    s->reverse_channel = (uint8_t)(s->info >> 7);
    s->rc_crc_residue = (uint8_t)(dmr_crc7(bits,4,DMR_CRC7_MASK_REVERSE_CHANNEL) ^ (s->info & 0x7f));
    return;
  }
  uint32_t const opcode = s->info & 7u;
  switch(opcode){
  case 0:
    s->kind = dmr_short_burst_crc3_ok(s->info) ? DMR_SB_NULL : DMR_SB_UNKNOWN;
    break;
  case 1:
  case 4:
  case 5:
    s->kind = DMR_SB_ENCRYPTION_PARAMETERS;
    s->key_id = (uint8_t)(s->info >> 3);
    s->algorithm = (uint8_t)opcode;
    s->algorithm_id = opcode == 1 ? DMR_ALG_DMRA_RC4 : opcode == 4 ? DMR_ALG_DMRA_AES128 : DMR_ALG_DMRA_AES256;
    break;
  case 3:
    if(dmr_short_burst_crc3_ok(s->info)){
      s->kind = DMR_SB_TXI_DELAY;
      s->txi_delay = (uint8_t)((s->info >> 3) & 0x1f);
    }
    break;
  default:
    break;
  }
}

bool dmr_single_burst_decode_burst(struct dmr_single_burst *s,struct dmr_burst const *b,float max_corrected,
                                   bool reverse_channel,bool *other_form){
  uint8_t bits[32];
  float confidence[32];
  dmr_embedded_from_burst(b->bits,b->confidence,bits,confidence);
  if(other_form != NULL)
    *other_form = dmr_single_burst_decode(bits,confidence,!reverse_channel,max_corrected).valid;
  struct dmr_soft const d = dmr_single_burst_decode(bits,confidence,reverse_channel,max_corrected);
  if(!d.valid)
    return false;
  dmr_single_burst_parse(s,d.data,reverse_channel);
  s->corrected = d.errors;
  return true;
}

int dmr_single_burst_describe(char *buf,size_t size,struct dmr_single_burst const *s){
  switch(s->kind){
  case DMR_SB_NULL:
    return snprintf(buf,size,"EMB NULL");
  case DMR_SB_ENCRYPTION_PARAMETERS:
    return snprintf(buf,size,"EMB ENCRYPTION key=%u algorithm=%s",(unsigned)s->key_id,dmr_algorithm_name(s->algorithm_id));
  case DMR_SB_TXI_DELAY:
    return snprintf(buf,size,"EMB TXI delay=%u",(unsigned)s->txi_delay);
  case DMR_SB_REVERSE_CHANNEL:
    return snprintf(buf,size,"EMB REVERSE CHANNEL rc=%u",(unsigned)s->reverse_channel);
  case DMR_SB_UNKNOWN:
    break;
  }
  return snprintf(buf,size,"EMB UNKNOWN info=%03X",(unsigned)s->info);
}

// ---------------- Hidden IV ----------------

int dmr_hidden_iv_describe(char *buf,size_t size,struct dmr_hidden_iv const *iv){
  return snprintf(buf,size,"VOICE IV %08X golay_errors=%d",(unsigned)iv->iv,iv->golay_errors);
}

uint8_t dmr_hidden_iv_crc4(uint32_t iv){
  uint8_t bits[32];
  uint_to_bits(iv,32,bits);
  return (uint8_t)((crc_bits(bits,32,4,0x3,0) ^ 0xfu) & 0xfu);
}

void dmr_hidden_iv_nibbles(uint8_t nibbles[3],struct dmr_burst const *b){
  for(int f=0; f < 3; f++){
    uint8_t v = 0;
    for(int bit=71; bit >= 59; bit -= 4)
      v = (uint8_t)((v << 1) | (b->bits[dmr_voice_bit_position(f,bit)] & 1));
    nibbles[f] = v;
  }
}

bool dmr_hidden_iv_decode(struct dmr_hidden_iv *iv,uint8_t const nibbles[6][3]){
  uint32_t data[3];
  int errors = 0;
  for(int w=0; w < 3; w++){
    uint32_t word = 0;
    for(int b=0; b < 6; b++)
      word = (word << 4) | (nibbles[b][w] & 0xfu);
    // Bits 23-1 of word are the Golay(23,12) codeword (data first), bit 0 the overall parity
    uint8_t code[23];
    for(int i=0; i < 23; i++)
      code[i] = (word >> (23 - i)) & 1;
    int e = golay23_decode(code,NULL);
    int ones = (int)(word & 1);
    for(int i=0; i < 23; i++)
      ones += code[i];
    if(ones & 1)
      e++; // one more error (perhaps the parity bit)
    if(e > 3)
      return false;
    errors += e;
    data[w] = 0;
    for(int i=0; i < 12; i++)
      data[w] = (data[w] << 1) | code[i];
  }
  uint32_t const v = (data[0] << 20) | (data[1] << 8) | (data[2] >> 4);
  if(dmr_hidden_iv_crc4(v) != (data[2] & 0xfu))
    return false;
  iv->iv = v;
  iv->golay_errors = errors;
  return true;
}

void dmr_hidden_iv_reset(struct dmr_hidden_iv_collector *c){
  c->present = 0;
  c->first_clock = 0;
}

bool dmr_hidden_iv_on_voice_burst(struct dmr_hidden_iv_collector *c,struct dmr_hidden_iv *iv,
                                  struct dmr_burst const *b,int position){
  if(position < 0 || position > 5){
    dmr_hidden_iv_reset(c);
    return false;
  }
  if(position == 0){
    dmr_hidden_iv_reset(c);
    c->first_clock = b->dibit_clock;
  } else if(c->first_clock != 0 && b->dibit_clock != 0){
    int64_t const expected = (int64_t)c->first_clock + position * DMR_SLOT_BURST_SPACING_DIBITS;
    int64_t const delta = (int64_t)b->dibit_clock - expected;
    if(delta < -24 || delta > 24){
      dmr_hidden_iv_reset(c); // not the superframe burst A began
      return false;
    }
  }
  dmr_hidden_iv_nibbles(c->nibbles[position],b);
  c->present |= 1u << position;
  if(position != 5)
    return false;
  bool const complete = c->present == 0x3fu;
  dmr_hidden_iv_reset(c);
  return complete && dmr_hidden_iv_decode(iv,(uint8_t const (*)[3])c->nibbles);
}

// ---------------- Short LC ----------------

char const *dmr_slc_kind_name(enum dmr_slc_kind k){
  switch(k){
  case DMR_SLC_NULL: return "NULL";
  case DMR_SLC_ACTIVITY_UPDATE: return "ACTIVITY UPDATE";
  case DMR_SLC_CONTROL_CHANNEL_SYS_PARMS: return "TIER III CONTROL CHANNEL";
  case DMR_SLC_TRAFFIC_CHANNEL_SYS_PARMS: return "TIER III TRAFFIC CHANNEL";
  case DMR_SLC_HYTERA_XPT_CHANNEL: return "HYTERA XPT CHANNEL";
  case DMR_SLC_CONNECT_PLUS_TRAFFIC: return "CONNECT PLUS TRAFFIC CHANNEL";
  case DMR_SLC_CONNECT_PLUS_CONTROL: return "CONNECT PLUS CONTROL CHANNEL";
  case DMR_SLC_CAP_PLUS_REST_CHANNEL: return "CAP+ REST CHANNEL";
  case DMR_SLC_UNKNOWN: return "UNKNOWN";
  }
  return "?";
}

char const *dmr_slot_activity_name(uint8_t activity){
  switch(activity){
  case 0: return "idle";
  case 2: return "group-csbk";
  case 3: return "indiv-csbk";
  case 8: return "group-voice";
  case 9: return "indiv-voice";
  case 10: return "indiv-data";
  case 11: return "group-data";
  case 12: return "emerg-group-voice";
  case 13: return "emerg-indiv-voice";
  default: return "reserved";
  }
}

void dmr_slc_parse(struct dmr_short_lc *s,uint8_t const bits28[28]){
  memset(s,0,sizeof *s);
  s->slco = (uint8_t)bits_to_uint(bits28,4);
  s->data = bits_to_uint(bits28 + 4,24);
  s->kind = DMR_SLC_UNKNOWN;
  s->body = DMR_SLCB_UNKNOWN;
#define FIELD(first,count) bits_to_uint(bits28 + (first),(count))
  switch(s->slco){
  case 0:
    s->kind = DMR_SLC_NULL;
    s->body = DMR_SLCB_NULL;
    break;
  case 1:
    s->u.activity.ts1_activity = (uint8_t)FIELD(4,4);
    s->u.activity.ts2_activity = (uint8_t)FIELD(8,4);
    s->u.activity.ts1_hash = (uint8_t)FIELD(12,8);
    s->u.activity.ts2_hash = (uint8_t)FIELD(20,8);
    s->kind = DMR_SLC_ACTIVITY_UPDATE;
    s->body = DMR_SLCB_ACTIVITY_UPDATE;
    break;
  case 2:
  case 3: {
    static int const Network_bits[4] = { 9, 7, 4, 2 };
    struct dmr_slc_sys_parms *p = &s->u.sys_parms;
    p->system_identity_code = (uint16_t)FIELD(4,14);
    p->model = (enum dmr_network_model)FIELD(4,2);
    int const net_bits = Network_bits[p->model];
    p->network = (uint16_t)FIELD(6,net_bits);
    p->site = (uint16_t)FIELD(6 + net_bits,12 - net_bits);
    if(s->slco == 2)
      p->registration_required = FIELD(18,1) != 0;
    else
      p->composite_control_channel = FIELD(18,1) != 0;
    p->common_slot_counter = (uint16_t)FIELD(19,9);
    s->kind = s->slco == 2 ? DMR_SLC_CONTROL_CHANNEL_SYS_PARMS : DMR_SLC_TRAFFIC_CHANNEL_SYS_PARMS;
    s->body = DMR_SLCB_SYS_PARMS;
    break;
  }
  case 8:
    s->u.xpt.fid = (uint8_t)FIELD(4,8);
    s->u.xpt.free_repeater = (uint8_t)FIELD(12,4);
    s->u.xpt.priority_repeater = (uint8_t)FIELD(16,4);
    s->u.xpt.priority_hash = (uint8_t)FIELD(20,8);
    s->kind = DMR_SLC_HYTERA_XPT_CHANNEL;
    s->body = DMR_SLCB_HYTERA_XPT_CHANNEL;
    break;
  case 9:
  case 10:
    s->u.connect_plus.network = (uint16_t)FIELD(4,12);
    s->u.connect_plus.site = (uint8_t)FIELD(16,8);
    s->kind = s->slco == 9 ? DMR_SLC_CONNECT_PLUS_TRAFFIC : DMR_SLC_CONNECT_PLUS_CONTROL;
    s->body = DMR_SLCB_CONNECT_PLUS;
    break;
  case 15:
    if(FIELD(4,8) == DMR_FID_MOTOROLA){
      s->u.rest.unknown1 = (uint8_t)FIELD(12,3);
      s->u.rest.rest_lsn = (uint8_t)FIELD(15,5);
      s->u.rest.site = (uint8_t)FIELD(20,5);
      s->u.rest.unknown2 = (uint8_t)FIELD(25,3);
      s->kind = DMR_SLC_CAP_PLUS_REST_CHANNEL;
      s->body = DMR_SLCB_CAP_PLUS_REST_CHANNEL;
    }
    break;
  default:
    break;
  }
#undef FIELD
}

int dmr_slc_describe(char *buf,size_t size,struct dmr_short_lc const *s){
  size_t len = 0;
  append(buf,size,&len,"SLC %s",dmr_slc_kind_name(s->kind));
  switch(s->body){
  case DMR_SLCB_UNKNOWN:
    append(buf,size,&len," slco=%u data=%06X",(unsigned)s->slco,(unsigned)s->data);
    break;
  case DMR_SLCB_NULL:
    break;
  case DMR_SLCB_ACTIVITY_UPDATE: {
    struct dmr_slc_activity_update const *a = &s->u.activity;
    append(buf,size,&len," ts1=%s hash=%02X ts2=%s hash=%02X",dmr_slot_activity_name(a->ts1_activity),
           (unsigned)a->ts1_hash,dmr_slot_activity_name(a->ts2_activity),(unsigned)a->ts2_hash);
    break;
  }
  case DMR_SLCB_SYS_PARMS: {
    static char const *Model[4] = { "tiny", "small", "large", "huge" };
    struct dmr_slc_sys_parms const *p = &s->u.sys_parms;
    append(buf,size,&len," model=%s net=%u site=%u%s%s slot_counter=%u",Model[p->model & 3],(unsigned)p->network,
           (unsigned)p->site,p->registration_required ? " registration" : "",
           p->composite_control_channel ? " composite-cc" : "",(unsigned)p->common_slot_counter);
    break;
  }
  case DMR_SLCB_CONNECT_PLUS:
    append(buf,size,&len," net=%u site=%u",(unsigned)s->u.connect_plus.network,(unsigned)s->u.connect_plus.site);
    break;
  case DMR_SLCB_CAP_PLUS_REST_CHANNEL:
    append(buf,size,&len," rest_lsn=%u site=%u",(unsigned)s->u.rest.rest_lsn,(unsigned)s->u.rest.site);
    break;
  case DMR_SLCB_HYTERA_XPT_CHANNEL:
    append(buf,size,&len," free_rptr=%u pri_rptr=%u pri_hash=%02X",(unsigned)s->u.xpt.free_repeater,
           (unsigned)s->u.xpt.priority_repeater,(unsigned)s->u.xpt.priority_hash);
    break;
  }
  return finish(buf,size,len);
}

enum { SLC_CLOCK_TOLERANCE = 24 }; // dibits of slack on the 144 between CACHs

void dmr_slc_assembler_init(struct dmr_slc_assembler *a){
  memset(a,0,sizeof *a);
}
void dmr_slc_assembler_reset(struct dmr_slc_assembler *a){
  if(a->count > 0)
    a->abandoned++;
  a->count = 0;
  a->last_clock = 0;
}

bool dmr_slc_on_burst(struct dmr_slc_assembler *a,struct dmr_short_lc *s,struct dmr_burst const *b){
  if(!b->has_cach){
    dmr_slc_assembler_reset(a);
    return false;
  }
  // Consecutive CACHs are 144 dibits apart; a larger step means a burst was lost between them
  if(a->count > 0 && b->dibit_clock != 0 && a->last_clock != 0){
    uint64_t const step = b->dibit_clock - a->last_clock;
    if(b->dibit_clock <= a->last_clock || step > (uint64_t)DMR_SLOT_DIBITS + SLC_CLOCK_TOLERANCE
       || step + SLC_CLOCK_TOLERANCE < (uint64_t)DMR_SLOT_DIBITS){
      if(a->count > 0)
        a->abandoned++;
      a->count = 0;
    }
  }
  a->last_clock = b->dibit_clock;

  bool take = false;
  if(!b->tact_valid){
    take = a->count > 0; // flywheel: the next fragment of the message in progress
  } else {
    switch(b->tact_lcss){
    case DMR_LCSS_FIRST:
      if(a->count > 0)
        a->abandoned++;
      a->count = 0;
      take = true;
      break;
    case DMR_LCSS_CONTINUATION:
      take = a->count == 1 || a->count == 2;
      break;
    case DMR_LCSS_LAST:
      take = a->count == 3;
      break;
    case DMR_LCSS_SINGLE:
      break; // not used for the Short LC
    }
  }
  if(!take){
    if(a->count > 0)
      a->abandoned++;
    a->count = 0;
    return false;
  }
  dmr_cach_split(b->cach,b->cach_confidence,NULL,NULL,a->bits + 17 * a->count,a->confidence + 17 * a->count);
  if(++a->count < 4)
    return false;
  a->count = 0;

  struct dmr_bptc r;
  uint8_t info[36];
  bool const ok = dmr_bptc68_decode(&r,info,a->bits,a->confidence,DMR_BPTC68_MAX_ERRORS);
  if(!ok || !dmr_slc_crc_check(info)){
    a->failed++;
    return false;
  }
  dmr_slc_parse(s,info);
  s->corrected = r.corrected;
  a->decoded++;
  return true;
}

// ---------------- Talker alias ----------------

int dmr_talker_alias_describe(char *buf,size_t size,struct dmr_talker_alias const *a){
  return snprintf(buf,size,"TALKER ALIAS \"%s\"",a->text);
}

// A code point into the text, as UTF-8; a control character becomes a space. Text that would not
// fit (it always does: see DMR_TALKER_ALIAS_TEXT) is dropped
static void ta_emit(char *text,size_t *len,uint32_t cp){
  if(cp < 0x20u || (cp >= 0x7fu && cp <= 0x9fu))
    cp = 0x20u;
  uint8_t out[4];
  size_t n;
  if(cp < 0x80u){
    out[0] = (uint8_t)cp;
    n = 1;
  } else if(cp < 0x800u){
    out[0] = (uint8_t)(0xc0u | (cp >> 6));
    out[1] = (uint8_t)(0x80u | (cp & 0x3fu));
    n = 2;
  } else if(cp < 0x10000u){
    out[0] = (uint8_t)(0xe0u | (cp >> 12));
    out[1] = (uint8_t)(0x80u | ((cp >> 6) & 0x3fu));
    out[2] = (uint8_t)(0x80u | (cp & 0x3fu));
    n = 3;
  } else {
    out[0] = (uint8_t)(0xf0u | (cp >> 18));
    out[1] = (uint8_t)(0x80u | ((cp >> 12) & 0x3fu));
    out[2] = (uint8_t)(0x80u | ((cp >> 6) & 0x3fu));
    out[3] = (uint8_t)(0x80u | (cp & 0x3fu));
    n = 4;
  }
  if(*len + n >= DMR_TALKER_ALIAS_TEXT)
    return;
  memcpy(text + *len,out,n);
  *len += n;
}

// UTF-8 octets to code points, at most max_cp of them: U+FFFD for each octet that does not start a
// well-formed sequence (overlong forms, surrogates and values past U+10FFFF included). A NUL octet is
// padding and ends the text (*nul); a sequence cut off by the end of the octets is dropped
// (*incomplete), since its other octets are in a block not yet received. Returns the code points
static int ta_decode_utf8(char *text,size_t *len,uint8_t const *s,int n,int max_cp,bool *nul,bool *incomplete){
  int i = 0,cps = 0;
  *nul = *incomplete = false;
  while(i < n && cps < max_cp){
    uint8_t const c = s[i];
    if(c == 0){
      *nul = true;
      break;
    }
    cps++;
    int extra;
    uint32_t cp,minimum;
    if(c < 0x80u){
      ta_emit(text,len,c);
      i++;
      continue;
    }
    if((c & 0xe0u) == 0xc0u){
      extra = 1; cp = c & 0x1fu; minimum = 0x80u;
    } else if((c & 0xf0u) == 0xe0u){
      extra = 2; cp = c & 0x0fu; minimum = 0x800u;
    } else if((c & 0xf8u) == 0xf0u){
      extra = 3; cp = c & 0x07u; minimum = 0x10000u;
    } else {
      ta_emit(text,len,0xfffdu);
      i++;
      continue;
    }
    if(i + extra > n - 1){ // the rest of the sequence is not here
      cps--;
      *incomplete = true;
      break;
    }
    bool ok = true;
    for(int k=1; ok && k <= extra; k++){
      if((s[i + k] & 0xc0u) != 0x80u)
        ok = false;
      else
        cp = (cp << 6) | (s[i + k] & 0x3fu);
    }
    if(!ok || cp < minimum || cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)){
      ta_emit(text,len,0xfffdu);
      i++;
      continue;
    }
    ta_emit(text,len,cp);
    i += extra + 1;
  }
  return cps;
}

void dmr_ta_reset(struct dmr_ta_assembler *a){
  a->have_header = false;
  memset(a->have_block,0,sizeof a->have_block);
  a->reported[0] = '\0';
  a->have_reported = false;
}

// Unit `index` of the alias: unit_bits bits from bit offset + index * unit_bits
static uint32_t ta_unit(uint8_t const bits[217],int offset,int unit_bits,int index){
  uint32_t v = 0;
  for(int i=0; i < unit_bits; i++)
    v = (v << 1) | bits[offset + index * unit_bits + i];
  return v;
}

static bool ta_assemble(struct dmr_ta_assembler *a,struct dmr_talker_alias *alias){
  if(!a->have_header)
    return false;
  bool const seven_bit = a->header.format == DMR_TA_7BIT;
  bool const wide = a->header.format == DMR_TA_UTF16BE;
  int const unit_bits = seven_bit ? 7 : wide ? 16 : 8;
  int const offset = seven_bit ? 0 : 1;
  int const max_units = (217 - offset) / unit_bits; // 31, 27, 13
  int units = a->header.length < max_units ? a->header.length : max_units;
  int blocks_needed = 0;
  bool const utf8 = a->header.format == DMR_TA_UTF8;
  if(utf8){
    // Motorola's length counts characters, which in UTF-8 may take two or more octets each (sdrtrunk
    // 9359f523, GPL-3, Dennis Sheirer, issue #2421: Cyrillic aliases cut short), so every octet of the
    // blocks received in order is decoded and the text cut at the length in characters, below
    while(blocks_needed < 3 && a->have_block[blocks_needed])
      blocks_needed++;
    units = (49 + 56 * blocks_needed - offset) / 8; // 6, 13, 20, 27
  } else {
    int const total_bits = offset + units * unit_bits;
    blocks_needed = total_bits <= 49 ? 0 : (total_bits - 49 + 55) / 56;
    for(int b=0; b < blocks_needed; b++){
      if(!a->have_block[b])
        return false;
    }
  }
  uint8_t bits[217] = {0};
  for(int i=0; i < 49; i++)
    bits[i] = a->header.data[i] & 1;
  for(int b=0; b < blocks_needed; b++){
    for(int i=0; i < 56; i++)
      bits[49 + 56 * b + i] = a->blocks[b][i] & 1;
  }
#define UNIT(index) ta_unit(bits,offset,unit_bits,(index))
  char text[DMR_TALKER_ALIAS_TEXT];
  size_t len = 0;
  switch(a->header.format){
  case DMR_TA_7BIT:
  case DMR_TA_ISO8859_1:
    for(int i=0; i < units; i++)
      ta_emit(text,&len,UNIT(i));
    break;
  case DMR_TA_UTF8: {
    uint8_t octets[27];
    for(int i=0; i < units; i++)
      octets[i] = (uint8_t)UNIT(i);
    bool nul,incomplete;
    int const cps = ta_decode_utf8(text,&len,octets,units,a->header.length,&nul,&incomplete);
    // Whole when the length is reached, padding is seen, every block has come, or the length read as
    // octets is covered with no character cut off (a radio that counts octets sends no more blocks)
    if(!(cps >= a->header.length || nul || blocks_needed == 3 || (units >= a->header.length && !incomplete)))
      return false;
    break;
  }
  case DMR_TA_UTF16BE:
    for(int i=0; i < units; i++){
      uint32_t const u = UNIT(i);
      if(u >= 0xd800u && u <= 0xdbffu && i + 1 < units){
        uint32_t const low = UNIT(i + 1);
        if(low >= 0xdc00u && low <= 0xdfffu){
          ta_emit(text,&len,0x10000u + ((u - 0xd800u) << 10) + (low - 0xdc00u));
          i++;
          continue;
        }
      }
      ta_emit(text,&len,(u >= 0xd800u && u <= 0xdfffu) ? 0xfffdu : u);
    }
    break;
  }
#undef UNIT
  while(len > 0 && text[len - 1] == ' ')
    len--;
  text[len] = '\0';
  if(len == 0)
    return false; // length 0 or all padding: no alias
  if(a->have_reported && strcmp(text,a->reported) == 0)
    return false;
  memcpy(a->reported,text,len + 1);
  a->have_reported = true;

  memcpy(alias->text,text,len + 1);
  alias->format = a->header.format;
  alias->length = a->header.length;
  alias->blocks = (uint8_t)blocks_needed;
  return true;
}

bool dmr_ta_on_lc(struct dmr_ta_assembler *a,struct dmr_talker_alias *alias,struct dmr_lc const *lc){
  if(lc->body == DMR_LCB_TALKER_ALIAS_HEADER){
    struct dmr_lc_talker_alias_header const *h = &lc->u.alias_header;
    if(a->have_header && (h->format != a->header.format || h->length != a->header.length
                          || memcmp(h->data,a->header.data,sizeof h->data) != 0))
      memset(a->have_block,0,sizeof a->have_block); // another alias: the blocks held were the old one's
    a->header = *h;
    a->have_header = true;
  } else if(lc->body == DMR_LCB_TALKER_ALIAS_BLOCK){
    struct dmr_lc_talker_alias_block const *b = &lc->u.alias_block;
    if(b->block < 1 || b->block > 3)
      return false;
    memcpy(a->blocks[b->block - 1],b->data,sizeof b->data);
    a->have_block[b->block - 1] = true;
  } else {
    return false;
  }
  return ta_assemble(a,alias);
}

// ---------------- The message decoder ----------------

void dmr_msg_options_init(struct dmr_msg_options *o){
  dmr_data_options_init(&o->data);
  o->hidden_iv_max_golay_errors = 3;
  o->single_burst_max_corrected = DMR_SINGLE_BURST_MAX_CORRECTED;
  o->slot_gap_dibits = 4800;
  o->learn_crc_masks = false;
}

static void slot_reset(struct dmr_msg_slot *s){
  dmr_elc_reset(&s->embedded);
  dmr_hidden_iv_reset(&s->hidden_iv);
  dmr_ta_reset(&s->alias);
  s->last_clock = 0;
  s->have_identity = false;
}

void dmr_msg_init(struct dmr_msg_decoder *d,struct dmr_msg_options const *options){
  assert(d != NULL);
  memset(d,0,sizeof *d);
  if(options != NULL)
    d->options = *options;
  else
    dmr_msg_options_init(&d->options);
  dmr_slc_assembler_init(&d->short_lc);
  dmr_crc_learner_init(&d->learner);
  for(int i=0; i < 3; i++){
    dmr_elc_init(&d->slots[i].embedded);
    d->slots[i].embedded.learner = d->options.learn_crc_masks ? &d->learner : NULL;
    dmr_hidden_iv_reset(&d->slots[i].hidden_iv);
    dmr_ta_reset(&d->slots[i].alias);
  }
}

void dmr_msg_reset(struct dmr_msg_decoder *d){
  dmr_slc_assembler_reset(&d->short_lc);
  for(int i=0; i < 3; i++)
    slot_reset(&d->slots[i]);
}

void dmr_msg_reset_slot(struct dmr_msg_decoder *d,int slot){
  if(slot >= 0 && slot <= 2)
    slot_reset(&d->slots[slot]);
}

// A new talker or a new call starts the talker alias again; the first identity of a transmission
// does not (on a late entry its alias may have come before its voice LC)
static void note_identity(struct dmr_msg_slot *s,struct dmr_lc const *lc){
  struct dmr_voice_identity id;
  if(!dmr_lc_voice_identity(lc,&id))
    return;
  if(s->have_identity && (s->source != id.source || s->destination != id.destination))
    dmr_ta_reset(&s->alias);
  s->have_identity = true;
  s->source = id.source;
  s->destination = id.destination;
}

static void on_data(struct dmr_msg_decoder *dec,struct dmr_burst const *b,struct dmr_msg_slot *s,
                    struct dmr_burst_messages *m){
  // A data burst ends whatever voice superframe was being collected on the slot
  dmr_elc_reset(&s->embedded);
  dmr_hidden_iv_reset(&s->hidden_iv);

  m->has_data = true;
  dmr_data_decode_learning(&m->data,b,&dec->options.data,dec->options.learn_crc_masks ? &dec->learner : NULL);
  struct dmr_data_burst const *d = &m->data;
  dec->counters.data_bursts++;
  switch(d->status){
  case DMR_DATA_VALID: dec->counters.data_valid++; break;
  case DMR_DATA_UNCHECKED:
  case DMR_DATA_NOT_BPTC: dec->counters.data_unchecked++; break;
  case DMR_DATA_CHECK_FAILED: dec->counters.data_check_failed++; break;
  case DMR_DATA_REFUSED: dec->counters.data_refused++; break;
  }
  if(d->status == DMR_DATA_REFUSED || d->status == DMR_DATA_CHECK_FAILED)
    return;
  // Known to be a data burst: the transmission the alias belonged to is over, or a new one begins
  dmr_ta_reset(&s->alias);
  s->have_identity = false;
  if(dmr_data_lc_usable(d) && d->data_type == DMR_DT_VOICE_LC_HEADER)
    note_identity(s,&d->lc);
}

static void on_voice(struct dmr_msg_decoder *dec,struct dmr_burst const *b,struct dmr_msg_slot *s,
                     struct dmr_burst_messages *m){
  m->has_voice = true;
  dmr_voice_extract(&m->voice,b);
  dec->counters.voice_bursts++;
  dec->counters.voice_frame_fec_errors += (uint64_t)dmr_voice_fec_errors(&m->voice);

  int position = -1;
  if(b->kind >= DMR_KIND_VOICE_A && b->kind <= DMR_KIND_VOICE_F)
    position = (int)b->kind - (int)DMR_KIND_VOICE_A;

  struct dmr_elc_result r;
  dmr_elc_on_voice_burst(&s->embedded,&r,b);
  if(position < 0 && r.fragment >= 0)
    position = r.fragment + 1;
  if(r.failed){
    m->embedded_lc_failed = true;
    dec->counters.embedded_lc_failed++;
  }
  if(r.has_lc){
    m->has_embedded_lc = true;
    m->embedded_lc = r.lc;
    dec->counters.embedded_lc_decoded++;
    note_identity(s,&r.lc.lc);
    m->has_talker_alias = dmr_ta_on_lc(&s->alias,&m->talker_alias,&r.lc.lc);
    if(m->has_talker_alias)
      dec->counters.talker_aliases++;
  }
  if(b->kind != DMR_KIND_VOICE_A && b->emb_valid && b->emb_lcss == DMR_LCSS_SINGLE){
    if(position < 0)
      position = 5;
    m->has_single_burst = dmr_single_burst_decode_burst(&m->single_burst,b,dec->options.single_burst_max_corrected,
                                                        b->emb_pi,&m->single_burst_form_mismatch);
    if(m->has_single_burst)
      dec->counters.single_bursts++;
    else
      dec->counters.single_bursts_undecoded++;
    if(m->single_burst_form_mismatch)
      dec->counters.single_burst_form_mismatch++;
  }
  m->superframe_position = position;
  struct dmr_hidden_iv iv;
  if(dmr_hidden_iv_on_voice_burst(&s->hidden_iv,&iv,b,position) && iv.golay_errors <= dec->options.hidden_iv_max_golay_errors){
    m->has_hidden_iv = true;
    m->hidden_iv = iv;
  }
}

void dmr_msg_decode(struct dmr_msg_decoder *d,struct dmr_burst_messages *m,struct dmr_burst const *b){
  assert(d != NULL && m != NULL && b != NULL);
  memset(m,0,sizeof *m);
  m->superframe_position = -1;
  m->slot = b->slot;
  struct dmr_msg_slot *s = &d->slots[b->slot <= 2 ? b->slot : 0];

  // A burst with no CACH drops the Short LC in progress
  m->has_short_lc = dmr_slc_on_burst(&d->short_lc,&m->short_lc,b);
  if(m->has_short_lc)
    d->counters.short_lc_decoded++;

  if(s->last_clock != 0 && b->dibit_clock > s->last_clock + d->options.slot_gap_dibits)
    slot_reset(s);
  if(b->dibit_clock != 0)
    s->last_clock = b->dibit_clock;

  if(b->kind == DMR_KIND_DATA)
    on_data(d,b,s,m);
  else if(dmr_is_voice(b->kind))
    on_voice(d,b,s,m);
}
