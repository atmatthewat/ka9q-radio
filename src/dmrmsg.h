// DMR message layer (ETSI TS 102 361-1, -2): from the bursts the sink hands on to checked messages.
// Data bursts (voice LC header, terminator, PI header, idle; the BPTC bits of CSBK, MBC and data bursts
// passed on), the full link control, embedded LC assembly, burst F single-burst signalling, the IV some
// systems hide in the voice frames, Short LC on the CACH, talker alias, and the AMBE+2 frames.
// dmrmsg.c has the theory of operation
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRMSG_H
#define _DMRMSG_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmr.h"

// Conventions: bits one per uint8_t, index 0 first sent; a field packed into an integer has its first
// sent bit most significant. Nothing here allocates or keeps global state beyond one table built once.
// An optional part of a result has a has_ flag; when it is false the part is zeroed.

enum { DMR_DESCRIBE_MAX = 256 };  // a describe() line always fits in this many bytes

// ---------------- Link control (TS 102 361-2 7.1.1) ----------------

// Service options octet of a voice LC
static inline bool dmr_so_emergency(uint8_t so){ return (so & 0x80) != 0; }
static inline bool dmr_so_privacy(uint8_t so){ return (so & 0x40) != 0; }   // the call is encrypted
static inline bool dmr_so_broadcast(uint8_t so){ return (so & 0x08) != 0; }
static inline bool dmr_so_ovcm(uint8_t so){ return (so & 0x04) != 0; }      // open voice call mode
static inline uint8_t dmr_so_priority(uint8_t so){ return so & 0x03; }

enum dmr_lc_kind {
  DMR_LC_UNKNOWN = 0,
  DMR_LC_GROUP_VOICE,                    // FID 0x00 FLCO 0x00
  DMR_LC_UNIT_TO_UNIT_VOICE,             // FID 0x00 FLCO 0x03
  DMR_LC_TALKER_ALIAS_HEADER,            // FLCO 0x04 (FID 0x00 or 0x68)
  DMR_LC_TALKER_ALIAS_BLOCK,             // FLCO 0x05-0x07
  DMR_LC_GPS_INFO,                       // FLCO 0x08
  DMR_LC_TERMINATOR_DATA,                // FID 0x00 FLCO 0x30
  DMR_LC_MOTOROLA_GROUP_VOICE,           // FID 0x10 FLCO 0x00
  DMR_LC_CAP_PLUS_WIDE_AREA_VOICE,       // FID 0x10 FLCO 0x04
  DMR_LC_CAP_MAX_GROUP_VOICE,            // FID 0x10 FLCO 0x10
  DMR_LC_CAP_MAX_TALKER_ALIAS,           // FID 0x10 FLCO 0x14, 0x15
  DMR_LC_CAP_PLUS_ENCRYPTED_VOICE,       // FID 0x10 FLCO 0x20
  DMR_LC_MOTOROLA_ENCRYPTION_PARAMETERS, // FID 0x10 FLCO 0x21
  DMR_LC_HYTERA_GROUP_VOICE,             // FID 0x68 / 0x08 FLCO 0x00
  DMR_LC_HYTERA_UNIT_TO_UNIT_VOICE,      // FID 0x68 / 0x08 FLCO 0x03
  DMR_LC_HYTERA_XPT_CHANNEL_GRANT,       // FID 0x68 / 0x08 FLCO 0x09
  DMR_LC_HYTERA_TERMINATOR,              // FID 0x68 FLCO 0x30
};
char const *dmr_lc_kind_name(enum dmr_lc_kind k);

// Which member of struct dmr_lc's union is filled (several kinds share a layout)
enum dmr_lc_body {
  DMR_LCB_UNKNOWN = 0,            // bytes[] is all there is
  DMR_LCB_VOICE_USER,             // GROUP_VOICE, UNIT_TO_UNIT_VOICE, MOTOROLA_GROUP_VOICE, CAP_MAX_GROUP_VOICE, HYTERA_GROUP_VOICE
  DMR_LCB_CAP_PLUS_WIDE_AREA_VOICE,
  DMR_LCB_CAP_PLUS_ENCRYPTED_VOICE,
  DMR_LCB_ENCRYPTION_PARAMETERS,
  DMR_LCB_HYTERA_VOICE,           // HYTERA_UNIT_TO_UNIT_VOICE, HYTERA_TERMINATOR
  DMR_LCB_HYTERA_XPT_GRANT,
  DMR_LCB_TERMINATOR_DATA,
  DMR_LCB_GPS_INFO,
  DMR_LCB_TALKER_ALIAS_HEADER,
  DMR_LCB_TALKER_ALIAS_BLOCK,
  DMR_LCB_CAP_MAX_TALKER_ALIAS,
};

// The standard voice channel user layout: service options 16-23, destination 24-47, source 48-71
struct dmr_lc_voice_user {
  uint8_t options;
  bool group;              // destination is a talkgroup (false: the called unit)
  uint32_t destination;    // 24 bits
  uint32_t source;         // 24 bits
};
// Capacity Plus wide-area (linked) voice: talkgroups 1-255, radio IDs 1-65535. Bits 24-39 not understood
struct dmr_lc_cap_plus_wide_area_voice {
  uint8_t options;
  uint16_t unknown;        // bits 24-39
  uint8_t group;           // bits 40-47
  uint8_t rest_lsn;        // bits 51-55: the rest channel's logical slot number; 0 = none given
  uint16_t source;         // bits 56-71
};
// Capacity Plus voice channel user seen on encrypted calls
struct dmr_lc_cap_plus_encrypted_voice {
  uint8_t options;
  uint8_t unknown1;        // bits 24-31
  uint16_t target;         // bits 32-47 (a talkgroup, as sdrtrunk reads it)
  uint8_t unknown2;        // bits 48-55
  uint16_t source;         // bits 56-71
};
// Motorola encryption parameters where an LC is expected: a PI header's content cut to 72 bits
// (the 24-bit destination to its upper 16). One source only
struct dmr_lc_encryption_parameters {
  uint8_t key_id;          // bits 16-23
  uint32_t mi;             // bits 24-55
  uint16_t destination_high; // bits 56-71
};
// Hytera voice LC with repeater fields (unit-to-unit, terminator); addresses read as 16 bits
struct dmr_lc_hytera_voice {
  uint8_t options;
  uint8_t free_repeater;     // bits 24-27
  uint8_t priority_repeater; // bits 28-31
  uint16_t target;           // bits 32-47
  uint8_t priority_hash;     // bits 48-55
  uint16_t source;           // bits 56-71
};
struct dmr_lc_hytera_xpt_grant {
  uint8_t channel;         // bits 16-19
  uint8_t unknown;         // bits 20-23
  uint32_t target;         // bits 24-47 (a talkgroup)
  uint32_t source;         // bits 48-71
};
// Terminator data LC (ends a data transmission)
struct dmr_lc_terminator_data {
  uint32_t destination;    // bits 16-39
  uint32_t source;         // bits 40-63
  bool group;              // bit 64
  bool response_requested; // bit 65
  bool full_message;       // bit 66
  bool resync;             // bit 68
  uint8_t send_sequence;   // bits 69-71
};
// GPS info LC (TS 102 361-2 7.1.1.3)
struct dmr_lc_gps_info {
  uint8_t position_error;  // bits 20-22: 0 < 2 m, 1 < 20 m ... 6 > 200 km, 7 not known
  int32_t longitude_raw;   // bits 23-47, two's complement, units of 360 / 2^25 degrees
  int32_t latitude_raw;    // bits 48-71, two's complement, units of 180 / 2^24 degrees
  double longitude;        // degrees, east positive
  double latitude;         // degrees, north positive
};
enum dmr_ta_format { DMR_TA_7BIT = 0, DMR_TA_ISO8859_1 = 1, DMR_TA_UTF8 = 2, DMR_TA_UTF16BE = 3 };
struct dmr_lc_talker_alias_header {
  enum dmr_ta_format format; // bits 16-17
  uint8_t length;          // bits 18-22: characters, octets or 16-bit units
  uint8_t data[49];        // bits 23-71
};
struct dmr_lc_talker_alias_block {
  uint8_t block;           // 1-3
  uint8_t data[56];        // bits 16-71
};
// Capacity Max talker alias: first fragment (FLCO 0x14, up to 6 octets) or continuation (0x15, 7)
struct dmr_lc_cap_max_talker_alias {
  bool continuation;
  uint8_t length;          // first fragment: bits 19-22
  uint8_t count;           // octets in text[]
  uint8_t text[7];
};

struct dmr_lc {
  uint8_t bytes[9];        // the 72 bits, first sent = top bit of bytes[0]
  bool protect;            // PF
  bool reserved_bit;
  uint8_t flco;            // 6 bits
  uint8_t fid;
  enum dmr_lc_kind kind;
  enum dmr_lc_body body;
  union {
    struct dmr_lc_voice_user voice_user;
    struct dmr_lc_cap_plus_wide_area_voice wide_area;
    struct dmr_lc_cap_plus_encrypted_voice cap_plus_encrypted;
    struct dmr_lc_encryption_parameters encryption;
    struct dmr_lc_hytera_voice hytera_voice;
    struct dmr_lc_hytera_xpt_grant xpt_grant;
    struct dmr_lc_terminator_data terminator_data;
    struct dmr_lc_gps_info gps;
    struct dmr_lc_talker_alias_header alias_header;
    struct dmr_lc_talker_alias_block alias_block;
    struct dmr_lc_cap_max_talker_alias cap_max_alias;
  } u;
};
// Parse nine LC octets (or 72 bits). Never fails: an unknown (FID, FLCO) gives DMR_LC_UNKNOWN.
// Whether the bits are to be believed is the carrier's business (RS, BPTC and checksum)
void dmr_lc_parse(struct dmr_lc *lc,uint8_t const lc9[9]);
void dmr_lc_parse_bits(struct dmr_lc *lc,uint8_t const bits72[72]);

// Who is talking to whom, from a voice channel user LC of any layout
struct dmr_voice_identity {
  bool group;              // destination is a talkgroup
  uint32_t destination;
  uint32_t source;
  uint8_t options;         // service options
  uint8_t address_bits;    // width as sent: 24, or 16 in the vendor short forms
};
// False (and *id untouched) if lc is not a voice channel user LC
bool dmr_lc_voice_identity(struct dmr_lc const *lc,struct dmr_voice_identity *id);

// What an LC says about encryption; ask only an LC that passed its carrier's check. PF is not read
enum dmr_lc_privacy {
  DMR_LC_NO_STATEMENT = 0, // not a voice LC
  DMR_LC_CLEAR,            // a voice channel user LC with the privacy bit clear
  DMR_LC_ENCRYPTED,        // privacy bit set, a Cap+ encrypted voice LC, or encryption parameters
};
enum dmr_lc_privacy dmr_lc_privacy(struct dmr_lc const *lc);

// One control log line, e.g. "GROUP VOICE src=1234567 tg=9001 emergency". Returns snprintf()'s value
int dmr_lc_describe(char *buf,size_t size,struct dmr_lc const *lc);

// ---------------- Data bursts ----------------

char const *dmr_data_type_name(enum dmr_data_type t);
bool dmr_is_bptc_data_type(enum dmr_data_type t); // the 196 payload bits are a BPTC(196,96) codeword

// Encryption algorithm IDs (PI header, vendor encryption headers); values as sdrtrunk's
// type/EncryptionAlgorithm.java (GPL-3, Dennis Sheirer)
enum {
  DMR_ALG_NONE = 0x00,
  DMR_ALG_HYTERA_BP = 0x01,
  DMR_ALG_HYTERA_EP = 0x02,
  DMR_ALG_DMRA_RC4 = 0x21,
  DMR_ALG_DMRA_AES128 = 0x24,
  DMR_ALG_DMRA_AES256 = 0x25,
  DMR_ALG_HYTERA_EP2 = 0x26,
};
char const *dmr_algorithm_name(uint8_t algorithm_id);

// A PI header that passed its CRC: the voice that follows is encrypted
struct dmr_pi_header {
  uint8_t algorithm_octet; // octet 0 as sent
  uint8_t algorithm_id;    // its low six bits: a DMR_ALG_* value
  uint8_t fid;
  uint8_t key_id;
  uint32_t mi;             // message indicator
  uint32_t destination;    // 24 bits
};
void dmr_pi_header_parse(struct dmr_pi_header *p,uint8_t const info80[80]);
int dmr_pi_header_describe(char *buf,size_t size,struct dmr_pi_header const *p);

// The idle message: its 96 information bits and its 196 BPTC bits as sent (reserved bits zero)
uint8_t const *dmr_idle_info_bits(void);
uint8_t const *dmr_idle_payload_bits(void);

enum dmr_data_status {
  DMR_DATA_REFUSED = 0,      // not a data burst, no slot type, or BPTC found no acceptable codeword
  DMR_DATA_CHECK_FAILED,     // BPTC accepted a codeword but the message's own check failed
  DMR_DATA_UNCHECKED,        // BPTC accepted a codeword; the check belongs to whoever parses this type
  DMR_DATA_NOT_BPTC,         // rate 3/4, rate 1, reserved: payload[] is the 196 bits as sent
  DMR_DATA_VALID,            // the message's own check passed: lc / pi / idle can be used
};

struct dmr_data_options {
  bool rs_correct;           // let RS(12,9) repair one octet of a header / terminator LC (rs_corrected says so)
  bool accept_zero_rs_mask;  // accept an LC whose RS parity has no mask, uncorrected only (Hytera Tier III)
  int idle_max_bit_errors;   // an idle burst may differ from the idle pattern in this many of its 196 bits
  float bptc_max_weighted_errors;
};
void dmr_data_options_init(struct dmr_data_options *o); // true, true, 20, DMR_BPTC196_MAX_ERRORS

struct dmr_data_burst {
  enum dmr_data_type data_type;
  uint8_t color_code;
  enum dmr_data_status status;

  // The BPTC(196,96) decode (not run for NOT_BPTC types)
  bool bptc_ok;
  int bptc_corrected;
  float bptc_weighted_errors;
  float bptc_margin;
  uint8_t info[96];          // information bits with the RS parity / CRC as sent (RS-corrected on a valid LC)
  uint8_t reserved[4];       // R(3) R(2) R(1) R(0)

  // The 196 payload bits as sent (burst bits 0-97, 166-263) and their confidences
  uint8_t payload[196];
  float payload_confidence[196];

  // Voice LC header / terminator with LC, when status == DMR_DATA_VALID
  bool has_lc;
  struct dmr_lc lc;
  int rs_corrected;          // octets RS(12,9) corrected: 0 or 1
  bool lc_uncorrected;       // passed RS as BPTC delivered it: the stricter test for "clear"
  uint8_t rs_mask;           // the mask it passed with: 0x96, 0x99, or 0x00 (Hytera)
  uint32_t rs_observed_mask; // parity XOR recomputed parity, 0xAABBCC; set whenever bptc_ok

  // PI header, when status == DMR_DATA_VALID
  bool has_pi;
  struct dmr_pi_header pi;

  int idle_bit_errors;       // idle: bits of the 196 that differ from the idle burst; -1 otherwise
};
static inline bool dmr_data_valid(struct dmr_data_burst const *d){
  return d->status == DMR_DATA_VALID;
}
// A voice LC header or terminator whose LC can be used
static inline bool dmr_data_lc_usable(struct dmr_data_burst const *d){
  return d->status == DMR_DATA_VALID && d->has_lc;
}
// b->kind must be DMR_KIND_DATA and its slot type valid, or the result is DMR_DATA_REFUSED.
// options may be NULL (the defaults)
void dmr_data_decode(struct dmr_data_burst *d,struct dmr_burst const *b,struct dmr_data_options const *options);
int dmr_data_describe(char *buf,size_t size,struct dmr_data_burst const *d);

// ---------------- Voice frames ----------------

// The burst bit that carries bit `bit` (0-71) of voice frame `frame` (0-2)
static inline int dmr_voice_bit_position(int frame,int bit){
  return frame == 0 ? bit : frame == 1 ? (bit < 36 ? 72 + bit : 156 + (bit - 36)) : 192 + bit;
}
struct dmr_voice_frame {
  uint8_t bytes[DMR_VOICE_FRAME_BYTES]; // the 72 bits as sent (interleaved, c1 whitened), msb first
  int errors_c0;           // Golay(24,12) corrections in c0: 0-3, 4 = a fourth error its parity bit saw
  int errors_c1;           // Golay(23,12) corrections in c1: 0-3
  int fec_errors;          // errors_c0 + errors_c1
  // The decoded frame for a vocoder: u0 u1 u2 u3 (12, 12, 11, 14 bits), msb first, as mbelib's
  // ambe_d[49]; and the corrections in u0 and u1 alone (mbelib's errs = data_errors[0],
  // errs2 = data_errors[0] + data_errors[1])
  uint8_t info[49];
  int data_errors[2];
};
struct dmr_voice_burst {
  struct dmr_voice_frame frames[DMR_VOICE_FRAMES];
};
static inline int dmr_voice_fec_errors(struct dmr_voice_burst const *v){
  return v->frames[0].fec_errors + v->frames[1].fec_errors + v->frames[2].fec_errors;
}
// The three frames of a voice burst (any of A-F: the layout is the same)
void dmr_voice_extract(struct dmr_voice_burst *v,struct dmr_burst const *b);
// Decode one frame from its 9 octets as sent (fills everything but bytes[], which it reads)
void dmr_voice_frame_decode(struct dmr_voice_frame *f);

// ---------------- Embedded LC (voice bursts B-E) ----------------

enum { DMR_SLOT_BURST_SPACING_DIBITS = 2 * DMR_SLOT_DIBITS }; // between bursts of one timeslot

// An embedded LC that passed BPTC(128,77) and its 5-bit checksum
struct dmr_embedded_lc {
  struct dmr_lc lc;
  int corrected;           // bits BPTC changed (0 = the 128 bits arrived as a codeword)
  float weighted_errors;   // those bits' confidences, in units of the mean confidence
  int inferred_fragments;  // fragments taken from bursts whose EMB did not decode, placed by timing
};
// One per timeslot
struct dmr_elc_assembler {
  bool active;
  int count;
  int inferred;
  uint64_t first_clock;
  bool present[4];
  uint8_t bits[128];
  float confidence[128];
  uint64_t decoded;
  uint64_t failed;         // four fragments that failed BPTC or the checksum
  uint64_t abandoned;      // messages dropped incomplete
};
struct dmr_elc_result {
  bool has_lc;             // this burst completed an LC
  struct dmr_embedded_lc lc;
  bool failed;             // this burst completed four fragments that failed BPTC or the checksum
  int fragment;            // where (0-3 = bursts B-E) this burst's 32 bits went, or -1
};
void dmr_elc_init(struct dmr_elc_assembler *a);
void dmr_elc_reset(struct dmr_elc_assembler *a); // forget the fragments held
// Feed every voice burst of the timeslot (A-F or DMR_KIND_VOICE_UNKNOWN)
void dmr_elc_on_voice_burst(struct dmr_elc_assembler *a,struct dmr_elc_result *r,struct dmr_burst const *b);

// ---------------- Burst F: single-burst embedded signalling ----------------

enum dmr_single_burst_kind {
  DMR_SB_NULL = 0,                 // the null embedded message, or a vendor null short burst
  DMR_SB_ENCRYPTION_PARAMETERS,    // vendor short burst: key ID and algorithm. Says "encrypted"
  DMR_SB_TXI_DELAY,                // vendor short burst: when the transmission may be interrupted
  DMR_SB_REVERSE_CHANNEL,          // ETSI reverse channel signalling (the complemented form)
  DMR_SB_UNKNOWN,                  // decoded, but none of the above (or its CRC-3 failed)
};
struct dmr_single_burst {
  enum dmr_single_burst_kind kind;
  uint16_t info;           // the 11 information bits, first sent most significant
  bool reverse_channel_form; // the second row was the complement of the first
  int corrected;           // bits of the 32 the decode changed
  uint8_t key_id;          // encryption parameters
  uint8_t algorithm;       // ... the 3 bits as sent: 1 ARC4, 4 AES-128, 5 AES-256
  uint8_t algorithm_id;    // ... as a PI header names it: DMR_ALG_DMRA_*
  uint8_t txi_delay;       // TXI: 0 any time, 2 frame E, 4 frame D, 6 frame C, 8 frame B
  uint8_t reverse_channel; // reverse channel: the 4 RC bits
  uint8_t rc_crc_residue;  // ... CRC-7 of them XOR the 7 sent (the mask is not confirmed; not used)
};
// Corrections a single-burst decode is accepted with by default: one fewer than the code's radius
#define DMR_SINGLE_BURST_MAX_CORRECTED 2.0f
bool dmr_short_burst_crc3_ok(uint32_t info11);
void dmr_single_burst_parse(struct dmr_single_burst *s,uint32_t info11,bool reverse_channel_form);
// Decode the 32 embedded bits of a voice burst (EMB LCSS single fragment). False if neither form of
// the code decodes within max_corrected (confidence-weighted) corrections
bool dmr_single_burst_decode_burst(struct dmr_single_burst *s,struct dmr_burst const *b,float max_corrected);
int dmr_single_burst_describe(char *buf,size_t size,struct dmr_single_burst const *s);

// ---------------- IV hidden in the voice frames of a superframe ----------------

// A candidate IV: three Golay(24,12) words decoded and the CRC-4 matched. NOT an indicator of
// encryption: on clear voice the same bits pass by chance (dmrmsg.c)
struct dmr_hidden_iv {
  uint32_t iv;
  int golay_errors;        // bits corrected over the three words (0-9)
};
int dmr_hidden_iv_describe(char *buf,size_t size,struct dmr_hidden_iv const *iv);
uint8_t dmr_hidden_iv_crc4(uint32_t iv);
// The four hidden bits of each of a burst's three frames (frame bits 71, 67, 63, 59, msb first)
void dmr_hidden_iv_nibbles(uint8_t nibbles[3],struct dmr_burst const *b);
// nibbles[b][f]: frame f of burst b (0 = A .. 5 = F)
bool dmr_hidden_iv_decode(struct dmr_hidden_iv *iv,uint8_t const nibbles[6][3]);
struct dmr_hidden_iv_collector {
  unsigned present;
  uint64_t first_clock;
  uint8_t nibbles[6][3];
};
void dmr_hidden_iv_reset(struct dmr_hidden_iv_collector *c);
// position: 0-5 for bursts A-F, -1 when not known. True (and *iv) when burst F completes a
// superframe whose six bursts were all seen
bool dmr_hidden_iv_on_voice_burst(struct dmr_hidden_iv_collector *c,struct dmr_hidden_iv *iv,
                                  struct dmr_burst const *b,int position);

// ---------------- Short LC (CACH, TS 102 361-2 7.1.3) ----------------

enum dmr_slc_kind {
  DMR_SLC_NULL = 0,                  // SLCO 0 Nul_Msg
  DMR_SLC_ACTIVITY_UPDATE,           // SLCO 1 Act_Updt
  DMR_SLC_CONTROL_CHANNEL_SYS_PARMS, // SLCO 2 C_SYS_Parms: a Tier III control channel
  DMR_SLC_TRAFFIC_CHANNEL_SYS_PARMS, // SLCO 3 P_SYS_Parms: a Tier III payload channel
  DMR_SLC_HYTERA_XPT_CHANNEL,        // SLCO 8
  DMR_SLC_CONNECT_PLUS_TRAFFIC,      // SLCO 9
  DMR_SLC_CONNECT_PLUS_CONTROL,      // SLCO 10
  DMR_SLC_CAP_PLUS_REST_CHANNEL,     // SLCO 15, FID 0x10
  DMR_SLC_UNKNOWN,
};
char const *dmr_slc_kind_name(enum dmr_slc_kind k);
// Act_Updt slot activity (TS 102 361-2 7.1.3.2); other values reserved
enum dmr_slot_activity {
  DMR_ACT_IDLE = 0, DMR_ACT_GROUP_CSBK = 2, DMR_ACT_INDIVIDUAL_CSBK = 3, DMR_ACT_GROUP_VOICE = 8,
  DMR_ACT_INDIVIDUAL_VOICE = 9, DMR_ACT_INDIVIDUAL_DATA = 10, DMR_ACT_GROUP_DATA = 11,
  DMR_ACT_EMERGENCY_GROUP_VOICE = 12, DMR_ACT_EMERGENCY_INDIVIDUAL_VOICE = 13,
};
char const *dmr_slot_activity_name(uint8_t activity);
enum dmr_slc_body {
  DMR_SLCB_UNKNOWN = 0, DMR_SLCB_NULL, DMR_SLCB_ACTIVITY_UPDATE, DMR_SLCB_SYS_PARMS, DMR_SLCB_CONNECT_PLUS,
  DMR_SLCB_CAP_PLUS_REST_CHANNEL, DMR_SLCB_HYTERA_XPT_CHANNEL,
};
enum dmr_network_model { DMR_NET_TINY = 0, DMR_NET_SMALL = 1, DMR_NET_LARGE = 2, DMR_NET_HUGE = 3 };
struct dmr_slc_activity_update {
  uint8_t ts1_activity;    // bits 4-7 (enum dmr_slot_activity, or reserved)
  uint8_t ts2_activity;    // bits 8-11
  uint8_t ts1_hash;        // bits 12-19: hashed destination of the call on each slot
  uint8_t ts2_hash;        // bits 20-27
};
// C_SYS_Parms / P_SYS_Parms: system identity code at bits 4-17 (model 2 bits, then network / site:
// tiny 9 / 3, small 7 / 5, large 4 / 8, huge 2 / 10), registration required (18), common slot counter (19-27)
struct dmr_slc_sys_parms {
  enum dmr_network_model model;
  uint16_t network;
  uint16_t site;
  bool registration_required;
  uint16_t common_slot_counter;
  uint16_t system_identity_code; // the 14 bits as sent
};
struct dmr_slc_connect_plus {
  uint16_t network;        // bits 4-15
  uint8_t site;            // bits 16-23
};
struct dmr_slc_cap_plus_rest_channel {
  uint8_t rest_lsn;        // bits 15-19, logical slot number 1-16
  uint8_t site;            // bits 20-24
  uint8_t unknown1;        // bits 12-14
  uint8_t unknown2;        // bits 25-27
};
struct dmr_slc_hytera_xpt_channel {
  uint8_t fid;             // bits 4-11
  uint8_t free_repeater;   // bits 12-15
  uint8_t priority_repeater; // bits 16-19
  uint8_t priority_hash;   // bits 20-27
};
// A Short LC that passed BPTC(68,36) and its CRC-8
struct dmr_short_lc {
  uint8_t slco;            // 4 bits
  uint32_t data;           // the 24 bits after it
  enum dmr_slc_kind kind;
  enum dmr_slc_body body;
  union {
    struct dmr_slc_activity_update activity;
    struct dmr_slc_sys_parms sys_parms;
    struct dmr_slc_connect_plus connect_plus;
    struct dmr_slc_cap_plus_rest_channel rest;
    struct dmr_slc_hytera_xpt_channel xpt;
  } u;
  int corrected;           // bits the BPTC decode changed
};
// Parse the 28 bits (SLCO + data) of a Short LC whose CRC-8 was checked. Never fails
void dmr_slc_parse(struct dmr_short_lc *s,uint8_t const bits28[28]);
int dmr_slc_describe(char *buf,size_t size,struct dmr_short_lc const *s);
// One per carrier: feed it every burst of both slots
struct dmr_slc_assembler {
  int count;
  uint64_t last_clock;
  uint8_t bits[68];
  float confidence[68];
  uint64_t decoded;
  uint64_t failed;         // complete but failed BPTC or the CRC-8
  uint64_t abandoned;      // dropped part way
};
void dmr_slc_assembler_init(struct dmr_slc_assembler *a);
void dmr_slc_assembler_reset(struct dmr_slc_assembler *a);
// True (and *s) when this burst completed a Short LC that decoded and passed its CRC-8
bool dmr_slc_on_burst(struct dmr_slc_assembler *a,struct dmr_short_lc *s,struct dmr_burst const *b);

// ---------------- Talker alias ----------------

enum { DMR_TALKER_ALIAS_TEXT = 128 }; // the longest alias in UTF-8 (27 octets as U+FFFD each) and its NUL
struct dmr_talker_alias {
  char text[DMR_TALKER_ALIAS_TEXT]; // UTF-8, NUL terminated, one log line (no control characters)
  enum dmr_ta_format format;
  uint8_t length;          // as the header gave it
  uint8_t blocks;          // block LCs it took besides the header: 0-3
};
int dmr_talker_alias_describe(char *buf,size_t size,struct dmr_talker_alias const *a);
// One per timeslot; reset at every new transmission
struct dmr_ta_assembler {
  bool have_header;
  struct dmr_lc_talker_alias_header header;
  bool have_block[3];
  uint8_t blocks[3][56];
  bool have_reported;
  char reported[DMR_TALKER_ALIAS_TEXT];
};
void dmr_ta_reset(struct dmr_ta_assembler *a);
// Feed an LC that passed its check. True (and *alias) when it completes an alias not reported
// since the last reset
bool dmr_ta_on_lc(struct dmr_ta_assembler *a,struct dmr_talker_alias *alias,struct dmr_lc const *lc);

// ---------------- The message decoder: one per carrier ----------------

struct dmr_msg_options {
  struct dmr_data_options data;
  int hidden_iv_max_golay_errors; // a hidden IV is reported only within this many corrections in all
  float single_burst_max_corrected;
  uint64_t slot_gap_dibits; // a slot's assembly state is dropped after this long silent
};
void dmr_msg_options_init(struct dmr_msg_options *o); // data defaults, 3, 2, 4800

// What one burst produced
struct dmr_burst_messages {
  uint8_t slot;
  bool has_short_lc;       // BS: a Short LC completed on the CACH (about the carrier, not this slot)
  struct dmr_short_lc short_lc;
  bool has_data;           // every burst of kind DMR_KIND_DATA: check data.status
  struct dmr_data_burst data;
  bool has_voice;          // every voice burst (A-F, unknown)
  struct dmr_voice_burst voice;
  int superframe_position; // voice: 0-5 = A-F when known, else -1
  bool has_embedded_lc;    // the embedded LC this burst completed
  struct dmr_embedded_lc embedded_lc;
  bool embedded_lc_failed; // four fragments were collected and failed BPTC or the checksum
  bool has_single_burst;   // burst F
  struct dmr_single_burst single_burst;
  bool has_hidden_iv;
  struct dmr_hidden_iv hidden_iv;
  bool has_talker_alias;
  struct dmr_talker_alias talker_alias;
};

struct dmr_msg_counters {
  uint64_t data_bursts;
  uint64_t data_valid;
  uint64_t data_unchecked;    // handed on for another check (NOT_BPTC included)
  uint64_t data_check_failed;
  uint64_t data_refused;
  uint64_t voice_bursts;
  uint64_t voice_frame_fec_errors;
  uint64_t embedded_lc_decoded;
  uint64_t embedded_lc_failed;
  uint64_t single_bursts;
  uint64_t single_bursts_undecoded;
  uint64_t short_lc_decoded;
  uint64_t talker_aliases;
};

struct dmr_msg_slot {
  struct dmr_elc_assembler embedded;
  struct dmr_hidden_iv_collector hidden_iv;
  struct dmr_ta_assembler alias;
  uint64_t last_clock;
  bool have_identity;
  uint32_t source;
  uint32_t destination;
};
struct dmr_msg_decoder {
  struct dmr_msg_options options;
  struct dmr_slc_assembler short_lc;
  struct dmr_msg_slot slots[3]; // 0 = slot not known, 1, 2
  struct dmr_msg_counters counters;
};
// options may be NULL (the defaults)
void dmr_msg_init(struct dmr_msg_decoder *d,struct dmr_msg_options const *options);
// Feed every burst, both slots, in the order received
void dmr_msg_decode(struct dmr_msg_decoder *d,struct dmr_burst_messages *m,struct dmr_burst const *b);
void dmr_msg_reset(struct dmr_msg_decoder *d);              // sync loss, retune
void dmr_msg_reset_slot(struct dmr_msg_decoder *d,int slot); // the call tracker ended the slot's transmission by a timeout

#endif
