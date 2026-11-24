// DMR control signalling blocks (ETSI TS 102 361-2, -4, and the vendor layouts): the CSBK with its CRC
// mask rule, the parsed messages of every system flavour, multi-block CSBK assembly, the ways a message
// names a channel, the channel grants whatever their flavour, and the LCN to frequency map of a site.
// dmrcsbk.c has the theory of operation
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRCSBK_H
#define _DMRCSBK_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmr.h"

// Conventions as dmrmsg.h: bits one per uint8_t, index 0 first sent; a field packed into an integer has
// its first sent bit most significant. Bit numbers in the comments are those of the 96-bit block.

enum { DMR_CSBK_DESCRIBE_MAX = 1024 };  // a CSBK describe line always fits in this many bytes

// ---------------- Channels: LSN, Tier III, absolute ----------------
// After sdrtrunk (GPL-3, Dennis Sheirer): channel/DMRLsn.java, DMRTier3Channel.java, DMRAbsoluteChannel.java

enum { DMR_CAP_PLUS_MAX_LSN = 16, DMR_CON_PLUS_MAX_LSN = 31 };

// The repeater (LCN, from 1) of a logical slot number; 0 for an LSN below 1 (there is no LSN 0)
static inline int dmr_lsn_to_lcn(int lsn){ return lsn >= 1 ? (lsn - 1) / 2 + 1 : 0; }
// Its timeslot, 1 or 2; 0 for an LSN below 1
static inline int dmr_lsn_to_timeslot(int lsn){ return lsn >= 1 ? (lsn - 1) % 2 + 1 : 0; }
// The LSN of a repeater's timeslot; 0 unless lcn >= 1 and the timeslot is 1 or 2
static inline int dmr_lsn_from_lcn(int lcn,int timeslot){
  return (lcn >= 1 && (timeslot == 1 || timeslot == 2)) ? (lcn - 1) * 2 + timeslot : 0;
}
// The other timeslot of the same repeater
static inline int dmr_lsn_sister(int lsn){
  return lsn >= 1 ? (dmr_lsn_to_timeslot(lsn) == 1 ? lsn + 1 : lsn - 1) : 0;
}
// sdrtrunk's display number of a Tier III channel, LCN * 2 + TS (logs only; the map is keyed by LCN)
static inline int dmr_tier3_channel_id(int lcn,int timeslot){ return lcn * 2 + timeslot; }

enum dmr_chref_kind {
  DMR_CHREF_NONE = 0,    // the message names no usable channel
  DMR_CHREF_LSN,         // Capacity Plus / Connect Plus: lsn, with lcn and timeslot derived from it
  DMR_CHREF_TIER3,       // lcn (12 bits) and timeslot; the frequency comes from the channel map
  DMR_CHREF_ABSOLUTE,    // lcn, timeslot and the frequencies of a CG_AP block
};
struct dmr_channel_ref {
  enum dmr_chref_kind kind;
  uint16_t lcn;          // the repeater / logical physical channel number: the channel map's key
  uint8_t timeslot;      // 1 or 2; 0 = not known
  uint8_t lsn;           // DMR_CHREF_LSN only
  uint64_t downlink_hz;  // DMR_CHREF_ABSOLUTE only: what the base station sends (what is tuned)
  uint64_t uplink_hz;    // DMR_CHREF_ABSOLUTE only
};
static inline bool dmr_chref_valid(struct dmr_channel_ref const *c){ return c->kind != DMR_CHREF_NONE; }
static inline bool dmr_chref_has_frequency(struct dmr_channel_ref const *c){
  return c->kind == DMR_CHREF_ABSOLUTE && c->downlink_hz != 0;
}
struct dmr_channel_ref dmr_chref_none(void);
struct dmr_channel_ref dmr_chref_from_lsn(int lsn);              // NONE for an LSN outside 1-255
struct dmr_channel_ref dmr_chref_from_tier3(int lcn,int timeslot); // lcn to 12 bits; timeslot other than 1, 2 = 0
struct dmr_channel_ref dmr_chref_from_absolute(int lcn,int timeslot,uint64_t downlink_hz,uint64_t uplink_hz);
// "LSN 3 (LCN 2 TS1)", "LCN 100 TS2", "LCN 100 TS1 451.012500 MHz", "no channel"
int dmr_chref_describe(char *buf,size_t size,struct dmr_channel_ref const *c);
// "451.012500" for 451012500 Hz
int dmr_format_mhz(char *buf,size_t size,uint64_t hz);

// CG_AP, the absolute channel parameters (the first continuation block of some multi-block CSBKs).
// Layout: sdrtrunk (GPL-3, Dennis Sheirer) message/type/AbsoluteChannelParameters.java
struct dmr_cgap {
  bool last_block;
  bool protect;
  uint8_t opcode;          // bits 2-7
  uint8_t color_code;      // 12-15
  uint8_t cdef_type;       // 16-19; only 0 is defined
  uint16_t lcn;            // 22-33
  uint16_t uplink_mhz;     // 34-43
  uint16_t uplink_steps;   // 44-56, 125 Hz
  uint16_t downlink_mhz;   // 57-66
  uint16_t downlink_steps; // 67-79, 125 Hz
};
void dmr_cgap_parse(struct dmr_cgap *p,uint8_t const bits80[80]); // the CRC is the assembler's business
static inline uint64_t dmr_cgap_uplink_hz(struct dmr_cgap const *p){
  return (uint64_t)p->uplink_mhz * 1000000ull + (uint64_t)p->uplink_steps * 125ull;
}
static inline uint64_t dmr_cgap_downlink_hz(struct dmr_cgap const *p){
  return (uint64_t)p->downlink_mhz * 1000000ull + (uint64_t)p->downlink_steps * 125ull;
}
// CDEF type 0, a downlink, and step counts below one MHz
static inline bool dmr_cgap_plausible(struct dmr_cgap const *p){
  return p->cdef_type == 0 && p->downlink_mhz != 0 && p->downlink_steps < 8000 && p->uplink_steps < 8000;
}
struct dmr_channel_ref dmr_cgap_channel(struct dmr_cgap const *p,int timeslot);
int dmr_cgap_describe(char *buf,size_t size,struct dmr_cgap const *p); // "CG_AP LCN 5 cc=1 down=... up=... MHz"

// ---------------- The block every CSBK (and multi-block header) shares ----------------

// LB (0), PF (1), CSBKO (2-7), FID (8-15), 64 payload bits (16-79), CRC-CCITT (80-95): sdrtrunk (GPL-3,
// Dennis Sheirer) CSBKMessage.java and OP25 (GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al.) dmr_slot.cc
struct dmr_csbk_block {
  uint64_t timestamp_us;
  uint8_t slot;            // 1 or 2 (0 = not known), as the caller gave it
  uint8_t color_code;
  bool crc_ok;
  uint16_t crc_mask;       // the mask the check was made with
  uint16_t observed_mask;  // the mask that makes these bits pass (== crc_mask when crc_ok)
  // As received; not to be trusted when !crc_ok (given so a failure can be logged and counted)
  bool last_block;
  bool protect;
  uint8_t opcode;
  uint8_t fid;
  uint64_t payload;        // bits 16-79, bit 16 most significant
  uint8_t bits[96];
};
// crc_mask: DMR_CRC_MASK_CSBK, DMR_CRC_MASK_MBC_HEADER, or a vendor mask the caller decided to accept
void dmr_csbk_read_block(struct dmr_csbk_block *k,uint8_t const info96[96],uint8_t slot,uint8_t color_code,
                         uint64_t timestamp_us,uint16_t crc_mask);
// Bits first .. first + count - 1, count <= 32
uint32_t dmr_csbk_bits(struct dmr_csbk_block const *k,int first,int count);

// The masks seen on blocks that failed the standard check, per (CSBKO, FID). It never makes a block valid
enum { DMR_CSBK_MASK_COUNTER_MAX = 256 };
struct dmr_csbk_mask_entry {
  uint8_t opcode;
  uint8_t fid;
  uint16_t mask;
  uint32_t count;
};
struct dmr_csbk_mask_counter {
  size_t max_entries;      // at most DMR_CSBK_MASK_COUNTER_MAX
  size_t count;
  struct dmr_csbk_mask_entry entries[DMR_CSBK_MASK_COUNTER_MAX];
};
void dmr_csbk_mask_counter_init(struct dmr_csbk_mask_counter *c,size_t max_entries); // 0 = the maximum
// A block that failed its CRC: how many times its (CSBKO, FID, observed mask) has been seen now; 0 if it
// passed, or could not be recorded
uint32_t dmr_csbk_mask_note_block(struct dmr_csbk_mask_counter *c,struct dmr_csbk_block const *k);
uint32_t dmr_csbk_mask_note(struct dmr_csbk_mask_counter *c,uint8_t opcode,uint8_t fid,uint16_t mask);
uint32_t dmr_csbk_mask_count(struct dmr_csbk_mask_counter const *c,uint8_t opcode,uint8_t fid,uint16_t mask);
// The mask seen most often for this (CSBKO, FID), if at least min_count times
bool dmr_csbk_mask_most_seen(struct dmr_csbk_mask_counter const *c,uint8_t opcode,uint8_t fid,uint32_t min_count,
                             uint16_t *mask);
void dmr_csbk_mask_clear(struct dmr_csbk_mask_counter *c);

// ---------------- Opcodes ----------------
// The (FID, CSBKO) values and names are sdrtrunk's (GPL-3, Dennis Sheirer): message/data/csbk/Opcode.java

enum {
  // Standard, FID 0x00 (sdrtrunk Opcode.java:35-66)
  DMR_CSBKO_UU_V_REQ = 4, DMR_CSBKO_UU_ANS_RSP = 5, DMR_CSBKO_CHANNEL_TIMING = 7, DMR_CSBKO_ALOHA = 25,
  DMR_CSBKO_AHOY = 28, DMR_CSBKO_RANDOM_ACCESS = 31, DMR_CSBKO_ACK_OUTBOUND_TSCC = 32,
  DMR_CSBKO_ACK_INBOUND_TSCC = 33, DMR_CSBKO_ACK_OUTBOUND_PAYLOAD = 34, DMR_CSBKO_ACK_INBOUND_PAYLOAD = 35,
  DMR_CSBKO_NACK = 38, DMR_CSBKO_BROADCAST = 40, DMR_CSBKO_CLEAR = 46, DMR_CSBKO_PROTECT = 47,
  DMR_CSBKO_PV_GRANT = 48, DMR_CSBKO_TV_GRANT = 49, DMR_CSBKO_BTV_GRANT = 50, DMR_CSBKO_PD_GRANT = 51,
  DMR_CSBKO_TD_GRANT = 52, DMR_CSBKO_PV_GRANT_DX = 53, DMR_CSBKO_PD_GRANT_DX = 54, DMR_CSBKO_PD_GRANT_MI = 55,
  DMR_CSBKO_TD_GRANT_MI = 56,  // also BS_Dwn_Act on a Tier II inbound burst
  DMR_CSBKO_MOVE_TSCC = 57, DMR_CSBKO_PREAMBLE = 61,
  // Connect Plus, FID 0x06 (Opcode.java:68-78)
  DMR_CSBKO_CON_PLUS_NEIGHBORS = 1, DMR_CSBKO_CON_PLUS_VOICE_CHANNEL_USER = 3,
  DMR_CSBKO_CON_PLUS_DATA_CHANNEL_GRANT = 6, DMR_CSBKO_CON_PLUS_OTA_ANNOUNCEMENT = 10,
  DMR_CSBKO_CON_PLUS_TERMINATE_CHANNEL_GRANT = 12, DMR_CSBKO_CON_PLUS_CSBKO_16 = 16,
  DMR_CSBKO_CON_PLUS_REGISTRATION_REQUEST = 17, DMR_CSBKO_CON_PLUS_REGISTRATION_RESPONSE = 18,
  DMR_CSBKO_CON_PLUS_TALKGROUP_AFFILIATION = 24, DMR_CSBKO_CON_PLUS_DATA_WINDOW_ANNOUNCEMENT = 28,
  DMR_CSBKO_CON_PLUS_DATA_WINDOW_GRANT = 29,
  // Capacity Plus / Capacity Max, FID 0x10 (Opcode.java:80-91)
  DMR_CSBKO_CAP_MAX_ALOHA = 25, DMR_CSBKO_CAP_PLUS_CALL_ALERT = 31, DMR_CSBKO_CAP_PLUS_CALL_ALERT_ACK = 32,
  DMR_CSBKO_CAP_MAX_OPEN_MODE_UPDATE = 33, DMR_CSBKO_CAP_MAX_ADVANTAGE_MODE_UPDATE = 34,
  DMR_CSBKO_CAP_PLUS_DATA_WINDOW_ANNOUNCEMENT = 41, DMR_CSBKO_CAP_PLUS_DATA_WINDOW_GRANT = 42,
  DMR_CSBKO_CAP_PLUS_NEIGHBORS = 59, DMR_CSBKO_CAP_PLUS_CSBKO_60 = 60, DMR_CSBKO_CAP_PLUS_PREAMBLE = 61,
  DMR_CSBKO_CAP_PLUS_SITE_STATUS = 62,
  // Hytera, FID 0x08 and 0x68 (Opcode.java:93-108)
  DMR_CSBKO_HYTERA_ACK = 32, DMR_CSBKO_HYTERA_ANNOUNCEMENT = 40, DMR_CSBKO_HYTERA_08_CSBKO_44 = 44,
  DMR_CSBKO_HYTERA_08_TALKER_STATUS = 47, DMR_CSBKO_HYTERA_XPT_SITE_STATE = 10,
  DMR_CSBKO_HYTERA_XPT_ADJACENT_SITES = 11, DMR_CSBKO_HYTERA_68_ALOHA = 25, DMR_CSBKO_HYTERA_XPT_PREAMBLE = 61,
  DMR_CSBKO_HYTERA_68_SMS_AVAILABLE = 62,
};
// The name of a (FID, CSBKO) in sdrtrunk's opcode table, or NULL
char const *dmr_csbk_name(uint8_t fid,uint8_t opcode);
static inline bool dmr_csbk_is_grant_opcode(uint8_t opcode){
  return opcode >= DMR_CSBKO_PV_GRANT && opcode <= DMR_CSBKO_TD_GRANT_MI;
}

// ---------------- Standard (FID 0x00) messages ----------------
// Layouts after sdrtrunk (GPL-3, Dennis Sheirer) message/data/csbk/standard/*.java and message/type/*.java,
// and TS 102 361-2 / -4 for what sdrtrunk lacks; the fixes to sdrtrunk's are listed in dmrcsbk.c

// System identity code: model (2 bits), then network / site: tiny 9 / 3, small 7 / 5, large 4 / 8, huge 2 / 10;
// PAR (2 bits) after it where the message has one
enum dmr_system_model { DMR_MODEL_TINY = 0, DMR_MODEL_SMALL = 1, DMR_MODEL_LARGE = 2, DMR_MODEL_HUGE = 3 };
struct dmr_system_code {
  uint16_t raw;            // the 14 bits
  enum dmr_system_model model;
  uint16_t network;
  uint16_t site;
  bool has_par;
  uint8_t par;
};
char const *dmr_system_model_name(enum dmr_system_model m);
void dmr_system_code_parse(struct dmr_system_code *s,struct dmr_csbk_block const *k,int first,bool has_par);
static inline bool dmr_system_code_multiple_cc(struct dmr_system_code const *s){
  return s->has_par && (s->par == 1 || s->par == 2);
}

// Tier III gateway addresses
enum {
  DMR_GATEWAY_REGISTRATION = 0xFFFEC6, DMR_GATEWAY_TSI = 0xFFFECA, DMR_GATEWAY_STUN = 0xFFFECC,
  DMR_GATEWAY_KILL = 0xFFFECF, DMR_GATEWAY_ALL_MS = 0xFFFED4,
};
char const *dmr_tier3_gateway_name(uint32_t address); // NULL for an ordinary address

enum dmr_aloha_flavor { DMR_ALOHA_STANDARD = 0, DMR_ALOHA_CAPACITY_MAX, DMR_ALOHA_HYTERA };
struct dmr_csbk_aloha {
  enum dmr_aloha_flavor flavor;
  bool tsccas;                  // 17: this TSCC supports a TSCCAS (TS 102 361-4 table 7.19; sdrtrunk: reserved)
  bool site_timeslot_sync;      // 18
  uint8_t version;              // 19-21
  bool timing_offset;           // 22
  bool active_network_connection; // 23
  uint8_t mask;                 // 24-28
  uint8_t service_function;     // 29-30
  uint8_t nrand_wait;           // 31-34
  bool registration_required;   // 35
  uint8_t backoff;              // 36-39
  struct dmr_system_code system; // 40-55 with PAR
  uint32_t radio;               // 56-79, 0 = none
};

enum dmr_ahoy_kind {
  DMR_AHOY_SERVICE_RADIO_CHECK = 0, DMR_AHOY_RADIO_CHECK, DMR_AHOY_AUTHENTICATE, DMR_AHOY_CANCEL_CALL,
  DMR_AHOY_STUN, DMR_AHOY_REVIVE, DMR_AHOY_KILL, DMR_AHOY_OTHER,
};
struct dmr_csbk_ahoy {
  uint8_t service_options_mirror; // 16-22
  bool service_kind_flag;       // 23
  bool ambient_listening;       // 24
  bool target_is_talkgroup;     // 25
  uint8_t appended_blocks;      // 26-27
  uint8_t service_kind;         // 28-31
  uint32_t target;              // 32-55
  uint32_t source;              // 56-79, the multi-purpose field
};
enum dmr_ahoy_kind dmr_ahoy_kind(struct dmr_csbk_ahoy const *a);
char const *dmr_service_kind_name(uint8_t kind);

enum dmr_ack_class { DMR_ACK_NACK = 0, DMR_ACK_ACK = 1, DMR_ACK_QUEUED = 2, DMR_ACK_WAIT = 3 };
struct dmr_csbk_ack {
  uint8_t opcode;
  uint8_t fid;                  // 0x00, or 0x08 / 0x68 for the Hytera copies
  uint8_t response_info;        // 16-22
  uint8_t reason;               // 23-30
  bool group_flag;              // 16, overlapping the response info: not relied on
  uint32_t target;              // 32-55
  uint32_t source;              // 56-79
};
static inline enum dmr_ack_class dmr_ack_class(struct dmr_csbk_ack const *a){ return (enum dmr_ack_class)(a->reason >> 6); }
char const *dmr_ack_reason_name(uint8_t reason); // NULL for a code not listed (Queued-for-busy is 0xA1, not sdrtrunk's 0xAA)

// NACK_Rsp (CSBKO 38, FID 0), TS 102 361-2 7.1.2.4 table 7.6: a Tier II refusal, not a Tier III
// acknowledgement, with its own layout (the source before the target)
struct dmr_csbk_nack_response {
  bool additional_info;         // 16
  bool ms_sourced;              // 17
  uint8_t service_type;         // 18-23: the CSBKO of the service refused
  uint8_t reason;               // 24-31: 0x21 = the MS does not support the service
  uint32_t source;              // 32-55
  uint32_t target;              // 56-79
};

enum dmr_tier3_grant_kind {
  DMR_T3G_PRIVATE_VOICE = 0, DMR_T3G_TALKGROUP_VOICE, DMR_T3G_BROADCAST_TALKGROUP_VOICE, DMR_T3G_PRIVATE_DATA,
  DMR_T3G_TALKGROUP_DATA, DMR_T3G_DUPLEX_PRIVATE_VOICE, DMR_T3G_DUPLEX_PRIVATE_DATA, DMR_T3G_PRIVATE_DATA_MULTI,
  DMR_T3G_TALKGROUP_DATA_MULTI,
};
struct dmr_csbk_grant {
  enum dmr_tier3_grant_kind kind;
  uint8_t opcode;
  uint16_t lcn;                 // 16-27
  uint8_t timeslot;             // 28, as 1 or 2
  bool flag29;                  // data: HI_RATE; TV / BTV: Late_Entry (TS 102 361-4 tables 7.11-7.15)
  bool emergency;               // 30
  bool flag31;                  // duplex: call direction (the addresses are swapped); else offset timing
  uint32_t destination;         // 32-55 as sent
  uint32_t source;              // 56-79 as sent
};
char const *dmr_tier3_grant_name(enum dmr_tier3_grant_kind kind);
bool dmr_csbk_grant_is_data(struct dmr_csbk_grant const *g);
bool dmr_csbk_grant_is_duplex(struct dmr_csbk_grant const *g);
bool dmr_csbk_grant_to_talkgroup(struct dmr_csbk_grant const *g);
uint32_t dmr_csbk_grant_called(struct dmr_csbk_grant const *g);  // with the duplex swap applied
uint32_t dmr_csbk_grant_caller(struct dmr_csbk_grant const *g);
struct dmr_channel_ref dmr_csbk_grant_channel(struct dmr_csbk_grant const *g);

struct dmr_csbk_clear {         // P_CLEAR
  uint16_t lcn;                 // 16-27, the channel to return to (timeslot 1)
  bool target_is_talkgroup;     // 31
  uint32_t destination;
  uint32_t source;
};
struct dmr_csbk_protect {       // P_PROTECT
  uint8_t kind;                 // 28-30
  bool target_is_talkgroup;     // 31
  uint32_t destination;
  uint32_t source;
};
char const *dmr_protect_kind_name(uint8_t kind);
struct dmr_csbk_move_tscc {     // C_MOVE
  uint8_t mask;                 // 25-29
  bool registration_required;   // 35
  uint8_t backoff;              // 36-39
  uint16_t lcn;                 // 44-55
  uint32_t radio;               // 56-79, 0 = all
};
struct dmr_csbk_preamble {
  bool data_follows;            // 16
  bool target_is_talkgroup;     // 17
  uint8_t blocks_to_follow;     // 24-31
  uint32_t target;
  uint32_t source;
};

// C_BCAST (CSBKO 40) and the Hytera announcements
enum {
  DMR_BCAST_ANNOUNCE_WITHDRAW_TSCC = 0, DMR_BCAST_CALL_TIMERS = 1, DMR_BCAST_VOTE_NOW = 2, DMR_BCAST_LOCAL_TIME = 3,
  DMR_BCAST_MASS_REGISTRATION = 4, DMR_BCAST_CHANNEL_FREQUENCY = 5, DMR_BCAST_ADJACENT_SITE = 6,
};
struct dmr_bcast_common {
  uint8_t fid;
  uint8_t type;                 // 16-20
  uint16_t parameters1;         // 21-34
  bool registration_required;   // 35
  uint8_t backoff;              // 36-39
  struct dmr_system_code system; // 40-55 with PAR: this site's
  uint32_t parameters2;         // 56-79
};
static inline uint8_t dmr_bcast_type(struct dmr_csbk_block const *k){ return (uint8_t)dmr_csbk_bits(k,16,5); }
struct dmr_csbk_announce_withdraw_tscc {
  struct dmr_bcast_common common;
  uint8_t color_code1, color_code2; // 25-28, 29-32
  bool add1, add2;              // 33, 34
  uint16_t lcn1, lcn2;          // 56-67, 68-79 (0 = none)
};
struct dmr_csbk_call_timers {
  struct dmr_bcast_common common;
  uint16_t emergency;           // 21-29
  uint8_t packet;               // 30-34
  uint16_t ms_to_ms;            // 56-67
  uint16_t ms_to_line;          // 68-79
};
enum { DMR_CALL_TIMER_INFINITE = -1 };
int dmr_call_timer_emergency_seconds(int v);
int dmr_call_timer_packet_seconds(int v);
int dmr_call_timer_voice_seconds(int v);
// Vote now (type 2) and adjacent site (type 6): another site and its control channel
struct dmr_csbk_other_site {
  struct dmr_bcast_common common;
  struct dmr_system_code other; // 21-34, no PAR
  bool network_status_available; // 56
  bool active_network_connection; // 57
  uint8_t confirmed_priority;   // 58-60
  uint8_t adjacent_priority;    // 61-63
  uint16_t lcn;                 // 68-79
};
struct dmr_csbk_local_time {
  struct dmr_bcast_common common;
  uint8_t day;                  // 21-25
  uint8_t month;                // 26-29
  uint8_t utc_offset_hours;     // 30-33: 0-14, 15 = not sent (TS 102 361-4 table 7.73)
  bool utc_offset_negative;     // 34: local time lags UTC
  uint8_t hour;                 // 56-60
  uint8_t minute;               // 61-66
  uint8_t second;               // 67-72
  uint8_t day_of_week;          // 73-75
  uint8_t utc_offset_fraction;  // 76-77
};
struct dmr_csbk_mass_registration {
  struct dmr_bcast_common common;
  uint8_t window;               // 26-29
  uint8_t aloha_mask;           // 30-34
  uint32_t radio;               // 56-79
};

// Layouts neither sdrtrunk nor OP25 parses, from TS 102 361-2 / -4 (see dmrcsbk.c)
struct dmr_csbk_unit_to_unit {  // UU_V_Req, UU_Ans_Rsp
  bool is_answer;
  uint8_t service_options;      // 16-23
  uint8_t answer_response;      // 24-31
  uint32_t target;
  uint32_t source;
};
struct dmr_csbk_bs_downlink_activation { // BS_Dwn_Act
  uint32_t bs_address;          // 32-55
  uint32_t source;              // 56-79
};
struct dmr_csbk_random_access { // C_RAND
  uint8_t service_options;      // 16-22
  bool proxy_flag;              // 23
  uint8_t appended_supplementary_data; // 24-25
  uint8_t appended_short_data;  // 26-27
  uint8_t service_kind;         // 28-31
  uint32_t target;
  uint32_t source;
};

// ---------------- Motorola: Capacity Plus, Connect Plus, Capacity Max ----------------
// Layouts after sdrtrunk (GPL-3, Dennis Sheirer) message/data/csbk/motorola/*.java; the Connect Plus
// neighbours and voice channel user also OP25 (GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al.)

struct dmr_csbk_cap_plus_neighbors {
  uint8_t lcss;                 // 16-17
  uint8_t rest_lsn;             // 19-23
  bool async_beacon;            // 24
  uint8_t site;                 // 25-28
  uint8_t neighbor_count;       // 29-31 as sent; at most 6 fit
  struct { uint8_t site; uint8_t rest_lsn; } neighbors[6]; // from bit 32, 4 + 4 bits each
};
static inline int dmr_cap_plus_neighbors_present(struct dmr_csbk_cap_plus_neighbors const *n){
  return n->neighbor_count < 6 ? n->neighbor_count : 6;
}
enum { DMR_CAP_PLUS_ACTIVITY_MAX = 24 }; // 16 voice + 8 data
struct dmr_cap_plus_activity {
  uint8_t lsn;
  bool data;                    // false: voice (id: an 8-bit talkgroup); true: data revert (id: a 16-bit radio)
  bool id_known;                // false: the identifier is in a continuation segment
  uint16_t id;
};
struct dmr_csbk_cap_plus_site_status {
  uint8_t segment;              // 16-17: 2 first, 3 single, 0 continuation, 1 last
  uint8_t rest_lsn;             // 19-23
  int activity_count;
  struct dmr_cap_plus_activity activity[DMR_CAP_PLUS_ACTIVITY_MAX];
  uint64_t continuation;        // bits 24-79 of a segment that is not the first
};
static inline bool dmr_cap_plus_first_segment(struct dmr_csbk_cap_plus_site_status const *s){
  return s->segment == 2 || s->segment == 3;
}
// The activity on an LSN, or NULL when the message shows it idle
struct dmr_cap_plus_activity const *dmr_cap_plus_find(struct dmr_csbk_cap_plus_site_status const *s,int lsn,bool data);
struct dmr_csbk_cap_plus_preamble {
  bool data_follows;            // 16
  bool target_is_talkgroup;     // 17
  uint8_t blocks_to_follow;     // 18-22
  uint8_t unknown1;             // 24-31
  uint8_t unknown2;             // 32-39
  uint16_t target;              // 40-55
  uint8_t unknown3;             // 56-63
  uint16_t source;              // 64-79
};
struct dmr_csbk_cap_plus_data_window {
  bool is_grant;
  uint16_t radio;               // 24-39
  uint8_t window;               // 40-47
  uint8_t super_frame;          // 48-55
};
// The 5-bit Connect Plus channel field, in both readings (dmrcsbk.c)
struct dmr_con_plus_slot {
  uint8_t air;                  // the five bits
  int lsn_minus_one;            // sdrtrunk: air - 1, used as an LSN
  uint8_t repeater;             // OP25: the first four bits
  uint8_t timeslot;             // OP25: the fifth bit + 1
};
struct dmr_channel_ref dmr_con_plus_slot_channel(struct dmr_con_plus_slot const *s); // NONE for repeater 0
struct dmr_csbk_con_plus_neighbors {
  uint8_t sites[5];             // 16-55, 8 bits each, 0 = none
  uint32_t trailing;            // 56-79
};
static inline uint8_t dmr_con_plus_sixth_site(struct dmr_csbk_con_plus_neighbors const *n){
  return (uint8_t)(n->trailing >> 16);
}
struct dmr_csbk_con_plus_voice_channel_user {
  uint32_t source;              // 16-39
  uint32_t group;               // 40-63
  struct dmr_con_plus_slot slot; // 64-68
  uint8_t unknown;              // 72-79
};
struct dmr_csbk_con_plus_data_channel_grant {
  uint32_t target;              // 16-39
  struct dmr_con_plus_slot slot; // 40-44
  uint8_t unknown;              // 48-55
};
struct dmr_csbk_con_plus_ota_announcement {
  uint8_t message_type;         // 16-23
  uint16_t version;             // 24-39
  struct dmr_con_plus_slot slot; // 63-67
};
struct dmr_csbk_con_plus_terminate_channel_grant {
  uint32_t target;              // 16-39
  uint8_t unknown[5];           // 40-79
};
enum dmr_con_plus_radio_event_kind {
  DMR_CPRE_CSBKO_16 = 0, DMR_CPRE_REGISTRATION_REQUEST, DMR_CPRE_REGISTRATION_RESPONSE, DMR_CPRE_TALKGROUP_AFFILIATION,
};
struct dmr_csbk_con_plus_radio_event {
  enum dmr_con_plus_radio_event_kind kind;
  uint32_t source;              // 16-39
  uint32_t target;              // 40-63
  uint16_t unknown;             // 64-79
};
struct dmr_csbk_con_plus_data_window {
  bool is_grant;
  uint32_t radio;
  uint8_t window;
  uint8_t super_frame;
  uint8_t repeater;             // announcement only
};
struct dmr_csbk_cap_max_open_mode_update {
  uint16_t lcn;                 // 16-27
  uint8_t unknown;              // 28-31
  uint32_t talkgroup_ts1;       // 32-55
  uint32_t talkgroup_ts2;       // 56-79 (sdrtrunk's bit list fixed: dmrcsbk.c)
};
// The timeslot 2 talkgroup as sdrtrunk's faulty bit list reads it: for comparing logs only
uint32_t dmr_cap_max_ts2_as_sdrtrunk(struct dmr_csbk_block const *k);
struct dmr_csbk_cap_max_advantage_mode_update {
  struct { uint16_t lcn; uint16_t talkgroup_ts1; uint16_t talkgroup_ts2; } repeaters[2];
};

// ---------------- Hytera ----------------
// Layouts after sdrtrunk alone (GPL-3, Dennis Sheirer) message/data/csbk/hytera/*.java

struct dmr_csbk_hytera_talker_status {
  uint8_t unknown1;             // 16-23
  uint8_t unknown2;             // 24-31
  bool talker_inactive;         // 30
  uint32_t talker;              // 32-55
  uint32_t source;              // 56-79
};
struct dmr_csbk_hytera_xpt_site_state {
  uint8_t sequence;             // 0-1
  uint8_t free_repeater;        // 16-19, 0 = all busy
  uint8_t state[3];             // 20-31
  uint8_t hashed_address[6];    // 32-79: [2i] TS1, [2i + 1] TS2 of repeater i
};
static inline int dmr_xpt_repeater_number(struct dmr_csbk_hytera_xpt_site_state const *s,int i){
  return s->sequence <= 2 ? 3 * s->sequence + i + 1 : 0;
}
struct dmr_csbk_hytera_xpt_adjacent_sites {
  uint8_t sequence;             // 0-1
  struct { uint8_t site; uint8_t free_repeater; } sites[4]; // from 16, 16 bits each: site 5, free repeater 4
};
struct dmr_csbk_hytera_xpt_preamble {
  bool data_follows;            // 16
  bool target_is_talkgroup;     // 17
  uint8_t blocks_to_follow;     // 24-31
  uint8_t free_repeater;        // 32-35
  uint8_t priority_repeater;    // 36-39
  uint16_t target;              // 40-55
  uint8_t priority_hashed_address; // 56-63
  uint16_t source;              // 64-79
};
struct dmr_csbk_hytera_sms_available {
  uint16_t unknown;             // 16-31
  uint32_t destination;         // 32-55
  uint32_t source;              // 56-79
};
// A Hytera "compressed" talkgroup as the number a user dials
uint32_t dmr_hytera_dialable_talkgroup(uint32_t address);

// ---------------- The message ----------------

// What a CSBK is. The order is fixed (the tests compare it)
enum dmr_csbk_kind {
  DMR_CSBK_NONE = 0,           // not parsed: the CRC failed
  DMR_CSBK_UNKNOWN,            // a (FID, CSBKO) with no parser: u.unknown
  DMR_CSBK_ALOHA, DMR_CSBK_AHOY, DMR_CSBK_ACK, DMR_CSBK_NACK_RESPONSE, DMR_CSBK_GRANT, DMR_CSBK_CLEAR, DMR_CSBK_PROTECT, DMR_CSBK_MOVE_TSCC,
  DMR_CSBK_PREAMBLE, DMR_CSBK_BROADCAST, DMR_CSBK_ANNOUNCE_WITHDRAW_TSCC, DMR_CSBK_CALL_TIMERS, DMR_CSBK_VOTE_NOW,
  DMR_CSBK_LOCAL_TIME, DMR_CSBK_MASS_REGISTRATION, DMR_CSBK_CHANNEL_FREQUENCY, DMR_CSBK_ADJACENT_SITE,
  DMR_CSBK_UNIT_TO_UNIT, DMR_CSBK_BS_DOWNLINK_ACTIVATION, DMR_CSBK_RANDOM_ACCESS,
  DMR_CSBK_CAP_PLUS_NEIGHBORS, DMR_CSBK_CAP_PLUS_SITE_STATUS, DMR_CSBK_CAP_PLUS_PREAMBLE, DMR_CSBK_CAP_PLUS_DATA_WINDOW,
  DMR_CSBK_CON_PLUS_NEIGHBORS, DMR_CSBK_CON_PLUS_VOICE_CHANNEL_USER, DMR_CSBK_CON_PLUS_DATA_CHANNEL_GRANT,
  DMR_CSBK_CON_PLUS_OTA_ANNOUNCEMENT, DMR_CSBK_CON_PLUS_TERMINATE_CHANNEL_GRANT, DMR_CSBK_CON_PLUS_RADIO_EVENT,
  DMR_CSBK_CON_PLUS_DATA_WINDOW, DMR_CSBK_CAP_MAX_OPEN_MODE_UPDATE, DMR_CSBK_CAP_MAX_ADVANTAGE_MODE_UPDATE,
  DMR_CSBK_HYTERA_TALKER_STATUS, DMR_CSBK_HYTERA_XPT_SITE_STATE, DMR_CSBK_HYTERA_XPT_ADJACENT_SITES,
  DMR_CSBK_HYTERA_XPT_PREAMBLE, DMR_CSBK_HYTERA_SMS_AVAILABLE,
};
struct dmr_csbk_unknown {
  uint8_t opcode;
  uint8_t fid;
  uint64_t payload;             // bits 16-79
};

enum { DMR_MBC_MAX_CONTINUATION_BLOCKS = 3 };

struct dmr_csbk_message {
  struct dmr_csbk_block block;  // the common part; of the header for a multi-block message
  enum dmr_csbk_kind kind;
  union {
    struct dmr_csbk_unknown unknown;
    struct dmr_csbk_aloha aloha;
    struct dmr_csbk_nack_response nack_response;
    struct dmr_csbk_ahoy ahoy;
    struct dmr_csbk_ack ack;
    struct dmr_csbk_grant grant;
    struct dmr_csbk_clear clear;
    struct dmr_csbk_protect protect;
    struct dmr_csbk_move_tscc move_tscc;
    struct dmr_csbk_preamble preamble;
    struct dmr_bcast_common broadcast;          // BROADCAST and CHANNEL_FREQUENCY
    struct dmr_csbk_announce_withdraw_tscc announce_withdraw_tscc;
    struct dmr_csbk_call_timers call_timers;
    struct dmr_csbk_other_site other_site;      // VOTE_NOW and ADJACENT_SITE
    struct dmr_csbk_local_time local_time;
    struct dmr_csbk_mass_registration mass_registration;
    struct dmr_csbk_unit_to_unit unit_to_unit;
    struct dmr_csbk_bs_downlink_activation bs_downlink_activation;
    struct dmr_csbk_random_access random_access;
    struct dmr_csbk_cap_plus_neighbors cap_plus_neighbors;
    struct dmr_csbk_cap_plus_site_status cap_plus_site_status;
    struct dmr_csbk_cap_plus_preamble cap_plus_preamble;
    struct dmr_csbk_cap_plus_data_window cap_plus_data_window;
    struct dmr_csbk_con_plus_neighbors con_plus_neighbors;
    struct dmr_csbk_con_plus_voice_channel_user con_plus_voice_channel_user;
    struct dmr_csbk_con_plus_data_channel_grant con_plus_data_channel_grant;
    struct dmr_csbk_con_plus_ota_announcement con_plus_ota_announcement;
    struct dmr_csbk_con_plus_terminate_channel_grant con_plus_terminate_channel_grant;
    struct dmr_csbk_con_plus_radio_event con_plus_radio_event;
    struct dmr_csbk_con_plus_data_window con_plus_data_window;
    struct dmr_csbk_cap_max_open_mode_update cap_max_open_mode_update;
    struct dmr_csbk_cap_max_advantage_mode_update cap_max_advantage_mode_update;
    struct dmr_csbk_hytera_talker_status hytera_talker_status;
    struct dmr_csbk_hytera_xpt_site_state hytera_xpt_site_state;
    struct dmr_csbk_hytera_xpt_adjacent_sites hytera_xpt_adjacent_sites;
    struct dmr_csbk_hytera_xpt_preamble hytera_xpt_preamble;
    struct dmr_csbk_hytera_sms_available hytera_sms_available;
  } u;

  // Multi-block control: a message built from a header and its continuation blocks passed both CRCs
  bool from_mbc;
  uint8_t mbc_continuation_blocks;
  uint8_t mbc_continuation_bits[96 * DMR_MBC_MAX_CONTINUATION_BLOCKS]; // 96 per block, as decoded
  bool has_absolute;            // the CG_AP block, for the messages that carry one
  struct dmr_cgap absolute;
};
static inline bool dmr_csbk_parsed(struct dmr_csbk_message const *m){ return m->kind != DMR_CSBK_NONE; }

// Parse the payload of a block that has ALREADY passed its CRC into m->kind and m->u (the rest of m is
// not touched). mobile_sourced: the burst carried an MS sync; it decides FID 0 CSBKO 56
void dmr_csbk_parse_body(struct dmr_csbk_message *m,struct dmr_csbk_block const *k,bool mobile_sourced);
// Check and parse one CSBK. crc_mask: DMR_CRC_MASK_CSBK, or a vendor mask the caller decided to accept.
// A block that fails has kind DMR_CSBK_NONE; block.observed_mask says which mask would have passed
void dmr_csbk_parse(struct dmr_csbk_message *m,uint8_t const info96[96],uint8_t slot,uint8_t color_code,
                    uint64_t timestamp_us,uint16_t crc_mask,bool mobile_sourced);
// The common part of any C_BCAST announcement, or NULL
struct dmr_bcast_common const *dmr_csbk_broadcast_common(struct dmr_csbk_message const *m);
// An "announce channel frequency" broadcast with a plausible CG_AP block: its LCN -> frequency
bool dmr_csbk_channel_frequency(struct dmr_csbk_message const *m,struct dmr_cgap *p);
// One line for the control log (a failed CRC is described as such)
int dmr_csbk_describe(char *buf,size_t size,struct dmr_csbk_message const *m);

// ---------------- Multi-block control ----------------
// After sdrtrunk (GPL-3, Dennis Sheirer) message/data/mbc/*.java, with both CRCs checked; the continuation
// CRC's span is OP25's (GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al.)

enum dmr_mbc_status {
  DMR_MBC_NOT_MBC = 0,          // neither a header nor a continuation block
  DMR_MBC_HEADER_ACCEPTED,      // waiting for continuation blocks
  DMR_MBC_HEADER_CRC_FAILED,    // nothing started; observed_mask says what would have passed
  DMR_MBC_CONTINUATION_ACCEPTED, // a block with LB = 0 was stored
  DMR_MBC_COMPLETE,             // the message is set
  DMR_MBC_NO_HEADER,            // a continuation block with no header before it on this timeslot
  DMR_MBC_STALE,                // too long after the previous block; abandoned
  DMR_MBC_TOO_MANY_BLOCKS,      // more than DMR_MBC_MAX_CONTINUATION_BLOCKS; abandoned
  DMR_MBC_CRC_FAILED,           // the continuation blocks failed their CRC; abandoned
};
struct dmr_mbc_event {
  enum dmr_mbc_status status;
  bool has_message;             // only with DMR_MBC_COMPLETE
  struct dmr_csbk_message message;
  uint16_t observed_mask;       // HEADER_CRC_FAILED, CRC_FAILED
};
struct dmr_mbc_stats {
  uint64_t headers;
  uint64_t header_crc_failures;
  uint64_t completed;
  uint64_t crc_failures;
  uint64_t orphan_blocks;       // NO_HEADER
  uint64_t abandoned;           // stale, too many blocks, or cut short by another burst
};
struct dmr_mbc_pending {
  bool active;
  struct dmr_csbk_block header;
  bool mobile_sourced;          // the header came with an MS or direct mode sync
  int blocks;
  uint64_t last_timestamp_us;
  uint8_t bits[96 * DMR_MBC_MAX_CONTINUATION_BLOCKS];
};
struct dmr_mbc_assembler {
  uint64_t max_block_gap_us;    // 0 = no limit
  struct dmr_mbc_pending pending[2]; // timeslot 1 (and 0), timeslot 2
  struct dmr_mbc_stats stats;
};
#define DMR_MBC_MAX_BLOCK_GAP_US 90000
void dmr_mbc_init(struct dmr_mbc_assembler *a,uint64_t max_block_gap_us);
// The messages whose first continuation block is a CG_AP block. mobile_sourced: the header came from a
// mobile (CSBKO 56 from a mobile is BS_Dwn_Act, which carries none)
bool dmr_mbc_carries_absolute(struct dmr_csbk_block const *header,bool mobile_sourced);
// Feed every data burst of a carrier: headers and continuation blocks are assembled, any other data type
// abandons a message in progress on that timeslot. mobile_sourced: the burst carried an MS or direct
// mode sync; a header's decides how the completed message is parsed (dmr_csbk_parse_body())
void dmr_mbc_on_burst(struct dmr_mbc_assembler *a,struct dmr_mbc_event *e,enum dmr_data_type type,
                      uint8_t const info96[96],uint8_t slot,uint8_t color_code,uint64_t timestamp_us,
                      bool mobile_sourced);
void dmr_mbc_on_header(struct dmr_mbc_assembler *a,struct dmr_mbc_event *e,uint8_t const info96[96],uint8_t slot,
                       uint8_t color_code,uint64_t timestamp_us,bool mobile_sourced);
void dmr_mbc_on_continuation(struct dmr_mbc_assembler *a,struct dmr_mbc_event *e,uint8_t const info96[96],
                             uint8_t slot,uint64_t timestamp_us);
void dmr_mbc_on_other_burst(struct dmr_mbc_assembler *a,uint8_t slot); // any other burst on the timeslot
void dmr_mbc_reset(struct dmr_mbc_assembler *a);                       // carrier lost or retuned
bool dmr_mbc_in_progress(struct dmr_mbc_assembler const *a,uint8_t slot);

// ---------------- Grants, whatever the system ----------------
// From the layouts above (sdrtrunk, GPL-3, Dennis Sheirer; OP25, GPL-3, Max H. Parke KA1RBI, Graham J. Norbury et al.)

enum dmr_grant_kind {
  DMR_GRANT_GROUP_VOICE = 0, DMR_GRANT_UNIT_VOICE, DMR_GRANT_BROADCAST_VOICE, DMR_GRANT_GROUP_DATA,
  DMR_GRANT_UNIT_DATA,
};
enum dmr_grant_flavor { DMR_GRANT_TIER3 = 0, DMR_GRANT_CONNECT_PLUS, DMR_GRANT_CAPACITY_MAX };
struct dmr_grant {
  enum dmr_grant_kind kind;
  enum dmr_grant_flavor flavor;
  uint32_t destination;         // the talkgroup, or the called radio
  bool destination_is_group;
  uint32_t source;              // the caller, when has_source
  bool has_source;
  struct dmr_channel_ref channel; // NONE: the message named no usable channel (log it, do not tune)
  bool emergency;
  bool protect_flag;            // the CSBK's PF bit (sdrtrunk calls it encrypted). Says nothing of the call's encryption
  bool duplex;                  // Tier III duplex private call
  bool activity_update;         // repeated while the call lasts: it confirms a call and does not start one
  uint8_t opcode;
  uint8_t fid;
  uint8_t control_slot;         // the slot it was heard on
  uint64_t timestamp_us;
};
enum { DMR_MAX_GRANTS = 4 };    // per message
static inline bool dmr_grant_is_data(struct dmr_grant const *g){
  return g->kind == DMR_GRANT_GROUP_DATA || g->kind == DMR_GRANT_UNIT_DATA;
}
char const *dmr_grant_kind_name(enum dmr_grant_kind k);
char const *dmr_grant_flavor_name(enum dmr_grant_flavor f);
// The grants a message carries (0 to DMR_MAX_GRANTS); none for a message whose CRC failed
int dmr_csbk_grants(struct dmr_grant grants[DMR_MAX_GRANTS],struct dmr_csbk_message const *m);
// "GRANT group voice tier3 tg=1234 from=5678 LCN 12 TS2 EMERGENCY"
int dmr_grant_describe(char *buf,size_t size,struct dmr_grant const *g);

// ---------------- The channel map: LCN -> frequency of one site ----------------

enum dmr_map_source { DMR_MAP_CONFIG = 0, DMR_MAP_AIR };
struct dmr_map_entry {
  uint16_t lcn;
  uint64_t downlink_hz;
  uint64_t uplink_hz;           // 0 = not known
  enum dmr_map_source source;
};
// A new value that disagreed with the one held
struct dmr_map_conflict {
  uint16_t lcn;
  uint64_t held_hz;
  enum dmr_map_source held_source;
  uint64_t offered_hz;
  enum dmr_map_source offered_source;
  bool replaced;                // the offered value is now the map's
};
int dmr_map_conflict_describe(char *buf,size_t size,struct dmr_map_conflict const *c);
struct dmr_channel_map {
  uint64_t tolerance_hz;        // two frequencies this close are the same channel
  size_t count;
  size_t capacity;
  struct dmr_map_entry *entries; // sorted by LCN
  uint64_t conflicts;
};
void dmr_map_init(struct dmr_channel_map *m,uint64_t tolerance_hz);
void dmr_map_free(struct dmr_channel_map *m);
// A configured channel: replaces what is held. True (and *conflict, which may be NULL) when that was
// another frequency
bool dmr_map_set_from_config(struct dmr_channel_map *m,uint16_t lcn,uint64_t downlink_hz,uint64_t uplink_hz,
                             struct dmr_map_conflict *conflict);
// A channel announced on the air: fills a gap, confirms a match (and adds a missing uplink), never
// replaces a configured frequency; a newer air value replaces an older one. True on a conflict.
// A zero downlink is ignored
bool dmr_map_learn_from_air(struct dmr_channel_map *m,uint16_t lcn,uint64_t downlink_hz,uint64_t uplink_hz,
                            struct dmr_map_conflict *conflict);
bool dmr_map_learn_from_cgap(struct dmr_channel_map *m,struct dmr_cgap const *p,struct dmr_map_conflict *conflict);
struct dmr_map_entry const *dmr_map_find(struct dmr_channel_map const *m,uint16_t lcn);
uint64_t dmr_map_downlink_hz(struct dmr_channel_map const *m,uint16_t lcn); // 0 = not in the map
// The frequency to tune for a channel a message named: its own downlink, else the map's; 0 = not known
uint64_t dmr_map_resolve(struct dmr_channel_map const *m,struct dmr_channel_ref const *c);

#endif
