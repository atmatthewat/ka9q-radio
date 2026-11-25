// DMR (ETSI TS 102 361) types shared by the receiver, the burst sink, the message layer, the call
// tracker and dmrd: the air interface's constants, the sync words, and one burst as the sink hands it on
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMR_H
#define _DMR_H 1

#include <stdbool.h>
#include <stdint.h>

// Bit and dibit numbering: index 0 is the first transmitted. A dibit is (msb << 1) | lsb, msb sent
// first; dibit to symbol is 01 +3, 00 +1, 10 -1, 11 -3 (TS 102 361-1 table 10.3), as in P25
enum {
  DMR_SYMBOL_RATE = 4800,
  DMR_SLOT_DIBITS = 144,       // one 30 ms timeslot
  DMR_CACH_DIBITS = 12,        // base station outbound: the CACH ahead of each burst (MS / direct: guard time)
  DMR_CACH_BITS = 24,
  DMR_BURST_DIBITS = 132,      // 27.5 ms burst
  DMR_BURST_BITS = 264,
  DMR_SYNC_DIBITS = 24,
  DMR_SYNC_BITS = 48,
  DMR_SYNC_OFFSET_BITS = 108,  // the sync / EMB field's first bit in the burst
  DMR_SYNC_OFFSET_DIBITS = 54,
  DMR_VOICE_FRAME_BITS = 72,   // one AMBE+2 frame as transmitted
  DMR_VOICE_FRAME_BYTES = 9,
  DMR_VOICE_FRAMES = 3,        // per voice burst
};

// The 48-bit sync words (TS 102 361-1 table 9.2; values as sdrtrunk's DMRSyncPattern.java, GPL-3,
// Dennis Sheirer). Each is 24 dibits of 01 (+3) and 11 (-3) only
enum dmr_sync {
  DMR_SYNC_BS_VOICE = 0,  // base station sourced voice (burst A of a superframe)
  DMR_SYNC_BS_DATA,       // base station sourced data / control
  DMR_SYNC_MS_VOICE,
  DMR_SYNC_MS_DATA,
  DMR_SYNC_MS_REVERSE,    // MS sourced standalone reverse channel
  DMR_SYNC_DIRECT_VOICE_TS1, // TDMA direct mode
  DMR_SYNC_DIRECT_DATA_TS1,
  DMR_SYNC_DIRECT_VOICE_TS2,
  DMR_SYNC_DIRECT_DATA_TS2,
  DMR_SYNC_RESERVED,
  DMR_SYNC_NONE,          // no sync in this burst (voice B-F)
  DMR_SYNC_PATTERNS = DMR_SYNC_NONE,
};
extern uint64_t const Dmr_sync_words[DMR_SYNC_PATTERNS]; // dmrtypes.c
// Dibit i (0 = first sent) of a sync word
static inline int dmr_sync_dibit(enum dmr_sync p,int i){
  return (int)((Dmr_sync_words[p] >> (46 - 2 * i)) & 3);
}
static inline bool dmr_is_voice_sync(enum dmr_sync p){
  return p == DMR_SYNC_BS_VOICE || p == DMR_SYNC_MS_VOICE || p == DMR_SYNC_DIRECT_VOICE_TS1 || p == DMR_SYNC_DIRECT_VOICE_TS2;
}
static inline bool dmr_is_data_sync(enum dmr_sync p){
  return p == DMR_SYNC_BS_DATA || p == DMR_SYNC_MS_DATA || p == DMR_SYNC_DIRECT_DATA_TS1 || p == DMR_SYNC_DIRECT_DATA_TS2;
}

enum dmr_station { DMR_STATION_UNKNOWN = 0, DMR_STATION_BS, DMR_STATION_MS, DMR_STATION_DIRECT };
static inline enum dmr_station dmr_mode_of(enum dmr_sync p){
  switch(p){
  case DMR_SYNC_BS_VOICE: case DMR_SYNC_BS_DATA:
    return DMR_STATION_BS;
  case DMR_SYNC_MS_VOICE: case DMR_SYNC_MS_DATA: case DMR_SYNC_MS_REVERSE:
    return DMR_STATION_MS;
  case DMR_SYNC_DIRECT_VOICE_TS1: case DMR_SYNC_DIRECT_DATA_TS1: case DMR_SYNC_DIRECT_VOICE_TS2: case DMR_SYNC_DIRECT_DATA_TS2:
    return DMR_STATION_DIRECT;
  default:
    return DMR_STATION_UNKNOWN;
  }
}

// What a burst carries. A voice superframe is six bursts A-F on one slot (360 ms): A carries the voice
// sync, B-F the EMB and 32 bits of embedded signalling in its place
enum dmr_kind {
  DMR_KIND_DATA = 0,       // a data sync; the slot type names the data type
  DMR_KIND_VOICE_A,
  DMR_KIND_VOICE_B,
  DMR_KIND_VOICE_C,
  DMR_KIND_VOICE_D,
  DMR_KIND_VOICE_E,
  DMR_KIND_VOICE_F,
  DMR_KIND_VOICE_UNKNOWN,  // a voice burst (valid EMB) whose place in the superframe is not known yet (late entry)
  DMR_KIND_REVERSE_CHANNEL,
};
static inline bool dmr_is_voice(enum dmr_kind k){
  return k >= DMR_KIND_VOICE_A && k <= DMR_KIND_VOICE_UNKNOWN;
}

// Slot type data types (TS 102 361-1 table 9.13)
enum dmr_data_type {
  DMR_DT_PI_HEADER = 0,
  DMR_DT_VOICE_LC_HEADER = 1,
  DMR_DT_TERMINATOR_LC = 2,
  DMR_DT_CSBK = 3,
  DMR_DT_MBC_HEADER = 4,
  DMR_DT_MBC_CONTINUATION = 5,
  DMR_DT_DATA_HEADER = 6,
  DMR_DT_RATE12_DATA = 7,
  DMR_DT_RATE34_DATA = 8,
  DMR_DT_IDLE = 9,
  DMR_DT_RATE1_DATA = 10,
  DMR_DT_USB = 11,         // unified single block
  DMR_DT_RESERVED12 = 12,
  DMR_DT_RESERVED13 = 13,
  DMR_DT_RESERVED14 = 14,
  DMR_DT_RESERVED15 = 15,
};

// Feature set IDs: the manufacturer whose layout a link control or CSBK follows
enum {
  DMR_FID_STANDARD = 0x00,
  DMR_FID_CONNECT_PLUS = 0x06,  // Motorola Connect Plus
  DMR_FID_HYTERA_08 = 0x08,     // Hytera Tier III
  DMR_FID_MOTOROLA = 0x10,      // Motorola Capacity Plus, Capacity Max, IP Site Connect
  DMR_FID_HYTERA_68 = 0x68,     // Hytera XPT and Tier III
};

// EMB / TACT link control start-stop
enum dmr_lcss { DMR_LCSS_SINGLE = 0, DMR_LCSS_FIRST = 1, DMR_LCSS_LAST = 2, DMR_LCSS_CONTINUATION = 3 };

// One burst as the sink hands it on: the 264 burst bits with per-bit confidence (0 = no information,
// 1 = certain), the CACH before it on a base station carrier, and what the sink decoded to frame it.
// A field a burst does not have stays zero with its *_valid flag false
struct dmr_burst {
  uint64_t timestamp_us;   // of the burst's first dibit
  uint64_t dibit_clock;    // receiver symbol index of the burst's first dibit

  uint8_t slot;            // 1 or 2; 0 = not known
  enum dmr_station mode;
  enum dmr_sync sync;
  enum dmr_kind kind;
  float sync_correlation;  // of the sync that framed this burst (0-24); 0 for a flywheel burst
  // False: the sink placed this burst by counting alone: no sync, and its slot type or EMB did not
  // decode. Its bits are what was received there, which may be noise
  bool confirmed;
  // The carrier offset the sync's 24 known symbols show (their common level shift), Hz; only with
  // level_error_valid (a burst that carries a sync)
  bool level_error_valid;
  float level_error_hz;

  // Data bursts: the slot type (Golay(20,8))
  bool slot_type_valid;
  uint8_t color_code;      // from the slot type, or the EMB on voice B-F (voice A has neither: the frame's)
  enum dmr_data_type data_type;
  uint8_t slot_type_errors; // bits corrected

  // Voice bursts B-F: the EMB (QR(16,7,6)). emb_pi is ETSI's pre-emption and power control indicator,
  // NOT a privacy flag
  bool emb_valid;
  bool emb_pi;
  enum dmr_lcss emb_lcss;
  uint8_t emb_errors;      // bits corrected

  // Base station bursts: the 24 CACH bits as sent and the TACT (Hamming(7,4))
  bool has_cach;
  uint8_t cach[DMR_CACH_BITS];
  float cach_confidence[DMR_CACH_BITS];
  bool tact_valid;
  bool tact_access_busy;   // AT: the inbound channel is busy
  uint8_t tact_channel;    // TC: 0 = the burst that follows is timeslot 1, 1 = timeslot 2
  enum dmr_lcss tact_lcss;
  uint8_t tact_errors;     // bits corrected

  uint8_t bits[DMR_BURST_BITS];       // 0 / 1, as sent
  float confidence[DMR_BURST_BITS];
};

// A freshly cleared burst: every field zero but data_type DMR_DT_RESERVED15, sync DMR_SYNC_NONE and confirmed
void dmr_burst_init(struct dmr_burst *b);

#endif
