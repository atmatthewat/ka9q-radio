// DMR per-slot call tracker: from one channel's bursts and what the message layer made of them to
// voice records labelled clear or encrypted, call start and end events, and counters.
// dmrcall.c has the theory of operation, which is also the specification of the encryption rule
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRCALL_H
#define _DMRCALL_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmr.h"
#include "dmrmsg.h"

// ---------------- Why a transmission started and ended ----------------

enum dmr_call_start {
  DMR_START_HEADER = 0,    // a voice LC header that passed RS(12,9)
  DMR_START_PI_HEADER,     // a PI header with no voice LC header before it
  DMR_START_LATE_ENTRY,    // a voice burst with no transmission in progress
  DMR_START_NEW_TALKER,    // an embedded LC named another source or destination
  DMR_START_RESYNC,        // a voice burst off the superframe position or slot grid of the one in progress
  DMR_CALL_STARTS
};
char const *dmr_call_start_name(enum dmr_call_start r);

enum dmr_call_end {
  DMR_END_TERMINATOR = 0,  // a terminator with LC (by its slot type, whether or not its LC decoded)
  DMR_END_IDLE,            // an idle burst on the slot
  DMR_END_DATA_BURST,      // any other data burst on the slot
  DMR_END_NEW_HEADER,      // a voice LC header: the next transmission
  DMR_END_NEW_TALKER,
  DMR_END_RESYNC,
  DMR_END_FADE,            // no voice burst on the slot for fade_us
  DMR_END_NO_VOICE,        // a header or PI header that no voice followed in time
  DMR_END_SYNC_LOSS,       // dmr_call_on_sync_lost()
  DMR_END_RELEASE,         // dmr_call_end_call(): the channel was released (P_CLEAR)
  DMR_END_FLUSH,           // dmr_call_flush(): shutdown or retune
  DMR_CALL_ENDS
};
char const *dmr_call_end_name(enum dmr_call_end r);

// A transmission's encryption state, by the last word of each kind (dmrcall.c): Clear at its start,
// Encrypted while the last LC or the last encryption parameters said so, Clear again when the words
// that said so are undone by words of their own kind. DMR_ENC_UNKNOWN is only "no transmission"
enum dmr_encryption {
  DMR_ENC_UNKNOWN = 0,     // no transmission on the slot
  DMR_ENC_CLEAR,           // nothing in force says encrypted
  DMR_ENC_ENCRYPTED,       // the last LC, or the last encryption parameters, said encrypted
};

// ---------------- Configuration (dmrcall.c says what each is for) ----------------

struct dmr_call_config {
  uint64_t fade_us;                  // 1,000,000: a transmission ends after this long without voice
  uint64_t pre_voice_timeout_us;     // 360,000: a header that did not say encrypted waits this long for voice
  uint64_t voice_gap_us;             // 150,000: an embedded LC's fragments do not span a longer gap; 0 = off
  bool check_superframe_position;    // true: a voice burst off its superframe position starts a new transmission
  bool unconfirmed_is_missing;       // true: a burst the sink placed by counting alone is a missing burst ...
  int clean_voice_confirms_max_fec;  // 9: ... unless its voice needed at most this many corrections (-1 off)
  int unidentified_clear_max_fec;    // 9: before the transmission has an identity, a burst whose voice needed
                                     // more corrections is not labelled clear (noise, not speech); -1 off
  uint64_t slot_grid_tolerance_us;   // 5,000: a voice burst further off the 60 ms grid starts a new one; 0 off
  bool carry_encrypted;              // true: "encrypted" outlives an end that is no boundary
  bool carry_encrypted_across_sync_loss; // false: ... and a sync loss or a superframe resync
  bool record_unidentified;          // true: write the records of a transmission whose identity is not known
  // The system's talkgroups are in the compressed (dialable) form, TS 102 361-2 C.2.1.2 (sdrtrunk's
  // use_compressed_talkgroups, seen on Hytera Tier III): a group call's 24-bit destination is converted
  // (dmr_hytera_dialable_talkgroup()) before it is used for anything. Unit addresses and the vendor short
  // forms (8 / 16 bits) are not. False by default
  bool compressed_talkgroups;
};
void dmr_call_config_init(struct dmr_call_config *c);

// ---------------- The channel ----------------

// Where the bursts come from, as records and events name it. The strings are the caller's (NULL is
// ""); the tracker keeps copies, up to DMR_CALL_NAME_MAX - 1 bytes each
enum { DMR_CALL_NAME_MAX = 128, DMR_CALL_KEY_MAX = DMR_CALL_NAME_MAX + 8 };
struct dmr_channel {
  char const *system_name;
  char const *site_name;
  char const *channel_id;  // unique among the channels
  uint64_t frequency_hz;
  uint16_t lcn;            // the repeater's logical channel number in its site; 0 on a conventional channel
  uint32_t system_tag;     // the trunked site's identity; 0 = not known / conventional
};

// ---------------- The voice record ----------------

// One AMBE+2 frame with its call's identity and its encryption label. A record is clear only when
// flags has no DMR_VF_ENCRYPTED AND encryption_algorithm is DMR_VOICE_ALG_CLEAR (dmr_voice_record_encrypted())
enum {
  DMR_VF_ENCRYPTED = 0x01,          // encrypted, or not to be decoded
  DMR_VF_UNCONFIRMED = 0x02,        // with DMR_VF_ENCRYPTED: on no word of its own (carried, or noise)
  DMR_VF_EMERGENCY = 0x08,          // service options 0x80
  DMR_VF_IDENTITY_CARRIED = 0x20,   // source / destination not (yet) read from this transmission's own LC
  DMR_VF_CALL_TYPE_MASK = 0xc0,
  DMR_VF_CALL_GROUP = 0x00,         // destination_id is a talkgroup
  DMR_VF_CALL_UNIT_TO_UNIT = 0x80,  // destination_id is the called unit
};
enum {
  DMR_VOICE_ALG_CLEAR = 0x80,       // the P25 convention every reader tests
  DMR_VOICE_ALG_UNKNOWN = 0x00,
  DMR_VOICE_FEC_NOT_COUNTED = 0xff,
  DMR_VOICE_FEC_MAX = 0xfe,         // fec_errors saturates here
};
#define DMR_VOICE_FRAME_INTERVAL_US 20000ull // the three frames of a burst are 20 ms of speech each

struct dmr_voice_record {
  uint64_t timestamp_us;     // of this frame: the burst's + 20 ms per frame before it in the burst
  uint32_t source_id;        // 24 bits; 0 = not known
  uint32_t destination_id;   // talkgroup or called unit, 24 bits
  uint8_t flags;             // DMR_VF_*
  uint8_t slot_mode;         // slot (1, 2; 0 = not known) | enum dmr_station << 4
  uint8_t color_code;
  uint8_t frame_number;      // within the transmission, from 0, wraps at 256
  uint8_t service_options;
  uint8_t encryption_algorithm; // DMR_VOICE_ALG_CLEAR only on a clear frame
  uint8_t dmr_algorithm_id;  // DMR's algorithm number (PI header, encryption LC, burst F); 0 = none / not known
  uint8_t key_id;
  uint8_t fid;               // feature set ID of the call's LC
  uint8_t fec_errors;        // c0 + c1 Golay corrections of the frame
  uint32_t message_indicator; // the 32-bit MI; 0 = none
  uint32_t system_tag;
  uint16_t lcn;
  uint8_t voice[DMR_VOICE_FRAME_BYTES]; // the 72 AMBE+2 bits as sent, first in voice[0]'s 0x80
};
static inline bool dmr_voice_record_encrypted(struct dmr_voice_record const *r){
  return (r->flags & DMR_VF_ENCRYPTED) != 0 || r->encryption_algorithm != DMR_VOICE_ALG_CLEAR;
}
static inline uint8_t dmr_voice_record_slot(struct dmr_voice_record const *r){ return r->slot_mode & 0x0f; }
static inline enum dmr_station dmr_voice_record_mode(struct dmr_voice_record const *r){
  return (enum dmr_station)(r->slot_mode >> 4);
}
// A new record: labelled encrypted and unconfirmed, so that a record nobody labelled never reads clear
void dmr_voice_record_init(struct dmr_voice_record *r);

// ---------------- Call events ----------------

struct dmr_call_meta {
  char const *system_name;
  char const *site_name;
  char const *call_key;      // "<channel_id>:TS<slot>"
  uint32_t talkgroup_id;     // 0 until the identity is known
  uint32_t source_id;
  bool encrypted;            // the state when the event was made
  bool emergency;
  uint64_t start_timestamp_us;
  uint64_t end_timestamp_us; // end events
  uint32_t frame_count;      // end events
};
struct dmr_call_info {
  char const *channel_id;
  uint8_t slot;
  enum dmr_station mode;
  uint8_t color_code;
  bool identity_known;       // source / destination were read from an LC of this transmission
  bool unit_to_unit;
  uint8_t service_options;
  uint8_t fid;
  enum dmr_call_start started_by;
  enum dmr_call_end ended_by; // end events (DMR_END_FLUSH in a start event)
  enum dmr_encryption encryption;
  bool encryption_confirmed; // Encrypted by a word of this transmission (not only carried)
  uint8_t dmr_algorithm_id;
  uint8_t key_id;
  bool recorded;             // the talkgroup predicate's answer (true while the identity is not known)
  uint32_t frames_clear;     // end events: frames by the label they were given, written or not
  uint32_t frames_encrypted;
  uint32_t frames_unconfirmed;
};

// ---------------- Counters ----------------

struct dmr_call_counters {
  // Transmissions
  uint64_t transmissions;
  uint64_t started[DMR_CALL_STARTS];
  uint64_t ended[DMR_CALL_ENDS];
  uint64_t without_voice;          // ended with no voice frame
  uint64_t never_identified;       // ended with voice and no LC of their own
  uint64_t not_recorded;           // the talkgroup predicate said no
  uint64_t pi_headers_superseded;  // a PI-header-started transmission replaced by a header before any voice
  uint64_t undecoded_before_voice; // undecoded data bursts passed over between an "encrypted" header and its voice
  // Voice
  uint64_t voice_bursts;
  uint64_t unconfirmed_voice_bursts; // ... placed by the sink's count alone (no sync, no valid EMB)
  uint64_t unconfirmed_clean_voice;  // ... of them confirmed by their own voice
  uint64_t frames_clear;           // written labelled clear
  uint64_t frames_encrypted;       // written encrypted by a word of their transmission
  uint64_t frames_unconfirmed;     // written encrypted on no word of their own (carried, or noise)
  uint64_t frames_not_recorded;    // labelled, then not written (the predicate, or record_unidentified)
  uint64_t unidentified_noisy_bursts; // bursts before any identity whose voice looked like noise
  // Words
  uint64_t lc_clear;               // LCs that said clear: headers, embedded LCs
  uint64_t lc_encrypted;           // LCs that said encrypted (terminators included)
  uint64_t learned_mask_lcs;       // LCs valid only through a learned CRC residual: identity, never clear
  uint64_t learned_mask_clear_ignored; // ... of them, ones whose "clear" was not taken
  uint64_t lc_span_gap_ignored;    // embedded LCs whose fragments may span a gap: their "clear" not taken
  uint64_t parameters_encrypted;   // PI headers and burst F encryption parameters
  uint64_t parameters_clear;       // bursts F decoded as another message (null, TXI, reverse channel)
  uint64_t off_grid;
  uint64_t gaps;
  uint64_t encrypted_by_lc;        // transmissions turned encrypted, by the kind of word
  uint64_t encrypted_by_pi_header;
  uint64_t encrypted_by_burst_f;
  uint64_t encrypted_carried;
  uint64_t clear_then_encrypted;   // Clear -> Encrypted after frames went out clear
  uint64_t encrypted_then_clear;   // Encrypted -> Clear: the words that said so were undone
  uint64_t terminator_says_encrypted;
  uint64_t hidden_ivs_used;
  // EMB PI (counted, never used) against the transmission's LC in voice bursts with a valid EMB, added
  // at its end: emb_pi[pi][lc], lc 0 no voice LC read, 1 the LCs said clear, 2 an LC said encrypted
  uint64_t emb_pi[2][3];
};
static inline uint64_t dmr_call_frames_written(struct dmr_call_counters const *c){
  return c->frames_clear + c->frames_encrypted + c->frames_unconfirmed;
}
// The summary line (no newline): "[DMR calls <channel_id>] tx=... started header=... | ended ..."
int dmr_call_summary(char *buf,size_t size,char const *channel_id,struct dmr_call_counters const *c);

// ---------------- The tracker ----------------

// Callbacks run inside the tracker's calls and must not call back into it. The record and the
// event structs (and their strings) are valid only for the call
typedef void (*dmr_voice_fn)(void *arg,char const *system,char const *site,struct dmr_voice_record const *r);
typedef void (*dmr_call_fn)(void *arg,struct dmr_call_meta const *meta,struct dmr_call_info const *info);
// Whether a call's records are written; calls not recorded are tracked and counted all the same
typedef bool (*dmr_talkgroup_fn)(void *arg,uint32_t destination,bool unit_to_unit);

enum dmr_call_label { DMR_LABEL_CLEAR, DMR_LABEL_ENCRYPTED, DMR_LABEL_NOISE };

struct dmr_transmission {
  bool active;
  enum dmr_call_start started_by;
  uint64_t start_us;           // of the header, PI header or first voice burst
  uint64_t last_activity_us;   // of the last header, PI header or voice burst
  uint64_t last_confirmed_us;  // ... that something confirmed: the gap's
  uint32_t voice_bursts;
  uint32_t bursts_since_gap;
  uint32_t frames;             // the next frame's number

  bool identity_known;
  struct dmr_voice_identity id;
  uint8_t fid;
  bool recorded;
  bool start_announced;

  enum dmr_encryption state;   // Encrypted iff lc_encrypted or parameters_encrypted
  bool lc_encrypted;           // the last LC that said either way said encrypted
  bool parameters_encrypted;   // the last PI header or burst F said encrypted (burst F: until another says not)
  bool confirmed;              // a word of this transmission said encrypted (not only carried)
  uint8_t algorithm;
  uint8_t key_id;
  uint32_t mi;

  enum dmr_station mode;
  uint8_t color_code;

  bool position_known;         // superframe position of the last voice burst that had one
  int position;
  uint64_t position_us;

  bool lc_said_clear;
  bool lc_said_encrypted;
  uint32_t emb_pi0_bursts;
  uint32_t emb_pi1_bursts;

  uint32_t frames_clear;
  uint32_t frames_encrypted;
  uint32_t frames_unconfirmed;
};

// "Encrypted" left behind by a transmission that something other than a boundary ended
struct dmr_carry {
  bool active;
  uint64_t last_us;            // the transmission's last burst: the grid is counted from it
  uint64_t until_us;           // ... + fade_us
  bool lc_encrypted;           // which words said so
  bool parameters_encrypted;
  uint8_t algorithm;
  uint8_t key_id;
  uint32_t mi;
};

struct dmr_call_tracker {
  struct dmr_call_config config;
  dmr_voice_fn on_voice;
  void *voice_arg;
  dmr_call_fn on_start;
  void *start_arg;
  dmr_call_fn on_end;
  void *end_arg;
  dmr_talkgroup_fn predicate;
  void *predicate_arg;

  char system_name[DMR_CALL_NAME_MAX];
  char site_name[DMR_CALL_NAME_MAX];
  char channel_id[DMR_CALL_NAME_MAX];
  uint64_t frequency_hz;
  uint16_t lcn;
  uint32_t system_tag;
  char keys[3][DMR_CALL_KEY_MAX];

  struct dmr_transmission slots[3]; // 0 = slot not known, 1, 2
  struct dmr_carry carry[3];
  struct dmr_carry from_other;
  struct dmr_call_counters counters;
};

// config may be NULL (the defaults). Returns 0
int dmr_call_init(struct dmr_call_tracker *t,struct dmr_call_config const *config);
// Nothing is held: transmissions in progress are dropped without events (call dmr_call_flush() first
// for those)
void dmr_call_free(struct dmr_call_tracker *t);
void dmr_call_set_voice_sink(struct dmr_call_tracker *t,dmr_voice_fn fn,void *arg);
void dmr_call_set_talkgroup_predicate(struct dmr_call_tracker *t,dmr_talkgroup_fn fn,void *arg);
void dmr_call_set_start_callback(struct dmr_call_tracker *t,dmr_call_fn fn,void *arg);
void dmr_call_set_end_callback(struct dmr_call_tracker *t,dmr_call_fn fn,void *arg);

// Every burst of the channel, both slots, in order, with what dmr_msg_decode() made of it
void dmr_call_on_burst(struct dmr_call_tracker *t,struct dmr_channel const *ch,struct dmr_burst const *b,
                       struct dmr_burst_messages const *m);
// Frame sync was lost on the channel
void dmr_call_on_sync_lost(struct dmr_call_tracker *t,struct dmr_channel const *ch,uint64_t timestamp_us);
// Receiver time has reached now_us: at least every 100 ms of signal time, bursts or not
void dmr_call_on_time(struct dmr_call_tracker *t,struct dmr_channel const *ch,uint64_t now_us);
// End the transmission on slot (0-2), if any: a P_CLEAR for it, or the channel is otherwise known
// released. timestamp_us 0 = the transmission's last activity
void dmr_call_end_call(struct dmr_call_tracker *t,uint8_t slot,enum dmr_call_end reason,uint64_t timestamp_us);
// End every transmission (shutdown, retune): end events fire
void dmr_call_flush(struct dmr_call_tracker *t);

bool dmr_call_active(struct dmr_call_tracker const *t,uint8_t slot);
enum dmr_encryption dmr_call_encryption(struct dmr_call_tracker const *t,uint8_t slot);
// "<channel_id>:TS<slot>"
int dmr_call_key(char *buf,size_t size,char const *channel_id,uint8_t slot);

#endif
