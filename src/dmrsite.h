// DMR site layer: what one site says about itself (identity, rest channel, channel map, the call
// cross-check, grants and clear-downs), kept apart from the per-channel decoders; the control-plane
// routing each channel calls per burst; and the control log's lines (formatted, collapsed, handed to a
// sink: no files). dmrsite.c has the theory of operation
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRSITE_H
#define _DMRSITE_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmr.h"
#include "dmrmsg.h"
#include "dmrcsbk.h"

enum {
  DMR_SITE_NAME_MAX = 64,       // a system or site name, with its NUL
  DMR_CHANNEL_ID_MAX = 160,     // a channel id, with its NUL (the default id fits)
  DMR_SITE_LINE_MAX = 2048,     // a control log line's text always fits in this many bytes
};

// ---------------- Configuration ----------------

enum dmr_system_type {
  DMR_SYSTEM_CONVENTIONAL = 0,  // Tier II repeaters or simplex, no trunking
  DMR_SYSTEM_TIER3,             // ETSI Tier III
  DMR_SYSTEM_CAPACITY_PLUS,     // Motorola Capacity Plus, single site
  DMR_SYSTEM_LINKED_CAPACITY_PLUS,
  DMR_SYSTEM_CONNECT_PLUS,
  DMR_SYSTEM_CAPACITY_MAX,
  DMR_SYSTEM_HYTERA_XPT,
  DMR_SYSTEM_HYTERA_TIER3,      // Tier III with Hytera's additions
};
char const *dmr_system_type_name(enum dmr_system_type t); // "capacity_plus", ...
bool dmr_system_type_from_name(char const *name,enum dmr_system_type *t);

// Colour code settings, as dmrchan.h's (named apart from dmrsink.h's cc_mode): 0-15 pinned; TRACK: the first seen; ANY: every one. INHERIT: the
// site's setting on a channel, the system's on a site
enum { DMR_SITE_CC_TRACK = -1, DMR_SITE_CC_ANY = -2, DMR_SITE_CC_INHERIT = -3 };

struct dmr_site_channel_config {
  unsigned lcn;                 // as the system's signalling names the repeater; unique within the site
  uint64_t frequency_hz;        // the downlink (base station transmit)
  char channel_id[DMR_CHANNEL_ID_MAX]; // "" = dmr_default_channel_id()
  int color_code;               // DMR_SITE_CC_INHERIT by default
};
struct dmr_site_config {
  char system_name[DMR_SITE_NAME_MAX];
  char site_name[DMR_SITE_NAME_MAX];
  enum dmr_system_type type;
  int system_color_code;        // DMR_SITE_CC_TRACK by default
  int site_color_code;          // DMR_SITE_CC_INHERIT by default
  bool compressed_talkgroups;   // grants' talkgroups in the dialable form (dmrcall.h, compressed_talkgroups)
  int nchannels;
  struct dmr_site_channel_config const *channels; // copied by dmr_site_create()
};
void dmr_site_config_init(struct dmr_site_config *c);
void dmr_site_channel_config_init(struct dmr_site_channel_config *c);
// The setting in force on a channel: its own, else the site's, else the system's
int dmr_site_color_code_for(struct dmr_site_config const *c,struct dmr_site_channel_config const *ch);
// A name as one path / id component: anything but letters, digits, '.', '-' and '_' becomes '_'
int dmr_path_component(char *buf,size_t size,char const *name);
// "dmr_<system>_<site>_lcn<lcn>": depends only on the names and the LCN
int dmr_default_channel_id(char *buf,size_t size,char const *system_name,char const *site_name,unsigned lcn);

// ---------------- The site's identity: systemTag ----------------

// bits 31-28 the family, 27-0 the identity the air gives:
//   Tier III (tier3, hytera_tier3, capacity_max): the 14-bit system identity code
//   Capacity Plus (and linked): the 5-bit site number of the rest channel Short LC
//   Connect Plus: network (12 bits) << 8 | site (8 bits)
//   Hytera XPT: 0 (the air names no site)
enum dmr_tag_family { DMR_TAG_NONE = 0, DMR_TAG_TIER3 = 1, DMR_TAG_CAPACITY_PLUS = 2, DMR_TAG_CONNECT_PLUS = 3, DMR_TAG_HYTERA_XPT = 4 };
static inline uint32_t dmr_make_system_tag(enum dmr_tag_family f,uint32_t value){
  return ((uint32_t)f << 28) | (value & 0x0FFFFFFFu);
}
static inline uint32_t dmr_tier3_system_tag(uint16_t code){ return dmr_make_system_tag(DMR_TAG_TIER3,code & 0x3FFFu); }
static inline uint32_t dmr_cap_plus_system_tag(uint8_t site){ return dmr_make_system_tag(DMR_TAG_CAPACITY_PLUS,site & 0x1Fu); }
static inline uint32_t dmr_con_plus_system_tag(uint16_t network,uint8_t site){
  return dmr_make_system_tag(DMR_TAG_CONNECT_PLUS,((uint32_t)(network & 0xFFFu) << 8) | site);
}
static inline uint32_t dmr_xpt_system_tag(void){ return dmr_make_system_tag(DMR_TAG_HYTERA_XPT,0); }
static inline enum dmr_tag_family dmr_system_tag_family(uint32_t tag){
  return (tag >> 28) <= 4 ? (enum dmr_tag_family)(tag >> 28) : DMR_TAG_NONE;
}
enum dmr_tag_family dmr_tag_family_of(enum dmr_system_type t);
// "tier3 net=3 site=2 (small)", "cap+ site=3", "con+ net=100 site=5", "xpt", "none"
int dmr_system_tag_describe(char *buf,size_t size,uint32_t tag);

// ---------------- The control log ----------------

// A line: "2026-11-22 14:03:07.123 [cc 1] [<channel id>] [TS1] <text>", [cc -] for a colour code not
// known, [TS-] for a line about the carrier or (channel "site") the site; a collapsed line's count adds
// " (xN since HH:MM:SS, last HH:MM:SS)". Local time
#define DMR_NO_COLOR_CODE 0xFF
#define DMR_SITE_CHANNEL "site"
int dmr_control_line_format(char *buf,size_t size,int64_t now_us,char const *channel_id,uint8_t slot,uint8_t color_code,
                            char const *text,uint32_t repeats,int64_t since_us,int64_t last_us);
// "[DMR alias] radio=1234567 alias="..."", radio 0 = unknown
int dmr_control_alias_line(char *buf,size_t size,uint32_t radio,char const *alias);

struct dmr_control_line {
  char const *system_name;
  char const *site_name;
  char const *channel_id;       // "site" for a line about the site
  uint8_t slot;                 // 1, 2; 0 = the carrier / the site
  uint8_t color_code;           // DMR_NO_COLOR_CODE = not known
  char const *kind;             // "SLC", "LC", "PI", "ENC", "EMB", "CSBK", "MBC", "GRANT", "ALIAS", "SITE", "REST", "MAP", "WARN"
  char const *text;
  uint32_t repeats;             // a count line: the repeats it stands for
  char const *formatted;        // the whole line
};
typedef void (*dmr_control_sink)(void *arg,struct dmr_control_line const *line);
struct dmr_control_log_options {
  char system_name[DMR_SITE_NAME_MAX];
  char site_name[DMR_SITE_NAME_MAX];
  int repeat_interval_s;        // a collapsed line's count is written this long after the key's last line (60)
  size_t max_keys;              // keys held at once (1024)
  int64_t (*clock_us)(void *arg); // wall clock, us since 1970; NULL = the system's
  void *clock_arg;
};
void dmr_control_log_options_init(struct dmr_control_log_options *o);
struct dmr_control_log;
// Lines go to sink (on the thread that logged, no lock held); a NULL sink drops them. Thread safe
struct dmr_control_log *dmr_control_log_create(struct dmr_control_log_options const *o,dmr_control_sink sink,void *arg);
void dmr_control_log_destroy(struct dmr_control_log *log); // writes the pending counts first
void dmr_control_log_write(struct dmr_control_log *log,char const *channel_id,uint8_t slot,uint8_t color_code,
                           char const *kind,char const *text);
// Written the first time its key (NULL: the text) is seen on (channel, slot), then counted
void dmr_control_log_write_collapsed(struct dmr_control_log *log,char const *channel_id,uint8_t slot,uint8_t color_code,
                                     char const *kind,char const *text,char const *key);
void dmr_control_log_write_alias(struct dmr_control_log *log,char const *channel_id,uint8_t slot,uint8_t color_code,
                                 uint32_t radio,char const *alias);
void dmr_control_log_write_site(struct dmr_control_log *log,char const *kind,char const *text);
void dmr_control_log_write_site_collapsed(struct dmr_control_log *log,char const *kind,char const *text,char const *key);
void dmr_control_log_time(struct dmr_control_log *log);  // now and then: the counts that are due
void dmr_control_log_flush(struct dmr_control_log *log); // every pending count now
void dmr_control_log_close(struct dmr_control_log *log); // pending counts written, every key forgotten
uint64_t dmr_control_log_lines_written(struct dmr_control_log *log);
uint64_t dmr_control_log_lines_collapsed(struct dmr_control_log *log);

// ---------------- The site ----------------

// A channel as the site knows it (and as the clear callback names it)
struct dmr_site_context {
  char system_name[DMR_SITE_NAME_MAX];
  char site_name[DMR_SITE_NAME_MAX];
  char channel_id[DMR_CHANNEL_ID_MAX];
  uint64_t frequency_hz;
  uint16_t lcn;                 // 0 on a conventional channel
  uint32_t system_tag;          // the site's, at the time
  void *user;                   // the owner's (its per-channel decoder, say); not used here
};

// Which radiod and SSRC carry a frequency. This is the one place the answer comes from: a function the
// owner gives, never a global, so a site may span receivers (a control channel on one radiod and the
// traffic on another)
struct dmr_source {
  void *radiod;                 // the owner's handle for that radiod (its control connection, say)
  uint32_t ssrc;                // 0: none assigned; the owner asks the radiod for one
};
typedef bool (*dmr_locate_fn)(void *arg,uint64_t frequency_hz,struct dmr_source *source);
// The single-radiod answer, for arg a struct dmr_single_radiod: its radiod for every frequency in
// [low_hz, high_hz] (both 0: any), SSRC 0
struct dmr_single_radiod {
  void *radiod;
  uint64_t low_hz;
  uint64_t high_hz;
};
bool dmr_locate_single_radiod(void *arg,uint64_t frequency_hz,struct dmr_source *source);

struct dmr_site;
// A voice call announced on a timeslot of one of the site's repeaters (a Capacity Plus Site Status, an
// XPT grant, a Tier III or Connect Plus grant or its updates), or the site's rest channel (rest): what a
// follower needs to tune it. Every announcement and every report of the rest channel, repeats included,
// so that a follower can keep a channel it asked for alive
struct dmr_follow {
  uint16_t lcn;                 // 0: not known
  uint64_t frequency_hz;        // the repeater's downlink; 0: not known (not configured, not in the channel map)
  uint8_t timeslot;             // 1, 2; 0: not known
  bool configured;              // the site's configuration lists the repeater
  bool attached;                // a decoder is on it now
  bool repeating;               // an announcement that repeats while the call lasts
  bool rest;                    // the site's rest channel, not a call
  uint32_t talkgroup;           // the call's destination, when talkgroup_bits != 0
  uint8_t talkgroup_bits;       // 0: not known; 8: only its low 8 bits (Capacity Plus Site Status); 24
  bool group;                   // a talkgroup (else a radio)
  char channel_id[DMR_CHANNEL_ID_MAX]; // "" for a repeater the site does not know
  char what[96];                // the message that announced it
};
struct dmr_site_handlers {
  // GRANT FOLLOWING HOOK. Every grant the site hears (voice and data, repeats included), with the
  // frequency its CG_AP block or the channel map gives it (0: not known). The site does not follow it:
  // the follow hook below names the channel to a follower, which decides. Called on the thread of the
  // channel the grant was heard on, no lock held
  void (*grant)(void *arg,struct dmr_site *site,struct dmr_grant const *g,uint64_t frequency_hz);
  // A P_CLEAR heard on a channel's timeslot (reason "P_CLEAR"): end the call there
  // (dmr_call_end_call()). On that channel's thread, no lock held
  void (*clear)(void *arg,struct dmr_site_context const *channel,uint8_t slot,char const *reason);
  // CALL-FOLLOWING HOOK. Each announcement of a voice call (above). On the thread of the channel it
  // was heard on, no lock held
  void (*follow)(void *arg,struct dmr_site *site,struct dmr_follow const *f);
  void *arg;
  // Which radiod and SSRC serve a frequency (dmr_site_locate()); NULL: not known
  dmr_locate_fn locate;
  void *locate_arg;
};

struct dmr_site_options {
  uint64_t (*clock_us)(void *arg); // monotonic us; NULL = CLOCK_MONOTONIC
  void *clock_arg;
  uint64_t activity_grace_us;   // a repeated announcement, nothing heard: a miss after this long (2 s)
  uint64_t grant_grace_us;      // a one-message grant, nothing heard: a miss after this long (3 s)
  uint64_t heard_window_us;     // call activity this long before the first announcement counts (1 s)
  uint64_t pending_expiry_us;   // a repeated announcement not seen again for this long is forgotten (4 s)
  uint64_t warn_interval_us;    // one WARN line per channel timeslot (or unknown channel) per this long (30 s)
  uint64_t rest_holdoff_us;     // reports of the previous rest channel ignored this long after a move (0.5 s)
  int identity_confirmations;   // sightings running before an identity is adopted or replaced (2)
  uint64_t frequency_tolerance_hz; // two frequencies this close are the same channel (1 kHz)
  bool learn_from_any_cgap;     // also learn LCN -> frequency from a grant's (or another message's) CG_AP
  bool warnings_to_stderr;      // WARN lines also to stderr as "[DMR site <system>/<site>] ..." (true)
};
void dmr_site_options_init(struct dmr_site_options *o);

// options and handlers may be NULL (the defaults; no handlers); log may be NULL. NULL if out of memory
struct dmr_site *dmr_site_create(struct dmr_site_config const *config,struct dmr_control_log *log,
                                 struct dmr_site_options const *options,struct dmr_site_handlers const *handlers);
void dmr_site_destroy(struct dmr_site *s);
void dmr_site_set_handlers(struct dmr_site *s,struct dmr_site_handlers const *handlers); // before the channels start

// A channel being decoded: matched to the configuration by channel id, else LCN, else frequency; one
// the configuration does not list is added. Returns its handle (>= 0), -1 if out of memory
int dmr_site_attach(struct dmr_site *s,struct dmr_site_context const *channel);
// Its decoder is gone: what the site announces there counts as not monitored. False if no attached
// channel has the id
bool dmr_site_detach(struct dmr_site *s,char const *channel_id);
// The same, by the handle dmr_site_attach() returned: the one to use when two decoders may share an id
bool dmr_site_detach_handle(struct dmr_site *s,int handle);

// From the channels (any thread). dmr_cplane_burst() makes these calls; call them directly only
// without a struct dmr_cplane
uint32_t dmr_site_system_tag(struct dmr_site const *s); // 0 until the air has named the site
void dmr_site_burst(struct dmr_site *s,int handle,struct dmr_burst const *b);
void dmr_site_short_lc(struct dmr_site *s,int handle,uint8_t color_code,struct dmr_short_lc const *slc);
void dmr_site_link_control(struct dmr_site *s,int handle,uint8_t slot,uint8_t color_code,struct dmr_lc const *lc);
void dmr_site_csbk(struct dmr_site *s,int handle,struct dmr_csbk_message const *m); // one that failed its CRC is ignored
void dmr_site_sync_lost(struct dmr_site *s,int handle);
void dmr_site_time(struct dmr_site *s); // time has passed: the grace periods that ran out

// The frequency of an LCN as the channel map has it now; 0 = not known
uint64_t dmr_site_frequency_of(struct dmr_site *s,uint16_t lcn);
// Which radiod and SSRC serve a frequency, by the handlers' locate function. False if it has no answer
bool dmr_site_locate(struct dmr_site *s,uint64_t frequency_hz,struct dmr_source *source);

struct dmr_site_channel_report {
  char channel_id[DMR_CHANNEL_ID_MAX];
  uint16_t lcn;
  uint64_t frequency_hz;
  bool configured;
  bool attached;
  uint64_t bursts;
  uint64_t call_bursts[3];      // voice, voice LC header, PI header, terminator, by slot (0 = not known)
  uint64_t sync_losses;
  uint64_t color_code_bursts[16];
  int expected_color_code;      // pinned, or the first seen; -1 = any / none yet
  uint64_t color_code_mismatches;
  uint64_t announced[3];        // the cross-check, by slot (0 = the message named none)
  uint64_t heard[3];
  uint64_t missed[3];
  uint64_t alarms[3];
  int64_t last_burst_age_us;    // -1 = never
};
enum { DMR_SITE_MAX_NEIGHBOURS = 64 };
struct dmr_site_report {
  char system_name[DMR_SITE_NAME_MAX];
  char site_name[DMR_SITE_NAME_MAX];
  enum dmr_system_type type;
  uint32_t system_tag;
  uint64_t identity_changes;
  uint64_t foreign_identity_messages;
  int nneighbours;
  uint32_t neighbours[DMR_SITE_MAX_NEIGHBOURS]; // ascending
  char neighbour_details[DMR_SITE_MAX_NEIGHBOURS][40]; // what the air says of each, index for index: its
                                // control LCN and frequency (Tier III, Hytera), rest LSN (Capacity Plus), free
                                // repeater (XPT); "" if nothing
  bool rest_known;
  uint8_t rest_lsn;
  uint16_t rest_lcn;
  uint8_t rest_timeslot;
  uint64_t rest_moves;
  uint64_t rest_stale_reports;
  bool xpt_free_known;
  uint8_t xpt_free_repeater;
  uint64_t xpt_free_repeater_moves;
  uint64_t grants;
  uint64_t grants_voice;
  uint64_t grants_data;
  uint64_t grant_updates;
  uint64_t grants_unresolved;
  uint64_t clears;
  uint64_t announced;
  uint64_t announced_heard;
  uint64_t announced_missed;
  uint64_t miss_alarms;
  uint64_t announced_unconfirmed;
  uint64_t announced_pending;
  uint64_t announced_not_monitored;
  uint64_t announced_unconfigured;
  size_t map_entries;
  size_t map_entries_from_air;
  uint64_t map_conflicts;
  uint64_t color_code_mismatches;
  uint64_t color_code_ignored_messages;
  int nchannels;
  struct dmr_site_channel_report *channels; // malloc'd: dmr_site_report_free()
};
// False if out of memory (r is then empty)
bool dmr_site_report_get(struct dmr_site *s,struct dmr_site_report *r);
void dmr_site_report_free(struct dmr_site_report *r);
// "[DMR site <system>/<site>] type=... tag=... | grants=... | announced=... | map=... | cc_mismatch=... | LCN1[...]"
int dmr_site_format_summary(char *buf,size_t size,struct dmr_site_report const *r);
int dmr_site_summary(char *buf,size_t size,struct dmr_site *s);

// ---------------- The control plane of one channel ----------------

struct dmr_cplane_options {
  uint16_t csbk_crc_mask;       // DMR_CRC_MASK_CSBK; another only by the owner's decision (dmrcsbk.h)
  uint64_t mbc_max_block_gap_us; // DMR_MBC_MAX_BLOCK_GAP_US
  uint64_t slot_gap_dibits;     // a timeslot's transmission ends after this long silent (4800, 1 s)
  // Accept a CSBK whose CRC fails with a residual seen twice for its (CSBKO, FID) within two minutes
  // (dmrmsg.h, dmr_crc_learner; Motorola RAS and the like). Off by default
  bool learn_crc_masks;
  // Called the first time a residual is accepted (optional)
  void (*learned)(void *arg,enum dmr_crc_check kind,uint8_t opcode,uint8_t fid,uint32_t residual);
  void *learned_arg;
};
void dmr_cplane_options_init(struct dmr_cplane_options *o);

struct dmr_cplane_counters {
  uint64_t bursts;
  uint64_t bursts_by_slot[3];   // [0]: the slot was not known
  uint64_t bursts_by_kind[9];   // by enum dmr_kind
  uint64_t bursts_by_data_type[16]; // data bursts with a valid slot type
  uint64_t data_slot_type_invalid;
  uint64_t sync_losses;
  uint64_t short_lcs;
  uint64_t voice_lc_headers;    // with a valid LC
  uint64_t terminators;         // with a valid LC
  uint64_t pi_headers;
  uint64_t embedded_lcs;
  uint64_t talker_aliases;
  uint64_t emb_pi_set;          // voice bursts B-F with EMB PI = 1
  uint64_t burst_f_encryption;
  uint64_t hidden_ivs;
  uint64_t voice_frame_fec_errors;
  uint64_t csbks;               // passed the CRC (single block)
  uint64_t mbc_messages;        // multi-block messages completed
  uint64_t grants;
  uint64_t check_failed_by_data_type[16]; // BPTC accepted, the message's own check failed
  uint64_t refused_by_data_type[16];      // the slot type decoded, BPTC found no codeword
  uint64_t embedded_lc_failed;
  uint64_t single_bursts_undecoded;
  uint64_t single_burst_form_mismatch; // only the form PI did not select decodes
  uint64_t csbk_crc_failed;
  uint64_t mbc_header_crc_failed;
  uint64_t mbc_crc_failed;
  uint64_t mbc_abandoned;       // cut short, stale, too long, or a block with no header
};

struct dmr_cplane;
// One per channel, on that channel's thread. site and log may be NULL (a channel with no site, no
// log); given, they must outlive it. The channel is attached to the site here
struct dmr_cplane *dmr_cplane_create(struct dmr_site_context const *channel,struct dmr_site *site,
                                     struct dmr_control_log *log,struct dmr_cplane_options const *options);
void dmr_cplane_destroy(struct dmr_cplane *c); // dmr_cplane_flush() first; the site keeps the channel (dmr_site_detach())

// THE PER-BURST ENTRY POINT. Every burst the sink frames, both slots, in order, with what the message
// layer (dmr_msg_decode()) made of it, after the call tracker has had it. Parses the CSBKs and assembles
// the multi-block ones, then feeds the site and writes the channel's control log lines
void dmr_cplane_burst(struct dmr_cplane *c,struct dmr_burst const *b,struct dmr_burst_messages const *m);
// Sync lost: the assembly state goes (call dmr_msg_reset() too), and the site hears of it
void dmr_cplane_sync_lost(struct dmr_cplane *c);
// Time has passed (at least every 100 ms, bursts or not): the site's grace periods, the log's counts
void dmr_cplane_time(struct dmr_cplane *c);
// The call tracker ended the slot's transmission by a timeout or a release (call dmr_msg_reset_slot() too)
void dmr_cplane_reset_slot(struct dmr_cplane *c,uint8_t slot);
void dmr_cplane_reset(struct dmr_cplane *c);  // a retune: assembly state dropped
void dmr_cplane_flush(struct dmr_cplane *c);  // end of input: waiting lines written, assembly state dropped
// The channel as the site names it, with the system tag as of now
void dmr_cplane_context(struct dmr_cplane *c,struct dmr_site_context *channel);
int dmr_cplane_handle(struct dmr_cplane const *c); // in its site; -1 without one
uint64_t dmr_cplane_learned_csbks(struct dmr_cplane const *c); // CSBKs accepted with a learned residual
// A copy, from any thread
void dmr_cplane_get_counters(struct dmr_cplane *c,struct dmr_cplane_counters *out);
// The CRC masks seen on CSBKs that failed (a vendor mask shows as one entry with a large count); a copy
void dmr_cplane_get_masks(struct dmr_cplane *c,struct dmr_csbk_mask_counter *out);

#endif
