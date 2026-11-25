// DMR per-slot call tracker (see dmrcall.h): transmissions, the encryption rule, voice records
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dmrcall.h"
#include "dmrcsbk.h"

// Theory of operation
//
// One tracker per channel; each timeslot (and slot 0, "not known") has its own transmission. The
// input is every burst with what the message layer made of it, receiver time, sync loss, and the
// owner's end of a call (a P_CLEAR) or flush. The output is one record per voice frame, labelled,
// in order within a slot, and a start and an end event per transmission.
//
// THE RULE: the last word wins, as in p25d (p25audio.c). Each voice frame goes out as it arrives,
// labelled by the rule as it stands once its own burst's words have been taken in; nothing waits to
// be confirmed. A transmission starts clear. Downstream trusts only the label of each record, so the
// label is the whole of the rule's output.
//
// Transmissions start with a voice LC header that passed RS(12,9), a PI header with no header before
// it, a voice burst with nothing in progress (a late entry), an embedded LC naming another source
// or destination (the old one ends, the new one starts with the burst that completed the LC), or a
// voice burst off the superframe position or the slot grid (a resync, below). They end with a
// terminator, an idle burst, any other data burst on the slot (decoded or not), a voice LC header,
// a new talker, a resync, no voice for fade_us (1 s), a header no voice followed (within
// pre_voice_timeout_us, 360 ms, if it did not say encrypted; within fade_us if it did, and for a PI
// header), sync loss, dmr_call_end_call() and dmr_call_flush(). One exception to "any data burst":
// between a header that said encrypted and its voice, a data burst that did not decode is passed
// over, most likely another header of the same transmission, so that "encrypted" is not lost to it.
// A second header naming the same call before any voice joins the transmission, as a PI header
// before any voice does; a PI header in mid-voice ends it like any data burst and starts the next.
// A header after a transmission that a PI header started starts a new one: a PI header is bound by
// the next header, any other data burst, and fade_us.
//
// Identity comes from the transmission's own LCs: group or unit-to-unit, source, destination,
// service options, FID. Until one is read the records carry zeros and DMR_VF_IDENTITY_CARRIED; nothing
// is carried over from the slot's previous transmission, because a record is filed under its
// destination and a wrong one is worse than none. A terminator's LC names a transmission that never
// read one (for its end event: its frames have gone). LCs of different address
// widths (the vendor short forms) are not compared; the widest is kept.
//
// Two kinds of word say encrypted, and each is undone only by a word of its own kind. The transmission
// is Encrypted while either says so:
//   The LC. A checked voice LC header, embedded LC or terminator LC with the privacy bit set, a
//     Capacity Plus encrypted voice LC, or a vendor encryption parameters LC, says encrypted; a checked
//     header or embedded LC with the privacy bit clear says clear. (A terminator ends the transmission
//     anyway: its "clear" would change nothing.)
//   The encryption parameters. A PI header (CRC-CCITT), with the algorithm, key and MI, or burst F's
//     encryption parameters, says encrypted; burst F decoded as another message (null, TXI, reverse
//     channel) says clear. On systems whose LCs do not carry the privacy bit, burst F says encrypted
//     in every superframe, and the LCs saying clear between do not undo it.
// Nothing else counts. The EMB's PI bit is ETSI's pre-emption and power control indicator, not a
// privacy flag: some systems set it on clear calls, and under this rule that would mute them, so it
// is only counted (emb_pi[][]). An LC valid only through a learned CRC residual (dmrmsg.h) gives
// identity and may say encrypted, never clear. An embedded LC counts as saying clear only when its
// four bursts B-E all belong to this transmission since its last gap (more than voice_gap_us without
// a confirmed burst), so that one assembled across an unseen boundary cannot.
//
// What that costs, accepted so that no clear voice is lost. A damaged word that passes its checks with
// wrong contents mislabels the voice until the next word of its kind: an embedded LC or a burst F comes
// once a superframe (360 ms). One saying encrypted in a clear transmission mutes that much speech; one
// saying clear in an encrypted transmission lets that much through, decoded to noise. An encrypted
// transmission entered late (its header missed) is decoded until its first embedded LC or burst F
// says encrypted, up to a superframe. A rule that held voice until a word confirmed it clear, and asked
// two words to agree before muting, lost clear voice at a weak signal, where the confirming word often
// failed.
//
// Noise is not speech. Before a transmission has an identity (a late entry, until its first embedded
// LC), a burst whose three frames needed more than unidentified_clear_max_fec (9) Golay corrections is
// written encrypted and unconfirmed: a false sync on noise starts a late entry of a burst or two, and
// noise through the two Golay decodes needs about 17 (the code is perfect, so a random 23-bit word is
// on average 2.85 bits from its codeword, about 5.7 a frame); a burst received at a 5 % bit error rate
// needs about 7 (47 protected bits a frame). It labels each burst as it comes: nothing waits.
//
// Boundaries the tracker can see split one transmission from the next, and a new transmission starts
// clear. Four checks find boundaries that were not seen, so that "clear" said by one is not applied to
// the other's frames: none ends anything a real boundary would not.
//   The gap. A transmission's voice bursts are 60 ms apart, and between two transmissions there are
//     at least two bursts that are not voice (a terminator, a header). A gap of more than voice_gap_us
//     (150 ms) since the last confirmed burst ends nothing, but an embedded LC whose fragments span it
//     does not say clear.
//   Bursts nothing confirmed (unconfirmed_is_missing). Inside a call the sink hands on up to two
//     periods in a row in which it found neither a sync nor an EMB, as the voice bursts its count
//     expects. Such a burst counts as missing for the gap (two in a row are a gap though the timestamps
//     show none), unless its own voice confirms it: its three frames needed at most
//     clean_voice_confirms_max_fec (9) Golay corrections in all. Its frames are written as the rule
//     stands: most such bursts are real voice.
//   The superframe position. Superframes A-F follow each other without a break and a transmission
//     starts at A, so a voice burst whose position is not the one the transmission's timing calls for
//     is not that transmission's: it ends there and a new one starts (Resync).
//   The slot grid. The bursts of one timeslot are a whole number of 60 ms periods apart and the other
//     timeslot's are 30 ms from them. A voice burst (or a second header) more than
//     slot_grid_tolerance_us (5 ms) off the grid of the transmission's last burst is not that
//     transmission's: it ends there and a new one starts (Resync). This catches a sink that numbers a
//     timeslot's bursts with the other's number for a while, and another transmitter's timing.
//
// A new talker. An embedded LC naming another source or destination means one transmission ended and
// another began unseen: the old one ends there, but the new one keeps the words where they were (as
// p25d does), since the change is found only after it; the LC that named the new talker then says what
// it says.
//
// Ends that are no boundary (carry_encrypted). The sink can cut one transmission in two without a
// boundary: a noise window handed on as a data burst whose slot type does not decode, or a burst off
// the slot grid. Such an end leaves the words behind for fade_us from the last burst: a transmission
// that starts with a voice burst on the first one's 60 ms grid within that time, under either slot
// number, starts with them (Encrypted, unconfirmed, with its algorithm and key, if they said so);
// likewise one on the grid of an encrypted transmission in progress under the other slot number. A
// boundary seen on the slot (a data burst whose slot type decodes, a header, a PI header) clears it.
// A sync loss or a superframe resync leaves nothing behind unless carry_encrypted_across_sync_loss:
// there the end is more often a real one.
//
// Time. Burst timestamps must be signal time (60 ms from one burst of a slot to the next, exactly),
// not the time a burst was processed: the fade, the gap, the superframe position and the slot grid
// are all timed by it, and the records' timestamps are made from it.
//
// Not here: colour code gating, P_CLEAR decoding and the talker alias belong to the channel's owner,
// which calls dmr_call_end_call() for a P_CLEAR and dmr_msg_reset_slot() from the end event of a fade,
// no voice or release. Not thread safe: one tracker belongs to one channel's thread.

enum {
  SLOTS = 3,               // 0 = slot not known, 1, 2
  SUPERFRAME_BURSTS = 6,
};
#define BURST_PERIOD_US 60000ull // between bursts of one timeslot

enum indicator { BY_LC, BY_PI_HEADER, BY_BURST_F, BY_CARRIED };
// What an end means for the words left behind on the slot
enum end_kind {
  END_BOUNDARY,            // a boundary was seen, or time ran out: nothing is left behind
  END_NEUTRAL,             // sync loss, a superframe resync: what was left before stays, no more
  END_NOT_ONE,             // off the slot grid, an undecoded data burst: "encrypted" is left behind
};

char const *dmr_call_start_name(enum dmr_call_start r){
  switch(r){
  case DMR_START_HEADER: return "header";
  case DMR_START_PI_HEADER: return "pi";
  case DMR_START_LATE_ENTRY: return "late";
  case DMR_START_NEW_TALKER: return "newtalker";
  case DMR_START_RESYNC: return "resync";
  default: return "?";
  }
}
char const *dmr_call_end_name(enum dmr_call_end r){
  switch(r){
  case DMR_END_TERMINATOR: return "terminator";
  case DMR_END_IDLE: return "idle";
  case DMR_END_DATA_BURST: return "data";
  case DMR_END_NEW_HEADER: return "header";
  case DMR_END_NEW_TALKER: return "newtalker";
  case DMR_END_RESYNC: return "resync";
  case DMR_END_FADE: return "fade";
  case DMR_END_NO_VOICE: return "novoice";
  case DMR_END_SYNC_LOSS: return "syncloss";
  case DMR_END_RELEASE: return "release";
  case DMR_END_FLUSH: return "flush";
  default: return "?";
  }
}

void dmr_call_config_init(struct dmr_call_config *c){
  memset(c,0,sizeof *c);
  c->fade_us = 1000000;
  c->pre_voice_timeout_us = 360000;
  c->voice_gap_us = 150000;
  c->check_superframe_position = true;
  c->unconfirmed_is_missing = true;
  c->clean_voice_confirms_max_fec = 9;
  c->unidentified_clear_max_fec = 9;
  c->slot_grid_tolerance_us = 5000;
  c->carry_encrypted = true;
  c->carry_encrypted_across_sync_loss = false;
  c->record_unidentified = true;
}

void dmr_voice_record_init(struct dmr_voice_record *r){
  memset(r,0,sizeof *r);
  r->flags = DMR_VF_ENCRYPTED | DMR_VF_UNCONFIRMED;
  r->encryption_algorithm = DMR_VOICE_ALG_UNKNOWN;
  r->fec_errors = DMR_VOICE_FEC_NOT_COUNTED;
}

static void record_mark_clear(struct dmr_voice_record *r){
  r->flags = (uint8_t)(r->flags & ~(DMR_VF_ENCRYPTED | DMR_VF_UNCONFIRMED));
  r->encryption_algorithm = DMR_VOICE_ALG_CLEAR;
  r->dmr_algorithm_id = 0;
  r->key_id = 0;
  r->message_indicator = 0;
}
static void record_mark_encrypted(struct dmr_voice_record *r,bool unconfirmed){
  r->flags = (uint8_t)((r->flags & ~DMR_VF_UNCONFIRMED) | DMR_VF_ENCRYPTED | (unconfirmed ? DMR_VF_UNCONFIRMED : 0));
  r->encryption_algorithm = DMR_VOICE_ALG_UNKNOWN;
}
static void record_set_flag(struct dmr_voice_record *r,uint8_t flag,bool on){
  r->flags = (uint8_t)(on ? (r->flags | flag) : (r->flags & ~flag));
}
static void record_set_fec_errors(struct dmr_voice_record *r,int errors){
  r->fec_errors = errors < 0 ? DMR_VOICE_FEC_NOT_COUNTED : (uint8_t)(errors > DMR_VOICE_FEC_MAX ? DMR_VOICE_FEC_MAX : errors);
}

// A fresh transmission
static void tx_clear(struct dmr_transmission *tx){
  memset(tx,0,sizeof *tx);
  tx->started_by = DMR_START_LATE_ENTRY;
  tx->id.group = true;
  tx->id.address_bits = 24;
  tx->recorded = true;
  tx->state = DMR_ENC_UNKNOWN;
  tx->mode = DMR_STATION_UNKNOWN;
}

// ---------------- Channel ----------------

static void copy_name(char *dst,char const *src){
  if(src == NULL)
    src = "";
  snprintf(dst,DMR_CALL_NAME_MAX,"%s",src);
}
static bool same_name(char const *stored,char const *src){
  char copy[DMR_CALL_NAME_MAX];
  copy_name(copy,src);
  return strcmp(stored,copy) == 0;
}
int dmr_call_key(char *buf,size_t size,char const *channel_id,uint8_t slot){
  return snprintf(buf,size,"%s:TS%u",channel_id != NULL ? channel_id : "",(unsigned)slot);
}
static void remember(struct dmr_call_tracker *t,struct dmr_channel const *ch){
  if(ch == NULL)
    return;
  if(!same_name(t->channel_id,ch->channel_id) || !same_name(t->system_name,ch->system_name)
     || !same_name(t->site_name,ch->site_name)){
    copy_name(t->channel_id,ch->channel_id);
    copy_name(t->system_name,ch->system_name);
    copy_name(t->site_name,ch->site_name);
    for(uint8_t slot=0; slot < SLOTS; slot++)
      dmr_call_key(t->keys[slot],sizeof t->keys[slot],t->channel_id,slot);
  }
  t->frequency_hz = ch->frequency_hz;
  t->lcn = ch->lcn;
  t->system_tag = ch->system_tag;
}

// Something in the burst itself says it is one: a sync, a slot type or an EMB that decoded
static bool burst_confirmed(struct dmr_burst const *b){
  return b->sync != DMR_SYNC_NONE || b->slot_type_valid || b->emb_valid;
}
// Bursts of one timeslot are a whole number of 60 ms periods apart: true if now is, counted from
// from. Always true with the check off
static bool on_grid(struct dmr_call_tracker const *t,uint64_t from,uint64_t now){
  if(t->config.slot_grid_tolerance_us == 0 || now <= from)
    return true;
  uint64_t const off = (now - from) % BURST_PERIOD_US;
  uint64_t const distance = off < BURST_PERIOD_US - off ? off : BURST_PERIOD_US - off;
  return distance <= t->config.slot_grid_tolerance_us;
}
static bool off_grid(struct dmr_call_tracker const *t,struct dmr_transmission const *tx,uint64_t now){
  return !on_grid(t,tx->last_activity_us,now);
}
static void note_burst(struct dmr_transmission *tx,struct dmr_burst const *b){
  if(b->mode != DMR_STATION_UNKNOWN)
    tx->mode = b->mode;
  if(b->kind == DMR_KIND_DATA ? b->slot_type_valid : b->emb_valid)
    tx->color_code = b->color_code & 0x0f;
}
static int voice_fec_errors(struct dmr_voice_burst const *v){
  int sum = 0;
  for(int i=0; i < DMR_VOICE_FRAMES; i++)
    sum += v->frames[i].fec_errors;
  return sum;
}

// ---------------- Records ----------------

// Complete one frame's record with the transmission's identity and the label, count it, hand it on
static void write_frame(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,struct dmr_voice_record record,
                        enum dmr_call_label label){
  // A record is clear only out of a transmission in state Clear, whatever the caller asked for
  if(label == DMR_LABEL_CLEAR && tx->state != DMR_ENC_CLEAR)
    label = DMR_LABEL_ENCRYPTED;

  if(tx->identity_known){
    record.source_id = tx->id.source;
    record.destination_id = tx->id.destination;
    record.service_options = tx->id.options;
    record.fid = tx->fid;
    record.flags = (uint8_t)((record.flags & ~DMR_VF_CALL_TYPE_MASK)
                             | (tx->id.group ? DMR_VF_CALL_GROUP : DMR_VF_CALL_UNIT_TO_UNIT));
    record_set_flag(&record,DMR_VF_EMERGENCY,dmr_so_emergency(tx->id.options));
  } else {
    record_set_flag(&record,DMR_VF_IDENTITY_CARRIED,true);
  }
  record.slot_mode = (uint8_t)((slot & 0x0f) | ((uint8_t)tx->mode << 4));
  record.color_code = tx->color_code;
  record.system_tag = t->system_tag;
  record.lcn = t->lcn;

  bool const write = tx->identity_known ? tx->recorded : t->config.record_unidentified;
  struct dmr_call_counters *c = &t->counters;
  bool unconfirmed = false;
  switch(label){
  case DMR_LABEL_CLEAR:
    record_mark_clear(&record);
    tx->frames_clear++;
    if(write)
      c->frames_clear++;
    break;
  case DMR_LABEL_ENCRYPTED:
    record.dmr_algorithm_id = tx->algorithm;
    record.key_id = tx->key_id;
    record.message_indicator = tx->mi;
    unconfirmed = !tx->confirmed;
    break;
  case DMR_LABEL_NOISE:
    unconfirmed = true;
    break;
  }
  if(label != DMR_LABEL_CLEAR){
    record_mark_encrypted(&record,unconfirmed);
    if(unconfirmed)
      tx->frames_unconfirmed++;
    else
      tx->frames_encrypted++;
    if(write){
      if(unconfirmed)
        c->frames_unconfirmed++;
      else
        c->frames_encrypted++;
    }
  }
  if(!write){
    c->frames_not_recorded++;
    return;
  }
  if(t->on_voice != NULL)
    t->on_voice(t->voice_arg,t->system_name,t->site_name,&record);
}

// ---------------- Events ----------------

static void fill_meta(struct dmr_call_tracker const *t,struct dmr_transmission const *tx,uint8_t slot,struct dmr_call_meta *m){
  memset(m,0,sizeof *m);
  m->system_name = t->system_name;
  m->site_name = t->site_name;
  m->call_key = t->keys[slot];
  m->talkgroup_id = tx->identity_known ? tx->id.destination : 0;
  m->source_id = tx->identity_known ? tx->id.source : 0;
  m->encrypted = tx->state == DMR_ENC_ENCRYPTED;
  m->emergency = tx->identity_known && dmr_so_emergency(tx->id.options);
  m->start_timestamp_us = tx->start_us;
}
static void fill_info(struct dmr_call_tracker const *t,struct dmr_transmission const *tx,uint8_t slot,struct dmr_call_info *i){
  memset(i,0,sizeof *i);
  i->channel_id = t->channel_id;
  i->slot = slot;
  i->mode = tx->mode;
  i->color_code = tx->color_code;
  i->identity_known = tx->identity_known;
  i->unit_to_unit = tx->identity_known && !tx->id.group;
  i->service_options = tx->identity_known ? tx->id.options : 0;
  i->fid = tx->fid;
  i->started_by = tx->started_by;
  i->ended_by = DMR_END_FLUSH;
  i->encryption = tx->state;
  i->encryption_confirmed = tx->state == DMR_ENC_ENCRYPTED && tx->confirmed;
  i->dmr_algorithm_id = tx->algorithm;
  i->key_id = tx->key_id;
  i->recorded = tx->recorded;
  i->frames_clear = tx->frames_clear;
  i->frames_encrypted = tx->frames_encrypted;
  i->frames_unconfirmed = tx->frames_unconfirmed;
}
static void announce_start(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot){
  if(tx->start_announced)
    return;
  tx->start_announced = true;
  if(t->on_start != NULL){
    struct dmr_call_meta m;
    struct dmr_call_info i;
    fill_meta(t,tx,slot,&m);
    fill_info(t,tx,slot,&i);
    t->on_start(t->start_arg,&m,&i);
  }
}

// ---------------- Encryption ----------------

// The state from the two kinds of word
static void update_state(struct dmr_call_tracker *t,struct dmr_transmission *tx,enum indicator by){
  bool const encrypted = tx->lc_encrypted || tx->parameters_encrypted;
  struct dmr_call_counters *c = &t->counters;
  if(encrypted && tx->state != DMR_ENC_ENCRYPTED){
    if(tx->frames_clear > 0)
      c->clear_then_encrypted++;
    switch(by){
    case BY_LC: c->encrypted_by_lc++; break;
    case BY_PI_HEADER: c->encrypted_by_pi_header++; break;
    case BY_BURST_F: c->encrypted_by_burst_f++; break;
    case BY_CARRIED: c->encrypted_carried++; break;
    }
    tx->state = DMR_ENC_ENCRYPTED;
  } else if(!encrypted && tx->state != DMR_ENC_CLEAR){
    if(tx->state == DMR_ENC_ENCRYPTED)
      c->encrypted_then_clear++;
    tx->state = DMR_ENC_CLEAR;
  }
}
static void lc_says(struct dmr_call_tracker *t,struct dmr_transmission *tx,bool encrypted){
  tx->lc_encrypted = encrypted;
  if(encrypted){
    tx->confirmed = true;
    t->counters.lc_encrypted++;
  } else {
    t->counters.lc_clear++;
  }
  update_state(t,tx,BY_LC);
}
static void parameters_say(struct dmr_call_tracker *t,struct dmr_transmission *tx,bool encrypted,enum indicator by){
  tx->parameters_encrypted = encrypted;
  if(encrypted){
    tx->confirmed = true;
    t->counters.parameters_encrypted++;
  } else {
    t->counters.parameters_clear++;
  }
  update_state(t,tx,by);
}

// ---------------- Start and end ----------------

static void end(struct dmr_call_tracker *t,uint8_t slot,enum dmr_call_end reason,uint64_t now,enum end_kind kind){
  (void)now;
  struct dmr_transmission *tx = &t->slots[slot];
  if(!tx->active)
    return;

  // A boundary clears what was left behind on the slot; an end that is none leaves the words that
  // say encrypted, or leaves what was there
  if(kind == END_BOUNDARY){
    memset(&t->carry[slot],0,sizeof t->carry[slot]);
  } else if(kind == END_NOT_ONE && t->config.carry_encrypted && tx->state == DMR_ENC_ENCRYPTED){
    struct dmr_carry *c = &t->carry[slot];
    c->active = true;
    c->last_us = tx->last_activity_us;
    c->until_us = tx->last_activity_us + t->config.fade_us;
    c->lc_encrypted = tx->lc_encrypted;
    c->parameters_encrypted = tx->parameters_encrypted;
    c->algorithm = tx->algorithm;
    c->key_id = tx->key_id;
    c->mi = tx->mi;
  }

  struct dmr_call_counters *c = &t->counters;
  c->ended[reason]++;
  if(tx->frames == 0)
    c->without_voice++;
  else if(!tx->identity_known)
    c->never_identified++;
  int const lc = tx->lc_said_encrypted ? 2 : tx->lc_said_clear ? 1 : 0;
  c->emb_pi[0][lc] += tx->emb_pi0_bursts;
  c->emb_pi[1][lc] += tx->emb_pi1_bursts;

  announce_start(t,tx,slot);
  if(t->on_end != NULL){
    struct dmr_call_meta m;
    struct dmr_call_info i;
    fill_meta(t,tx,slot,&m);
    m.end_timestamp_us = tx->last_activity_us;
    m.frame_count = tx->frames;
    fill_info(t,tx,slot,&i);
    i.ended_by = reason;
    t->on_end(t->end_arg,&m,&i);
  }
  tx_clear(tx);
}

static void expire(struct dmr_call_tracker *t,uint64_t now){
  for(uint8_t slot=0; slot < SLOTS; slot++){
    struct dmr_transmission const *tx = &t->slots[slot];
    if(!tx->active || now <= tx->last_activity_us)
      continue;
    bool const voice = tx->voice_bursts > 0;
    // "Encrypted" holds for as long as the fade lets the transmission live, voice or not yet
    bool const fade = voice || tx->state == DMR_ENC_ENCRYPTED;
    if(now - tx->last_activity_us >= (fade ? t->config.fade_us : t->config.pre_voice_timeout_us))
      end(t,slot,voice ? DMR_END_FADE : DMR_END_NO_VOICE,now,END_BOUNDARY);
  }
}

static struct dmr_transmission *start(struct dmr_call_tracker *t,uint8_t slot,enum dmr_call_start reason,uint64_t now){
  struct dmr_transmission *tx = &t->slots[slot];
  tx_clear(tx);
  tx->active = true;
  tx->started_by = reason;
  tx->start_us = now;
  tx->last_activity_us = now;
  tx->last_confirmed_us = now;
  tx->state = DMR_ENC_CLEAR;
  t->counters.transmissions++;
  t->counters.started[reason]++;
  return tx;
}

// The encrypted transmission a voice burst at now on slot may continue: one that an end that is no
// boundary ended, under any slot number, less than the fade ago, or one in progress under another
// slot number; in both cases with this burst on its 60 ms grid. (Under another number: the sink's
// numbering changed and the burst is on the other timeslot's periods; the two timeslots' bursts are
// 30 ms apart, so nothing of one is on the other's grid otherwise)
static struct dmr_carry const *encrypted_before(struct dmr_call_tracker *t,uint8_t slot,uint64_t now){
  if(!t->config.carry_encrypted)
    return NULL;
  for(uint8_t q=0; q < SLOTS; q++){
    struct dmr_carry const *c = &t->carry[q];
    if(c->active && now > c->last_us && now <= c->until_us && on_grid(t,c->last_us,now))
      return c;
  }
  if(t->config.slot_grid_tolerance_us == 0)
    return NULL; // no grid: the numbers are all there is
  for(uint8_t q=0; q < SLOTS; q++){
    struct dmr_transmission const *other = &t->slots[q];
    if(q == slot || !other->active || other->state != DMR_ENC_ENCRYPTED)
      continue;
    if(now > other->last_activity_us && on_grid(t,other->last_activity_us,now)){
      struct dmr_carry *c = &t->from_other;
      c->active = true;
      c->last_us = other->last_activity_us;
      c->until_us = other->last_activity_us + t->config.fade_us;
      c->lc_encrypted = other->lc_encrypted;
      c->parameters_encrypted = other->parameters_encrypted;
      c->algorithm = other->algorithm;
      c->key_id = other->key_id;
      c->mi = other->mi;
      return c;
    }
  }
  return NULL;
}

// A transmission that starts with a voice burst takes the words of an encrypted transmission it may
// be the continuation of. Encrypted so, it is not confirmed: no word of its own said so yet
static struct dmr_transmission *start_with_voice(struct dmr_call_tracker *t,uint8_t slot,enum dmr_call_start reason,
                                                 uint64_t now){
  struct dmr_transmission *tx = start(t,slot,reason,now);
  struct dmr_carry const *from = encrypted_before(t,slot,now);
  if(from != NULL){
    tx->algorithm = from->algorithm;
    tx->key_id = from->key_id;
    tx->mi = from->mi;
    tx->lc_encrypted = from->lc_encrypted;
    tx->parameters_encrypted = from->parameters_encrypted;
    update_state(t,tx,BY_CARRIED);
  }
  return tx;
}

// ---------------- Identity ----------------

static bool same_call(struct dmr_voice_identity const *a,struct dmr_voice_identity const *b){
  return a->group == b->group && a->source == b->source && a->destination == b->destination;
}
// The identity an LC of this transmission carries; a different talker is the caller's to have handled
static void adopt_identity(struct dmr_call_tracker *t,struct dmr_transmission *tx,struct dmr_voice_identity const *id,
                           uint8_t fid){
  if(!tx->identity_known){
    tx->identity_known = true;
    tx->id = *id;
    tx->fid = fid;
    tx->recorded = t->predicate == NULL || t->predicate(t->predicate_arg,id->destination,!id->group);
    if(!tx->recorded)
      t->counters.not_recorded++;
  } else if(id->address_bits == tx->id.address_bits){
    if(same_call(&tx->id,id)){
      tx->id.options = id->options; // the same call: its service options may have changed
      tx->fid = fid;
    }
  } else if(id->address_bits > tx->id.address_bits){
    tx->id = *id; // a vendor short form first, the full addresses now
    tx->fid = fid;
  }
}

// The transmission's bursts stopped for longer than voice_gap_us and voice is here again: a boundary
// may be hidden in the gap, so an embedded LC assembled across it does not say clear
static void after_gap(struct dmr_call_tracker *t,struct dmr_transmission *tx){
  tx->bursts_since_gap = 0;
  t->counters.gaps++;
}

// What a checked LC of this transmission says: identity, then privacy. may_say_clear: false for an LC
// valid only through a learned CRC residual (dmrmsg.h), and an embedded LC whose fragments may span a
// gap: they give identity and may say encrypted, never clear
// identity_of(): dmr_lc_voice_identity() with the system's talkgroup form applied
// (config.compressed_talkgroups): every identity the tracker reads comes through here, so two LCs of
// one call compare alike. A voice LC naming source 0 says nothing of the call yet: Capacity Plus sends
// a wide-area voice header with source 0 and, 120 ms later, one naming the radio. Taken as an identity
// it opened a transmission of its own, ended empty by the next header; as none, the next header joins
// its transmission
static bool identity_of(struct dmr_call_tracker const *t,struct dmr_lc const *lc,struct dmr_voice_identity *id){
  if(!dmr_lc_voice_identity(lc,id) || id->source == 0)
    return false;
  if(t->config.compressed_talkgroups && id->group && id->address_bits == 24)
    id->destination = dmr_hytera_dialable_talkgroup(id->destination);
  return true;
}

static void apply_lc(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,struct dmr_lc const *lc,
                     bool may_say_clear,bool learned_mask){
  struct dmr_voice_identity id;
  if(identity_of(t,lc,&id))
    adopt_identity(t,tx,&id,lc->fid);
  switch(dmr_lc_privacy(lc)){
  case DMR_LC_ENCRYPTED:
    tx->lc_said_encrypted = true;
    if(lc->body == DMR_LCB_ENCRYPTION_PARAMETERS){
      tx->algorithm = lc->flco; // a PI header's content where an LC is expected: 0x21
      tx->key_id = lc->u.encryption.key_id;
      tx->mi = lc->u.encryption.mi;
    }
    lc_says(t,tx,true);
    break;
  case DMR_LC_CLEAR:
    tx->lc_said_clear = true;
    if(may_say_clear)
      lc_says(t,tx,false);
    else if(learned_mask)
      t->counters.learned_mask_clear_ignored++;
    else
      t->counters.lc_span_gap_ignored++;
    break;
  case DMR_LC_NO_STATEMENT:
    break;
  }
  if(tx->identity_known)
    announce_start(t,tx,slot); // after the privacy bit: the event says what the LC said
}

// ---------------- Data bursts ----------------

static void on_header(struct dmr_call_tracker *t,uint8_t slot,struct dmr_burst const *b,struct dmr_data_burst const *data,
                      uint64_t now){
  struct dmr_lc const *lc = &data->lc;
  struct dmr_voice_identity id;
  bool const has_id = identity_of(t,lc,&id);
  struct dmr_transmission *tx = &t->slots[slot];
  // Another header of the transmission that has not begun its voice yet?
  bool const join = tx->active && tx->voice_bursts == 0 && tx->started_by == DMR_START_HEADER
    && !(tx->identity_known && has_id && !same_call(&tx->id,&id)) && !off_grid(t,tx,now);
  if(!join){
    if(tx->active && tx->voice_bursts == 0 && tx->started_by == DMR_START_PI_HEADER)
      t->counters.pi_headers_superseded++;
    end(t,slot,DMR_END_NEW_HEADER,now,END_BOUNDARY);
    tx = start(t,slot,DMR_START_HEADER,now);
    memset(&t->carry[slot],0,sizeof t->carry[slot]); // a header is a boundary
  }
  tx->last_activity_us = now;
  tx->last_confirmed_us = now;
  note_burst(tx,b);
  if(data->learned_mask)
    t->counters.learned_mask_lcs++;
  apply_lc(t,tx,slot,lc,!data->learned_mask,data->learned_mask);
}

static void on_pi_header(struct dmr_call_tracker *t,uint8_t slot,struct dmr_burst const *b,struct dmr_pi_header const *pi,
                         uint64_t now){
  struct dmr_transmission *tx = &t->slots[slot];
  if(tx->active && tx->voice_bursts > 0)
    end(t,slot,DMR_END_DATA_BURST,now,END_BOUNDARY);
  if(!tx->active)
    tx = start(t,slot,DMR_START_PI_HEADER,now);
  memset(&t->carry[slot],0,sizeof t->carry[slot]); // it says encrypted itself
  tx->last_activity_us = now;
  tx->last_confirmed_us = now;
  note_burst(tx,b);
  tx->algorithm = pi->algorithm_id;
  tx->key_id = pi->key_id;
  tx->mi = pi->mi;
  parameters_say(t,tx,true,BY_PI_HEADER);
}

// A terminator's LC names a transmission that never read an LC, and it can say encrypted
static void on_terminator_lc(struct dmr_call_tracker *t,struct dmr_transmission *tx,struct dmr_lc const *lc){
  struct dmr_voice_identity id;
  bool const has_id = identity_of(t,lc,&id);
  if(has_id && tx->identity_known && id.address_bits == tx->id.address_bits && !same_call(&tx->id,&id))
    return; // not ours
  if(has_id)
    adopt_identity(t,tx,&id,lc->fid);
  if(dmr_lc_privacy(lc) == DMR_LC_ENCRYPTED){
    if(tx->state == DMR_ENC_CLEAR)
      t->counters.terminator_says_encrypted++;
    tx->lc_said_encrypted = true;
    lc_says(t,tx,true);
  }
}

static void on_data(struct dmr_call_tracker *t,uint8_t slot,struct dmr_burst const *b,struct dmr_burst_messages const *m,
                    uint64_t now){
  struct dmr_data_burst const *data = m->has_data ? &m->data : NULL;
  bool const typed = b->slot_type_valid;

  if(typed && b->data_type == DMR_DT_VOICE_LC_HEADER && data != NULL && dmr_data_lc_usable(data)){
    on_header(t,slot,b,data,now);
    return;
  }
  if(typed && b->data_type == DMR_DT_PI_HEADER && data != NULL && dmr_data_valid(data) && data->has_pi){
    on_pi_header(t,slot,b,&data->pi,now);
    return;
  }
  struct dmr_transmission *tx = &t->slots[slot];
  // A data burst whose slot type decoded is a boundary on the slot, whatever is in progress
  if(typed)
    memset(&t->carry[slot],0,sizeof t->carry[slot]);
  if(!tx->active)
    return;
  // Between a header that said encrypted and its voice, a data burst that did not decode is most
  // likely another header of the same transmission: "encrypted" holds (the fade still runs from the
  // last one that decoded)
  bool const decoded = typed && data != NULL && data->status != DMR_DATA_REFUSED && data->status != DMR_DATA_CHECK_FAILED;
  if(!decoded && tx->voice_bursts == 0 && tx->state == DMR_ENC_ENCRYPTED){
    t->counters.undecoded_before_voice++;
    return;
  }
  enum dmr_call_end reason = DMR_END_DATA_BURST;
  if(typed && b->data_type == DMR_DT_TERMINATOR_LC){
    reason = DMR_END_TERMINATOR;
    if(data != NULL && dmr_data_lc_usable(data))
      on_terminator_lc(t,tx,&data->lc);
  } else if(typed && b->data_type == DMR_DT_IDLE){
    reason = DMR_END_IDLE;
  } else if(typed && b->data_type == DMR_DT_VOICE_LC_HEADER){
    reason = DMR_END_NEW_HEADER; // a header that did not decode: its voice will be a late entry
  }
  end(t,slot,reason,now,typed ? END_BOUNDARY : END_NOT_ONE);
}

// ---------------- Voice bursts ----------------

// The burst's three frames, labelled as the rule now stands; before the transmission has an identity,
// a burst whose voice looks like noise is not labelled clear
static void add_frames(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,struct dmr_burst const *b,
                       struct dmr_voice_burst const *voice,int fec){
  enum dmr_call_label label = tx->state == DMR_ENC_CLEAR ? DMR_LABEL_CLEAR : DMR_LABEL_ENCRYPTED;
  if(label == DMR_LABEL_CLEAR && !tx->identity_known && t->config.unidentified_clear_max_fec >= 0
     && fec > t->config.unidentified_clear_max_fec){
    label = DMR_LABEL_NOISE;
    t->counters.unidentified_noisy_bursts++;
  }
  for(int k=0; k < DMR_VOICE_FRAMES; k++){
    struct dmr_voice_frame const *frame = &voice->frames[k];
    struct dmr_voice_record record;
    dmr_voice_record_init(&record);
    record.timestamp_us = b->timestamp_us + (uint64_t)k * DMR_VOICE_FRAME_INTERVAL_US;
    record.frame_number = (uint8_t)(tx->frames & 0xff);
    tx->frames++;
    memcpy(record.voice,frame->bytes,sizeof record.voice);
    record_set_fec_errors(&record,frame->fec_errors);
    write_frame(t,tx,slot,record,label);
  }
}

static void on_voice(struct dmr_call_tracker *t,uint8_t slot,struct dmr_burst const *b,struct dmr_burst_messages const *m,
                     uint64_t now){
  struct dmr_call_config const *cfg = &t->config;
  struct dmr_call_counters *c = &t->counters;
  struct dmr_transmission *tx = &t->slots[slot];
  int const position = m->superframe_position;
  bool const positioned = position >= 0 && position < SUPERFRAME_BURSTS;

  // Is this burst on the transmission's 60 ms grid at all?
  if(tx->active && off_grid(t,tx,now)){
    c->off_grid++;
    end(t,slot,DMR_END_RESYNC,now,END_NOT_ONE);
    tx = start_with_voice(t,slot,DMR_START_RESYNC,now);
  }
  // Is it where the transmission's superframes put it?
  if(tx->active && tx->position_known && positioned && cfg->check_superframe_position && now > tx->position_us){
    uint64_t const periods = (now - tx->position_us + BURST_PERIOD_US / 2) / BURST_PERIOD_US;
    if(((uint64_t)tx->position + periods) % SUPERFRAME_BURSTS != (uint64_t)position){
      // A new transmission, by its superframe: nothing is taken over (unless the wide carry is on)
      if(cfg->carry_encrypted_across_sync_loss){
        end(t,slot,DMR_END_RESYNC,now,END_NOT_ONE);
        tx = start_with_voice(t,slot,DMR_START_RESYNC,now);
      } else {
        end(t,slot,DMR_END_RESYNC,now,END_NEUTRAL);
        tx = start(t,slot,DMR_START_RESYNC,now);
      }
    }
  }

  // Did the bursts stop for long enough to hide a boundary? Timed from the last burst something
  // confirmed to this one, if something (or its own clean voice) confirms it
  int const fec = voice_fec_errors(&m->voice);
  bool const clean_voice = cfg->clean_voice_confirms_max_fec >= 0 && fec <= cfg->clean_voice_confirms_max_fec;
  bool const confirmed = burst_confirmed(b) || clean_voice || !cfg->unconfirmed_is_missing;
  if(!burst_confirmed(b)){
    c->unconfirmed_voice_bursts++;
    if(clean_voice)
      c->unconfirmed_clean_voice++;
  }
  if(tx->active && cfg->voice_gap_us != 0 && confirmed && now > tx->last_confirmed_us
     && now - tx->last_confirmed_us > cfg->voice_gap_us)
    after_gap(t,tx);

  // A new talker: an LC of this voice names another call than the one established. The new
  // transmission keeps the words where they were
  struct dmr_voice_identity embedded_id;
  bool const has_embedded_id = m->has_embedded_lc && identity_of(t,&m->embedded_lc.lc,&embedded_id);
  if(tx->active && tx->identity_known && has_embedded_id && embedded_id.address_bits == tx->id.address_bits
     && !same_call(&tx->id,&embedded_id)){
    bool const lc_encrypted = tx->lc_encrypted,parameters_encrypted = tx->parameters_encrypted;
    uint8_t const algorithm = tx->algorithm,key_id = tx->key_id;
    uint32_t const mi = tx->mi;
    end(t,slot,DMR_END_NEW_TALKER,now,END_BOUNDARY);
    tx = start(t,slot,DMR_START_NEW_TALKER,now);
    tx->lc_encrypted = lc_encrypted;
    tx->parameters_encrypted = parameters_encrypted;
    tx->algorithm = algorithm;
    tx->key_id = key_id;
    tx->mi = mi;
    update_state(t,tx,BY_CARRIED);
  }
  if(!tx->active)
    tx = start_with_voice(t,slot,DMR_START_LATE_ENTRY,now);

  tx->last_activity_us = now;
  if(confirmed)
    tx->last_confirmed_us = now;
  tx->voice_bursts++;
  tx->bursts_since_gap++;
  c->voice_bursts++;
  note_burst(tx,b);
  if(positioned){
    tx->position_known = true;
    tx->position = position;
    tx->position_us = now;
  }

  // What this burst says: it applies to the burst's own frames too
  if(b->kind != DMR_KIND_VOICE_A && b->emb_valid){
    if(b->emb_pi)
      tx->emb_pi1_bursts++; // counted only: not a privacy flag
    else
      tx->emb_pi0_bursts++;
  }
  if(m->has_single_burst && m->single_burst.kind == DMR_SB_ENCRYPTION_PARAMETERS){
    struct dmr_single_burst const *f = &m->single_burst;
    if(tx->algorithm == 0 && tx->key_id == 0){ // a PI header's parameters stand
      tx->algorithm = f->algorithm_id;
      tx->key_id = f->key_id;
    }
    parameters_say(t,tx,true,BY_BURST_F);
  } else if(m->has_single_burst && m->single_burst.kind != DMR_SB_UNKNOWN){
    parameters_say(t,tx,false,BY_BURST_F); // burst F decoded as another message: no parameters
  }
  if(m->has_embedded_lc){
    // The LC's four fragments came in the slot's last four voice bursts: all this transmission's,
    // and after its last gap, when it has had four since
    bool const learned = m->embedded_lc.learned_mask;
    if(learned)
      c->learned_mask_lcs++;
    apply_lc(t,tx,slot,&m->embedded_lc.lc,tx->bursts_since_gap >= 4 && !learned,learned);
  }
  if(m->has_hidden_iv && tx->state == DMR_ENC_ENCRYPTED && tx->confirmed){
    tx->mi = m->hidden_iv.iv;
    c->hidden_ivs_used++;
  }

  add_frames(t,tx,slot,b,&m->voice,fec);
}

// ---------------- The API ----------------

int dmr_call_init(struct dmr_call_tracker *t,struct dmr_call_config const *config){
  assert(t != NULL);
  memset(t,0,sizeof *t);
  if(config != NULL)
    t->config = *config;
  else
    dmr_call_config_init(&t->config);
  // The names and call keys stay empty until a channel with a name arrives
  for(uint8_t slot=0; slot < SLOTS; slot++)
    tx_clear(&t->slots[slot]);
  return 0;
}

void dmr_call_free(struct dmr_call_tracker *t){
  (void)t; // nothing is allocated
}

void dmr_call_set_voice_sink(struct dmr_call_tracker *t,dmr_voice_fn fn,void *arg){
  t->on_voice = fn;
  t->voice_arg = arg;
}
void dmr_call_set_talkgroup_predicate(struct dmr_call_tracker *t,dmr_talkgroup_fn fn,void *arg){
  t->predicate = fn;
  t->predicate_arg = arg;
}
void dmr_call_set_start_callback(struct dmr_call_tracker *t,dmr_call_fn fn,void *arg){
  t->on_start = fn;
  t->start_arg = arg;
}
void dmr_call_set_end_callback(struct dmr_call_tracker *t,dmr_call_fn fn,void *arg){
  t->on_end = fn;
  t->end_arg = arg;
}

void dmr_call_on_burst(struct dmr_call_tracker *t,struct dmr_channel const *ch,struct dmr_burst const *b,
                       struct dmr_burst_messages const *m){
  assert(t != NULL && b != NULL && m != NULL);
  remember(t,ch);
  uint64_t const now = b->timestamp_us;
  expire(t,now);
  uint8_t const slot = b->slot <= 2 ? b->slot : 0;
  if(b->kind == DMR_KIND_DATA)
    on_data(t,slot,b,m,now);
  else if(dmr_is_voice(b->kind) && m->has_voice)
    on_voice(t,slot,b,m,now);
  // A standalone reverse channel burst is not part of a voice transmission and does not end one
}

void dmr_call_on_sync_lost(struct dmr_call_tracker *t,struct dmr_channel const *ch,uint64_t timestamp_us){
  remember(t,ch);
  enum end_kind const kind = t->config.carry_encrypted_across_sync_loss ? END_NOT_ONE : END_NEUTRAL;
  for(uint8_t slot=0; slot < SLOTS; slot++)
    end(t,slot,DMR_END_SYNC_LOSS,timestamp_us,kind);
}

void dmr_call_on_time(struct dmr_call_tracker *t,struct dmr_channel const *ch,uint64_t now_us){
  remember(t,ch);
  expire(t,now_us);
}

void dmr_call_end_call(struct dmr_call_tracker *t,uint8_t slot,enum dmr_call_end reason,uint64_t timestamp_us){
  if(slot >= SLOTS)
    return;
  end(t,slot,reason,timestamp_us != 0 ? timestamp_us : t->slots[slot].last_activity_us,END_BOUNDARY);
}

void dmr_call_flush(struct dmr_call_tracker *t){
  for(uint8_t slot=0; slot < SLOTS; slot++)
    end(t,slot,DMR_END_FLUSH,t->slots[slot].last_activity_us,END_BOUNDARY);
}

bool dmr_call_active(struct dmr_call_tracker const *t,uint8_t slot){
  return slot < SLOTS && t->slots[slot].active;
}
enum dmr_encryption dmr_call_encryption(struct dmr_call_tracker const *t,uint8_t slot){
  return slot < SLOTS && t->slots[slot].active ? t->slots[slot].state : DMR_ENC_UNKNOWN;
}

// ---------------- The summary line ----------------

static void put(char *buf,size_t size,size_t *len,char const *fmt,...) __attribute__((format(printf,4,5)));
static void put(char *buf,size_t size,size_t *len,char const *fmt,...){
  if(*len >= size)
    return;
  va_list ap;
  va_start(ap,fmt);
  int const n = vsnprintf(buf + *len,size - *len,fmt,ap);
  va_end(ap);
  if(n > 0)
    *len += (size_t)n < size - *len ? (size_t)n : size - *len - 1;
}

int dmr_call_summary(char *buf,size_t size,char const *channel_id,struct dmr_call_counters const *c){
#define N(v) ((unsigned long long)(v))
  size_t len = 0;
  if(size > 0)
    buf[0] = '\0';
  put(buf,size,&len,"[DMR calls %s] tx=%llu started",channel_id != NULL ? channel_id : "",N(c->transmissions));
  for(int i=0; i < DMR_CALL_STARTS; i++)
    put(buf,size,&len," %s=%llu",dmr_call_start_name((enum dmr_call_start)i),N(c->started[i]));
  put(buf,size,&len," | ended");
  for(int i=0; i < DMR_CALL_ENDS; i++)
    put(buf,size,&len," %s=%llu",dmr_call_end_name((enum dmr_call_end)i),N(c->ended[i]));
  put(buf,size,&len," | no_voice=%llu never_identified=%llu not_recorded=%llu"
      " | frames clear=%llu encrypted=%llu unconfirmed=%llu skipped=%llu noisy_unidentified_bursts=%llu",
      N(c->without_voice),N(c->never_identified),N(c->not_recorded),N(c->frames_clear),N(c->frames_encrypted),
      N(c->frames_unconfirmed),N(c->frames_not_recorded),N(c->unidentified_noisy_bursts));
  put(buf,size,&len," | lc clear=%llu encrypted=%llu clear_ignored learned=%llu gap=%llu | parameters encrypted=%llu clear=%llu"
      " | gaps=%llu unconfirmed_bursts=%llu (clean_voice=%llu) off_grid=%llu"
      " | encrypted_by lc=%llu pi_header=%llu burst_f=%llu carried=%llu"
      " | clear_then_encrypted=%llu encrypted_then_clear=%llu terminator_encrypted=%llu",
      N(c->lc_clear),N(c->lc_encrypted),N(c->learned_mask_clear_ignored),N(c->lc_span_gap_ignored),
      N(c->parameters_encrypted),N(c->parameters_clear),N(c->gaps),N(c->unconfirmed_voice_bursts),
      N(c->unconfirmed_clean_voice),N(c->off_grid),N(c->encrypted_by_lc),N(c->encrypted_by_pi_header),
      N(c->encrypted_by_burst_f),N(c->encrypted_carried),N(c->clear_then_encrypted),N(c->encrypted_then_clear),
      N(c->terminator_says_encrypted));
  put(buf,size,&len," | emb_pi=1 bursts: lc_encrypted=%llu lc_clear=%llu no_lc=%llu; emb_pi=0 bursts: lc_encrypted=%llu"
      " lc_clear=%llu no_lc=%llu",
      N(c->emb_pi[1][2]),N(c->emb_pi[1][1]),N(c->emb_pi[1][0]),N(c->emb_pi[0][2]),N(c->emb_pi[0][1]),
      N(c->emb_pi[0][0]));
#undef N
  return (int)len;
}
