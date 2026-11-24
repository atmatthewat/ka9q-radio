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
// THE RULE. Audio of encrypted frames must never be put online; the archive keeps everything.
// Voice is labelled clear only after something in its own transmission said clear; anything that
// says encrypted holds for the rest of the transmission. Frames that wait are released in order or
// written labelled encrypted, never dropped. Downstream trusts only the label of each record, so the
// label is the whole of the rule's output. A short burst of mislabelled audio at low signal is
// accepted; complicated enforcement is not wanted.
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
// destination and a wrong one is worse than none. Held frames get the identity known when they are
// released. A terminator's LC names a transmission that never read one. LCs of different address
// widths (the vendor short forms) are not compared; the widest is kept.
//
// Says encrypted, from that burst's frames on:
//   strong, final at once (and "confirmed": the records are not marked unconfirmed)
//     - a checked header, terminator or embedded LC with the privacy bit, a Capacity Plus encrypted
//       voice LC, or a vendor encryption parameters LC;
//     - a PI header (CRC-CCITT), with the algorithm, key and MI.
//   weak: burst F's encryption parameters (confirmed only if its 32 bits arrived as a codeword),
//     and EMB PI = 1 (unconfirmed). Both need two words, below.
//   carried: "encrypted" left by the transmission before, when no boundary ended it (unconfirmed).
// The EMB's PI bit is ETSI's pre-emption and power control indicator, not a privacy flag, so PI = 0
// never says clear and PI = 1 is kept only in the cautious direction (emb_pi_mode: encrypted by
// default; ignored; or nothing in a transmission already Clear on its own LC). It counts only from
// an EMB received as a codeword (emb_pi_max_errors 0): the sink takes an EMB within one corrected bit,
// and the noise of a lost burst is such an EMB with the channel's colour code often enough that, half
// of those with PI = 1, it would mark clear transmissions encrypted; noise is an exact EMB with the
// channel's colour code one time in 8,192 (8 codewords of the 65,536 words of 16 bits). A corrected
// EMB still counts when its burst's three voice frames
// needed at most emb_pi_clean_voice_max_fec (14) Golay corrections, which noise seldom does, or when
// the transmission's EMB before it had PI = 1 too (a real PI = 1 is in every burst B-F).
// Unconfirmed becomes confirmed when stronger evidence comes (records already written keep their
// label). A later LC that says clear does not undo "encrypted": it is counted (contradictions).
//
// Says clear, only from Unknown:
//   - a voice LC header with the privacy bit 0 that passed RS(12,9) WITHOUT a correction. A random
//     96-bit word passes RS uncorrected one time in 16.7 million but one time in 5,480 with the
//     one-octet correction; and when BPTC(196,96) delivers the codeword that was sent RS has nothing
//     to correct, so a correction means BPTC delivered another one. Refusing costs little: the
//     embedded LC follows 300 ms later;
//   - an embedded LC with the privacy bit 0 in which BPTC(128,77) changed at most
//     embedded_clear_max_corrected (4) bits, which is everything the message layer delivers. Its
//     5-bit checksum passes one wrong LC in 31, so everything rests on BPTC: a wrong codeword is at
//     least 8 bits from the one sent, so one accepted with 4 changed bits needs at least 4 errors on
//     the positions where it differs. A stricter limit is the safer direction but costs clear audio
//     (a late entry waits longer, and a clear transmission that ends before a good enough LC is
//     written encrypted); the preference here is for clear audio, since a wrong LC that says clear on
//     an encrypted call is followed within a superframe by the next one, which says encrypted;
//   - an LC that is not good enough alone (an RS-corrected header, an embedded LC with more changed
//     bits) when it repeats, octet for octet, the transmission's last LC that said clear
//     (clear_on_repeated_lc): a wrong one would have to be the same wrong codeword twice.
// An embedded LC counts only when its four bursts B-E all belong to this transmission after its last
// gap, so the LC that names a new talker gives the new transmission its identity, and can say
// encrypted, but clear waits for the next one: a single wrong LC cannot turn an encrypted
// transmission clear. Nothing else says clear: not a terminator's LC, not EMB PI = 0, not direct mode
// (it carries LCs like any other), not the transmission before.
//
// Two words for a weak indicator (weak_indicators_need_two). On real air a decoded encryption word
// sometimes has wrong contents (p25d found this on P25), and when one word is final a single bad one
// mutes the rest of a clear transmission. Burst F is a (32,11) code with no CRC, so noise decodes as encryption
// parameters now and then; PI = 1 comes from lost bursts' noise as above. So a weak word makes the
// transmission encrypted only when a second word of the same kind agrees: another burst F with the
// same algorithm and key (one that differs takes the first one's place), another PI = 1; or when a
// strong indicator comes. A word of the other weak kind is not a second word. Until then the
// transmission stays as it is (Unknown frames are held, Clear stays Clear), and its frames wait with
// the word (hold_while_weak_pending), so the second word writes them encrypted from the first word's
// burst on. A clear word of the same field forgets a waiting word (weak_forgotten_by_clear_word):
// burst F decoded as a null, TXI or reverse channel message, or a valid EMB with PI = 0; the frames
// that waited go out clear. A checked LC that says clear does not (weak_forgotten_by_clear_lc off):
// where the LCs do not carry the privacy bit, burst E's LC says clear between every two bursts F, and
// a call that says "encrypted" only in burst F would never get its second word. A word still waiting
// at the end is not believed: frames of bursts up to the last confirmed one go out as the state says
// (Clear: clear), the rest unconfirmed.
//
// Hold until first. Frames of a transmission in state Unknown are held, in order: Clear writes them
// clear and the live frames follow; Encrypted writes them encrypted (confirmed or not, as the
// evidence is), and the rest too; an end still Unknown writes them encrypted and unconfirmed. A
// transmission caught at its header holds nothing; a late entry holds until burst E completes the
// embedded LC. In a Clear transmission the frames of a burst nothing confirmed wait too, for the
// next confirmed voice burst (written clear) or a gap or the end (unconfirmed); and so do the frames
// while a weak word waits. At most max_held_frames (3,000, 60 s) wait per slot; beyond that the oldest
// are written encrypted and unconfirmed. Nothing is dropped and the order within a slot is kept.
//
// Boundaries nobody saw. Apart from a system whose own LCs say clear on encrypted voice, a wrong LC
// that passes its checks, and a weak word without its second, encrypted voice can be labelled clear
// in one way: a boundary between two transmissions the tracker did not see, so that "clear" said by
// one is applied to the other's frames (forwards: more voice after a clear transmission; backwards:
// held frames released by the next one's LC). Four checks close it, none of which ends anything a
// real boundary would not:
//   The gap. A transmission's voice bursts are 60 ms apart, and between two transmissions there are
//     at least two bursts that are not voice (a terminator, a header). So when voice resumes more than
//     voice_gap_us (150 ms: two or more bursts missing) after the last confirmed burst, "clear" does not
//     cross: held frames from before are written unconfirmed, Clear goes back to Unknown and the
//     frames after wait for the next LC. The transmission goes on (identity, frame numbers, Encrypted
//     if it was); a dropout costs a hold, not audio, unless the transmission ends before its next LC.
//   Bursts nothing confirmed (unconfirmed_is_missing). Inside a call the sink hands on up to two
//     periods in a row in which it found neither a sync nor an EMB, as the voice bursts its count
//     expects. Such a burst is whatever was received there: voice whose EMB failed, noise, or a damaged
//     terminator and header. It counts as missing for the gap (two in a row are a gap though the
//     timestamps show none), and in a Clear transmission its frames wait for the next confirmed burst:
//     with no gap between they are written clear, in place; with a gap or the end first, unconfirmed.
//     Every frame is still written: most such bursts are real voice. A burst's own voice confirms it
//     when its three frames needed at most clean_voice_confirms_max_fec (9) Golay corrections in all:
//     noise through the two Golay decodes needs about 17: the code is perfect, so a random 23-bit word
//     is on average 2.85 bits from its codeword (of the 2,048 syndromes 1, 23, 253 and 1,771 are
//     patterns of 0, 1, 2 and 3 bits), about 5.7 a frame; a burst received at a 5 % bit error rate
//     needs about 7 (47 protected bits a frame).
//   The superframe position. Superframes A-F follow each other without a break and a transmission
//     starts at A, so a voice burst whose position is not the one the transmission's timing calls for
//     is not that transmission's: it ends there and a new one starts, Unknown (Resync).
//   The slot grid. The bursts of one timeslot are a whole number of 60 ms periods apart and the other
//     timeslot's are 30 ms from them. A voice burst (or a second header) more than
//     slot_grid_tolerance_us (5 ms) off the grid of the transmission's last burst is not that
//     transmission's: it ends there and a new one starts (Resync). This catches a sink that numbers a
//     timeslot's bursts with the other's number for a while, and another transmitter's timing.
// What is left: two transmissions in step (the next burst A exactly where the last superframe's
// would have been) with nothing at all, or a single lost burst, between them. The one case in which
// a transmission's records go from encrypted to clear: after a gap or the hold limit wrote held
// frames unconfirmed, a later LC says clear.
//
// Ends that are no boundary (carry_encrypted). The sink can cut one transmission in two without a
// boundary: a noise window handed on as a data burst whose slot type does not decode, or a burst off
// the slot grid. Where every LC carries the privacy bit that costs nothing, but where "encrypted" is
// said once (a PI header on a system whose LCs lack the bit) the second part's own LC would say
// clear. So such an end leaves "encrypted" behind for fade_us from the last burst: a transmission that
// starts with a voice burst on the first one's 60 ms grid within that time, under either slot number,
// starts encrypted, unconfirmed, with its algorithm and key; likewise one on the grid of an encrypted
// transmission in progress under the other slot number. A boundary seen on the slot (a data burst
// whose slot type decodes, a header, a PI header) clears it. A sync loss or a superframe resync leaves
// nothing behind unless carry_encrypted_across_sync_loss: there the end is more often a real one, and
// carrying would write a clear call that follows an encrypted one encrypted.
//
// Time. Burst timestamps must be signal time (60 ms from one burst of a slot to the next, exactly),
// not the time a burst was processed: the fade, the gap, the superframe position and the slot grid
// are all timed by it, and the records' timestamps are made from it.
//
// Not here: colour code gating, P_CLEAR decoding and the talker alias belong to the channel's owner,
// which calls dmr_call_end_call() for a P_CLEAR and dmr_msg_reset_slot() from the end event of a fade,
// no voice or release. Not thread safe: one tracker belongs to one channel's thread.

uint64_t const Dmr_hold_bin_limit_us[DMR_HOLD_BINS - 1] = { 60000, 360000, 720000, 2000000 };

enum {
  SLOTS = 3,               // 0 = slot not known, 1, 2
  SUPERFRAME_BURSTS = 6,
};
#define BURST_PERIOD_US 60000ull // between bursts of one timeslot

// What an LC that says clear is worth: nothing, something when repeated, enough by itself
enum clear_evidence { EVIDENCE_NONE, EVIDENCE_REPEATED, EVIDENCE_ALONE };
enum indicator { BY_LC, BY_PI_HEADER, BY_BURST_F, BY_EMB_PI, BY_CARRIED };
// What an end means for "encrypted" left behind on the slot
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
char const *dmr_emb_pi_mode_name(enum dmr_emb_pi_mode m){
  switch(m){
  case DMR_EMB_PI_ENCRYPTED: return "encrypted";
  case DMR_EMB_PI_IGNORE: return "ignore";
  case DMR_EMB_PI_UNLESS_LC_CLEAR: return "unless-clear";
  }
  return "?";
}

void dmr_call_config_init(struct dmr_call_config *c){
  memset(c,0,sizeof *c);
  c->fade_us = 1000000;
  c->pre_voice_timeout_us = 360000;
  c->max_held_frames = 3000;
  c->voice_gap_us = 150000;
  c->embedded_clear_max_corrected = 4;
  c->header_clear_needs_uncorrected = true;
  c->clear_on_repeated_lc = true;
  c->emb_pi_says_encrypted = true;
  c->emb_pi_max_errors = 0;
  c->emb_pi_repeat_counts = true;
  c->emb_pi_clean_voice_max_fec = 14;
  c->emb_pi_mode = DMR_EMB_PI_ENCRYPTED;
  c->weak_indicators_need_two = true;
  c->weak_forgotten_by_clear_word = true;
  c->weak_forgotten_by_clear_lc = false;
  c->hold_while_weak_pending = true;
  c->check_superframe_position = true;
  c->unconfirmed_is_missing = true;
  c->clean_voice_confirms_max_fec = 9;
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

// ---------------- Held frames ----------------

static struct dmr_voice_record *held_at(struct dmr_held_frames const *h,size_t i){
  return &h->rec[(h->head + i) % h->capacity];
}
static bool held_push(struct dmr_held_frames *h,struct dmr_voice_record const *r){
  if(h->count == h->capacity){
    size_t const capacity = h->capacity == 0 ? 48 : 2 * h->capacity;
    struct dmr_voice_record *rec = malloc(capacity * sizeof *rec);
    if(rec == NULL)
      return false;
    for(size_t i=0; i < h->count; i++) // unroll the ring
      rec[i] = *held_at(h,i);
    free(h->rec);
    h->rec = rec;
    h->capacity = capacity;
    h->head = 0;
  }
  h->rec[(h->head + h->count) % h->capacity] = *r;
  h->count++;
  return true;
}
static void held_pop(struct dmr_held_frames *h,size_t n){
  if(n > h->count)
    n = h->count;
  if(h->capacity > 0)
    h->head = (h->head + n) % h->capacity;
  h->count -= n;
}

// A fresh transmission, keeping the held frames' buffer
static void tx_clear(struct dmr_transmission *tx){
  struct dmr_held_frames held = tx->held;
  memset(tx,0,sizeof *tx);
  tx->started_by = DMR_START_LATE_ENTRY;
  tx->id.group = true;
  tx->id.address_bits = 24;
  tx->recorded = true;
  tx->state = DMR_ENC_UNKNOWN;
  tx->mode = DMR_STATION_UNKNOWN;
  tx->held.rec = held.rec;
  tx->held.capacity = held.capacity;
  tx->held.head = 0;
  tx->held.count = 0;
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
                        enum dmr_call_label label,bool was_held){
  // A record is clear only out of a transmission in state Clear, whatever the caller asked for
  if(label == DMR_LABEL_CLEAR && tx->state != DMR_ENC_CLEAR)
    label = DMR_LABEL_UNCONFIRMED_AT_END;

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
  switch(label){
  case DMR_LABEL_CLEAR:
    record_mark_clear(&record);
    tx->frames_clear++;
    if(write)
      c->frames_clear++;
    if(was_held)
      c->held_released_clear++;
    break;
  case DMR_LABEL_ENCRYPTED:
    record.dmr_algorithm_id = tx->algorithm;
    record.key_id = tx->key_id;
    record.message_indicator = tx->mi;
    record_mark_encrypted(&record,!tx->confirmed);
    if(tx->confirmed)
      tx->frames_encrypted++;
    else
      tx->frames_unconfirmed++;
    if(write){
      if(tx->confirmed)
        c->frames_encrypted++;
      else
        c->frames_unconfirmed++;
    }
    if(was_held)
      c->held_released_encrypted++;
    break;
  case DMR_LABEL_UNCONFIRMED_AT_END:
  case DMR_LABEL_UNCONFIRMED_AT_CAP:
  case DMR_LABEL_UNCONFIRMED_AT_GAP:
    record_mark_encrypted(&record,true);
    tx->frames_unconfirmed++;
    if(write)
      c->frames_unconfirmed++;
    if(was_held){
      if(label == DMR_LABEL_UNCONFIRMED_AT_END)
        c->held_unconfirmed_at_end++;
      else if(label == DMR_LABEL_UNCONFIRMED_AT_CAP)
        c->held_unconfirmed_at_cap++;
      else
        c->held_unconfirmed_at_gap++;
    }
    break;
  }
  if(!write){
    c->frames_not_recorded++;
    return;
  }
  if(t->on_voice != NULL)
    t->on_voice(t->voice_arg,t->system_name,t->site_name,&record);
}

// Write the transmission's held frames (or the first count of them), oldest first, with one label
static void release_held(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,enum dmr_call_label label,
                         uint64_t now,size_t count){
  struct dmr_call_counters *c = &t->counters;
  uint64_t const held_since = held_at(&tx->held,0)->timestamp_us;
  uint64_t const hold_us = now > held_since ? now - held_since : 0;
  c->holds++;
  if(hold_us > c->longest_hold_us)
    c->longest_hold_us = hold_us;
  int bin = 0;
  while(bin < DMR_HOLD_BINS - 1 && hold_us > Dmr_hold_bin_limit_us[bin])
    bin++;
  c->hold_bins[bin]++;
  if(count > tx->held.count)
    count = tx->held.count;
  for(size_t i=0; i < count; i++)
    write_frame(t,tx,slot,*held_at(&tx->held,i),label,true);
  held_pop(&tx->held,count);
  tx->held_through_confirmed = tx->held_through_confirmed > count ? tx->held_through_confirmed - count : 0;
}
static void release_all(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,enum dmr_call_label label,
                        uint64_t now){
  release_held(t,tx,slot,label,now,SIZE_MAX);
}

// ---------------- Events ----------------

static void fill_meta(struct dmr_call_tracker const *t,struct dmr_transmission const *tx,uint8_t slot,struct dmr_call_meta *m){
  memset(m,0,sizeof *m);
  m->system_name = t->system_name;
  m->site_name = t->site_name;
  m->call_key = t->keys[slot];
  m->talkgroup_id = tx->identity_known ? tx->id.destination : 0;
  m->source_id = tx->identity_known ? tx->id.source : 0;
  m->encrypted = tx->state != DMR_ENC_CLEAR; // not shown to be clear counts as encrypted
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

// ---------------- Start and end ----------------

// Clear, its frames held for a weak word that never got a second: one word is not believed
static bool holding_for_weak(struct dmr_call_tracker const *t,struct dmr_transmission const *tx){
  return t->config.hold_while_weak_pending && (tx->pending_pi || tx->pending_f);
}

static void end(struct dmr_call_tracker *t,uint8_t slot,enum dmr_call_end reason,uint64_t now,enum end_kind kind){
  struct dmr_transmission *tx = &t->slots[slot];
  if(!tx->active)
    return;
  // Clear, with frames held for a weak word that got no second: those of bursts up to the last
  // confirmed one are clear
  if(tx->state == DMR_ENC_CLEAR && holding_for_weak(t,tx) && tx->held_through_confirmed > 0)
    release_held(t,tx,slot,DMR_LABEL_CLEAR,now,tx->held_through_confirmed);
  // Still Unknown: nothing in the transmission said clear, so its frames are not
  if(tx->held.count > 0)
    release_all(t,tx,slot,DMR_LABEL_UNCONFIRMED_AT_END,now);

  // A boundary clears what was left behind on the slot; an end that is none leaves "encrypted",
  // or leaves what was there
  if(kind == END_BOUNDARY){
    memset(&t->carry[slot],0,sizeof t->carry[slot]);
  } else if(kind == END_NOT_ONE && t->config.carry_encrypted && tx->state == DMR_ENC_ENCRYPTED){
    struct dmr_carry *c = &t->carry[slot];
    c->active = true;
    c->last_us = tx->last_activity_us;
    c->until_us = tx->last_activity_us + t->config.fade_us;
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
  c->weak_never_confirmed += (tx->pending_pi ? 1u : 0u) + (tx->pending_f ? 1u : 0u);
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
  t->counters.transmissions++;
  t->counters.started[reason]++;
  return tx;
}

static void say_encrypted(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,uint64_t now,bool strong,
                          enum indicator by);

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
      c->algorithm = other->algorithm;
      c->key_id = other->key_id;
      c->mi = other->mi;
      return c;
    }
  }
  return NULL;
}

// A transmission that starts with a voice burst takes "encrypted" from an encrypted transmission it
// may be the continuation of
static struct dmr_transmission *start_with_voice(struct dmr_call_tracker *t,uint8_t slot,enum dmr_call_start reason,
                                                 uint64_t now){
  struct dmr_transmission *tx = start(t,slot,reason,now);
  struct dmr_carry const *from = encrypted_before(t,slot,now);
  if(from != NULL){
    tx->algorithm = from->algorithm;
    tx->key_id = from->key_id;
    tx->mi = from->mi;
    say_encrypted(t,tx,slot,now,false,BY_CARRIED);
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

// ---------------- Encryption ----------------

static void say_clear(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,uint64_t now){
  if(tx->state != DMR_ENC_UNKNOWN)
    return;
  tx->state = DMR_ENC_CLEAR;
  if(tx->held.count > 0 && !holding_for_weak(t,tx))
    release_all(t,tx,slot,DMR_LABEL_CLEAR,now);
}

static void say_encrypted(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,uint64_t now,bool strong,
                          enum indicator by){
  if(tx->state == DMR_ENC_ENCRYPTED){
    if(strong)
      tx->confirmed = true;
    return;
  }
  struct dmr_call_counters *c = &t->counters;
  if(tx->state == DMR_ENC_CLEAR)
    c->clear_then_encrypted++;
  tx->state = DMR_ENC_ENCRYPTED;
  tx->confirmed = strong;
  tx->pending_pi = tx->pending_f = false; // nothing waits any more
  switch(by){
  case BY_LC: c->encrypted_by_lc++; break;
  case BY_PI_HEADER: c->encrypted_by_pi_header++; break;
  case BY_BURST_F: c->encrypted_by_burst_f++; break;
  case BY_EMB_PI: c->encrypted_by_emb_pi++; break;
  case BY_CARRIED: c->encrypted_carried++; break;
  }
  if(tx->held.count > 0)
    release_all(t,tx,slot,DMR_LABEL_ENCRYPTED,now);
}

// A weak indicator waits for its second word unless the transmission is already encrypted or this
// word agrees with the one waiting
static bool weak_waits(struct dmr_call_tracker const *t,struct dmr_transmission const *tx,bool agrees){
  return t->config.weak_indicators_need_two && tx->state != DMR_ENC_ENCRYPTED && !agrees;
}

// The transmission's bursts stopped for longer than voice_gap_us and voice is here again: a
// boundary may be hidden in the gap, so "clear" does not cross it. Encrypted does
static void after_gap(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,uint64_t now,
                      bool unconfirmed_between){
  tx->bursts_since_gap = 0;
  if(tx->state == DMR_ENC_ENCRYPTED)
    return;
  t->counters.gaps++;
  if(unconfirmed_between)
    t->counters.gaps_unconfirmed++;
  if(tx->held.count > 0)
    release_all(t,tx,slot,DMR_LABEL_UNCONFIRMED_AT_GAP,now);
  if(tx->state == DMR_ENC_CLEAR){
    tx->state = DMR_ENC_UNKNOWN;
    t->counters.clear_lost_at_gap++;
  }
}

// What a checked LC of this transmission says: identity, then privacy. evidence: what the LC is
// worth if it says clear
// learned_mask: the LC is valid only through a learned CRC residual (dmrmsg.h): it gives identity and may
// say encrypted, never clear (its evidence is NONE)
// dmr_lc_voice_identity() with the system's talkgroup form applied (config.compressed_talkgroups): every
// identity the tracker reads comes through here, so two LCs of one call compare alike
// A voice LC naming source 0 says nothing of the call yet: Capacity Plus sends a wide-area voice header
// with source 0 and, 120 ms later, one naming the radio. Taken as an identity it opened a transmission of
// its own, ended empty by the next header; as none, the next header joins its transmission
static bool identity_of(struct dmr_call_tracker const *t,struct dmr_lc const *lc,struct dmr_voice_identity *id){
  if(!dmr_lc_voice_identity(lc,id) || id->source == 0)
    return false;
  if(t->config.compressed_talkgroups && id->group && id->address_bits == 24)
    id->destination = dmr_hytera_dialable_talkgroup(id->destination);
  return true;
}

static void apply_lc(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,uint64_t now,struct dmr_lc const *lc,
                     enum clear_evidence evidence,bool header,bool learned_mask){
  struct dmr_call_counters *c = &t->counters;
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
    say_encrypted(t,tx,slot,now,true,BY_LC);
    break;
  case DMR_LC_CLEAR:
    tx->lc_said_clear = true;
    if(t->config.weak_forgotten_by_clear_lc && (tx->pending_pi || tx->pending_f)){
      c->weak_forgotten_by_lc += (tx->pending_pi ? 1u : 0u) + (tx->pending_f ? 1u : 0u);
      tx->pending_pi = tx->pending_f = false;
    }
    if(tx->state == DMR_ENC_ENCRYPTED){
      c->contradictions++;
    } else if(tx->state == DMR_ENC_UNKNOWN){
      if(evidence == EVIDENCE_ALONE){
        if(header)
          c->clear_by_header++;
        else
          c->clear_by_embedded_lc++;
        say_clear(t,tx,slot,now);
      } else if(evidence == EVIDENCE_REPEATED && t->config.clear_on_repeated_lc && tx->have_clear_lc
                && memcmp(tx->clear_lc,lc->bytes,sizeof tx->clear_lc) == 0){
        c->clear_by_repeated_lc++;
        say_clear(t,tx,slot,now);
      } else if(evidence == EVIDENCE_NONE && learned_mask){
        c->clear_refused_learned_mask++;
      } else {
        if(header)
          c->clear_refused_header++;
        else
          c->clear_refused_embedded++;
      }
    }
    if(evidence != EVIDENCE_NONE){
      tx->have_clear_lc = true;
      memcpy(tx->clear_lc,lc->bytes,sizeof tx->clear_lc);
    }
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
  bool const alone = data->lc_uncorrected || !t->config.header_clear_needs_uncorrected;
  if(data->learned_mask)
    t->counters.learned_mask_lcs++;
  apply_lc(t,tx,slot,now,lc,data->learned_mask ? EVIDENCE_NONE : alone ? EVIDENCE_ALONE : EVIDENCE_REPEATED,true,
           data->learned_mask);
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
  say_encrypted(t,tx,slot,now,true,BY_PI_HEADER);
}

// A terminator's LC names a transmission that never read an LC (for the frames still held, written
// encrypted whatever it says: a terminator does not say clear), and it can say encrypted
static void on_terminator_lc(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,struct dmr_lc const *lc,
                             uint64_t now){
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
    say_encrypted(t,tx,slot,now,true,BY_LC);
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
      on_terminator_lc(t,tx,slot,&data->lc,now);
  } else if(typed && b->data_type == DMR_DT_IDLE){
    reason = DMR_END_IDLE;
  } else if(typed && b->data_type == DMR_DT_VOICE_LC_HEADER){
    reason = DMR_END_NEW_HEADER; // a header that did not decode: its voice will be a late entry
  }
  end(t,slot,reason,now,typed ? END_BOUNDARY : END_NOT_ONE);
}

// ---------------- Voice bursts ----------------

static void add_frames(struct dmr_call_tracker *t,struct dmr_transmission *tx,uint8_t slot,struct dmr_burst const *b,
                       struct dmr_voice_burst const *voice,uint64_t now,bool confirmed){
  // Unknown: every frame waits. Clear: the frames of a burst nothing confirmed wait for the next
  // confirmed burst (whatever still waits then goes first, so the order holds)
  bool const wait = tx->state == DMR_ENC_UNKNOWN
    || (tx->state == DMR_ENC_CLEAR && (!confirmed || tx->held.count > 0 || holding_for_weak(t,tx)));
  for(int k=0; k < DMR_VOICE_FRAMES; k++){
    struct dmr_voice_frame const *frame = &voice->frames[k];
    struct dmr_voice_record record;
    dmr_voice_record_init(&record);
    record.timestamp_us = b->timestamp_us + (uint64_t)k * DMR_VOICE_FRAME_INTERVAL_US;
    record.frame_number = (uint8_t)(tx->frames & 0xff);
    tx->frames++;
    memcpy(record.voice,frame->bytes,sizeof record.voice);
    record_set_fec_errors(&record,frame->fec_errors);
    if(wait){
      if(held_push(&tx->held,&record)){
        t->counters.frames_held++;
        continue;
      }
      // Out of memory: what waits goes out unconfirmed, in order, and this frame after it
      if(tx->held.count > 0)
        release_all(t,tx,slot,DMR_LABEL_UNCONFIRMED_AT_CAP,now);
      write_frame(t,tx,slot,record,DMR_LABEL_UNCONFIRMED_AT_CAP,false);
    } else {
      write_frame(t,tx,slot,record,tx->state == DMR_ENC_CLEAR ? DMR_LABEL_CLEAR : DMR_LABEL_ENCRYPTED,false);
    }
  }
  if(wait && confirmed)
    tx->held_through_confirmed = tx->held.count;
  while(tx->held.count > t->config.max_held_frames){
    struct dmr_voice_record const first = *held_at(&tx->held,0);
    uint64_t const held_since = first.timestamp_us;
    if(now > held_since && now - held_since > t->counters.longest_hold_us)
      t->counters.longest_hold_us = now - held_since;
    write_frame(t,tx,slot,first,DMR_LABEL_UNCONFIRMED_AT_CAP,true);
    held_pop(&tx->held,1);
    if(tx->held_through_confirmed > 0)
      tx->held_through_confirmed--;
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
    after_gap(t,tx,slot,now,now - tx->last_activity_us <= cfg->voice_gap_us);

  // A new talker: an LC of this voice names another call than the one established
  struct dmr_voice_identity embedded_id;
  bool const has_embedded_id = m->has_embedded_lc && identity_of(t,&m->embedded_lc.lc,&embedded_id);
  if(tx->active && tx->identity_known && has_embedded_id && embedded_id.address_bits == tx->id.address_bits
     && !same_call(&tx->id,&embedded_id)){
    end(t,slot,DMR_END_NEW_TALKER,now,END_BOUNDARY);
    tx = start(t,slot,DMR_START_NEW_TALKER,now);
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

  // What this burst says, the encrypted side first: it applies to the burst's own frames too
  if(b->kind != DMR_KIND_VOICE_A && b->emb_valid){
    if(b->emb_pi){
      tx->emb_pi1_bursts++;
      enum dmr_emb_pi_mode const mode = dmr_call_effective_emb_pi_mode(cfg);
      bool const repeated = cfg->emb_pi_repeat_counts && tx->last_emb_pi;
      bool const clean = cfg->emb_pi_clean_voice_max_fec >= 0 && fec <= cfg->emb_pi_clean_voice_max_fec;
      if(b->emb_errors > cfg->emb_pi_max_errors && !repeated && !clean){
        c->emb_pi_over_errors++; // a corrected EMB: its PI bit says nothing
      } else if(mode == DMR_EMB_PI_IGNORE){
        c->emb_pi_ignored++;
      } else if(mode == DMR_EMB_PI_UNLESS_LC_CLEAR && tx->state == DMR_ENC_CLEAR){
        c->emb_pi_with_clear_lc++;
      } else if(weak_waits(t,tx,tx->pending_pi)){
        tx->pending_pi = true; // the first word: the next PI = 1 says encrypted
        c->weak_pending++;
      } else {
        say_encrypted(t,tx,slot,now,false,BY_EMB_PI);
      }
    } else {
      tx->emb_pi0_bursts++;
      if(tx->pending_pi && cfg->weak_forgotten_by_clear_word){ // a clear word of the same field
        tx->pending_pi = false;
        c->weak_forgotten_by_word++;
      }
    }
    tx->last_emb_pi = b->emb_pi;
  }
  if(m->has_single_burst && m->single_burst.kind == DMR_SB_ENCRYPTION_PARAMETERS){
    struct dmr_single_burst const *f = &m->single_burst;
    bool const agrees = tx->pending_f && tx->pending_f_algorithm == f->algorithm_id && tx->pending_f_key == f->key_id;
    if(weak_waits(t,tx,agrees)){
      // The first word, or one that does not agree with the one waiting: it waits in its place
      tx->pending_f = true;
      tx->pending_f_algorithm = f->algorithm_id;
      tx->pending_f_key = f->key_id;
      c->weak_pending++;
    } else {
      if(tx->algorithm == 0 && tx->key_id == 0){ // a PI header's parameters stand
        tx->algorithm = f->algorithm_id;
        tx->key_id = f->key_id;
      }
      say_encrypted(t,tx,slot,now,f->corrected == 0,BY_BURST_F);
    }
  } else if(m->has_single_burst && m->single_burst.kind != DMR_SB_UNKNOWN && tx->pending_f
            && cfg->weak_forgotten_by_clear_word){
    tx->pending_f = false; // burst F decoded as another message: a clear word of the same field
    c->weak_forgotten_by_word++;
  }
  if(m->has_embedded_lc){
    // The LC's four fragments came in the slot's last four voice bursts: all this transmission's,
    // and after its last gap, when it has had four since
    enum clear_evidence evidence = EVIDENCE_NONE;
    if(tx->bursts_since_gap >= 4 && !m->embedded_lc.learned_mask) // a learned residual never says clear
      evidence = m->embedded_lc.corrected <= cfg->embedded_clear_max_corrected ? EVIDENCE_ALONE : EVIDENCE_REPEATED;
    if(m->embedded_lc.learned_mask)
      c->learned_mask_lcs++;
    apply_lc(t,tx,slot,now,&m->embedded_lc.lc,evidence,false,m->embedded_lc.learned_mask);
  }
  if(m->has_hidden_iv && tx->state == DMR_ENC_ENCRYPTED && tx->confirmed){
    tx->mi = m->hidden_iv.iv;
    c->hidden_ivs_used++;
  }

  // Frames of unconfirmed bursts that waited in a clear transmission (or for a weak word this burst's
  // clear word forgot): this confirmed burst follows them without a gap and said nothing encrypted
  if(confirmed && tx->state == DMR_ENC_CLEAR && tx->held.count > 0 && !holding_for_weak(t,tx))
    release_all(t,tx,slot,DMR_LABEL_CLEAR,now);

  add_frames(t,tx,slot,b,&m->voice,now,confirmed);
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
  for(uint8_t slot=0; slot < SLOTS; slot++){
    struct dmr_transmission *tx = &t->slots[slot];
    if(tx->active && tx->held.count > 0)
      release_all(t,tx,slot,DMR_LABEL_UNCONFIRMED_AT_END,tx->last_activity_us);
    free(tx->held.rec);
    tx->held.rec = NULL;
    tx->held.capacity = tx->held.count = tx->held.head = 0;
  }
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
  return slot < SLOTS ? t->slots[slot].state : DMR_ENC_UNKNOWN;
}
size_t dmr_call_held_frames(struct dmr_call_tracker const *t,uint8_t slot){
  return slot < SLOTS ? t->slots[slot].held.count : 0;
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
      " | frames clear=%llu encrypted=%llu unconfirmed=%llu skipped=%llu"
      " | held=%llu released clear=%llu encrypted=%llu at_end=%llu at_gap=%llu at_cap=%llu longest_ms=%llu",
      N(c->without_voice),N(c->never_identified),N(c->not_recorded),N(c->frames_clear),N(c->frames_encrypted),
      N(c->frames_unconfirmed),N(c->frames_not_recorded),N(c->frames_held),N(c->held_released_clear),
      N(c->held_released_encrypted),N(c->held_unconfirmed_at_end),N(c->held_unconfirmed_at_gap),
      N(c->held_unconfirmed_at_cap),N(c->longest_hold_us / 1000));
  put(buf,size,&len," | clear_by header=%llu lc=%llu repeated_lc=%llu refused header=%llu lc=%llu gaps=%llu (unconfirmed=%llu)"
      " clear_lost_at_gap=%llu unconfirmed_bursts=%llu (clean_voice=%llu) off_grid=%llu"
      " | encrypted_by lc=%llu pi_header=%llu burst_f=%llu emb_pi=%llu carried=%llu"
      " | weak_waited=%llu forgotten word=%llu lc=%llu never_confirmed=%llu"
      " | clear_then_encrypted=%llu contradictions=%llu terminator_encrypted=%llu",
      N(c->clear_by_header),N(c->clear_by_embedded_lc),N(c->clear_by_repeated_lc),N(c->clear_refused_header),
      N(c->clear_refused_embedded),N(c->gaps),N(c->gaps_unconfirmed),N(c->clear_lost_at_gap),N(c->unconfirmed_voice_bursts),
      N(c->unconfirmed_clean_voice),N(c->off_grid),N(c->encrypted_by_lc),N(c->encrypted_by_pi_header),
      N(c->encrypted_by_burst_f),N(c->encrypted_by_emb_pi),N(c->encrypted_carried),N(c->weak_pending),
      N(c->weak_forgotten_by_word),N(c->weak_forgotten_by_lc),N(c->weak_never_confirmed),N(c->clear_then_encrypted),
      N(c->contradictions),N(c->terminator_says_encrypted));
  put(buf,size,&len," | emb_pi=1 bursts: lc_encrypted=%llu lc_clear=%llu no_lc=%llu; emb_pi=0 bursts: lc_encrypted=%llu"
      " lc_clear=%llu no_lc=%llu | emb_pi=1 not counted: corrected_emb=%llu ignored=%llu clear_lc=%llu",
      N(c->emb_pi[1][2]),N(c->emb_pi[1][1]),N(c->emb_pi[1][0]),N(c->emb_pi[0][2]),N(c->emb_pi[0][1]),
      N(c->emb_pi[0][0]),N(c->emb_pi_over_errors),N(c->emb_pi_ignored),N(c->emb_pi_with_clear_lc));
#undef N
  return (int)len;
}
