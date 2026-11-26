// DMR site layer (see dmrsite.h): configuration, the site's identity, the control log, the site state
// shared by a site's channels, and the control plane each channel runs per burst
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dmrfec.h"
#include "dmrsite.h"

// Theory of operation
//
// The split. A trunked DMR site is several carriers: a control or rest channel and the repeaters that
// carry the calls. Each carrier has its own decoder on its own thread (dmrchan.c: receiver, burst sink,
// message layer, call tracker), and nothing in those decoders knows about the others. What the site
// says about itself belongs to the site, not to any carrier: its identity, which repeater is the rest
// channel, LCN -> frequency, which calls it is announcing and where, its grants and clear-downs. That is
// the struct dmr_site here, one per site, which every channel of the site reports to. Between the two
// sits a struct dmr_cplane per channel (the control plane of that channel): it takes each burst with
// what the message layer made of it, parses the CSBKs and assembles the multi-block ones (dmrcsbk.c),
// and routes the site-level parts to the site and the log-worthy parts to the control log.
//
// One radiod first, but not assumed. dmrd today takes a fixed list of repeater channels from one
// radiod. Planned are sites whose repeaters span two receivers (two Airspys, one on 450-455 MHz and one
// on 460-465 MHz, with the control channel on one and the traffic on the other). So nothing here
// assumes one radiod: a channel is known by its id, LCN and frequency, never by a receiver, and the
// question "which radiod and SSRC serve this frequency" has exactly one answer, the locate function in
// struct dmr_site_handlers (dmr_site_locate()). It is a function the owner gives, never a global;
// dmr_locate_single_radiod() is the answer for one radiod, and a two-receiver owner replaces it with
// one that picks the radiod whose span covers the frequency. Site-level state stays out of the
// per-channel decoders for the same reason: the channels of one site may be on different receivers
// and threads, and the site is what joins them.
//
// Grant following is not built here. Every grant goes to the handlers' grant function with the
// frequency it resolves to (the hook); a follower decides from it (talkgroup lists, data or voice,
// encryption, how many at once, hang time), asks dmr_site_locate() which radiod and SSRC carry the
// frequency, asks that radiod for the channel, and attaches a new channel's decoder to the site
// (dmr_site_attach(); dmr_site_detach() when it lets the channel go). The site's P_CLEAR hook names the
// channel and slot whose call has ended, for that channel's call tracker.
//
// Threads. The site is shared: one mutex, held for a few table updates. What an entry point decides to
// write or call (log lines, the grant and clear hooks) is collected under the lock and done after it is
// released, on the reporting channel's thread, so a hook may call back into the site. The system tag is
// read without the lock (every channel reads it every burst).
//
// Identity (systemTag). What the air says, by the family the configured system type belongs to:
//   Tier III family (tier3, hytera_tier3, capacity_max): the 14-bit system identity code of an Aloha
//     (standard, Capacity Max or Hytera), of any C_BCAST, or of the Sys_Parms Short LC;
//   Capacity Plus family (capacity_plus, linked_capacity_plus): the site of the rest channel Short LC;
//   Connect Plus: the network and site of its Short LC;
//   Hytera XPT: nothing decoded names the site, so the tag says only "an XPT site";
//   conventional: none, the tag stays 0.
// An identity is adopted, or replaces the one held, only when the same value has come
// identity_confirmations (2) times running: the Short LC has only an 8-bit CRC, and a record's tag must
// not flicker on one bad decode. A message of another family never sets the identity; it is counted and
// reported once per family, since the configured type is probably wrong. The tag is family << 28 | the
// identity (Tier III: the 14 bits; Capacity Plus: the 5-bit site; Connect Plus: network << 8 | site;
// XPT: 0). It depends only on what the site sends and the configured family, so it is the same after a
// restart and on another receiver, and never 0 once known. Two unrelated systems may send the same
// identity (many a single-site Capacity Plus system is "site 1"): the tag tells sites apart within a
// system, the system name tells systems apart.
//
// The cross-check. With every repeater monitored, the site's own signalling says what should be heard.
// Three kinds of message say a timeslot carries a voice call: a Capacity Plus Site Status (its voice map,
// LSN by LSN), a Short LC Act_Updt (the two timeslots of the carrier it came on), and a grant (Tier III
// PV / TV / BTV, one message at call start; Connect Plus voice channel user and Capacity Max channel
// updates, repeated while the call lasts; the Hytera XPT channel grant LC). The channel named is looked
// up (by LCN, or by frequency for an absolute channel) and then:
//   attached (a decoder reports for it): the announcement is "heard" if that timeslot had call activity
//     (a voice burst, a voice LC header, a PI header or a terminator: the last covers the hang time,
//     while the site still lists the call) from heard_window_us (1 s) before the first announcement on.
//     It is "missed" when a repeated announcement has gone on for activity_grace_us (2 s), or a
//     one-message grant has waited grant_grace_us (3 s), with nothing heard. A miss is an alarm: counted,
//     and logged as a WARN at most once per channel timeslot per warn_interval_us (30 s), the next line
//     saying how many were not logged; the wait starts again with the next announcement, so a call that
//     is never heard raises an alarm every grace period for as long as it is listed. A repeated
//     announcement that stops (not seen for pending_expiry_us, 4 s) before its grace period is forgotten
//     (unconfirmed), as is what waits on a timeslot when a P_CLEAR is heard there. Every announcement
//     ends in one counter: announced = heard + missed + unconfirmed + not monitored + unconfigured +
//     still pending.
//   configured, nothing attached: counted (a channel only followed on demand: expected);
//   not configured: counted and logged, at most once per channel per warn_interval_us (the site has a
//     repeater the configuration does not list; at most 64 such channels are remembered).
// Data activity (data revert, data grants) is not cross-checked. Time here is the site's own monotonic
// clock, not burst time: the channels' receivers do not share a time base.
//
// The rest. The channel map (dmrcsbk.c) holds the configured channels plus what a C_BCAST "announce
// channel frequency" says; the configuration wins, and a disagreement is logged once per (LCN,
// frequency) (256 remembered). Another message's CG_AP block (a grant's) is compared with the map, and
// learned only with learn_from_any_cgap. Colour codes: per channel, bursts are counted by colour code
// against the channel's (pinned, or the first seen when tracked); another one is counted and logged once
// per (channel, colour code), and what comes with it is another system on the frequency: its Short LCs,
// CSBKs and LCs are counted and ignored (they never name this site, move its rest channel or announce
// its calls), and its voice is not "heard". A channel set to any colour code takes everything. Rest
// channel (Capacity Plus): from the Short LC, Site Status, the neighbours CSBK and the wide-area voice
// LC; each move is counted and logged, and a report of the previous rest channel within rest_holdoff_us
// (0.5 s) of a move is ignored, since one channel may be a few bursts behind another. Grants: each one
// is counted, logged with the frequency the map gives it (a GRANT line, collapsed), passed to the hook,
// and its channel cross-checked if it is voice. P_CLEAR: the pending announcement of that timeslot is
// forgotten and the clear hook called.
//
// The control plane of a channel, per burst (dmr_cplane_burst()):
//   1. a CSBK burst whose BPTC passed is parsed (the CRC with csbk_crc_mask, 0xA5A5 unless the owner
//      chose another; a block that fails is counted with the mask that would have passed); an MBC header
//      or continuation goes to the assembler (both CRCs checked); any other burst on the timeslot
//      abandons a multi-block message in progress there;
//   2. the site hears of the burst (colour code, call activity), of a Short LC, of a voice LC header's,
//      terminator's or embedded LC's link control, and of a CSBK or multi-block message that passed;
//   3. the control log gets, on the timeslot's line unless noted:
//        collapsed (written once, then counted, "(xN since ..., last ...)" each repeat_interval_s):
//          every Short LC, on the carrier's line (TS-), keyed by its text (so a moved rest channel or a
//          changed activity is a new line at once) except Sys_Parms, keyed without its slot counter;
//          every CSBK and multi-block message that passed, "CSBK <text>" / "MBC <text>", keyed by the
//          text except the data revert window announcements (their window counter changes every time),
//          keyed by kind; the site's GRANT lines;
//        once per transmission (from the first voice LC header, PI header or voice burst on the timeslot
//          to the first other burst there, or slot_gap_dibits, 4,800 = 1 s, of silence): voice LC header,
//          PI header, terminator, each different embedded LC, burst F encryption parameters, and
//          "EMB PI=1" (ETSI's pre-emption and power control indicator: the embedded field carries
//          reverse channel information for the other logical channel; not an encryption indicator);
//        every time: a completed talker alias with the talker of its transmission (one that completes
//          before the talker is known waits for it, radio unknown if the transmission ends first), and
//          "CSBK CRC FAIL ..." the 3rd time a (CSBKO, FID, observed mask) comes and every 1,000th after;
//        never: idle and voice bursts, failed checks (counted), hidden IVs, payload of any kind.
//   At most 32 once-per-transmission keys are held per timeslot; beyond that they are forgotten and at
//   worst a line is written again. Data headers and packets are not handled here.
//
// The control log. A line is "YYYY-MM-DD HH:MM:SS.mmm [cc N] [<channel id>] [TSn] <text>" in local
// time, "[cc -]" when the colour code is not known, "[TS-]" for the carrier or (channel "site") the
// site. A continuous control channel repeats itself (a Tier III control channel sends 33 CSBKs a second,
// most the same Aloha; every base station carrier a Short LC every 120 ms), so collapsed lines are
// written the first time their key ((channel, slot, key text)) is seen and then counted; the count line
// " (xN since HH:MM:SS, last HH:MM:SS)" is written once repeat_interval_s (60 s) has passed since the
// key's last line, when it next arrives or at the next dmr_control_log_time() or flush. N is the repeats
// not written, "since" the time of the key's previous line, "last" that of the last repeat, and the
// text the last repeat's. A key not seen for repeat_interval_s is forgotten (checked every quarter of
// it), so a message that returns after a quiet minute is written in full. At most max_keys (1,024) keys
// are held; when the table is full every pending count is written and it starts again. At a change of
// the local hour the pending counts are written and the table cleared, so each hour starts with every
// message in full. Nothing is dropped uncounted. There are no files: each line goes to the sink (dmrd
// prints it). When several counts come due at once they are written in the order their keys were first
// seen.

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
// Seconds from microseconds, for the log lines' "%.1f s": a division the compiler cannot turn into a
// multiplication by the reciprocal (the tree's -funsafe-math-optimizations would, and 1e-6 is inexact,
// so a tenth would flip where the value falls on a rounding boundary)
static double seconds_of(double us){
  static double volatile const million = 1e6;
  return us / million;
}
// format() into a buffer of a fixed size, truncated as format() truncates
static int format(char *buf,size_t size,char const *fmt,...) __attribute__((format(printf,3,4)));
static int format(char *buf,size_t size,char const *fmt,...){
  va_list ap;
  va_start(ap,fmt);
  int const n = vsnprintf(buf,size,fmt,ap);
  va_end(ap);
  return n;
}
static void copy_string(char *dst,size_t size,char const *src){
  if(size == 0)
    return;
  size_t n = src != NULL ? strlen(src) : 0;
  if(n >= size)
    n = size - 1;
  if(n > 0)
    memcpy(dst,src,n);
  dst[n] = '\0';
}

// ---------------- Configuration ----------------

char const *dmr_system_type_name(enum dmr_system_type t){
  switch(t){
  case DMR_SYSTEM_CONVENTIONAL: return "conventional";
  case DMR_SYSTEM_TIER3: return "tier3";
  case DMR_SYSTEM_CAPACITY_PLUS: return "capacity_plus";
  case DMR_SYSTEM_LINKED_CAPACITY_PLUS: return "linked_capacity_plus";
  case DMR_SYSTEM_CONNECT_PLUS: return "connect_plus";
  case DMR_SYSTEM_CAPACITY_MAX: return "capacity_max";
  case DMR_SYSTEM_HYTERA_XPT: return "hytera_xpt";
  case DMR_SYSTEM_HYTERA_TIER3: return "hytera_tier3";
  }
  return "unknown";
}
bool dmr_system_type_from_name(char const *name,enum dmr_system_type *t){
  for(int i = DMR_SYSTEM_CONVENTIONAL; i <= DMR_SYSTEM_HYTERA_TIER3; i++){
    if(name != NULL && strcmp(name,dmr_system_type_name((enum dmr_system_type)i)) == 0){
      if(t != NULL)
        *t = (enum dmr_system_type)i;
      return true;
    }
  }
  return false;
}
void dmr_site_config_init(struct dmr_site_config *c){
  assert(c != NULL);
  memset(c,0,sizeof *c);
  c->type = DMR_SYSTEM_CONVENTIONAL;
  c->system_color_code = DMR_SITE_CC_TRACK;
  c->site_color_code = DMR_SITE_CC_INHERIT;
}
void dmr_site_channel_config_init(struct dmr_site_channel_config *c){
  assert(c != NULL);
  memset(c,0,sizeof *c);
  c->color_code = DMR_SITE_CC_INHERIT;
}
int dmr_site_color_code_for(struct dmr_site_config const *c,struct dmr_site_channel_config const *ch){
  if(ch != NULL && ch->color_code != DMR_SITE_CC_INHERIT)
    return ch->color_code;
  if(c->site_color_code != DMR_SITE_CC_INHERIT)
    return c->site_color_code;
  return c->system_color_code == DMR_SITE_CC_INHERIT ? DMR_SITE_CC_TRACK : c->system_color_code;
}
int dmr_path_component(char *buf,size_t size,char const *name){
  size_t len = 0;
  for(char const *p = name != NULL ? name : ""; *p != '\0'; p++){
    char const c = *p;
    bool const keep = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
    append(buf,size,&len,"%c",keep ? c : '_');
  }
  return finish(buf,size,len);
}
int dmr_default_channel_id(char *buf,size_t size,char const *system_name,char const *site_name,unsigned lcn){
  char system[DMR_SITE_NAME_MAX],site[DMR_SITE_NAME_MAX];
  dmr_path_component(system,sizeof system,system_name);
  dmr_path_component(site,sizeof site,site_name);
  return format(buf,size,"dmr_%s_%s_lcn%u",system,site,lcn);
}

// ---------------- The system tag ----------------

enum dmr_tag_family dmr_tag_family_of(enum dmr_system_type t){
  switch(t){
  case DMR_SYSTEM_TIER3:
  case DMR_SYSTEM_HYTERA_TIER3:
  case DMR_SYSTEM_CAPACITY_MAX:
    return DMR_TAG_TIER3;
  case DMR_SYSTEM_CAPACITY_PLUS:
  case DMR_SYSTEM_LINKED_CAPACITY_PLUS:
    return DMR_TAG_CAPACITY_PLUS;
  case DMR_SYSTEM_CONNECT_PLUS:
    return DMR_TAG_CONNECT_PLUS;
  case DMR_SYSTEM_HYTERA_XPT:
    return DMR_TAG_HYTERA_XPT;
  case DMR_SYSTEM_CONVENTIONAL:
    break;
  }
  return DMR_TAG_NONE;
}
int dmr_system_tag_describe(char *buf,size_t size,uint32_t tag){
  uint32_t const v = tag & 0x0FFFFFFFu;
  switch(dmr_system_tag_family(tag)){
  case DMR_TAG_TIER3: {
    static char const * const model_names[4] = {"tiny", "small", "large", "huge"};
    static int const network_bits[4] = {9, 7, 4, 2};
    unsigned const model = (v >> 12) & 3u;
    int const site_bits = 12 - network_bits[model];
    return format(buf,size,"tier3 net=%u site=%u (%s)",(v & 0xFFFu) >> site_bits,v & ((1u << site_bits) - 1u),model_names[model]);
  }
  case DMR_TAG_CAPACITY_PLUS:
    return format(buf,size,"cap+ site=%u",v & 0x1Fu);
  case DMR_TAG_CONNECT_PLUS:
    return format(buf,size,"con+ net=%u site=%u",(v >> 8) & 0xFFFu,v & 0xFFu);
  case DMR_TAG_HYTERA_XPT:
    return format(buf,size,"xpt");
  case DMR_TAG_NONE:
    break;
  }
  return format(buf,size,"none");
}

// ---------------- The control log ----------------

static int64_t wall_clock_us(void){
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME,&ts);
  return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}
static struct tm local_time(int64_t us){
  time_t const seconds = (time_t)(us / 1000000);
  struct tm local;
  memset(&local,0,sizeof local);
  localtime_r(&seconds,&local);
  return local;
}

int dmr_control_line_format(char *buf,size_t size,int64_t now_us,char const *channel_id,uint8_t slot,uint8_t color_code,
                            char const *text,uint32_t repeats,int64_t since_us,int64_t last_us){
  struct tm const local = local_time(now_us);
  int64_t const ms = (now_us / 1000) % 1000;
  char cc[8];
  if(color_code <= 15)
    format(cc,sizeof cc,"%u",(unsigned)color_code);
  else
    format(cc,sizeof cc,"-");
  size_t len = 0;
  append(buf,size,&len,"%04d-%02d-%02d %02d:%02d:%02d.%03d [cc %s] [%s%s%s",local.tm_year + 1900,local.tm_mon + 1,
         local.tm_mday,local.tm_hour,local.tm_min,local.tm_sec,(int)(ms < 0 ? 0 : ms),cc,channel_id != NULL ? channel_id : "",
         slot == 1 ? "] [TS1] " : slot == 2 ? "] [TS2] " : "] [TS-] ",text != NULL ? text : "");
  if(repeats > 0){
    struct tm const since = local_time(since_us);
    struct tm const last = local_time(last_us);
    append(buf,size,&len," (x%u since %02d:%02d:%02d, last %02d:%02d:%02d)",(unsigned)repeats,since.tm_hour,since.tm_min,
           since.tm_sec,last.tm_hour,last.tm_min,last.tm_sec);
  }
  return finish(buf,size,len);
}

int dmr_control_alias_line(char *buf,size_t size,uint32_t radio,char const *alias){
  if(radio != 0)
    return format(buf,size,"[DMR alias] radio=%u alias=\"%s\"",radio,alias != NULL ? alias : "");
  return format(buf,size,"[DMR alias] radio=unknown alias=\"%s\"",alias != NULL ? alias : "");
}

void dmr_control_log_options_init(struct dmr_control_log_options *o){
  assert(o != NULL);
  memset(o,0,sizeof *o);
  o->repeat_interval_s = 60;
  o->max_keys = 1024;
}

struct repeat {
  uint32_t hash;
  char *key;                    // channel id, slot, key text
  char *channel_id;
  uint8_t slot;
  uint8_t color_code;
  char kind[16];
  char *text;
  uint32_t pending;
  int64_t last_written_us;
  int64_t last_seen_us;
};
// Lines made under the lock, delivered after it
struct batch_line {
  uint8_t slot;
  uint8_t color_code;
  uint32_t repeats;
  char kind[16];
  char *channel_id;
  char *text;
  char *formatted;
};
struct batch {
  int count;
  int capacity;
  struct batch_line *lines;
};

struct dmr_control_log {
  struct dmr_control_log_options o;
  dmr_control_sink sink;
  void *arg;
  pthread_mutex_t lock;
  struct repeat *repeats;       // in the order their keys were first seen
  size_t nrepeats;
  size_t capacity;
  bool hour_open;               // a line has been written since the last rotation
  int hour;                     // ... in this local hour (day of year * 24 + hour)
  int64_t next_sweep_us;
  uint64_t lines_written;
  uint64_t lines_collapsed;
};

static uint32_t fnv1a(char const *s){
  uint32_t h = 2166136261u;
  for(; *s != '\0'; s++){
    h ^= (uint8_t)*s;
    h *= 16777619u;
  }
  return h;
}
static char *dup_string(char const *s){
  size_t const n = strlen(s) + 1;
  char *p = malloc(n);
  if(p != NULL)
    memcpy(p,s,n);
  return p;
}

static int64_t log_now(struct dmr_control_log const *log){
  return log->o.clock_us != NULL ? log->o.clock_us(log->o.clock_arg) : wall_clock_us();
}
static int64_t interval_us(struct dmr_control_log const *log){
  return (int64_t)log->o.repeat_interval_s * 1000000;
}
static int hour_of(int64_t us){
  struct tm const local = local_time(us);
  return local.tm_yday * 24 + local.tm_hour;
}

static void emit(struct dmr_control_log *log,struct batch *out,int64_t now,char const *channel_id,uint8_t slot,
                 uint8_t color_code,char const *kind,char const *text,uint32_t repeats,int64_t since,int64_t last){
  if(!log->hour_open){
    log->hour_open = true;
    log->hour = hour_of(now);
  }
  log->lines_written++;
  if(log->sink == NULL)
    return;
  char formatted[DMR_SITE_LINE_MAX + DMR_CHANNEL_ID_MAX + 128];
  dmr_control_line_format(formatted,sizeof formatted,now,channel_id,slot,color_code,text,repeats,since,last);
  if(out->count == out->capacity){
    int const capacity = out->capacity == 0 ? 8 : 2 * out->capacity;
    struct batch_line *lines = realloc(out->lines,(size_t)capacity * sizeof *lines);
    if(lines == NULL)
      return;
    out->lines = lines;
    out->capacity = capacity;
  }
  struct batch_line *l = &out->lines[out->count];
  memset(l,0,sizeof *l);
  l->slot = slot;
  l->color_code = color_code;
  l->repeats = repeats;
  copy_string(l->kind,sizeof l->kind,kind);
  l->channel_id = dup_string(channel_id);
  l->text = dup_string(text);
  l->formatted = dup_string(formatted);
  if(l->channel_id == NULL || l->text == NULL || l->formatted == NULL){
    free(l->channel_id);
    free(l->text);
    free(l->formatted);
    return;
  }
  out->count++;
}

static void deliver(struct dmr_control_log *log,struct batch *out){
  for(int i=0; i < out->count; i++){
    struct batch_line const *l = &out->lines[i];
    struct dmr_control_line line = {log->o.system_name, log->o.site_name, l->channel_id, l->slot, l->color_code, l->kind,
                                    l->text, l->repeats, l->formatted};
    if(log->sink != NULL)
      log->sink(log->arg,&line);
    free(l->channel_id);
    free(l->text);
    free(l->formatted);
  }
  free(out->lines);
  out->lines = NULL;
  out->count = out->capacity = 0;
}

static void write_count(struct dmr_control_log *log,struct batch *out,int64_t now,struct repeat *r){
  if(r->pending == 0)
    return;
  uint32_t const n = r->pending;
  int64_t const since = r->last_written_us;
  r->pending = 0;
  r->last_written_us = r->last_seen_us;
  emit(log,out,now,r->channel_id,r->slot,r->color_code,r->kind,r->text,n,since,r->last_seen_us);
}
static void free_repeat(struct repeat *r){
  free(r->key);
  free(r->channel_id);
  free(r->text);
}
static void forget_all(struct dmr_control_log *log){
  for(size_t i=0; i < log->nrepeats; i++)
    free_repeat(&log->repeats[i]);
  log->nrepeats = 0;
}
static void flush_pending(struct dmr_control_log *log,struct batch *out,int64_t now,bool forget){
  for(size_t i=0; i < log->nrepeats; i++)
    write_count(log,out,now,&log->repeats[i]);
  if(forget)
    forget_all(log);
}
// The local hour has changed since the first line of the last one: its pending counts are written and
// the table cleared, so the new hour starts with every message in full
static void rotate_if_due(struct dmr_control_log *log,struct batch *out,int64_t now){
  if(!log->hour_open || hour_of(now) == log->hour)
    return;
  flush_pending(log,out,now,true);
  log->hour_open = false;
}
static void sweep_if_due(struct dmr_control_log *log,struct batch *out,int64_t now){
  int64_t const interval = interval_us(log);
  if(now < log->next_sweep_us && now + interval >= log->next_sweep_us)
    return;  // not due (and the clock did not jump back)
  int64_t step = (int64_t)(log->o.repeat_interval_s / 4) * 1000000;
  if(step < 1000000)
    step = 1000000;
  log->next_sweep_us = now + step;
  size_t kept = 0;
  for(size_t i=0; i < log->nrepeats; i++){
    struct repeat *r = &log->repeats[i];
    if(r->pending > 0){
      if(now - r->last_written_us >= interval)
        write_count(log,out,now,r);
    } else if(now - r->last_seen_us >= interval){
      free_repeat(r);
      continue;
    }
    log->repeats[kept++] = *r;
  }
  log->nrepeats = kept;
}

struct dmr_control_log *dmr_control_log_create(struct dmr_control_log_options const *o,dmr_control_sink sink,void *arg){
  struct dmr_control_log *log = calloc(1,sizeof *log);
  if(log == NULL)
    return NULL;
  if(o != NULL)
    log->o = *o;
  else
    dmr_control_log_options_init(&log->o);
  if(log->o.repeat_interval_s < 1)
    log->o.repeat_interval_s = 1;
  if(log->o.max_keys == 0)
    log->o.max_keys = 1;
  log->sink = sink;
  log->arg = arg;
  pthread_mutex_init(&log->lock,NULL);
  return log;
}
void dmr_control_log_destroy(struct dmr_control_log *log){
  if(log == NULL)
    return;
  dmr_control_log_close(log);
  forget_all(log);
  free(log->repeats);
  pthread_mutex_destroy(&log->lock);
  free(log);
}

void dmr_control_log_write(struct dmr_control_log *log,char const *channel_id,uint8_t slot,uint8_t color_code,
                           char const *kind,char const *text){
  if(log == NULL)
    return;
  struct batch out = {0, 0, NULL};
  pthread_mutex_lock(&log->lock);
  int64_t const now = log_now(log);
  rotate_if_due(log,&out,now);
  sweep_if_due(log,&out,now);
  emit(log,&out,now,channel_id,slot,color_code,kind,text,0,now,now);
  pthread_mutex_unlock(&log->lock);
  deliver(log,&out);
}

void dmr_control_log_write_collapsed(struct dmr_control_log *log,char const *channel_id,uint8_t slot,uint8_t color_code,
                                     char const *kind,char const *text,char const *key){
  if(log == NULL)
    return;
  if(channel_id == NULL)
    channel_id = "";
  if(text == NULL)
    text = "";
  struct batch out = {0, 0, NULL};
  pthread_mutex_lock(&log->lock);
  int64_t const now = log_now(log);
  rotate_if_due(log,&out,now);
  sweep_if_due(log,&out,now);

  // The key: channel, slot, key text, joined by unit separators
  char const *k = key != NULL && key[0] != '\0' ? key : text;
  size_t const key_len = strlen(channel_id) + strlen(k) + 4;
  char *table_key = malloc(key_len + 1);
  if(table_key == NULL){
    pthread_mutex_unlock(&log->lock);
    deliver(log,&out);
    return;
  }
  format(table_key,key_len + 1,"%s\x1f%c\x1f%s",channel_id,(char)('0' + (slot <= 2 ? slot : 0)),k);
  uint32_t const hash = fnv1a(table_key);
  struct repeat *r = NULL;
  for(size_t i=0; i < log->nrepeats; i++){
    if(log->repeats[i].hash == hash && strcmp(log->repeats[i].key,table_key) == 0){
      r = &log->repeats[i];
      break;
    }
  }
  if(r == NULL){
    if(log->nrepeats >= log->o.max_keys)
      flush_pending(log,&out,now,true);
    if(log->nrepeats == log->capacity){
      size_t const capacity = log->capacity == 0 ? 64 : 2 * log->capacity;
      struct repeat *repeats = realloc(log->repeats,capacity * sizeof *repeats);
      if(repeats != NULL){
        log->repeats = repeats;
        log->capacity = capacity;
      }
    }
    struct repeat n;
    memset(&n,0,sizeof n);
    n.hash = hash;
    n.key = table_key;
    n.channel_id = dup_string(channel_id);
    n.slot = slot;
    n.color_code = color_code;
    copy_string(n.kind,sizeof n.kind,kind);
    n.text = dup_string(text);
    n.last_written_us = now;
    n.last_seen_us = now;
    if(log->nrepeats < log->capacity && n.channel_id != NULL && n.text != NULL){
      log->repeats[log->nrepeats++] = n;
    } else {
      free_repeat(&n);  // out of memory: written, not remembered
    }
    emit(log,&out,now,channel_id,slot,color_code,kind,text,0,now,now);
  } else {
    free(table_key);
    r->pending++;
    log->lines_collapsed++;
    if(strcmp(r->text,text) != 0){
      char *t = dup_string(text);
      if(t != NULL){
        free(r->text);
        r->text = t;
      }
    }
    r->color_code = color_code;
    r->last_seen_us = now;
    if(now - r->last_written_us >= interval_us(log))
      write_count(log,&out,now,r);
  }
  pthread_mutex_unlock(&log->lock);
  deliver(log,&out);
}

void dmr_control_log_write_alias(struct dmr_control_log *log,char const *channel_id,uint8_t slot,uint8_t color_code,
                                 uint32_t radio,char const *alias){
  char text[DMR_SITE_LINE_MAX];
  dmr_control_alias_line(text,sizeof text,radio,alias);
  dmr_control_log_write(log,channel_id,slot,color_code,"ALIAS",text);
}
void dmr_control_log_write_site(struct dmr_control_log *log,char const *kind,char const *text){
  dmr_control_log_write(log,DMR_SITE_CHANNEL,0,DMR_NO_COLOR_CODE,kind,text);
}
void dmr_control_log_write_site_collapsed(struct dmr_control_log *log,char const *kind,char const *text,char const *key){
  dmr_control_log_write_collapsed(log,DMR_SITE_CHANNEL,0,DMR_NO_COLOR_CODE,kind,text,key);
}
void dmr_control_log_time(struct dmr_control_log *log){
  if(log == NULL)
    return;
  struct batch out = {0, 0, NULL};
  pthread_mutex_lock(&log->lock);
  int64_t const now = log_now(log);
  rotate_if_due(log,&out,now);
  sweep_if_due(log,&out,now);
  pthread_mutex_unlock(&log->lock);
  deliver(log,&out);
}
void dmr_control_log_flush(struct dmr_control_log *log){
  if(log == NULL)
    return;
  struct batch out = {0, 0, NULL};
  pthread_mutex_lock(&log->lock);
  flush_pending(log,&out,log_now(log),false);
  pthread_mutex_unlock(&log->lock);
  deliver(log,&out);
}
void dmr_control_log_close(struct dmr_control_log *log){
  if(log == NULL)
    return;
  struct batch out = {0, 0, NULL};
  pthread_mutex_lock(&log->lock);
  flush_pending(log,&out,log_now(log),true);
  log->hour_open = false;
  pthread_mutex_unlock(&log->lock);
  deliver(log,&out);
}
uint64_t dmr_control_log_lines_written(struct dmr_control_log *log){
  pthread_mutex_lock(&log->lock);
  uint64_t const n = log->lines_written;
  pthread_mutex_unlock(&log->lock);
  return n;
}
uint64_t dmr_control_log_lines_collapsed(struct dmr_control_log *log){
  pthread_mutex_lock(&log->lock);
  uint64_t const n = log->lines_collapsed;
  pthread_mutex_unlock(&log->lock);
  return n;
}

// ---------------- The site ----------------

bool dmr_locate_single_radiod(void *arg,uint64_t frequency_hz,struct dmr_source *source){
  struct dmr_single_radiod const *r = arg;
  if(r == NULL)
    return false;
  if((r->low_hz != 0 || r->high_hz != 0) && (frequency_hz < r->low_hz || frequency_hz > r->high_hz))
    return false;
  if(source != NULL){
    source->radiod = r->radiod;
    source->ssrc = 0;
  }
  return true;
}

void dmr_site_options_init(struct dmr_site_options *o){
  assert(o != NULL);
  memset(o,0,sizeof *o);
  o->activity_grace_us = 2000000;
  o->grant_grace_us = 3000000;
  o->heard_window_us = 1000000;
  o->pending_expiry_us = 4000000;
  o->warn_interval_us = 30000000;
  o->rest_holdoff_us = 500000;
  o->identity_confirmations = 2;
  o->frequency_tolerance_hz = 1000;
  o->learn_from_any_cgap = false;
  o->warnings_to_stderr = true;
}

enum { WHAT_MAX = 768, MAX_UNCONFIGURED = 64, MAX_CONFLICTS_LOGGED = 256 };

// An announcement waiting for its verdict
struct pending {
  bool active;
  bool one_shot;
  uint64_t first_us;
  uint64_t last_us;
  uint64_t count;               // announcements waiting in it
  char what[WHAT_MAX];          // the message that announced it, for the warning
  char heard_on[DMR_CHANNEL_ID_MAX]; // the channel it was heard on
};
struct site_slot {
  uint64_t call_bursts;
  bool ever_call;
  uint64_t last_call_us;
  struct pending pending;
  uint64_t announced;
  uint64_t heard;
  uint64_t missed;
  uint64_t alarms;
  bool ever_warned;
  uint64_t last_warn_us;
  uint64_t misses_not_logged;
};
struct site_channel {
  char channel_id[DMR_CHANNEL_ID_MAX];
  uint16_t lcn;
  uint64_t frequency_hz;
  bool configured;
  bool attached;
  int color_code;               // the setting: 0-15, DMR_SITE_CC_TRACK, DMR_SITE_CC_ANY
  int expected_color_code;
  struct dmr_site_context context;
  uint64_t bursts;
  bool ever_burst;
  uint64_t last_burst_us;
  uint64_t sync_losses;
  uint64_t color_code_bursts[16];
  uint64_t color_code_mismatches;
  uint16_t color_codes_logged;
  struct site_slot slots[3];    // [0]: the slot is not known / the message named none
};

struct dmr_site {
  struct dmr_site_options o;
  int default_color_code;       // the setting a channel the configuration does not list gets: the site's, else the system's
  char system_name[DMR_SITE_NAME_MAX];
  char site_name[DMR_SITE_NAME_MAX];
  enum dmr_system_type type;
  enum dmr_tag_family family;
  bool compressed_talkgroups;
  struct dmr_control_log *log;

  pthread_mutex_t lock;
  struct dmr_site_handlers h;
  struct site_channel *channels;
  int nchannels;
  int capacity;
  struct dmr_channel_map map;
  int nconflicts_logged;
  struct { uint16_t lcn; uint64_t hz; } conflicts_logged[MAX_CONFLICTS_LOGGED];

  uint32_t system_tag;          // atomic
  uint32_t candidate_tag;
  int candidate_count;
  uint64_t identity_changes;
  uint64_t foreign_identity;
  unsigned foreign_logged;
  int nneighbours;
  uint32_t neighbours[DMR_SITE_MAX_NEIGHBOURS];
  char neighbour_details[DMR_SITE_MAX_NEIGHBOURS][40];

  bool rest_known;
  uint8_t rest_lsn;
  bool rest_has_previous;
  uint8_t rest_previous_lsn;
  uint64_t rest_moved_us;
  uint64_t rest_moves;
  uint64_t rest_stale;
  bool xpt_free_known;
  uint8_t xpt_free;
  uint64_t xpt_free_moves;

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
  uint64_t announced_not_monitored;
  uint64_t announced_unconfigured;
  int nunconfigured;
  struct { uint64_t key; uint64_t last_warn_us; uint64_t not_logged; } unconfigured[MAX_UNCONFIGURED];
  uint64_t color_code_ignored;
};

// What an entry point decided to do, done after the lock is released
struct action_line {
  char kind[16];
  bool collapsed;
  bool site;                    // about the site, not the reporting channel
  bool warning;
  char text[DMR_SITE_LINE_MAX];
};
struct actions {
  char channel_id[DMR_CHANNEL_ID_MAX]; // the reporting channel, for lines about a message heard there
  uint8_t slot;
  uint8_t color_code;
  int nlines;
  int capacity;
  struct action_line *lines;
  int ngrants;
  struct dmr_grant grants[DMR_MAX_GRANTS];
  uint64_t grant_hz[DMR_MAX_GRANTS];
  bool have_clear;
  int nfollows;
  struct dmr_follow follows[8];
  struct dmr_site_context clear_channel;
  uint8_t clear_slot;
  struct dmr_site_handlers h;   // the hooks as they were under the lock
};
static void actions_init(struct actions *a){
  memset(a,0,sizeof *a);
  a->color_code = DMR_NO_COLOR_CODE;
}
static struct action_line *new_line(struct actions *a,char const *kind,bool collapsed,bool site,bool warning){
  if(a->nlines == a->capacity){
    int const capacity = a->capacity == 0 ? 4 : 2 * a->capacity;
    struct action_line *lines = realloc(a->lines,(size_t)capacity * sizeof *lines);
    if(lines == NULL)
      return NULL;
    a->lines = lines;
    a->capacity = capacity;
  }
  struct action_line *l = &a->lines[a->nlines++];
  copy_string(l->kind,sizeof l->kind,kind);
  l->collapsed = collapsed;
  l->site = site;
  l->warning = warning;
  l->text[0] = '\0';
  return l;
}
static void line_text(struct actions *a,char const *kind,bool collapsed,char const *text){
  struct action_line *l = new_line(a,kind,collapsed,false,false);
  if(l != NULL)
    copy_string(l->text,sizeof l->text,text);
}
static void site_text(struct actions *a,char const *kind,char const *text){
  struct action_line *l = new_line(a,kind,false,true,false);
  if(l != NULL)
    copy_string(l->text,sizeof l->text,text);
}
static void warn_text(struct actions *a,char const *text){
  struct action_line *l = new_line(a,"WARN",false,true,true);
  if(l != NULL)
    copy_string(l->text,sizeof l->text,text);
}

static void run(struct dmr_site *s,struct actions *a){
  for(int i=0; i < a->nlines; i++){
    struct action_line const *l = &a->lines[i];
    if(s->log != NULL){
      if(l->site)
        dmr_control_log_write_site(s->log,l->kind,l->text);
      else if(l->collapsed)
        dmr_control_log_write_collapsed(s->log,a->channel_id,a->slot,a->color_code,l->kind,l->text,NULL);
      else
        dmr_control_log_write(s->log,a->channel_id,a->slot,a->color_code,l->kind,l->text);
    }
    if(l->warning && s->o.warnings_to_stderr)
      fprintf(stderr,"[DMR site %s/%s] %s\n",s->system_name,s->site_name,l->text);
  }
  if(a->h.grant != NULL){
    for(int i=0; i < a->ngrants; i++)
      a->h.grant(a->h.arg,s,&a->grants[i],a->grant_hz[i]);
  }
  if(a->h.follow != NULL){
    for(int i=0; i < a->nfollows; i++)
      a->h.follow(a->h.arg,s,&a->follows[i]);
  }
  if(a->h.clear != NULL && a->have_clear)
    a->h.clear(a->h.arg,&a->clear_channel,a->clear_slot,"P_CLEAR");
  free(a->lines);
  a->lines = NULL;
  a->nlines = a->capacity = 0;
}

static uint64_t monotonic_us(void){
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}
static uint64_t clock_now(struct dmr_site const *s){
  return s->o.clock_us != NULL ? s->o.clock_us(s->o.clock_arg) : monotonic_us();
}
static struct site_channel *channel_at(struct dmr_site *s,int handle){
  return handle >= 0 && handle < s->nchannels ? &s->channels[handle] : NULL;
}
static bool same_frequency(struct dmr_site const *s,uint64_t a,uint64_t b){
  return (a > b ? a - b : b - a) <= s->o.frequency_tolerance_hz;
}
// The channel of an LCN (lcn != 0), else of a frequency (hz != 0), configured or attached
static struct site_channel *find_channel(struct dmr_site *s,uint16_t lcn,uint64_t hz){
  if(lcn != 0){
    for(int i=0; i < s->nchannels; i++){
      if(s->channels[i].lcn == lcn)
        return &s->channels[i];
    }
  }
  if(hz != 0){
    for(int i=0; i < s->nchannels; i++){
      if(s->channels[i].frequency_hz != 0 && same_frequency(s,s->channels[i].frequency_hz,hz))
        return &s->channels[i];
    }
  }
  return NULL;
}
static struct site_channel *new_channel(struct dmr_site *s){
  if(s->nchannels == s->capacity){
    int const capacity = s->capacity == 0 ? 8 : 2 * s->capacity;
    struct site_channel *c = realloc(s->channels,(size_t)capacity * sizeof *c);
    if(c == NULL)
      return NULL;
    s->channels = c;
    s->capacity = capacity;
  }
  struct site_channel *c = &s->channels[s->nchannels++];
  memset(c,0,sizeof *c);
  c->color_code = DMR_SITE_CC_TRACK;
  c->expected_color_code = -1;
  return c;
}

static bool is_voice_activity(uint8_t activity){
  return activity == DMR_ACT_GROUP_VOICE || activity == DMR_ACT_INDIVIDUAL_VOICE || activity == DMR_ACT_EMERGENCY_GROUP_VOICE
    || activity == DMR_ACT_EMERGENCY_INDIVIDUAL_VOICE;
}

struct dmr_site *dmr_site_create(struct dmr_site_config const *config,struct dmr_control_log *log,
                                 struct dmr_site_options const *options,struct dmr_site_handlers const *handlers){
  assert(config != NULL);
  struct dmr_site *s = calloc(1,sizeof *s);
  if(s == NULL)
    return NULL;
  if(options != NULL)
    s->o = *options;
  else
    dmr_site_options_init(&s->o);
  if(s->o.identity_confirmations < 1)
    s->o.identity_confirmations = 1;
  if(handlers != NULL)
    s->h = *handlers;
  copy_string(s->system_name,sizeof s->system_name,config->system_name);
  copy_string(s->site_name,sizeof s->site_name,config->site_name);
  s->type = config->type;
  s->default_color_code = dmr_site_color_code_for(config,NULL);
  s->compressed_talkgroups = config->compressed_talkgroups;
  s->family = dmr_tag_family_of(config->type);
  s->log = log;
  pthread_mutex_init(&s->lock,NULL);
  dmr_map_init(&s->map,s->o.frequency_tolerance_hz);
  for(int i=0; i < config->nchannels; i++){
    struct dmr_site_channel_config const *ch = &config->channels[i];
    struct site_channel *c = new_channel(s);
    if(c == NULL){
      dmr_site_destroy(s);
      return NULL;
    }
    if(ch->channel_id[0] == '\0')
      dmr_default_channel_id(c->channel_id,sizeof c->channel_id,config->system_name,config->site_name,ch->lcn);
    else
      copy_string(c->channel_id,sizeof c->channel_id,ch->channel_id);
    c->lcn = (uint16_t)ch->lcn;
    c->frequency_hz = ch->frequency_hz;
    c->configured = true;
    c->color_code = dmr_site_color_code_for(config,ch);
    if(c->color_code >= 0 && c->color_code <= 15)
      c->expected_color_code = c->color_code;
    copy_string(c->context.system_name,sizeof c->context.system_name,config->system_name);
    copy_string(c->context.site_name,sizeof c->context.site_name,config->site_name);
    copy_string(c->context.channel_id,sizeof c->context.channel_id,c->channel_id);
    c->context.frequency_hz = ch->frequency_hz;
    c->context.lcn = c->lcn;
    if(ch->frequency_hz != 0)
      dmr_map_set_from_config(&s->map,(uint16_t)ch->lcn,ch->frequency_hz,0,NULL);
  }
  return s;
}

void dmr_site_destroy(struct dmr_site *s){
  if(s == NULL)
    return;
  dmr_map_free(&s->map);
  free(s->channels);
  pthread_mutex_destroy(&s->lock);
  free(s);
}

void dmr_site_set_handlers(struct dmr_site *s,struct dmr_site_handlers const *handlers){
  pthread_mutex_lock(&s->lock);
  if(handlers != NULL)
    s->h = *handlers;
  else
    memset(&s->h,0,sizeof s->h);
  pthread_mutex_unlock(&s->lock);
}

static void forget(struct dmr_site *s,struct pending *p){
  if(!p->active)
    return;
  p->active = false;
  s->announced_unconfirmed += p->count;
}

// An entry already attached for another live decoder is never taken over (two decoders can hold one
// LCN at once, an old carrier still held while a new one is made for it): the second gets an entry, and
// a handle, of its own, so that what is heard on each is routed to it and each detaches its own
int dmr_site_attach(struct dmr_site *s,struct dmr_site_context const *channel){
  assert(s != NULL && channel != NULL);
  pthread_mutex_lock(&s->lock);
  int index = -1;
  for(int i=0; i < s->nchannels && index < 0; i++){
    if(!s->channels[i].attached && channel->channel_id[0] != '\0' && strcmp(s->channels[i].channel_id,channel->channel_id) == 0)
      index = i;
  }
  for(int i=0; i < s->nchannels && index < 0; i++){
    if(!s->channels[i].attached && channel->lcn != 0 && s->channels[i].lcn == channel->lcn)
      index = i;
  }
  for(int i=0; i < s->nchannels && index < 0; i++){
    if(!s->channels[i].attached && channel->frequency_hz != 0
       && same_frequency(s,s->channels[i].frequency_hz,channel->frequency_hz))
      index = i;
  }
  if(index < 0){
    struct site_channel *c = new_channel(s);
    if(c == NULL){
      pthread_mutex_unlock(&s->lock);
      return -1;
    }
    copy_string(c->channel_id,sizeof c->channel_id,channel->channel_id);
    c->lcn = channel->lcn;
    c->frequency_hz = channel->frequency_hz;
    // The site's colour code setting, not first-seen tracking: a pinned system stays pinned on it
    c->color_code = s->default_color_code;
    if(c->color_code >= 0 && c->color_code <= 15)
      c->expected_color_code = c->color_code;
    index = s->nchannels - 1;
  }
  struct site_channel *c = &s->channels[index];
  c->attached = true;
  c->context = *channel;
  pthread_mutex_unlock(&s->lock);
  return index;
}

bool dmr_site_detach_handle(struct dmr_site *s,int handle){
  if(s == NULL)
    return false;
  pthread_mutex_lock(&s->lock);
  bool const ok = handle >= 0 && handle < s->nchannels && s->channels[handle].attached;
  if(ok){
    struct site_channel *c = &s->channels[handle];
    c->attached = false;
    for(int k=0; k < 3; k++)
      forget(s,&c->slots[k].pending);
  }
  pthread_mutex_unlock(&s->lock);
  return ok;
}

bool dmr_site_detach(struct dmr_site *s,char const *channel_id){
  pthread_mutex_lock(&s->lock);
  for(int i=0; i < s->nchannels; i++){
    struct site_channel *c = &s->channels[i];
    if(strcmp(c->channel_id,channel_id) != 0 || !c->attached)
      continue;
    c->attached = false;
    for(int k=0; k < 3; k++)
      forget(s,&c->slots[k].pending);
    pthread_mutex_unlock(&s->lock);
    return true;
  }
  pthread_mutex_unlock(&s->lock);
  return false;
}

uint32_t dmr_site_system_tag(struct dmr_site const *s){
  return __atomic_load_n(&s->system_tag,__ATOMIC_RELAXED);
}

// ---- the cross-check ----

static bool heard_since(struct dmr_site const *s,struct site_channel const *ch,int k,uint64_t first_us){
  bool recent[3];
  for(int i=0; i < 3; i++)
    recent[i] = ch->slots[i].ever_call && ch->slots[i].last_call_us + s->o.heard_window_us >= first_us;
  if(k == 0)
    return recent[0] || recent[1] || recent[2];
  return recent[k] || recent[0];
}

// Settle what is pending on one timeslot of a channel, if it can be settled now
static void evaluate(struct dmr_site *s,struct site_channel *ch,int k,uint64_t now,struct actions *a){
  struct site_slot *slot = &ch->slots[k];
  struct pending *p = &slot->pending;
  if(!p->active)
    return;
  if(heard_since(s,ch,k,p->first_us)){
    p->active = false;
    slot->heard += p->count;
    s->announced_heard += p->count;
    return;
  }
  bool const due = p->one_shot ? now - p->first_us >= s->o.grant_grace_us : p->last_us - p->first_us >= s->o.activity_grace_us;
  if(!due){
    if(!p->one_shot && now - p->last_us > s->o.pending_expiry_us)
      forget(s,p);
    return;
  }
  p->active = false;
  slot->missed += p->count;
  s->announced_missed += p->count;
  slot->alarms++;
  s->miss_alarms++;
  if(slot->ever_warned && now - slot->last_warn_us < s->o.warn_interval_us){
    slot->misses_not_logged++;
    return;
  }
  struct action_line *l = new_line(a,"WARN",false,true,true);
  if(l != NULL){
    size_t len = 0;
    size_t const size = sizeof l->text;
    char buf[160];
    append(l->text,size,&len,"WARN no call heard on ");
    if(ch->lcn != 0)
      append(l->text,size,&len,"LCN %u ",ch->lcn);
    if(k != 0)
      append(l->text,size,&len,"TS%d ",k);
    append(l->text,size,&len,"(%s) although %s on %s",ch->channel_id,p->what,p->heard_on);
    format(buf,sizeof buf," announced a call there %.1f s ago",seconds_of((double)(now - p->first_us)));
    append(l->text,size,&len,"%s",buf);
    if(k != 0 && slot->ever_call){
      format(buf,sizeof buf,"; last call burst there %.1f s ago",seconds_of((double)(now - slot->last_call_us)));
      append(l->text,size,&len,"%s",buf);
    } else
      append(l->text,size,&len,"; no call burst there yet");
    if(ch->ever_burst){
      format(buf,sizeof buf,", last burst of any kind %.1f s ago",seconds_of((double)(now - ch->last_burst_us)));
      append(l->text,size,&len,"%s",buf);
    } else
      append(l->text,size,&len,", the channel has delivered no burst at all");
    if(slot->misses_not_logged != 0)
      append(l->text,size,&len," (+%llu since the last warning)",(unsigned long long)slot->misses_not_logged);
  }
  slot->ever_warned = true;
  slot->last_warn_us = now;
  slot->misses_not_logged = 0;
}

static void evaluate_all(struct dmr_site *s,uint64_t now,struct actions *a){
  for(int i=0; i < s->nchannels; i++){
    for(int k=0; k < 3; k++){
      if(s->channels[i].slots[k].pending.active)
        evaluate(s,&s->channels[i],k,now,a);
    }
  }
}

// Who an announced call is for, when the message says
struct follow_who {
  uint32_t talkgroup;
  uint8_t bits;                 // 0 not known
  bool group;
};
static struct follow_who const Nobody = {0, 0, false};

// For a follower: the repeater, as well as the site knows it
static void push_follow(struct dmr_site *s,struct actions *a,struct site_channel const *target,uint16_t lcn,
                        uint64_t hz,uint8_t timeslot,bool repeating,bool rest,char const *what,struct follow_who who){
  if(a->nfollows >= (int)(sizeof a->follows / sizeof a->follows[0]))
    return;
  struct dmr_follow *f = &a->follows[a->nfollows++];
  memset(f,0,sizeof *f);
  f->lcn = target != NULL && target->lcn != 0 ? target->lcn : lcn;
  f->frequency_hz = target != NULL && target->frequency_hz != 0 ? target->frequency_hz
    : hz != 0 ? hz : lcn != 0 ? dmr_map_downlink_hz(&s->map,lcn) : 0;
  f->timeslot = timeslot;
  f->configured = target != NULL && target->configured;
  f->attached = target != NULL && target->attached;
  f->repeating = repeating;
  f->rest = rest;
  f->talkgroup = who.talkgroup;
  f->talkgroup_bits = who.bits;
  f->group = who.group;
  if(target != NULL)
    copy_string(f->channel_id,sizeof f->channel_id,target->channel_id);
  copy_string(f->what,sizeof f->what,what);
}

// A message heard on 'by' says a timeslot carries a voice call. direct: the channel itself (Act_Updt
// names the carrier it is on); else it is looked up by LCN or frequency. who: the call's destination
static void announce_on(struct dmr_site *s,struct site_channel *direct,uint16_t lcn,uint64_t hz,uint8_t timeslot,bool repeating,
                        char const *what,struct follow_who who,struct site_channel const *by,uint64_t now,struct actions *a){
  s->announced++;
  struct site_channel *target = direct != NULL ? direct : find_channel(s,lcn,hz);
  push_follow(s,a,target,lcn,hz,timeslot,repeating,false,what,who);
  if(target == NULL || (!target->configured && !target->attached)){
    s->announced_unconfigured++;
    uint64_t const key = hz != 0 ? hz : lcn;
    int index = -1;
    for(int i=0; i < s->nunconfigured; i++){
      if(s->unconfigured[i].key == key)
        index = i;
    }
    if(index >= 0 && now - s->unconfigured[index].last_warn_us < s->o.warn_interval_us){
      s->unconfigured[index].not_logged++;
      return;
    }
    if(index < 0){
      if(s->nunconfigured >= MAX_UNCONFIGURED)
        return;  // bounded; the counter still counts
      index = s->nunconfigured++;
      s->unconfigured[index].key = key;
      s->unconfigured[index].last_warn_us = 0;
      s->unconfigured[index].not_logged = 0;
    }
    struct action_line *l = new_line(a,"WARN",false,true,true);
    if(l != NULL){
      size_t len = 0;
      size_t const size = sizeof l->text;
      append(l->text,size,&len,"WARN activity on a channel that is not configured: ");
      if(hz != 0){
        char mhz[40];
        dmr_format_mhz(mhz,sizeof mhz,hz);
        append(l->text,size,&len,"%s MHz",mhz);
      } else
        append(l->text,size,&len,"LCN %u",lcn);
      if(timeslot == 1 || timeslot == 2)
        append(l->text,size,&len," TS%u",timeslot);
      append(l->text,size,&len,", announced by %s on %s",what,by->channel_id);
      if(s->unconfigured[index].not_logged != 0)
        append(l->text,size,&len," (+%llu since the last warning)",(unsigned long long)s->unconfigured[index].not_logged);
    }
    s->unconfigured[index].last_warn_us = now;
    s->unconfigured[index].not_logged = 0;
    return;
  }
  if(!target->attached){
    s->announced_not_monitored++;
    return;
  }
  int const k = (timeslot == 1 || timeslot == 2) ? timeslot : 0;
  struct site_slot *slot = &target->slots[k];
  slot->announced++;
  struct pending *p = &slot->pending;
  if(!p->active){
    p->active = true;
    p->one_shot = !repeating;
    p->first_us = now;
    p->count = 0;
    copy_string(p->what,sizeof p->what,what);
    copy_string(p->heard_on,sizeof p->heard_on,by->channel_id);
  }
  p->count++;
  p->last_us = now;
  evaluate(s,target,k,now,a);
}

// ---- identity ----

// True when the site is configured as this family; otherwise counted, and reported once per family
static bool family_is(struct dmr_site *s,enum dmr_tag_family family,char const *source,struct actions *a){
  if(s->family == family)
    return true;
  s->foreign_identity++;
  unsigned const bit = 1u << (unsigned)family;
  if((s->foreign_logged & bit) == 0){
    s->foreign_logged |= bit;
    char text[DMR_SITE_LINE_MAX];
    format(text,sizeof text,"WARN %s heard on a site configured as %s: it is not used for the site's identity (is the system type right?)",
             source,dmr_system_type_name(s->type));
    warn_text(a,text);
  }
  return false;
}

// A sighting of the site's identity. Returns whether the message's family is the site's
static bool identity(struct dmr_site *s,enum dmr_tag_family family,uint32_t tag,char const *source,struct actions *a){
  if(!family_is(s,family,source,a))
    return false;
  uint32_t const held = dmr_site_system_tag(s);
  if(tag == held){
    s->candidate_count = 0;
    return true;
  }
  if(tag == s->candidate_tag && s->candidate_count > 0)
    s->candidate_count++;
  else {
    s->candidate_tag = tag;
    s->candidate_count = 1;
  }
  if(s->candidate_count < s->o.identity_confirmations)
    return true;
  s->candidate_count = 0;
  __atomic_store_n(&s->system_tag,tag,__ATOMIC_RELAXED);
  char buf[DMR_SITE_LINE_MAX],new_text[64],held_text[64]; // two identities and a source fit
  dmr_system_tag_describe(new_text,sizeof new_text,tag);
  if(held == 0){
    format(buf,sizeof buf,"SITE identity %s, systemTag 0x%08X (from %s)",new_text,(unsigned)tag,source);
    site_text(a,"SITE",buf);
  } else {
    s->identity_changes++;
    dmr_system_tag_describe(held_text,sizeof held_text,held);
    format(buf,sizeof buf,"WARN site identity changed: %s (0x%08X) -> %s (0x%08X) (from %s)",held_text,(unsigned)held,new_text,
             (unsigned)tag,source);
    warn_text(a,buf);
  }
  return true;
}

// A neighbour site, with what the message says of it (detail; NULL or "" for nothing: what is held stays)
static void neighbour(struct dmr_site *s,uint32_t site,char const *detail){
  int i = 0;
  while(i < s->nneighbours && s->neighbours[i] < site)
    i++;
  if(i == s->nneighbours || s->neighbours[i] != site){
    if(s->nneighbours >= DMR_SITE_MAX_NEIGHBOURS)
      return;
    memmove(&s->neighbours[i + 1],&s->neighbours[i],(size_t)(s->nneighbours - i) * sizeof s->neighbours[0]);
    memmove(&s->neighbour_details[i + 1],&s->neighbour_details[i],(size_t)(s->nneighbours - i) * sizeof s->neighbour_details[0]);
    s->neighbours[i] = site;
    s->neighbour_details[i][0] = '\0';
    s->nneighbours++;
  }
  if(detail != NULL && detail[0] != '\0')
    copy_string(s->neighbour_details[i],sizeof s->neighbour_details[i],detail);
}

// ---- rest channel ----

static void rest_channel(struct dmr_site *s,uint8_t lsn,uint64_t now,struct actions *a){
  if(lsn == 0)
    return;  // there is no LSN 0
  // Every report of the rest channel, for a follower: the site's control information is there
  {
    uint16_t const lcn = (uint16_t)dmr_lsn_to_lcn(lsn);
    char what[48];
    format(what,sizeof what,"rest channel LSN %u",(unsigned)lsn);
    push_follow(s,a,find_channel(s,lcn,0),lcn,0,(uint8_t)dmr_lsn_to_timeslot(lsn),true,true,what,Nobody);
  }
  if(s->rest_known && lsn == s->rest_lsn)
    return;
  if(s->rest_known && s->rest_has_previous && lsn == s->rest_previous_lsn && now - s->rest_moved_us < s->o.rest_holdoff_us){
    s->rest_stale++;  // a channel a few bursts behind still names the old one
    return;
  }
  char buf[200];
  struct site_channel const *target = find_channel(s,(uint16_t)dmr_lsn_to_lcn(lsn),0);
  char const *note = target == NULL ? " (NOT CONFIGURED: the plan lists no such repeater)" : target->attached ? "" : " (not monitored)";
  if(!s->rest_known)
    format(buf,sizeof buf,"REST channel is LSN %u (LCN %d TS%d)%s",(unsigned)lsn,dmr_lsn_to_lcn(lsn),dmr_lsn_to_timeslot(lsn),note);
  else {
    s->rest_moves++;
    s->rest_has_previous = true;
    s->rest_previous_lsn = s->rest_lsn;
    format(buf,sizeof buf,"REST channel moved: LSN %u (LCN %d TS%d) -> LSN %u (LCN %d TS%d)%s",(unsigned)s->rest_lsn,
             dmr_lsn_to_lcn(s->rest_lsn),dmr_lsn_to_timeslot(s->rest_lsn),(unsigned)lsn,dmr_lsn_to_lcn(lsn),dmr_lsn_to_timeslot(lsn),note);
  }
  s->rest_known = true;
  s->rest_lsn = lsn;
  s->rest_moved_us = now;
  site_text(a,"REST",buf);
}

static void xpt_free_repeater(struct dmr_site *s,uint8_t repeater,struct actions *a){
  if(s->xpt_free_known && repeater == s->xpt_free)
    return;
  char buf[96];
  if(s->xpt_free_known){
    s->xpt_free_moves++;
    format(buf,sizeof buf,"XPT free repeater moved: %u -> %u",(unsigned)s->xpt_free,(unsigned)repeater);
  } else
    format(buf,sizeof buf,"XPT free repeater is %u",(unsigned)repeater);
  s->xpt_free_known = true;
  s->xpt_free = repeater;
  site_text(a,"REST",buf);
}

// ---- channel map ----

static void note_air_channel(struct dmr_site *s,struct dmr_cgap const *p,bool learn,struct actions *a){
  struct dmr_map_conflict conflict;
  bool have_conflict = false;
  if(learn){
    bool const had = dmr_map_find(&s->map,p->lcn) != NULL;
    have_conflict = dmr_map_learn_from_cgap(&s->map,p,&conflict);
    if(!had && !have_conflict){
      char mhz[40],buf[128];
      dmr_format_mhz(mhz,sizeof mhz,dmr_cgap_downlink_hz(p));
      format(buf,sizeof buf,"MAP learned from the air: LCN %u = %s MHz",p->lcn,mhz);
      site_text(a,"MAP",buf);
    }
  } else {
    struct dmr_map_entry const *held = dmr_map_find(&s->map,p->lcn);
    // Compared only: neither the map nor its conflict counter changes
    if(held != NULL && !same_frequency(s,held->downlink_hz,dmr_cgap_downlink_hz(p))){
      conflict = (struct dmr_map_conflict){p->lcn, held->downlink_hz, held->source, dmr_cgap_downlink_hz(p), DMR_MAP_AIR, false};
      have_conflict = true;
    }
  }
  if(!have_conflict)
    return;
  for(int i=0; i < s->nconflicts_logged; i++){
    if(s->conflicts_logged[i].lcn == conflict.lcn && s->conflicts_logged[i].hz == conflict.offered_hz)
      return;
  }
  if(s->nconflicts_logged >= MAX_CONFLICTS_LOGGED)
    return;
  s->conflicts_logged[s->nconflicts_logged].lcn = conflict.lcn;
  s->conflicts_logged[s->nconflicts_logged].hz = conflict.offered_hz;
  s->nconflicts_logged++;
  char desc[256],text[300];
  dmr_map_conflict_describe(desc,sizeof desc,&conflict);
  format(text,sizeof text,"WARN channel map conflict: %s",desc);
  warn_text(a,text);
}

// ---- colour codes ----

// A message that came with color_code is this channel's: the channel takes any colour code, the colour
// code is not known (above 15), none is expected yet, or it is the expected one
static bool color_code_ok(struct site_channel const *ch,uint8_t color_code){
  return ch->color_code == DMR_SITE_CC_ANY || color_code > 15 || ch->expected_color_code < 0 || ch->expected_color_code == color_code;
}
static void note_color_code(struct site_channel *ch,uint8_t color_code,struct actions *a){
  ch->color_code_bursts[color_code]++;
  if(ch->color_code == DMR_SITE_CC_ANY)
    return;
  if(ch->expected_color_code < 0){
    ch->expected_color_code = color_code;  // a tracked channel: the first seen
    return;
  }
  if(ch->expected_color_code == color_code)
    return;
  ch->color_code_mismatches++;
  uint16_t const bit = (uint16_t)(1u << color_code);
  if((ch->color_codes_logged & bit) != 0)
    return;
  ch->color_codes_logged |= bit;
  char buf[DMR_SITE_LINE_MAX]; // a channel id may be long
  format(buf,sizeof buf,"WARN colour code %u heard on %s (%s %d)",(unsigned)color_code,ch->channel_id,
           (ch->color_code >= 0 && ch->color_code <= 15) ? "configured" : "first seen",ch->expected_color_code);
  warn_text(a,buf);
}

// ---- entry points ----

void dmr_site_burst(struct dmr_site *s,int handle,struct dmr_burst const *b){
  struct actions a;
  actions_init(&a);
  pthread_mutex_lock(&s->lock);
  struct site_channel *ch = channel_at(s,handle);
  if(ch == NULL){
    pthread_mutex_unlock(&s->lock);
    return;
  }
  uint64_t const now = clock_now(s);
  ch->bursts++;
  ch->ever_burst = true;
  ch->last_burst_us = now;

  bool const voice = dmr_is_voice(b->kind);
  bool const data = b->kind == DMR_KIND_DATA && b->slot_type_valid;
  // A burst has a colour code of its own in its slot type, or in the EMB of voice bursts B-F
  bool const has_color_code = data || (voice && b->kind != DMR_KIND_VOICE_A && b->emb_valid);
  if(has_color_code)
    note_color_code(ch,b->color_code & 0xFu,&a);
  bool const ours = !has_color_code || color_code_ok(ch,b->color_code & 0xFu);

  bool const call = voice || (data && (b->data_type == DMR_DT_VOICE_LC_HEADER || b->data_type == DMR_DT_PI_HEADER
                                        || b->data_type == DMR_DT_TERMINATOR_LC));
  if(call && ours){
    int const k = b->slot <= 2 ? b->slot : 0;
    struct site_slot *slot = &ch->slots[k];
    slot->call_bursts++;
    slot->ever_call = true;
    slot->last_call_us = now;
    // Something that was announced is here: settle it at once
    for(int p=0; p < 3; p++){
      if(ch->slots[p].pending.active && (p == k || p == 0 || k == 0))
        evaluate(s,ch,p,now,&a);
    }
  }
  a.h = s->h;  // the hooks as they are now, called once the lock is let go
  pthread_mutex_unlock(&s->lock);
  run(s,&a);
}

void dmr_site_short_lc(struct dmr_site *s,int handle,uint8_t color_code,struct dmr_short_lc const *slc){
  struct actions a;
  actions_init(&a);
  pthread_mutex_lock(&s->lock);
  struct site_channel *ch = channel_at(s,handle);
  if(ch == NULL){
    pthread_mutex_unlock(&s->lock);
    return;
  }
  uint64_t const now = clock_now(s);
  copy_string(a.channel_id,sizeof a.channel_id,ch->channel_id);
  a.color_code = color_code;
  if(!color_code_ok(ch,color_code)){
    s->color_code_ignored++;
    pthread_mutex_unlock(&s->lock);
    return;
  }
  switch(slc->body){
  case DMR_SLCB_ACTIVITY_UPDATE: {
    uint8_t const activity[2] = {slc->u.activity.ts1_activity, slc->u.activity.ts2_activity};
    for(int ts=1; ts <= 2; ts++){
      if(!is_voice_activity(activity[ts - 1]))
        continue;
      char what[64];
      format(what,sizeof what,"SLC activity update (%s)",dmr_slot_activity_name(activity[ts - 1]));
      announce_on(s,ch,ch->lcn,ch->frequency_hz,(uint8_t)ts,true,what,Nobody,ch,now,&a);
    }
    break;
  }
  case DMR_SLCB_SYS_PARMS:
    identity(s,DMR_TAG_TIER3,dmr_tier3_system_tag(slc->u.sys_parms.system_identity_code),"Tier III Sys_Parms Short LC",&a);
    break;
  case DMR_SLCB_CONNECT_PLUS:
    identity(s,DMR_TAG_CONNECT_PLUS,dmr_con_plus_system_tag(slc->u.connect_plus.network,slc->u.connect_plus.site),
             "Connect Plus Short LC",&a);
    break;
  case DMR_SLCB_CAP_PLUS_REST_CHANNEL:
    if(identity(s,DMR_TAG_CAPACITY_PLUS,dmr_cap_plus_system_tag(slc->u.rest.site),"Capacity Plus rest-channel Short LC",&a))
      rest_channel(s,slc->u.rest.rest_lsn,now,&a);
    break;
  case DMR_SLCB_HYTERA_XPT_CHANNEL:
    if(identity(s,DMR_TAG_HYTERA_XPT,dmr_xpt_system_tag(),"Hytera XPT Short LC",&a))
      xpt_free_repeater(s,slc->u.xpt.free_repeater,&a);
    break;
  default:
    break;
  }
  evaluate_all(s,now,&a);
  a.h = s->h;  // the hooks as they are now, called once the lock is let go
  pthread_mutex_unlock(&s->lock);
  run(s,&a);
}

void dmr_site_link_control(struct dmr_site *s,int handle,uint8_t slot,uint8_t color_code,struct dmr_lc const *lc){
  bool const wide_area = lc->kind == DMR_LC_CAP_PLUS_WIDE_AREA_VOICE;
  bool const hytera = lc->body == DMR_LCB_HYTERA_VOICE || lc->kind == DMR_LC_HYTERA_XPT_CHANNEL_GRANT;
  if(!wide_area && !hytera)
    return;  // nothing site-level in it: no lock taken
  struct actions a;
  actions_init(&a);
  pthread_mutex_lock(&s->lock);
  struct site_channel *ch = channel_at(s,handle);
  if(ch == NULL){
    pthread_mutex_unlock(&s->lock);
    return;
  }
  uint64_t const now = clock_now(s);
  copy_string(a.channel_id,sizeof a.channel_id,ch->channel_id);
  a.slot = slot;
  a.color_code = color_code;
  if(!color_code_ok(ch,color_code)){
    s->color_code_ignored++;
    pthread_mutex_unlock(&s->lock);
    return;
  }
  if(lc->body == DMR_LCB_CAP_PLUS_WIDE_AREA_VOICE){
    if(s->family == DMR_TAG_CAPACITY_PLUS && lc->u.wide_area.rest_lsn != 0)
      rest_channel(s,lc->u.wide_area.rest_lsn,now,&a);
  } else if(s->family == DMR_TAG_HYTERA_XPT){
    if(lc->body == DMR_LCB_HYTERA_VOICE)
      xpt_free_repeater(s,lc->u.hytera_voice.free_repeater,&a);
    else if(lc->body == DMR_LCB_HYTERA_XPT_GRANT){
      struct dmr_lc_hytera_xpt_grant const *g = &lc->u.xpt_grant;
      xpt_free_repeater(s,g->free_repeater,&a);
      if(g->channel != 0){
        char what[64];
        format(what,sizeof what,"XPT channel grant %s=%u",g->group ? "tg" : "unit",(unsigned)g->target);
        struct follow_who const who = {g->target, 16, g->group};
        announce_on(s,NULL,lc->u.xpt_grant.channel,0,0,false,what,who,ch,now,&a);
      }
    }
  }
  a.h = s->h;  // the hooks as they are now, called once the lock is let go
  pthread_mutex_unlock(&s->lock);
  run(s,&a);
}

void dmr_site_csbk(struct dmr_site *s,int handle,struct dmr_csbk_message const *m){
  if(!dmr_csbk_parsed(m))
    return;
  struct actions a;
  actions_init(&a);
  pthread_mutex_lock(&s->lock);
  struct site_channel *ch = channel_at(s,handle);
  if(ch == NULL){
    pthread_mutex_unlock(&s->lock);
    return;
  }
  uint64_t const now = clock_now(s);
  copy_string(a.channel_id,sizeof a.channel_id,ch->channel_id);
  a.slot = m->block.slot;
  a.color_code = m->block.color_code;
  if(!color_code_ok(ch,m->block.color_code)){
    s->color_code_ignored++;
    pthread_mutex_unlock(&s->lock);
    return;
  }

  // Identity
  struct dmr_bcast_common const *common = dmr_csbk_broadcast_common(m);
  if(m->kind == DMR_CSBK_ALOHA)
    identity(s,DMR_TAG_TIER3,dmr_tier3_system_tag(m->u.aloha.system.raw),"Aloha",&a);
  else if(common != NULL)
    identity(s,DMR_TAG_TIER3,dmr_tier3_system_tag(common->system.raw),"C_BCAST",&a);

  // Channel map
  struct dmr_cgap announced;
  if(dmr_csbk_channel_frequency(m,&announced))
    note_air_channel(s,&announced,true,&a);
  else if(m->has_absolute && dmr_cgap_plausible(&m->absolute))
    note_air_channel(s,&m->absolute,s->o.learn_from_any_cgap,&a);

  // Capacity Plus, neighbours, Hytera XPT
  switch(m->kind){
  case DMR_CSBK_CAP_PLUS_SITE_STATUS:
    if(family_is(s,DMR_TAG_CAPACITY_PLUS,"Capacity Plus Site Status",&a)){
      struct dmr_csbk_cap_plus_site_status const *status = &m->u.cap_plus_site_status;
      rest_channel(s,status->rest_lsn,now,&a);
      for(int i=0; i < status->activity_count; i++){
        struct dmr_cap_plus_activity const *act = &status->activity[i];
        if(act->data)
          continue;  // data revert: not cross-checked
        char what[64];
        if(act->id_known)
          format(what,sizeof what,"CAP+ Site Status (LSN %u tg %u)",act->lsn,act->id);
        else
          format(what,sizeof what,"CAP+ Site Status (LSN %u)",act->lsn);
        struct follow_who const who = {act->id, act->id_known ? 8 : 0, true};
        announce_on(s,NULL,(uint16_t)dmr_lsn_to_lcn(act->lsn),0,(uint8_t)dmr_lsn_to_timeslot(act->lsn),true,what,who,ch,now,&a);
      }
    }
    break;
  case DMR_CSBK_CAP_PLUS_NEIGHBORS:
    if(family_is(s,DMR_TAG_CAPACITY_PLUS,"Capacity Plus neighbours",&a)){
      rest_channel(s,m->u.cap_plus_neighbors.rest_lsn,now,&a);
      for(int i=0; i < dmr_cap_plus_neighbors_present(&m->u.cap_plus_neighbors); i++){
        char detail[40] = "";
        if(m->u.cap_plus_neighbors.neighbors[i].rest_lsn != 0)
          format(detail,sizeof detail,"rest LSN %u",(unsigned)m->u.cap_plus_neighbors.neighbors[i].rest_lsn);
        neighbour(s,m->u.cap_plus_neighbors.neighbors[i].site,detail);
      }
    }
    break;
  case DMR_CSBK_CON_PLUS_NEIGHBORS:
    for(int i=0; i < 5; i++){
      if(m->u.con_plus_neighbors.sites[i] != 0)
        neighbour(s,m->u.con_plus_neighbors.sites[i],NULL);
    }
    break;
  case DMR_CSBK_ADJACENT_SITE:
    {
      char detail[40] = "";
      uint16_t const lcn = m->u.other_site.lcn;
      if(lcn != 0){
        uint64_t const hz = dmr_map_downlink_hz(&s->map,lcn);
        char mhz[24] = "";
        if(hz != 0)
          dmr_format_mhz(mhz,sizeof mhz,hz);
        format(detail,sizeof detail,"LCN %u%s%s%s",(unsigned)lcn,hz != 0 ? " " : "",mhz,hz != 0 ? " MHz" : "");
      }
      neighbour(s,m->u.other_site.other.raw,detail);
    }
    break;
  case DMR_CSBK_HYTERA_XPT_SITE_STATE:
    if(identity(s,DMR_TAG_HYTERA_XPT,dmr_xpt_system_tag(),"Hytera XPT site state",&a))
      xpt_free_repeater(s,m->u.hytera_xpt_site_state.free_repeater,&a);
    break;
  case DMR_CSBK_HYTERA_XPT_ADJACENT_SITES:
    for(int i=0; i < 4; i++){
      if(m->u.hytera_xpt_adjacent_sites.sites[i].site != 0){
        char detail[40];
        format(detail,sizeof detail,"free %u",(unsigned)m->u.hytera_xpt_adjacent_sites.sites[i].free_repeater);
        neighbour(s,m->u.hytera_xpt_adjacent_sites.sites[i].site,detail);
      }
    }
    break;
  default:
    break;
  }

  // Grants
  struct dmr_grant grants[DMR_MAX_GRANTS];
  int const ngrants = dmr_csbk_grants(grants,m);
  for(int i=0; i < ngrants; i++){
    if(s->compressed_talkgroups && grants[i].destination_is_group)
      grants[i].destination = dmr_hytera_dialable_talkgroup(grants[i].destination);
    struct dmr_grant const *g = &grants[i];
    s->grants++;
    if(dmr_grant_is_data(g))
      s->grants_data++;
    else
      s->grants_voice++;
    if(g->activity_update)
      s->grant_updates++;
    uint64_t const hz = dmr_map_resolve(&s->map,&g->channel);
    if(hz == 0)
      s->grants_unresolved++;

    char desc[DMR_CSBK_DESCRIBE_MAX];
    dmr_grant_describe(desc,sizeof desc,g);
    struct site_channel const *target = dmr_chref_valid(&g->channel)
      ? find_channel(s,dmr_chref_has_frequency(&g->channel) ? 0 : g->channel.lcn,hz) : NULL;
    char text[DMR_SITE_LINE_MAX];
    size_t len = 0;
    append(text,sizeof text,&len,"%s",desc);
    if(hz != 0){
      char mhz[40];
      dmr_format_mhz(mhz,sizeof mhz,hz);
      append(text,sizeof text,&len," -> %s MHz",mhz);
      if(target == NULL)
        append(text,sizeof text,&len," (not configured)");
      else if(target->attached)
        append(text,sizeof text,&len," [%s]",target->channel_id);
      else
        append(text,sizeof text,&len," (not monitored)");
    } else if(dmr_chref_valid(&g->channel))
      append(text,sizeof text,&len," -> frequency unknown (LCN %u is not in the channel map)",g->channel.lcn);
    finish(text,sizeof text,len);
    line_text(&a,"GRANT",true,text);
    if(s->h.grant != NULL && a.ngrants < DMR_MAX_GRANTS){
      a.grants[a.ngrants] = *g;
      a.grant_hz[a.ngrants] = hz;
      a.ngrants++;
    }
    if(!dmr_grant_is_data(g) && dmr_chref_valid(&g->channel)){
      bool const absolute = dmr_chref_has_frequency(&g->channel);
      struct follow_who const who = {g->destination, 24, g->destination_is_group};
      announce_on(s,NULL,absolute ? 0 : g->channel.lcn,absolute ? hz : 0,g->channel.timeslot,g->activity_update,desc,who,ch,now,&a);
    }
  }

  // P_CLEAR: the payload channel's timeslot is released
  if(m->kind == DMR_CSBK_CLEAR){
    s->clears++;
    int const k = m->block.slot <= 2 ? m->block.slot : 0;
    forget(s,&ch->slots[k].pending);
    if(k != 0)
      forget(s,&ch->slots[0].pending);
    if(s->h.clear != NULL){
      a.have_clear = true;
      a.clear_channel = ch->context;
      a.clear_channel.system_tag = dmr_site_system_tag(s);
      a.clear_slot = m->block.slot;
    }
  }

  evaluate_all(s,now,&a);
  a.h = s->h;  // the hooks as they are now, called once the lock is let go
  pthread_mutex_unlock(&s->lock);
  run(s,&a);
}

void dmr_site_sync_lost(struct dmr_site *s,int handle){
  pthread_mutex_lock(&s->lock);
  struct site_channel *ch = channel_at(s,handle);
  if(ch != NULL)
    ch->sync_losses++;
  pthread_mutex_unlock(&s->lock);
}

void dmr_site_time(struct dmr_site *s){
  struct actions a;
  actions_init(&a);
  pthread_mutex_lock(&s->lock);
  evaluate_all(s,clock_now(s),&a);
  a.h = s->h;  // the hooks as they are now, called once the lock is let go
  pthread_mutex_unlock(&s->lock);
  run(s,&a);
}

uint64_t dmr_site_frequency_of(struct dmr_site *s,uint16_t lcn){
  pthread_mutex_lock(&s->lock);
  uint64_t const hz = dmr_map_downlink_hz(&s->map,lcn);
  pthread_mutex_unlock(&s->lock);
  return hz;
}

bool dmr_site_locate(struct dmr_site *s,uint64_t frequency_hz,struct dmr_source *source){
  pthread_mutex_lock(&s->lock);
  dmr_locate_fn const locate = s->h.locate;
  void * const arg = s->h.locate_arg;
  pthread_mutex_unlock(&s->lock);
  if(locate == NULL)
    return false;
  return locate(arg,frequency_hz,source);
}

// ---- reports ----

bool dmr_site_report_get(struct dmr_site *s,struct dmr_site_report *r){
  assert(s != NULL && r != NULL);
  memset(r,0,sizeof *r);
  pthread_mutex_lock(&s->lock);
  uint64_t const now = clock_now(s);
  copy_string(r->system_name,sizeof r->system_name,s->system_name);
  copy_string(r->site_name,sizeof r->site_name,s->site_name);
  r->type = s->type;
  r->system_tag = dmr_site_system_tag(s);
  r->identity_changes = s->identity_changes;
  r->foreign_identity_messages = s->foreign_identity;
  r->nneighbours = s->nneighbours;
  memcpy(r->neighbours,s->neighbours,sizeof r->neighbours);
  memcpy(r->neighbour_details,s->neighbour_details,sizeof r->neighbour_details);
  r->rest_known = s->rest_known;
  r->rest_lsn = s->rest_lsn;
  r->rest_lcn = (uint16_t)dmr_lsn_to_lcn(s->rest_lsn);
  r->rest_timeslot = (uint8_t)dmr_lsn_to_timeslot(s->rest_lsn);
  r->rest_moves = s->rest_moves;
  r->rest_stale_reports = s->rest_stale;
  r->xpt_free_known = s->xpt_free_known;
  r->xpt_free_repeater = s->xpt_free;
  r->xpt_free_repeater_moves = s->xpt_free_moves;
  r->grants = s->grants;
  r->grants_voice = s->grants_voice;
  r->grants_data = s->grants_data;
  r->grant_updates = s->grant_updates;
  r->grants_unresolved = s->grants_unresolved;
  r->clears = s->clears;
  r->announced = s->announced;
  r->announced_heard = s->announced_heard;
  r->announced_missed = s->announced_missed;
  r->miss_alarms = s->miss_alarms;
  r->announced_unconfirmed = s->announced_unconfirmed;
  r->announced_not_monitored = s->announced_not_monitored;
  r->announced_unconfigured = s->announced_unconfigured;
  r->map_entries = s->map.count;
  for(size_t i=0; i < s->map.count; i++){
    if(s->map.entries[i].source == DMR_MAP_AIR)
      r->map_entries_from_air++;
  }
  r->map_conflicts = s->map.conflicts;
  r->color_code_ignored_messages = s->color_code_ignored;
  if(s->nchannels > 0){
    r->channels = calloc((size_t)s->nchannels,sizeof *r->channels);
    if(r->channels == NULL){
      pthread_mutex_unlock(&s->lock);
      memset(r,0,sizeof *r);
      return false;
    }
  }
  r->nchannels = s->nchannels;
  for(int i=0; i < s->nchannels; i++){
    struct site_channel const *ch = &s->channels[i];
    struct dmr_site_channel_report *c = &r->channels[i];
    copy_string(c->channel_id,sizeof c->channel_id,ch->channel_id);
    c->lcn = ch->lcn;
    c->frequency_hz = ch->frequency_hz;
    c->configured = ch->configured;
    c->attached = ch->attached;
    c->bursts = ch->bursts;
    c->sync_losses = ch->sync_losses;
    memcpy(c->color_code_bursts,ch->color_code_bursts,sizeof c->color_code_bursts);
    c->expected_color_code = ch->expected_color_code;
    c->color_code_mismatches = ch->color_code_mismatches;
    r->color_code_mismatches += ch->color_code_mismatches;
    for(int k=0; k < 3; k++){
      c->call_bursts[k] = ch->slots[k].call_bursts;
      c->announced[k] = ch->slots[k].announced;
      c->heard[k] = ch->slots[k].heard;
      c->missed[k] = ch->slots[k].missed;
      c->alarms[k] = ch->slots[k].alarms;
      if(ch->slots[k].pending.active)
        r->announced_pending += ch->slots[k].pending.count;
    }
    c->last_burst_age_us = ch->ever_burst ? (int64_t)(now >= ch->last_burst_us ? now - ch->last_burst_us : 0) : -1;
  }
  pthread_mutex_unlock(&s->lock);
  return true;
}

void dmr_site_report_free(struct dmr_site_report *r){
  if(r == NULL)
    return;
  free(r->channels);
  r->channels = NULL;
  r->nchannels = 0;
}

int dmr_site_format_summary(char *buf,size_t size,struct dmr_site_report const *r){
  typedef unsigned long long ull;
  size_t len = 0;
  char b[640],tag[64];
  append(buf,size,&len,"[DMR site %s/%s] type=%s",r->system_name,r->site_name,dmr_system_type_name(r->type));
  dmr_system_tag_describe(tag,sizeof tag,r->system_tag);
  append(buf,size,&len," tag=0x%08X (%s)",(unsigned)r->system_tag,tag);
  if(r->identity_changes != 0 || r->foreign_identity_messages != 0)
    append(buf,size,&len," id_changes=%llu foreign_id=%llu",(ull)r->identity_changes,(ull)r->foreign_identity_messages);
  if(r->rest_known)
    append(buf,size,&len," rest=LSN %u (LCN %u TS%u) moves=%llu",(unsigned)r->rest_lsn,(unsigned)r->rest_lcn,(unsigned)r->rest_timeslot,
           (ull)r->rest_moves);
  if(r->xpt_free_known)
    append(buf,size,&len," xpt_free=%u moves=%llu",(unsigned)r->xpt_free_repeater,(ull)r->xpt_free_repeater_moves);
  format(b,sizeof b," | grants=%llu voice=%llu data=%llu updates=%llu unresolved=%llu clears=%llu | announced=%llu heard=%llu "
           "missed=%llu alarms=%llu unconfirmed=%llu not_monitored=%llu unconfigured=%llu | map=%zu air=%zu "
           "conflicts=%llu | cc_mismatch=%llu",
           (ull)r->grants,(ull)r->grants_voice,(ull)r->grants_data,(ull)r->grant_updates,(ull)r->grants_unresolved,(ull)r->clears,
           (ull)r->announced,(ull)r->announced_heard,(ull)r->announced_missed,(ull)r->miss_alarms,(ull)r->announced_unconfirmed,
           (ull)r->announced_not_monitored,(ull)r->announced_unconfigured,r->map_entries,r->map_entries_from_air,(ull)r->map_conflicts,
           (ull)r->color_code_mismatches);
  append(buf,size,&len,"%s",b);
  if(r->color_code_ignored_messages != 0)
    append(buf,size,&len," cc_ignored=%llu",(ull)r->color_code_ignored_messages);
  if(r->nneighbours > 0){
    append(buf,size,&len," | neighbours=");
    for(int i=0; i < r->nneighbours; i++){
      append(buf,size,&len,"%s%u",i ? "," : "",r->neighbours[i]);
      if(r->neighbour_details[i][0] != '\0')
        append(buf,size,&len,"(%s)",r->neighbour_details[i]);
    }
  }
  append(buf,size,&len," |");
  for(int i=0; i < r->nchannels; i++){
    struct dmr_site_channel_report const *c = &r->channels[i];
    if(c->lcn != 0)
      append(buf,size,&len," LCN%u",c->lcn);
    else
      append(buf,size,&len," %s",c->channel_id);
    if(!c->attached){
      append(buf,size,&len,"[off]");
      continue;
    }
    append(buf,size,&len,"[bursts=%llu call=%llu/%llu",(ull)c->bursts,(ull)c->call_bursts[1],(ull)c->call_bursts[2]);
    if(c->call_bursts[0] != 0)
      append(buf,size,&len,"/?%llu",(ull)c->call_bursts[0]);
    append(buf,size,&len," cc=");
    bool any = false;
    for(int cc=0; cc < 16; cc++){
      if(c->color_code_bursts[cc] == 0)
        continue;
      if(any)
        append(buf,size,&len,",");
      append(buf,size,&len,"%d",cc);
      // The counts only when there is more than the expected colour code to show
      if(c->color_code_mismatches != 0)
        append(buf,size,&len,":%llu",(ull)c->color_code_bursts[cc]);
      any = true;
    }
    if(!any)
      append(buf,size,&len,"-");
    append(buf,size,&len," alarms=%llu",(ull)(c->alarms[0] + c->alarms[1] + c->alarms[2]));
    if(c->sync_losses != 0)
      append(buf,size,&len," syncloss=%llu",(ull)c->sync_losses);
    if(c->last_burst_age_us < 0)
      append(buf,size,&len," last=never]");
    else
      append(buf,size,&len," last=%.1fs]",seconds_of((double)c->last_burst_age_us));
  }
  return finish(buf,size,len);
}

int dmr_site_summary(char *buf,size_t size,struct dmr_site *s){
  struct dmr_site_report r;
  if(!dmr_site_report_get(s,&r))
    return finish(buf,size,0);
  int const n = dmr_site_format_summary(buf,size,&r);
  dmr_site_report_free(&r);
  return n;
}

// ---------------- The control plane of one channel ----------------

enum { MAX_LOGGED_KEYS = 32, LOGGED_KEY_MAX = DMR_DESCRIBE_MAX + 8 };

// Per timeslot, for the control log: which lines this transmission has written, and who is talking
struct cplane_slot {
  bool open;                    // a voice transmission is in progress
  bool have_clock;
  uint64_t last_clock;
  uint8_t color_code;
  int nlogged;
  char logged[MAX_LOGGED_KEYS][LOGGED_KEY_MAX]; // keys of the once-per-transmission lines
  bool have_source;
  uint32_t source;
  bool alias_pending;
  char alias[DMR_TALKER_ALIAS_TEXT]; // completed before the talker was known
};

struct dmr_cplane {
  struct dmr_cplane_options o;
  struct dmr_site_context context;
  struct dmr_site *site;
  struct dmr_control_log *log;
  int handle;
  struct dmr_mbc_assembler mbc;
  struct dmr_csbk_mask_counter masks;
  bool masks_changed;
  struct dmr_crc_learner learner; // CSBKs, when o.learn_crc_masks
  struct cplane_slot slots[3];
  struct dmr_cplane_counters counters; // the channel thread's

  pthread_mutex_t lock;         // guards the published copies
  struct dmr_cplane_counters published;
  struct dmr_csbk_mask_counter published_masks;
};

void dmr_cplane_options_init(struct dmr_cplane_options *o){
  assert(o != NULL);
  memset(o,0,sizeof *o);
  o->csbk_crc_mask = DMR_CRC_MASK_CSBK;
  o->mbc_max_block_gap_us = DMR_MBC_MAX_BLOCK_GAP_US;
  o->slot_gap_dibits = 4800;
}

static void slot_clear(struct cplane_slot *slot){
  memset(slot,0,sizeof *slot);
  slot->color_code = DMR_NO_COLOR_CODE;
}

struct dmr_cplane *dmr_cplane_create(struct dmr_site_context const *channel,struct dmr_site *site,
                                     struct dmr_control_log *log,struct dmr_cplane_options const *options){
  assert(channel != NULL);
  struct dmr_cplane *c = calloc(1,sizeof *c);
  if(c == NULL)
    return NULL;
  if(options != NULL)
    c->o = *options;
  else
    dmr_cplane_options_init(&c->o);
  c->context = *channel;
  c->site = site;
  c->log = log;
  c->handle = -1;
  dmr_mbc_init(&c->mbc,c->o.mbc_max_block_gap_us);
  dmr_crc_learner_init(&c->learner);
  c->learner.learned = c->o.learned;
  c->learner.learned_arg = c->o.learned_arg;
  dmr_csbk_mask_counter_init(&c->masks,0);
  dmr_csbk_mask_counter_init(&c->published_masks,0);
  for(int k=0; k < 3; k++)
    slot_clear(&c->slots[k]);
  pthread_mutex_init(&c->lock,NULL);
  if(site != NULL){
    c->handle = dmr_site_attach(site,&c->context);
    c->context.system_tag = dmr_site_system_tag(site);
  }
  return c;
}

static void refresh_system_tag(struct dmr_cplane *c){
  if(c->site != NULL)
    c->context.system_tag = dmr_site_system_tag(c->site);
}

static void line(struct dmr_cplane *c,uint8_t slot,uint8_t color_code,char const *kind,char const *text){
  if(c->log != NULL)
    dmr_control_log_write(c->log,c->context.channel_id,slot,color_code,kind,text);
}

// True the first time key is offered in the slot's transmission
static bool first_in_transmission(struct cplane_slot *slot,char const *key){
  for(int i=0; i < slot->nlogged; i++){
    if(strcmp(slot->logged[i],key) == 0)
      return false;
  }
  if(slot->nlogged >= MAX_LOGGED_KEYS)
    slot->nlogged = 0;  // bounded: at worst a line is written again
  copy_string(slot->logged[slot->nlogged++],LOGGED_KEY_MAX,key);
  return true;
}

static void write_alias(struct dmr_cplane *c,struct cplane_slot const *slot,uint8_t slot_number,char const *alias){
  if(c->log != NULL)
    dmr_control_log_write_alias(c->log,c->context.channel_id,slot_number,slot->color_code,slot->have_source ? slot->source : 0,alias);
}

static void end_transmission(struct dmr_cplane *c,struct cplane_slot *slot,uint8_t slot_number){
  if(slot->alias_pending){
    write_alias(c,slot,slot_number,slot->alias);  // the talker never became known
    slot->alias_pending = false;
    slot->alias[0] = '\0';
  }
  slot->open = false;
}

static void begin_transmission(struct dmr_cplane *c,struct cplane_slot *slot,uint8_t slot_number){
  if(slot->open)
    return;
  end_transmission(c,slot,slot_number);
  slot->open = true;
  slot->nlogged = 0;
  slot->have_source = false;
  slot->source = 0;
}

// The talker of the slot's transmission, from a voice LC of any layout
static void note_talker(struct dmr_cplane *c,struct cplane_slot *slot,uint8_t slot_number,struct dmr_lc const *lc){
  struct dmr_voice_identity id;
  if(!dmr_lc_voice_identity(lc,&id))
    return;
  slot->have_source = true;
  slot->source = id.source;
  if(slot->alias_pending){  // an alias that completed before the talker was known (a late entry)
    write_alias(c,slot,slot_number,slot->alias);
    slot->alias_pending = false;
    slot->alias[0] = '\0';
  }
}

static void hex_key(char *key,size_t size,char prefix,uint8_t const bytes[9]){
  size_t len = 0;
  append(key,size,&len,"%c",prefix);
  for(int i=0; i < 9; i++)
    append(key,size,&len,"%02X",bytes[i]);
}

static void drop_assembly_state(struct dmr_cplane *c){
  for(int k=0; k < 3; k++)
    end_transmission(c,&c->slots[k],(uint8_t)k);
  dmr_mbc_reset(&c->mbc);
  for(int k=0; k < 3; k++)
    slot_clear(&c->slots[k]);
}

static void publish(struct dmr_cplane *c){
  c->counters.mbc_header_crc_failed = c->mbc.stats.header_crc_failures;
  c->counters.mbc_crc_failed = c->mbc.stats.crc_failures;
  c->counters.mbc_abandoned = c->mbc.stats.abandoned + c->mbc.stats.orphan_blocks;
  pthread_mutex_lock(&c->lock);
  c->published = c->counters;
  if(c->masks_changed){
    c->published_masks = c->masks;
    c->masks_changed = false;
  }
  pthread_mutex_unlock(&c->lock);
}

static void count_burst(struct dmr_cplane *c,struct dmr_burst const *b){
  c->counters.bursts++;
  c->counters.bursts_by_slot[b->slot <= 2 ? b->slot : 0]++;
  if((unsigned)b->kind < 9)
    c->counters.bursts_by_kind[b->kind]++;
  if(b->kind == DMR_KIND_DATA){
    if(b->slot_type_valid)
      c->counters.bursts_by_data_type[b->data_type & 15u]++;
    else
      c->counters.data_slot_type_invalid++;
  }
}

// The key a Short LC collapses on: its text, but Sys_Parms without its common slot counter
static void short_lc_key(char *key,size_t size,struct dmr_short_lc const *slc,char const *text){
  if(slc->body == DMR_SLCB_SYS_PARMS)
    format(key,size,"SLC SYS_PARMS %u %04X %d",(unsigned)slc->slco,(unsigned)slc->u.sys_parms.system_identity_code,
             slc->u.sys_parms.registration_required || slc->u.sys_parms.composite_control_channel ? 1 : 0);
  else
    copy_string(key,size,text);
}

static void control_plane(struct dmr_cplane *c,struct dmr_burst const *b,struct dmr_burst_messages const *m,
                          struct dmr_csbk_message const *csbk,bool csbk_crc_failed){
  uint8_t const slot_number = b->slot <= 2 ? b->slot : 0;
  struct cplane_slot *slot = &c->slots[slot_number];
  bool const color_code_known = (b->kind == DMR_KIND_DATA && b->slot_type_valid)
    || (dmr_is_voice(b->kind) && b->kind != DMR_KIND_VOICE_A && b->emb_valid);
  if(color_code_known)
    slot->color_code = b->color_code & 0xFu;
  uint8_t const cc = color_code_known ? (uint8_t)(b->color_code & 0xFu) : slot->color_code;

  // A long silence on the slot ends its transmission, as it drops the message layer's slot state
  if(slot->have_clock && b->dibit_clock > slot->last_clock + c->o.slot_gap_dibits)
    end_transmission(c,slot,slot_number);
  if(b->dibit_clock != 0){
    slot->last_clock = b->dibit_clock;
    slot->have_clock = true;
  }

  if(c->site != NULL)
    dmr_site_burst(c->site,c->handle,b);

  char text[DMR_SITE_LINE_MAX];
  char key[DMR_SITE_LINE_MAX];
  if(m->has_short_lc){
    c->counters.short_lcs++;
    if(c->site != NULL)
      dmr_site_short_lc(c->site,c->handle,cc,&m->short_lc);
    if(c->log != NULL){
      dmr_slc_describe(text,sizeof text,&m->short_lc);
      short_lc_key(key,sizeof key,&m->short_lc,text);
      dmr_control_log_write_collapsed(c->log,c->context.channel_id,0,cc,"SLC",text,key);
    }
  }

  if(m->has_data){
    struct dmr_data_burst const *d = &m->data;
    unsigned const type = (unsigned)d->data_type & 15u;
    bool const starts_voice = b->slot_type_valid && (d->data_type == DMR_DT_VOICE_LC_HEADER || d->data_type == DMR_DT_PI_HEADER);
    bool const terminator = b->slot_type_valid && d->data_type == DMR_DT_TERMINATOR_LC;
    if(starts_voice)
      begin_transmission(c,slot,slot_number);
    else if(!terminator)
      end_transmission(c,slot,slot_number);

    if(d->status == DMR_DATA_CHECK_FAILED)
      c->counters.check_failed_by_data_type[type]++;
    if(d->status == DMR_DATA_REFUSED && b->slot_type_valid)
      c->counters.refused_by_data_type[type]++;

    if(dmr_data_lc_usable(d)){
      if(d->data_type == DMR_DT_VOICE_LC_HEADER){
        c->counters.voice_lc_headers++;
        note_talker(c,slot,slot_number,&d->lc);
      } else
        c->counters.terminators++;
      if(c->site != NULL)
        dmr_site_link_control(c->site,c->handle,slot_number,cc,&d->lc);
      hex_key(key,sizeof key,d->data_type == DMR_DT_VOICE_LC_HEADER ? 'H' : 'T',d->lc.bytes);
      if(first_in_transmission(slot,key)){
        dmr_data_describe(text,sizeof text,d);
        line(c,slot_number,cc,"LC",text);
      }
    } else if(d->has_pi){
      c->counters.pi_headers++;
      dmr_pi_header_describe(text,sizeof text,&d->pi);
      format(key,sizeof key,"P%s",text);
      if(first_in_transmission(slot,key))
        line(c,slot_number,cc,"PI",text);
    }
    if(terminator)
      end_transmission(c,slot,slot_number);

    if(csbk != NULL && dmr_csbk_parsed(csbk)){
      if(csbk->from_mbc)
        c->counters.mbc_messages++;
      else
        c->counters.csbks++;
      struct dmr_grant grants[DMR_MAX_GRANTS];
      c->counters.grants += (uint64_t)dmr_csbk_grants(grants,csbk);
      if(c->log != NULL){
        // "CSBK <text>", or the text's own "MBC ..." / "CSBK ..." where it has one
        char desc[DMR_CSBK_DESCRIBE_MAX];
        dmr_csbk_describe(desc,sizeof desc,csbk);
        if(csbk->from_mbc || strncmp(desc,"CSBK",4) == 0)
          copy_string(text,sizeof text,desc);
        else
          format(text,sizeof text,"CSBK %s",desc);
        // The data revert window announcements carry a counter: keyed by kind
        char const *k = text;
        if(csbk->kind == DMR_CSBK_CON_PLUS_DATA_WINDOW && !csbk->u.con_plus_data_window.is_grant)
          k = "CSBK CON+ data revert window announcement";
        else if(csbk->kind == DMR_CSBK_CAP_PLUS_DATA_WINDOW && !csbk->u.cap_plus_data_window.is_grant)
          k = "CSBK CAP+ data revert window announcement";
        dmr_control_log_write_collapsed(c->log,c->context.channel_id,slot_number,cc,csbk->from_mbc ? "MBC" : "CSBK",text,k);
      }
      if(c->site != NULL)
        dmr_site_csbk(c->site,c->handle,csbk);
    } else if(csbk_crc_failed && csbk != NULL){
      c->counters.csbk_crc_failed++;
      uint32_t const seen = dmr_csbk_mask_note_block(&c->masks,&csbk->block);
      c->masks_changed = true;
      if(seen == 3 || (seen != 0 && seen % 1000 == 0)){
        char desc[DMR_CSBK_DESCRIBE_MAX];
        dmr_csbk_describe(desc,sizeof desc,csbk);
        format(text,sizeof text,"%s (this CSBKO, FID and mask seen %u times)",desc,seen);
        line(c,slot_number,cc,"CSBK",text);
      }
    }
  } else if(m->has_voice){
    begin_transmission(c,slot,slot_number);
    c->counters.voice_frame_fec_errors += (uint64_t)dmr_voice_fec_errors(&m->voice);
    if(m->embedded_lc_failed)
      c->counters.embedded_lc_failed++;
    if(b->kind != DMR_KIND_VOICE_A && b->emb_valid && b->emb_pi){
      c->counters.emb_pi_set++;
      if(first_in_transmission(slot,"EMBPI"))
        line(c,slot_number,cc,"EMB","EMB PI=1: the embedded field carries reverse channel information for the other logical channel (TS 102 361-1 9.3.2)");
    }
    if(m->has_embedded_lc){
      struct dmr_lc const *lc = &m->embedded_lc.lc;
      c->counters.embedded_lcs++;
      note_talker(c,slot,slot_number,lc);
      if(c->site != NULL)
        dmr_site_link_control(c->site,c->handle,slot_number,cc,lc);
      hex_key(key,sizeof key,'E',lc->bytes);
      if(first_in_transmission(slot,key)){
        char desc[DMR_DESCRIBE_MAX];
        dmr_lc_describe(desc,sizeof desc,lc);
        format(text,sizeof text,"EMBEDDED LC: %s",desc);
        line(c,slot_number,cc,"LC",text);
      }
    }
    if(b->kind != DMR_KIND_VOICE_A && b->emb_valid && b->emb_lcss == DMR_LCSS_SINGLE && !m->has_single_burst)
      c->counters.single_bursts_undecoded++;
    if(m->single_burst_form_mismatch){
      c->counters.single_burst_form_mismatch++;
      if(first_in_transmission(slot,"FFORM"))
        line(c,slot_number,cc,"EMB",b->emb_pi ? "BURST F: EMB PI=1 but only the single burst form decodes (not used)"
                                                : "BURST F: EMB PI=0 but only the reverse channel form decodes (not used)");
    }
    if(m->has_single_burst && m->single_burst.kind == DMR_SB_ENCRYPTION_PARAMETERS){
      c->counters.burst_f_encryption++;
      char desc[DMR_DESCRIBE_MAX];
      dmr_single_burst_describe(desc,sizeof desc,&m->single_burst);
      format(key,sizeof key,"F%s",desc);
      if(first_in_transmission(slot,key)){
        format(text,sizeof text,"BURST F: %s",desc);
        line(c,slot_number,cc,"ENC",text);
      }
    }
    if(m->has_hidden_iv)
      c->counters.hidden_ivs++;
    if(m->has_talker_alias){
      c->counters.talker_aliases++;
      if(slot->have_source)
        write_alias(c,slot,slot_number,m->talker_alias.text);
      else {
        slot->alias_pending = true;  // waits for the talker, or the end of the transmission
        copy_string(slot->alias,sizeof slot->alias,m->talker_alias.text);
      }
    }
  }
}

void dmr_cplane_burst(struct dmr_cplane *c,struct dmr_burst const *b,struct dmr_burst_messages const *m){
  assert(c != NULL && b != NULL && m != NULL);
  refresh_system_tag(c);
  count_burst(c,b);

  // The data bursts the message layer hands on unchecked
  struct dmr_mbc_event e;
  struct dmr_csbk_message const *csbk = NULL;
  bool crc_failed = false;
  bool const unchecked = m->has_data && m->data.status == DMR_DATA_UNCHECKED;
  bool const mobile_sourced = b->mode == DMR_STATION_MS || b->mode == DMR_STATION_DIRECT;
  if(unchecked && m->data.data_type == DMR_DT_CSBK){
    dmr_mbc_on_other_burst(&c->mbc,b->slot);
    dmr_csbk_parse(&e.message,m->data.info,b->slot,b->color_code,b->timestamp_us,c->o.csbk_crc_mask,mobile_sourced);
    if(!dmr_csbk_parsed(&e.message) && c->o.learn_crc_masks){
      // A residual seen twice for this (CSBKO, FID) within the window: the CSBK as it is, with that mask
      uint16_t const mask = e.message.block.observed_mask;
      if(dmr_crc_learner_check(&c->learner,DMR_CRC_CHECK_CSBK,e.message.block.opcode,e.message.block.fid,mask,b->timestamp_us))
        dmr_csbk_parse(&e.message,m->data.info,b->slot,b->color_code,b->timestamp_us,mask,mobile_sourced);
    }
    csbk = &e.message;
    crc_failed = !dmr_csbk_parsed(csbk);
  } else if(unchecked && (m->data.data_type == DMR_DT_MBC_HEADER || m->data.data_type == DMR_DT_MBC_CONTINUATION)){
    dmr_mbc_on_burst(&c->mbc,&e,m->data.data_type,m->data.info,b->slot,b->color_code,b->timestamp_us,mobile_sourced);
    if(e.has_message)
      csbk = &e.message;
  } else
    dmr_mbc_on_other_burst(&c->mbc,b->slot); // voice, idle, a burst that did not decode: a message in progress is over

  control_plane(c,b,m,csbk,crc_failed);
  publish(c);
}

void dmr_cplane_sync_lost(struct dmr_cplane *c){
  refresh_system_tag(c);
  c->counters.sync_losses++;
  drop_assembly_state(c);
  if(c->site != NULL)
    dmr_site_sync_lost(c->site,c->handle);
  publish(c);
}

void dmr_cplane_time(struct dmr_cplane *c){
  refresh_system_tag(c);
  if(c->site != NULL)
    dmr_site_time(c->site);
  if(c->log != NULL)
    dmr_control_log_time(c->log);
}

void dmr_cplane_reset_slot(struct dmr_cplane *c,uint8_t slot){
  if(slot > 2)
    return;
  end_transmission(c,&c->slots[slot],slot);
}

void dmr_cplane_reset(struct dmr_cplane *c){
  drop_assembly_state(c);
}

void dmr_cplane_flush(struct dmr_cplane *c){
  refresh_system_tag(c);
  drop_assembly_state(c);
  publish(c);
}

void dmr_cplane_destroy(struct dmr_cplane *c){
  if(c == NULL)
    return;
  pthread_mutex_destroy(&c->lock);
  free(c);
}

void dmr_cplane_context(struct dmr_cplane *c,struct dmr_site_context *channel){
  refresh_system_tag(c);
  *channel = c->context;
}

uint64_t dmr_cplane_learned_csbks(struct dmr_cplane const *c){
  return c != NULL ? c->learner.accepted[DMR_CRC_CHECK_CSBK] : 0;
}
int dmr_cplane_handle(struct dmr_cplane const *c){
  return c->handle;
}

void dmr_cplane_get_counters(struct dmr_cplane *c,struct dmr_cplane_counters *out){
  pthread_mutex_lock(&c->lock);
  *out = c->published;
  pthread_mutex_unlock(&c->lock);
}

void dmr_cplane_get_masks(struct dmr_cplane *c,struct dmr_csbk_mask_counter *out){
  pthread_mutex_lock(&c->lock);
  *out = c->published_masks;
  pthread_mutex_unlock(&c->lock);
}
