// One DMR carrier from I/Q to labelled voice: receiver, burst sink, message layer and call tracker
// joined on the channel's thread (see dmrchan.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "timing.h"
#include "dmr.h"
#include "dmrrx.h"
#include "dmrsink.h"
#include "dmrmsg.h"
#include "dmrcall.h"
#include "dmrcsbk.h"
#include "dmrsite.h"
#include "dmrdata.h"
#include "dmrdataapp.h"
#include "dmrchan.h"

// Theory of operation
//
// The layers. Samples go to the receiver (dmrrx.c), whose burst sink (dmrsink.c) frames the soft
// dibits into bursts; each burst goes to the message layer (dmrmsg.c) and, with what that decoded, to
// the call tracker (dmrcall.c), which decides every voice frame's encryption label and hands the
// frames on in order. This file joins them and gives them one time base.
//
// Time. Every burst carries the receiver's symbol index of its first dibit, and its time is made from
// that: time(index) = anchor + (index - anchor index) / 4800 s, in microseconds since the GPS epoch,
// so 144 symbols (one slot period) are 30,000 us exactly and two bursts of a slot are 60 ms apart for
// as long as a frame is held. The anchor is the sender's time of the first sample (radiod's clock
// reference, as every block carries it), given to the symbol the first sample becomes: the receiver
// delivers a dibit sampled at sample 4i as symbol i + 13 (DMR_RX_DELAY_SYMBOLS: its receive filter,
// matched filter and interpolator). Two things keep the clock honest. With no frame held, no
// transmission in progress on either slot, the symbol count is a free-running timing loop's, which
// on noise runs a few tenths of a percent off; so while the channel is idle the anchor is put back on
// the sample count after every block (never back past a burst already delivered). And about once a
// second of signal (every 16 ticks, 0.96 s) the symbol clock is compared with the stream's own clock
// (the block's sender time); if they differ by more than a second (samples lost upstream and not
// filled, a sender restart) the anchor moves to the stream's clock at a moment when no transmission is
// in progress.
//
// Timeouts. The tracker ends a transmission whose voice stops (a fade) by time, not by a burst, so it
// is told the time: before each burst, that burst's time; and every 288 symbols (60 ms), the time of
// the symbol 1,728 symbols (360 ms) back, since the sink may hand a burst on up to that long after its
// first dibit and a timeout must not run ahead of a burst still on its way.
//
// The control plane (dmrsite.c) takes every burst too, after the tracker, with the slot type as the
// sink decoded it: it parses CSBKs and multi-block CSBKs and feeds the carrier's site (identity, rest
// channel, channel map, grants), which is the owner's and shared by the site's channels: nothing here
// assumes one radiod or one channel per site.
//
// The wiring the layers leave to their owner: on sync loss the message layer's state is dropped
// before the control plane and the tracker hear of it; a transmission the tracker ends by a fade, a header no voice
// followed, or a release drops that slot's message state (its embedded LC and talker alias); a data
// burst whose slot type names another colour code than the one the sink requires is another system
// on the frequency, and reaches the tracker as a data burst that did not decode, which ends a
// transmission in progress on its slot and can neither start one nor say clear; at the end the sink
// is reset (its held bursts come out), the tracker flushed, and the message state dropped.
//
// What leaves. Each voice record the tracker writes becomes one struct dmr_chan_frame with its label:
// clear only when the tracker labelled it clear (no encrypted flag and the clear algorithm), else
// encrypted or unconfirmed. dmrd decodes only the clear ones. Transmission starts and ends become
// events.

enum {
  TICK_SYMBOLS = 288,       // the tracker's timeouts every 60 ms of signal
  TICK_LAG_SYMBOLS = 1728,  // ... at the time 360 ms back
  DRIFT_CHECK_TICKS = 16,   // the symbol clock against the stream's every 0.96 s
};
static uint64_t const Max_clock_drift_us = 1000000;

struct dmr_chan {
  struct dmr_chan_handlers h;
  struct dmr_rx *rx;
  struct dmr_msg_decoder msg;
  struct dmr_call_tracker tracker;
  struct dmr_cplane *cplane;       // NULL without a site
  struct dmr_data_assembler *data; // NULL: no packet data
  uint64_t data_last_us;           // the last burst it was given
  bool auto_stations;
  enum dmr_station family;         // the family locked to (auto_stations); UNKNOWN: not yet
  uint64_t family_syncs[3];        // synced bursts: bs, ms, direct
  struct dmr_site *site;
  struct dmr_channel channel;
  char channel_id[32];
  double samprate;

  // Time
  bool anchored;
  uint64_t anchor_us;
  int64_t anchor_symbol;
  uint64_t sample_anchor_us;  // sender time of the first sample
  uint64_t samples;           // since the first
  uint64_t block_us;          // sender time of the current block's first sample (0: not known)
  uint64_t block_start;       // sample count at the current block's start
  uint64_t symbol_index;      // of the newest symbol
  bool tick_started;
  int64_t first_symbol;
  uint64_t next_tick;
  uint64_t ticks;
  uint64_t last_burst_us;
  bool flushing;

  // Per slot (0 = not known, 1, 2): the talker alias of the transmission in progress
  char alias[3][64];

  struct dmr_chan_stats stats;
};

void dmr_chan_config_init(struct dmr_chan_config *c){
  assert(c != NULL);
  memset(c,0,sizeof *c);
  c->color_code = -1;
  c->base_station = true;
  c->decode_data = true;
}

static uint64_t time_of_symbol(struct dmr_chan const *c,uint64_t index){
  int64_t const d = (int64_t)index - c->anchor_symbol;
  // floor(d * 1e6 / 4800) = floor(d * 625 / 3)
  int64_t const us = d >= 0 ? d * 625 / 3 : -((-d * 625 + 2) / 3);
  int64_t const t = (int64_t)c->anchor_us + us;
  return t > 0 ? (uint64_t)t : 0;
}

static void anchor_at(struct dmr_chan *c,uint64_t us,int64_t symbol){
  c->anchor_us = us;
  c->anchor_symbol = symbol;
  c->anchored = true;
}

// Nothing in progress that measures time: no frame held by the sink, no transmission
static bool idle(struct dmr_chan const *c){
  return !dmr_rx_locked(c->rx) && !dmr_call_active(&c->tracker,0) && !dmr_call_active(&c->tracker,1)
    && !dmr_call_active(&c->tracker,2);
}

// With no frame held: the next symbol to come is the newest sample less the receiver's delay
static void anchor_to_samples(struct dmr_chan *c){
  uint64_t const sample_us = c->sample_anchor_us + (uint64_t)((double)c->samples * 1e6 / c->samprate);
  int64_t const symbol = (int64_t)dmr_rx_symbol_count(c->rx) + DMR_RX_DELAY_SYMBOLS;
  if(sample_us <= c->last_burst_us)
    return; // never back past a burst already delivered
  anchor_at(c,sample_us,symbol);
}

// The stream's own clock at the newest sample
static uint64_t stream_us(struct dmr_chan const *c){
  if(c->block_us == 0)
    return 0;
  return c->block_us + (uint64_t)((double)(c->samples - c->block_start) * 1e6 / c->samprate);
}

static void check_clock(struct dmr_chan *c,uint64_t index){
  uint64_t const wall = stream_us(c);
  if(wall == 0)
    return;
  uint64_t const signal = time_of_symbol(c,index);
  int64_t const drift = (int64_t)wall - (int64_t)signal;
  int64_t const magnitude = drift < 0 ? -drift : drift;
  if((uint64_t)magnitude <= Max_clock_drift_us)
    return;
  if(dmr_call_active(&c->tracker,0) || dmr_call_active(&c->tracker,1) || dmr_call_active(&c->tracker,2))
    return;
  if(drift < 0 && wall <= c->last_burst_us)
    return;
  anchor_at(c,wall,(int64_t)index);
  c->sample_anchor_us = (uint64_t)((int64_t)c->sample_anchor_us + drift);
  if(c->h.log != NULL){
    char text[128];
    snprintf(text,sizeof text,"signal time was %+.3f s from the stream's clock: re-anchored",-(double)drift / 1e6);
    c->h.log(c->h.arg,(int64_t)wall * 1000,text);
  }
}

// The sink's clock: the time of a symbol index
static uint64_t sink_clock(void *arg,uint64_t index){
  return time_of_symbol((struct dmr_chan const *)arg,index);
}

// Each symbol, after the sink: the tracker's timeouts
enum { DATA_IDLE_FLUSH_US = 500000 }; // a packet left open this long on a quiet carrier is delivered

static void on_symbol(void *arg,uint64_t index){
  struct dmr_chan * const c = arg;
  c->symbol_index = index;
  if(!c->tick_started){
    c->tick_started = true;
    c->first_symbol = (int64_t)index;
    c->next_tick = index + TICK_SYMBOLS;
  }
  if(index < c->next_tick)
    return;
  c->next_tick = index + TICK_SYMBOLS;
  c->ticks++;
  int64_t const behind = (int64_t)index - TICK_LAG_SYMBOLS;
  if(behind >= c->first_symbol)
    dmr_call_on_time(&c->tracker,&c->channel,time_of_symbol(c,(uint64_t)behind));
  if(c->cplane != NULL)
    dmr_cplane_time(c->cplane);
  // A packet left open on a carrier quiet for half a second is delivered as it is
  if(c->data != NULL && dmr_data_packet_open(c->data) && c->anchored
     && time_of_symbol(c,index) - c->data_last_us > DATA_IDLE_FLUSH_US)
    dmr_data_flush(c->data);
  if(c->ticks % DRIFT_CHECK_TICKS == 0)
    check_clock(c,index);
}

// Packet data lines: what the packet carries (its application's line, or the packet's own when it has
// none); at -v (the log handler) the packet's assembly and CRC evidence too, and every data header
static void on_data_packet(void *arg,struct dmr_data_packet const *p){
  struct dmr_chan * const c = arg;
  c->stats.data_packets++;
  if(p->complete)
    c->stats.data_packets_complete++;
  char line[DMR_DATA_DESCRIBE_MAX],text[DMR_DATA_DESCRIBE_MAX + 16];
  int64_t const when = (int64_t)p->first_timestamp_us * 1000;
  if(c->h.data != NULL){
    if(p->app != NULL)
      dmr_data_app_describe(line,sizeof line,p->app);
    else
      dmr_data_packet_describe(line,sizeof line,p);
    snprintf(text,sizeof text,"slot %u DATA %s",(unsigned)p->slot,line);
    c->h.data(c->h.arg,when,text);
  }
  if(c->h.log != NULL && p->app != NULL){
    dmr_data_packet_describe(line,sizeof line,p);
    snprintf(text,sizeof text,"slot %u %s",(unsigned)p->slot,line);
    c->h.log(c->h.arg,when,text);
  }
  if(c->h.packet != NULL)
    c->h.packet(c->h.arg,p);
}
static void on_data_header(void *arg,struct dmr_data_header const *hd){
  struct dmr_chan * const c = arg;
  if(c->h.log == NULL)
    return;
  char line[DMR_DATA_DESCRIBE_MAX],text[DMR_DATA_DESCRIBE_MAX + 16];
  dmr_data_header_describe(line,sizeof line,hd);
  snprintf(text,sizeof text,"slot %u %s",(unsigned)hd->slot,line);
  c->h.log(c->h.arg,(int64_t)hd->timestamp_us * 1000,text);
}
static void on_data_usbd(void *arg,struct dmr_usbd const *u){
  struct dmr_chan * const c = arg;
  if(c->h.data != NULL){
    char line[DMR_DATA_DESCRIBE_MAX],text[DMR_DATA_DESCRIBE_MAX + 16];
    dmr_usbd_describe(line,sizeof line,u);
    snprintf(text,sizeof text,"slot %u DATA %s",(unsigned)u->slot,line);
    c->h.data(c->h.arg,(int64_t)u->timestamp_us * 1000,text);
  }
  if(c->h.single_block != NULL)
    c->h.single_block(c->h.arg,u);
}

// A data burst of another colour code than the one the sink requires
static bool foreign_color_code(struct dmr_chan const *c,struct dmr_burst const *b){
  int const required = dmr_sink_color_code(dmr_rx_sink(c->rx));
  return b->kind == DMR_KIND_DATA && b->slot_type_valid && required >= 0 && (b->color_code & 0xf) != required;
}

static void note_family(struct dmr_chan *c,enum dmr_sync sync);

static void on_burst(void *arg,struct dmr_burst const *from_sink){
  struct dmr_chan * const c = arg;
  struct dmr_burst burst = *from_sink;
  burst.timestamp_us = time_of_symbol(c,burst.dibit_clock);
  if(burst.timestamp_us > c->last_burst_us)
    c->last_burst_us = burst.timestamp_us;
  c->stats.bursts++;
  if(burst.sync != DMR_SYNC_NONE){
    c->stats.syncs++;
    if(c->auto_stations && c->family == DMR_STATION_UNKNOWN)
      note_family(c,burst.sync);
  }
  if(dmr_is_voice(burst.kind))
    c->stats.voice_bursts++;

  dmr_call_on_time(&c->tracker,&c->channel,burst.timestamp_us);
  struct dmr_burst_messages m;
  dmr_msg_decode(&c->msg,&m,&burst);
  int const slot = burst.slot <= 2 ? burst.slot : 0;
  if(m.has_talker_alias){
    strlcpy(c->alias[slot],m.talker_alias.text,sizeof c->alias[slot]);
    if(c->h.log != NULL){
      char text[160];
      snprintf(text,sizeof text,"slot %d talker alias \"%s\"",slot,m.talker_alias.text);
      c->h.log(c->h.arg,(int64_t)burst.timestamp_us * 1000,text);
    }
  }
  bool const foreign = foreign_color_code(c,&burst);
  if(c->data != NULL && !foreign){ // another system's data is not this channel's packets
    dmr_data_on_burst(c->data,&burst,&m);
    c->data_last_us = burst.timestamp_us;
  }
  if(!foreign)
    dmr_call_on_burst(&c->tracker,&c->channel,&burst,&m);
  else {
    // As a data burst that did not decode: it ends a transmission, and says nothing
    struct dmr_burst undecoded = burst;
    undecoded.slot_type_valid = false;
    struct dmr_burst_messages nothing;
    memset(&nothing,0,sizeof nothing);
    nothing.slot = m.slot;
    nothing.superframe_position = -1;
    dmr_call_on_burst(&c->tracker,&c->channel,&undecoded,&nothing);
  }
  // The control plane sees it as the sink framed it (it counts and logs another colour code itself)
  if(c->cplane != NULL)
    dmr_cplane_burst(c->cplane,&burst,&m);
}

static void on_acquired(void *arg){
  struct dmr_chan * const c = arg;
  c->stats.acquisitions++;
}

static void on_lost(void *arg){
  struct dmr_chan * const c = arg;
  if(c->flushing)
    return; // the sink's reset at the end is not a sync loss
  dmr_msg_reset(&c->msg);
  if(c->data != NULL)
    dmr_data_sync_lost(c->data);
  if(c->cplane != NULL)
    dmr_cplane_sync_lost(c->cplane);
  dmr_call_on_sync_lost(&c->tracker,&c->channel,time_of_symbol(c,c->symbol_index));
}

static void on_voice(void *arg,char const *system,char const *site,struct dmr_voice_record const *r){
  (void)system;
  (void)site;
  struct dmr_chan * const c = arg;
  struct dmr_chan_frame f;
  memset(&f,0,sizeof f);
  f.slot = dmr_voice_record_slot(r);
  if(!dmr_voice_record_encrypted(r)){
    f.label = DMR_CHAN_CLEAR;
    c->stats.frames_clear++;
  } else if(r->flags & DMR_VF_UNCONFIRMED){
    f.label = DMR_CHAN_UNCONFIRMED;
    c->stats.frames_unconfirmed++;
  } else {
    f.label = DMR_CHAN_ENCRYPTED;
    c->stats.frames_encrypted++;
  }
  f.when = (int64_t)r->timestamp_us * 1000;
  for(int i=0; i < DMR_VOICE_FRAME_BITS; i++)
    f.bits[i] = (r->voice[i / 8] >> (7 - i % 8)) & 1;
  f.group = (r->flags & DMR_VF_CALL_TYPE_MASK) == DMR_VF_CALL_GROUP;
  f.destination = r->destination_id;
  f.source = r->source_id;
  f.color_code = r->color_code;
  f.emergency = (r->flags & DMR_VF_EMERGENCY) != 0;
  if(f.slot <= 2)
    strlcpy(f.alias,c->alias[f.slot],sizeof f.alias);
  if(c->h.frame != NULL)
    c->h.frame(c->h.arg,&f);
}

static char const *label_name(struct dmr_call_info const *info){
  switch(info->encryption){
  case DMR_ENC_CLEAR: // frames that only looked like noise, and none clear: say so
    return info->frames_clear == 0 && info->frames_unconfirmed > 0 ? "unconfirmed" : "clear";
  case DMR_ENC_ENCRYPTED:
    return info->encryption_confirmed ? "encrypted" : "encrypted (unconfirmed)";
  default:
    return "unconfirmed";
  }
}

static void event(struct dmr_chan *c,struct dmr_call_meta const *meta,struct dmr_call_info const *info,bool start){
  if(c->h.event == NULL)
    return;
  struct dmr_chan_event e;
  memset(&e,0,sizeof e);
  e.slot = info->slot;
  e.start = start;
  e.when = (int64_t)(start ? meta->start_timestamp_us : meta->end_timestamp_us) * 1000;
  e.group = !info->unit_to_unit;
  e.destination = meta->talkgroup_id;
  e.source = meta->source_id;
  e.color_code = info->color_code;
  e.how = start ? dmr_call_start_name(info->started_by) : dmr_call_end_name(info->ended_by);
  e.label = label_name(info);
  e.frames = (int)meta->frame_count;
  c->h.event(c->h.arg,&e);
}

static void on_call_start(void *arg,struct dmr_call_meta const *meta,struct dmr_call_info const *info){
  struct dmr_chan * const c = arg;
  if(info->slot <= 2)
    c->alias[info->slot][0] = '\0'; // a new transmission's alias comes with it
  event(c,meta,info,true);
}

static void on_call_end(void *arg,struct dmr_call_meta const *meta,struct dmr_call_info const *info){
  struct dmr_chan * const c = arg;
  if(info->ended_by == DMR_END_FADE || info->ended_by == DMR_END_NO_VOICE || info->ended_by == DMR_END_RELEASE){
    dmr_msg_reset_slot(&c->msg,info->slot);
    if(c->cplane != NULL)
      dmr_cplane_reset_slot(c->cplane,info->slot);
  }
  event(c,meta,info,false);
}

// Automatic station family: one more synced burst of a family; lock to it once it leads both others by
// more than 10
static char const *family_name(enum dmr_station m){
  return m == DMR_STATION_BS ? "base station" : m == DMR_STATION_MS ? "mobile station" : m == DMR_STATION_DIRECT ? "direct mode" : "unknown";
}
static void note_family(struct dmr_chan *c,enum dmr_sync sync){
  enum dmr_station const mode = dmr_mode_of(sync);
  int const i = mode == DMR_STATION_BS ? 0 : mode == DMR_STATION_MS ? 1 : mode == DMR_STATION_DIRECT ? 2 : -1;
  if(i < 0)
    return;
  c->family_syncs[i]++;
  for(int f=0; f < 3; f++){
    uint64_t const a = c->family_syncs[f],b = c->family_syncs[(f + 1) % 3],d = c->family_syncs[(f + 2) % 3];
    if(a > b + 10 && a > d + 10){
      c->family = f == 0 ? DMR_STATION_BS : f == 1 ? DMR_STATION_MS : DMR_STATION_DIRECT;
      dmr_rx_restrict_family(c->rx,c->family);
      if(c->h.notice != NULL){
        char text[160];
        snprintf(text,sizeof text,"stations auto: %s (synced bursts bs %llu ms %llu direct %llu); the other families are no longer looked for",
                 family_name(c->family),(unsigned long long)c->family_syncs[0],(unsigned long long)c->family_syncs[1],
                 (unsigned long long)c->family_syncs[2]);
        c->h.notice(c->h.arg,c->anchored ? (int64_t)time_of_symbol(c,c->symbol_index) * 1000 : 0,text);
      }
      return;
    }
  }
}

// A CRC residual accepted for the first time (learn_crc_masks): worth a line whatever the verbosity
static void on_learned(void *arg,enum dmr_crc_check kind,uint8_t opcode,uint8_t fid,uint32_t residual){
  struct dmr_chan *c = arg;
  if(c->h.notice == NULL)
    return;
  char text[160];
  snprintf(text,sizeof text,"CRC mask learned: %s %s %u FID 0x%02X residual 0x%0*X, accepted from now on (an LC so accepted never says clear)",
           dmr_crc_check_name(kind),kind == DMR_CRC_CHECK_CSBK ? "CSBKO" : "FLCO",(unsigned)opcode,(unsigned)fid,
           kind == DMR_CRC_CHECK_RS129 ? 6 : kind == DMR_CRC_CHECK_CSBK ? 4 : 2,(unsigned)residual);
  c->h.notice(c->h.arg,c->anchored ? (int64_t)time_of_symbol(c,c->symbol_index) * 1000 : 0,text);
}

struct dmr_chan *dmr_chan_create(struct dmr_chan_config const *config,double samprate,struct dmr_chan_handlers const *h){
  assert(config != NULL && h != NULL);
  struct dmr_chan *c = calloc(1,sizeof *c);
  if(c == NULL)
    return NULL;
  c->h = *h;
  c->samprate = samprate;
  struct dmr_rx_config rc;
  dmr_rx_config_defaults(&rc);
  rc.samprate = samprate;
  rc.sink.base_station = config->base_station;
  rc.sink.mobile_station = config->mobile_station;
  rc.sink.direct = config->direct;
  c->auto_stations = config->auto_stations;
  if(config->decode_data){
    struct dmr_data_handlers const dh = {
      .arg = c,
      .on_header = on_data_header,
      .on_packet = on_data_packet,
      .on_usbd = on_data_usbd,
    };
    c->data = dmr_data_create(&dh,NULL);
  }
  if(config->color_code >= 0 && config->color_code <= 15){
    rc.sink.cc_mode = DMR_CC_PINNED;
    rc.sink.pinned_cc = (uint8_t)config->color_code;
  } else
    rc.sink.cc_mode = config->color_code == -2 ? DMR_CC_ANY : DMR_CC_TRACK;
  c->rx = create_dmr_rx(&rc);
  if(c->rx == NULL){
    FREE(c);
    return NULL;
  }
  dmr_rx_set_clock(c->rx,sink_clock,c);
  dmr_rx_set_burst_handler(c->rx,on_burst,c);
  dmr_rx_set_acquired_handler(c->rx,on_acquired,c);
  dmr_rx_set_lost_handler(c->rx,on_lost,c);
  dmr_rx_set_symbol_handler(c->rx,on_symbol,c);
  struct dmr_msg_options mo;
  dmr_msg_options_init(&mo);
  mo.learn_crc_masks = config->learn_crc_masks;
  dmr_msg_init(&c->msg,&mo);
  c->msg.learner.learned = on_learned;
  c->msg.learner.learned_arg = c;
  struct dmr_call_config cc;
  dmr_call_config_init(&cc);
  cc.compressed_talkgroups = config->compressed_talkgroups;
  dmr_call_init(&c->tracker,&cc);
  dmr_call_set_voice_sink(&c->tracker,on_voice,c);
  dmr_call_set_start_callback(&c->tracker,on_call_start,c);
  dmr_call_set_end_callback(&c->tracker,on_call_end,c);
  strlcpy(c->channel_id,config->channel_id != NULL ? config->channel_id : "dmr",sizeof c->channel_id);
  c->channel.system_name = "DMR";
  c->channel.site_name = "";
  c->channel.channel_id = c->channel_id;
  c->channel.frequency_hz = config->frequency_hz;
  c->channel.lcn = config->lcn;
  if(config->site != NULL){
    struct dmr_site_context ctx;
    memset(&ctx,0,sizeof ctx);
    strlcpy(ctx.system_name,"DMR",sizeof ctx.system_name);
    strlcpy(ctx.channel_id,c->channel_id,sizeof ctx.channel_id);
    ctx.frequency_hz = config->frequency_hz;
    ctx.lcn = config->lcn;
    ctx.user = c;
    struct dmr_cplane_options po;
    dmr_cplane_options_init(&po);
    po.learn_crc_masks = config->learn_crc_masks;
    po.learned = on_learned;
    po.learned_arg = c;
    c->cplane = dmr_cplane_create(&ctx,config->site,config->log,&po);
    c->site = config->site;
  }
  return c;
}

void dmr_chan_destroy(struct dmr_chan *c){
  if(c == NULL)
    return;
  c->flushing = true;
  dmr_rx_flush(c->rx);
  c->flushing = false;
  dmr_call_flush(&c->tracker);
  if(c->data != NULL){
    dmr_data_flush(c->data); // a packet in progress is delivered as it is
    dmr_data_destroy(c->data);
    c->data = NULL;
  }
  if(c->cplane != NULL){
    int const handle = dmr_cplane_handle(c->cplane);
    dmr_cplane_flush(c->cplane);
    dmr_cplane_destroy(c->cplane);
    dmr_site_detach_handle(c->site,handle); // what the site announces here is no longer monitored
  }
  dmr_msg_reset(&c->msg);
  dmr_call_free(&c->tracker);
  delete_dmr_rx(c->rx);
  FREE(c);
}

void dmr_chan_samples(struct dmr_chan *c,float complex const *iq,int n,int64_t when){
  if(c == NULL || n <= 0)
    return;
  if(when == 0) // the stream's clock not known yet: the block arrived just now
    when = gps_time_ns() - (int64_t)(1e9 * n / c->samprate);
  uint64_t const when_us = when > 0 ? (uint64_t)(when / 1000) : 0;
  if(!c->anchored){
    c->sample_anchor_us = when_us;
    anchor_at(c,when_us,(int64_t)dmr_rx_symbol_count(c->rx) + DMR_RX_DELAY_SYMBOLS);
  }
  // stream_us() reads this block's start during the block: good to a block (20 ms), against a 1 s limit
  c->block_us = when_us;
  c->block_start = c->samples;
  dmr_rx_samples(c->rx,iq,n); // on_burst(), on_symbol() and the tracker's callbacks run in here
  c->samples += (uint64_t)n;
  c->stats.samples += (uint64_t)n;
  if(idle(c))
    anchor_to_samples(c);
}

void dmr_chan_end_call(struct dmr_chan *c,uint8_t slot){
  if(c == NULL)
    return;
  dmr_call_end_call(&c->tracker,slot,DMR_END_RELEASE,c->anchored ? time_of_symbol(c,c->symbol_index) : 0);
}

void dmr_chan_get_stats(struct dmr_chan const *c,struct dmr_chan_stats *s){
  if(c == NULL || s == NULL)
    return;
  *s = c->stats;
  s->color_code = dmr_sink_color_code(dmr_rx_sink(c->rx));
  s->frequency_offset = dmr_rx_frequency_offset(c->rx);
  s->learned[0] = c->cplane != NULL ? dmr_cplane_learned_csbks(c->cplane) : 0;
  s->learned[1] = c->msg.learner.accepted[DMR_CRC_CHECK_RS129];
  s->learned[2] = c->msg.learner.accepted[DMR_CRC_CHECK_CRC5];
}
