// One DMR carrier (a repeater output, or an MS / direct mode frequency) from I/Q to labelled voice:
// receiver, burst sink, message layer and call tracker joined on the channel's thread
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRCHAN_H
#define _DMRCHAN_H 1

#include <complex.h>
#include <stdbool.h>
#include <stdint.h>

#include "dmr.h"

// What a voice frame's label says. Only DMR_CHAN_CLEAR may ever be heard
enum dmr_chan_label { DMR_CHAN_CLEAR = 0, DMR_CHAN_ENCRYPTED, DMR_CHAN_UNCONFIRMED };

// One AMBE+2 frame of a transmission, as the call tracker releases it (in order, per slot)
struct dmr_chan_frame {
  uint8_t slot;                    // 1 or 2
  enum dmr_chan_label label;
  int64_t when;                    // sender time of the frame, ns since the GPS epoch (0: not known)
  uint8_t bits[DMR_VOICE_FRAME_BITS]; // as transmitted, one per byte
  bool group;                      // a group call (else unit to unit)
  uint32_t destination;            // talkgroup or unit; 0 = not known yet
  uint32_t source;                 // 0 = not known
  uint8_t color_code;
  bool emergency;
  char alias[64];                  // the talker's alias, "" if none
};

// A transmission on one slot started or ended (for log lines and the speech stream)
struct dmr_chan_event {
  uint8_t slot;
  bool start;                      // else the end
  int64_t when;
  bool group;
  uint32_t destination;
  uint32_t source;
  uint8_t color_code;
  char const *how;                 // what started or ended it, e.g. "voice LC header", "terminator", "fade"
  char const *label;               // "clear", "encrypted", "unconfirmed"
  int frames;                      // at the end: frames in the transmission
};

struct dmr_chan_handlers {
  void (*frame)(void *arg,struct dmr_chan_frame const *f);
  void (*event)(void *arg,struct dmr_chan_event const *e);
  void (*log)(void *arg,int64_t when,char const *text); // other decoded messages worth a line (-v)
  void *arg;
};

struct dmr_chan_config {
  int color_code;                  // 0-15 pinned; -1 tracked from the first strong sync (default); -2 any
  bool base_station;               // look for base station syncs (a repeater output; default)
  bool mobile_station;             // and MS syncs
  bool direct;                     // and direct mode syncs
};
void dmr_chan_config_init(struct dmr_chan_config *c);

struct dmr_chan;
// samprate: the I/Q rate (19200 Hz: four samples a symbol)
struct dmr_chan *dmr_chan_create(struct dmr_chan_config const *config,double samprate,struct dmr_chan_handlers const *h);
void dmr_chan_destroy(struct dmr_chan *c);  // flushes: transmissions in progress end
// A block of samples whose first sample was sent at 'when' (ns since the GPS epoch; 0 if not known)
void dmr_chan_samples(struct dmr_chan *c,float complex const *iq,int n,int64_t when);

struct dmr_chan_stats {
  uint64_t samples;
  uint64_t bursts;
  uint64_t syncs;
  uint64_t acquisitions;
  uint64_t voice_bursts;
  uint64_t frames_clear;
  uint64_t frames_encrypted;
  uint64_t frames_unconfirmed;
  int color_code;                  // tracked, -1 not yet
  float frequency_offset;          // Hz, the receiver's correction
};
void dmr_chan_get_stats(struct dmr_chan const *c,struct dmr_chan_stats *s);

#endif
