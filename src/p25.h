// P25 receiver for a complex baseband (IQ) stream
// Phase 1 (FDMA): C4FM and the linear simulcast modulations (CQPSK/LSM) through one chain
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _P25_H
#define _P25_H 1

#include <complex.h>
#include <stdbool.h>
#include <stdint.h>

#include "digital.h"

enum {
  P25_SYMRATE = 4800,
  P25_SYNC_DIBITS = 24,
  P25_NID_DIBITS = 32,
};

// Data unit IDs as sent in the NID
enum p25_duid {
  P25_HDU = 0,    // header
  P25_TDU = 3,    // terminator
  P25_LDU1 = 5,   // voice, link control
  P25_TSDU = 7,   // trunking signalling, one to three blocks
  P25_LDU2 = 10,  // voice, encryption sync
  P25_PDU = 12,   // packet data
  P25_TDULC = 15, // terminator with link control
};

// One assembled data unit, status symbols removed. Valid only during the callback
struct p25_frame {
  int duid;             // enum p25_duid
  int block;            // TSDU: block 0-2 within the data unit
  uint16_t nac;
  float correlation;    // sync correlation of the data unit's frame sync, 24 = perfect
  bool weak_sync;       // accepted on a weak correlation because the NAC matched
  bool recovered_nid;   // NID decoded only with the channel's known NAC substituted
  int nbits;
  uint8_t const *bits;  // one bit per byte, in transmitted order.
                        // TSDU: the 96 trellis-decoded bits of one block (80 + CRC);
                        // others: the payload as received, before error correction
  float const *confidence; // per received bit, 0-1 (NULL for a decoded TSDU block)
  float const *phase;      // per received dibit, radians (NULL for a decoded TSDU block)
  int crc;              // TSDU: 0 passed, 1 passed after one bit was corrected, -1 failed
  uint64_t dibit;       // position in the dibit stream of the data unit's last dibit
};
typedef void (*p25_frame_handler)(void *arg,struct p25_frame const *frame);

struct p25p1_stats {
  uint64_t dibits;
  uint64_t syncs;        // strong frame syncs
  uint64_t weak_syncs;
  uint64_t nid_failures; // sync candidates whose NID did not decode
  uint64_t recovered_nids;
  uint64_t abandoned;    // data units cut short by a new frame sync
  uint64_t sync_losses;
  uint64_t tsbk_ok,tsbk_fixed,tsbk_bad;
  uint64_t hdu,ldu1,ldu2,tdu,tdulc,pdu,other;
  uint64_t retimed;      // frame syncs found by re-sampling a near miss at better timing
  uint64_t midpoint_syncs; // frame syncs found half a symbol away from where the loop sat
  bool locked;           // frame sync held (three syncs since the last loss)
  float frequency_offset; // Hz
  float timing_error;    // smoothed normalized timing detector output; about 0.1 on a clean signal
};

struct p25p1;

// Every soft dibit, before framing (tests and diagnostics)
typedef void (*p25_dibit_tap)(void *arg,struct softdibit const *sd);

struct p25p1 *create_p25p1(double samprate);
void delete_p25p1(struct p25p1 *p);
void p25p1_set_frame_handler(struct p25p1 *p,p25_frame_handler handler,void *arg);
void p25p1_set_dibit_tap(struct p25p1 *p,p25_dibit_tap tap,void *arg);
// Feed 'count' samples at the rate given to create_p25p1(); any block size
void p25p1_samples(struct p25p1 *p,float complex const *iq,int count);
// Feed dibits directly to the framer (tests): bypasses the receive chain
void p25p1_dibit(struct p25p1 *p,struct softdibit const *sd);
void p25p1_get_stats(struct p25p1 const *p,struct p25p1_stats *stats);
// A known carrier offset, e.g. the control channel's when a voice channel is granted
void p25p1_seed_frequency(struct p25p1 *p,float offset);
// Options, mainly for measurement; the defaults are what a decoder should use
void p25p1_set_decision_directed(struct p25p1 *p,bool enable); // frequency from decided symbols while locked
void p25p1_set_crc_correction(struct p25p1 *p,bool enable);    // single-bit correction of trunking blocks
void p25p1_set_sync_search(struct p25p1 *p,bool retime,bool midpoint); // timing search around near-miss syncs
// Timing loop bandwidths once frame sync is held: 'track' at once, 'settled' after 'settle_time'
// seconds of held sync. A negative value keeps the default
void p25p1_set_track_bandwidth(struct p25p1 *p,float track,float settled,float settle_time);
float p25p1_frequency_offset(struct p25p1 const *p); // Hz, estimated carrier offset
#endif
