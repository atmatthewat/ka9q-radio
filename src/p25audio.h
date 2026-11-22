// Voice output for the P25 decoder: an IMBE vocoder behind a small interface, and per channel
// an RTP audio stream (8 kHz mono s16be) with the status packets radiod sends with its own streams
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _P25AUDIO_H
#define _P25AUDIO_H 1

#include <stdbool.h>
#include <stdint.h>

#include "p25p1.h"

enum {
  P25_AUDIO_SAMPRATE = 8000,
  P25_AUDIO_FRAME = 160,   // samples per IMBE frame (20 ms)
};

// What p25_vocoder_decode() did with a frame
enum p25_voice {
  P25_VOICE_SPEECH = 0,    // synthesized from the frame
  P25_VOICE_REPEAT,        // the previous frame's parameters repeated (errors, or the frame was lost)
  P25_VOICE_MUTED,         // silence: error rate too high, or too many repeats in a row
};

// Voice codecs. Phase 1 is IMBE; Phase 2's AMBE+2 is to be added behind the same calls
enum p25_codec {
  P25_CODEC_IMBE = 0,      // 88 information bits per frame (TIA-102.BABA)
};

// Vocoder. The frame repeat and muting rules of the codec's standard are applied here, from the
// error counts the channel decoder supplies; IMBE synthesis is mbelib's when built with HAVE_MBELIB
struct p25_vocoder;
char const *p25_vocoder_name(enum p25_codec codec); // e.g. "mbelib 1.3.0"; NULL when not built in
struct p25_vocoder *p25_vocoder_create(enum p25_codec codec); // NULL when not built in
void p25_vocoder_reset(struct p25_vocoder *v); // start of a transmission
// One frame: its information bits, one per byte (IMBE: u0-u7, struct p25_imbe u[]), and the errors
// its decoder corrected (IMBE: e0 in c0, total in c0-c6). bits == NULL marks a lost frame.
// Writes 160 samples at 8 kHz
enum p25_voice p25_vocoder_decode(struct p25_vocoder *v,int16_t pcm[P25_AUDIO_FRAME],uint8_t const *bits,int e0,int total);
void p25_vocoder_destroy(struct p25_vocoder *v);

// Output: one multicast destination shared by every channel, one stream (SSRC) per channel
// Data goes to port 5004 and status to 5006 of the same group, from one socket, as radiod sends them
struct p25_audio_group;
// 'target' is "group[:port][,iface]"; a name that is not a literal address is hashed into
// 239.0.0.0/8 with make_maddr() and, if service_name != NULL, advertised with avahi_start() as
// an _rtp._udp service, as radiod does. ttl 0 keeps the stream on this host. NULL on error
struct p25_audio_group *p25_audio_open(char const *target,char const *iface,int ttl,int tos,char const *service_name);
void p25_audio_close(struct p25_audio_group *g);

struct p25_audio_stats {
  uint64_t spurts;         // transmissions started
  uint64_t frames;         // IMBE frames decoded (including lost ones filled in)
  uint64_t repeats;        // of those, repeated
  uint64_t muted;          // of those, muted
  uint64_t lost;           // frames filled in for missing voice data units
  uint64_t encrypted;      // voice data units not decoded because the call is encrypted
  uint64_t units;          // voice data units decoded
  uint64_t held;           // voice data units held while their encryption was not known
  uint64_t discarded;      // held units never confirmed clear, not decoded
  uint64_t packets;        // RTP data packets sent
  uint64_t status;         // status packets sent
  uint64_t errors;         // send failures
};

// Speech decoded from an encrypted voice unit, or from one not yet known to be clear, is never
// sent. A unit is decoded only when
//  - this module has seen, in the same transmission, a header or encryption sync word that passed
//    error correction with ALGID 0x80 (clear), and nothing since saying otherwise (a header or
//    sync with another ALGID, or link control that is protected or has the service options'
//    encryption bit set, marks the rest of the transmission encrypted), and
//  - when the channel has trunking logic, that logic labelled the unit clear: at once
//    (P25_AUDIO_CLEAR) or later (P25_AUDIO_HOLD, then p25_audio_release(a,true)).
// Units waiting for either are kept (their IMBE frames copied, at most P25_AUDIO_MAX_HELD) and,
// once both allow, decoded and sent in order with their original timestamps. Held units are
// discarded if the call turns out encrypted, if the transmission ends first, or if more than
// P25_AUDIO_MAX_HELD wait (the oldest go).
enum { P25_AUDIO_MAX_HELD = 8 };
enum p25_audio_label {
  P25_AUDIO_UNLABELLED = 0, // no trunking logic on this channel: only this module's own rule applies
  P25_AUDIO_CLEAR,          // the trunking logic says clear
  P25_AUDIO_HOLD,           // the trunking logic does not know yet; see p25_audio_release()
  P25_AUDIO_ENCRYPTED,      // the trunking logic says encrypted: not decoded, nor any unit held before it
  P25_AUDIO_NONE,           // the trunking logic knows no call on this channel: not decoded
};

// One channel's stream; used only by that channel's decode thread
struct p25_audio;
struct p25_audio *p25_audio_create(struct p25_audio_group *g,uint32_t ssrc); // NULL without a vocoder
void p25_audio_destroy(struct p25_audio *a); // ends a transmission in progress
// Times ('when') are the IQ sender's clock, ns since the GPS epoch (0: not known, use our own clock).
// A transmission's first RTP timestamp is that clock at 8 kHz, so a recording lines up with the
// IQ stream; within a transmission timestamps advance 160 per frame
// Once per block of samples fed to the receiver: the channel frequency (for the status), and the
// time at the block, to end a transmission that stopped without a terminator
void p25_audio_poll(struct p25_audio *a,double frequency,int64_t when);
// Every data unit from the receiver's frame callback, 'when' being the time at its end, with the
// trunking logic's label for a voice unit (P25_AUDIO_UNLABELLED on a channel without it):
// HDU and LDUs start a transmission (marker bit) and carry the talkgroup, source and encryption;
// LDUs are decoded and sent under the rule above, lost ones (counted from frame->dibit) filled with
// repeated, then muted, frames; TDU and TDULC end the transmission
void p25_audio_unit(struct p25_audio *a,struct p25_frame const *frame,int64_t when,enum p25_audio_label label);
// The same, unlabelled
void p25_audio_frame(struct p25_audio *a,struct p25_frame const *frame,int64_t when);
// The trunking logic decided about the units it labelled P25_AUDIO_HOLD: clear (they are decoded
// once this module's own rule also allows) or not (they are discarded)
void p25_audio_release(struct p25_audio *a,bool clear);
// The trunking logic ended the call on this channel: units still held are discarded and the
// transmission ends
void p25_audio_call_end(struct p25_audio *a);
// The stream's SSRC and the description its status carries (NULL: built from the voice channel's
// own link control). A change of SSRC ends a transmission in progress
void p25_audio_set_stream(struct p25_audio *a,uint32_t ssrc,char const *description);
// Diagnostics: called with each voice unit's time and dibit position just before it goes to the vocoder
void p25_audio_set_unit_tap(struct p25_audio *a,void (*tap)(void *arg,int64_t when,uint64_t dibit),void *arg);
// Lower level: send PCM for the current transmission, starting one if needed (frames of 160)
void p25_audio_pcm(struct p25_audio *a,int16_t const *pcm,int count,int64_t when);
void p25_audio_end(struct p25_audio *a);
void p25_audio_get_stats(struct p25_audio const *a,struct p25_audio_stats *stats);

#endif
