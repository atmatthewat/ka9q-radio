// Voice output for the DMR decoder: AMBE+2 frames the call tracker has labelled clear, decoded to
// 8 kHz speech and sent as a ka9q-radio audio stream, one stream per call
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRAUDIO_H
#define _DMRAUDIO_H 1

#include <stdbool.h>
#include <stdint.h>

#include "dmr.h"
#include "p25audio.h"

// One stream: one SSRC on the shared output group (p25_audio_open()), used by one thread at a time
struct dmr_audio;
// NULL without a group or a vocoder
struct dmr_audio *dmr_audio_create(struct p25_audio_group *group,uint32_t ssrc);
void dmr_audio_destroy(struct dmr_audio *a);  // ends a transmission in progress

// One voice frame as transmitted (72 bits, one per byte, as the burst carries them) that the tracker
// labelled clear, at sender time 'when' (ns since the GPS epoch; 0: our clock). Frames must come in
// time order; a gap of up to Dmr_audio_max_fill is filled with lost frames (repeated, then muted, by
// the vocoder) so the speech keeps its timing, a longer one starts a new transmission
void dmr_audio_frame(struct dmr_audio *a,uint8_t const frame[DMR_VOICE_FRAME_BITS],int64_t when);
// The transmission is over (terminator, fade, an encrypted label after clear frames, end of call)
void dmr_audio_end(struct dmr_audio *a);
// The stream's SSRC and the description its status carries (e.g. "DMR TG 1 src 7525 slot 1").
// A change of SSRC ends a transmission in progress
void dmr_audio_set_stream(struct dmr_audio *a,uint32_t ssrc,char const *description);
// The channel's frequency and radiod's signal measurements for the status (see p25_audio_set_signal())
void dmr_audio_set_signal(struct dmr_audio *a,double frequency,float bb_power,float n0,float low,float high);
// The time now on the channel: ends a transmission whose next frame is more than Dmr_audio_timeout late
void dmr_audio_poll(struct dmr_audio *a,int64_t when);
bool dmr_audio_active(struct dmr_audio const *a);

struct dmr_audio_stats {
  uint64_t spurts;     // transmissions started
  uint64_t frames;     // frames decoded to speech
  uint64_t lost;       // frames filled in for missing ones
  uint64_t repeats;    // frames the vocoder repeated (errors), lost ones included
  uint64_t muted;      // frames the vocoder muted
};
void dmr_audio_get_stats(struct dmr_audio const *a,struct dmr_audio_stats *stats);

#endif
