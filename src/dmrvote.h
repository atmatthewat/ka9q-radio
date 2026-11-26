// Voting between the repeaters that carry the same DMR call: one speech stream per call, each 20 ms
// frame taken from whichever repeater received it with the fewest errors
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRVOTE_H
#define _DMRVOTE_H 1

#include <stdbool.h>
#include <stdint.h>

#include "dmr.h"
#include "p25audio.h"

struct dmr_voter;
// group: the speech output (NULL: none). delay_ns: how long after its time a frame is played, so the
// other repeaters' copies of it have arrived (DMR_VOTE_DELAY). Safe to use from several threads
struct dmr_voter *dmr_voter_create(struct p25_audio_group *group,int64_t delay_ns);
void dmr_voter_destroy(struct dmr_voter *v); // ends every stream

enum { DMR_VOTE_DELAY_MS = 120 };

// What a stream did, at its end
struct dmr_vote_result {
  uint32_t ssrc;
  int frames;           // played
  int lost;             // no copy arrived in time
  int sources;          // repeater slots that contributed
  struct {
    uint32_t channel;   // channel SSRC (its label: two receivers may share one)
    uint32_t receiver;  // the receiver it came from (unique)
    int slot;
    int chosen;         // frames played from it
    int frames;         // frames it offered
    int fec;            // Golay corrections in the frames it offered
    bool aligned;
  } source[8];
};
typedef void (*dmr_vote_end_fn)(void *arg,struct dmr_vote_result const *r);
void dmr_voter_set_end_handler(struct dmr_voter *v,dmr_vote_end_fn fn,void *arg);

// One clear AMBE+2 frame (72 bits as sent, one per byte) at sender time 'when' for stream 'ssrc' from
// repeater 'channel' (its SSRC) and 'slot'. 'description' names the stream in its status (the first
// frame's is used). own_ssrc: the stream this repeater slot's frames go to instead if they turn out
// to be another conversation than the stream's (0: none, they are then dropped)
// 'receiver' tells sources apart and must be unique per receiver: two radiods on one frequency may send
// it under one SSRC. 'label' is what results call the source (its channel SSRC)
void dmr_voter_frame(struct dmr_voter *v,uint32_t ssrc,uint32_t own_ssrc,char const *description,uint32_t receiver,uint32_t label,int slot,
                     uint8_t const bits[DMR_VOICE_FRAME_BITS],int64_t when);
// That repeater slot's transmission ended (it offers no more frames to the stream)
void dmr_voter_source_end(struct dmr_voter *v,uint32_t ssrc,uint32_t receiver,int slot);
// The time now on a receiver (its signal time; 0: not known, ignored): frames now due on the streams it
// is a source of are played, and streams with nothing left end. Each stream plays by its own sources'
// receivers' times only, so a receiver whose clock is ahead takes nothing from another's stream.
// Receiver 0: a time for every stream (one clock for all: tests, replays)
void dmr_voter_poll(struct dmr_voter *v,uint32_t receiver,int64_t now);
// The signal measurements for a channel's status (see p25_audio_set_signal()): used for the stream a
// channel last contributed to
void dmr_voter_set_signal(struct dmr_voter *v,uint32_t receiver,double frequency,float bb_power,float n0,float low,float high);

#endif
