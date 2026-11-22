// P25 Phase 1 receiver: IQ samples in, data units out
// One chain for C4FM and the linear simulcast modulations: level, frequency correction,
// receive lowpass, symbol timing, then the phase change over one symbol. For C4FM that
// phase change is the integral of the deviation over the symbol, i.e. the standard
// integrate-and-dump receiver; for pi/4 DQPSK it is the differential detector
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "digital.h"
#include "dfec.h"
#include "p25.h"

// Timing loop bandwidths (normalized, per symbol): wide to acquire, narrower once frame sync is
// held, and narrower again once it has been held a while. Going straight to the narrowest on the
// first lock costs data units at the start of a transmission: the timing has not finished
// settling, and the narrow loop then takes a third of a second to finish the job
static float const Acquire_bw = 0.08f;
static float const Track_bw = 0.016f;
static float const Settled_bw = 0.004f;
static float const Settle_time = 0.5f; // seconds of held frame sync before the last step
static float const Loop_damping = 1.0f;
static float const Error_gain = 0.42f;
// Symbol rate error the timing loop may integrate: transmitter plus receiver clock errors are tens of ppm
static float const Rate_limit = 0.0003f;
static int const Interp_phases = 32;
// Frequency tracking corners
static double const Afc_acquire_corner = 10.0; // Hz
static double const Afc_track_corner = 1.0;
// Receive lowpass between the frequency correction and the timing loop
static double const Rx_cutoff = 3300.0; // Hz
static double const Rx_rolloff = 0.7;
static double const Rx_span = 31.0 / 19200.0; // filter length, seconds
static double const Level_time = 1.0 / 9.6;   // seconds

// Framing
enum {
  SYNC = P25_SYNC_DIBITS,
  WINDOW = P25_SYNC_DIBITS + P25_NID_DIBITS + 1, // sync, NID and the status symbol inside the NID
  STATUS_INTERVAL = 35,   // a status symbol follows every 35 dibits
  AFTER_NID = 21,         // dibits since the last status symbol when the NID ends
  MAX_BITS = 1680,        // longest data unit payload
  LOSS_DIBITS = 2000,     // this long searching without a sync is a loss of signal
  SECOND_CHANCE_DIBITS = 4800, // 1 s
};
// Internal continuations of a data unit, beyond the 16 DUIDs
enum {
  UNIT_TSBK2 = 16,
  UNIT_TSBK3 = 17,
  UNIT_PDU_DATA = 18,
  UNIT_NONE = -1,
};
// Sync thresholds on the soft correlation (24 = perfect). Per window, on noise a correlation
// above 17 happens about 7e-8 of the time and above 10 about 1.7e-3; a true sync passes 17
// 79% of the time at 4 dB Es/N0 and passes 10 99.9% of the time. A strong sync sets the NAC;
// a weak one is taken only if its NAC is the one already known. Both need the NID to decode
static float const Strong_sync = 17.0f;
static float const Weak_sync = 10.0f;
// Timing search around a near miss: a window the framer did not accept but whose correlation
// exceeds Candidate_sync is re-sampled at nearby timing; the best is offered again above Offer_sync
static float const Candidate_sync = 8.0f;
static float const Offer_sync = 9.9f;
static float const Midpoint_sync = 10.0f;
static float const Max_retime = 0.45f; // symbols

static uint8_t const Sync_pattern[SYNC] = { 1,1,1,1,1,3,1,1,3,3,1,1,3,3,3,3,1,3,1,3,3,3,3,3 };
static float const Nominal_phase[4] = { M_PI_4, 3 * M_PI_4, -M_PI_4, -3 * M_PI_4 };

struct wdibit {
  uint8_t dibit;
  float confidence;
  float c,s; // cos and sin of the phase
};
struct nac_entry {
  uint16_t nac;
  uint32_t count;
  uint64_t last_seen;
};

struct p25p1 {
  double samprate;
  struct level level;
  struct freqtrack afc;
  struct rxfilter rxf;
  struct symsync sync;
  bool primed;
  float complex prev_symbol; // differential detector memory
  float complex *scratch;
  int scratch_len;

  // loop state driven by frame sync
  bool tracking;             // frame sync held: narrow loops, frequency from decisions
  bool settled;              // ... and held long enough for the narrowest timing loop
  uint64_t tracking_since;   // dibit clock when tracking began
  float settled_bw;
  uint64_t settle_dibits;
  int lock_changes[8];       // +1 lock, -1 unlock; applied to the timing loop after the block
  int nlock_changes;
  bool decision_directed;
  double dd_error;           // sum of (phase - nominal phase of the decision) over this block
  int dd_symbols;

  // sync window: the last WINDOW dibits, stored twice so the window is always contiguous
  struct wdibit ring[2 * WINDOW];
  int ring_pos;
  float sync_ref_c[SYNC],sync_ref_s[SYNC];
  float last_correlation;

  // data unit assembly
  bool assembling;
  int unit;                  // DUID or UNIT_*
  int status_counter;
  int expected;              // bits
  int nbits;
  int trailing;              // status symbols still to skip after the data unit
  int searched;              // dibits since the last sync, while searching
  uint16_t nac;
  bool frame_weak,frame_recovered;
  float frame_correlation;
  int tsbk_block;
  uint8_t bits[MAX_BITS];
  float confidence[MAX_BITS];
  float phase[MAX_BITS / 2];
  uint64_t dibit_clock;
  uint64_t last_tsbk_dibit;
  bool have_tsbk;
  int consecutive_syncs;
  bool crc_correction;
  struct nac_entry nacs[3];
  uint64_t nac_clock;
  bool evaluating_replacement;
  // decoded contents of the data unit being passed up
  struct p25_word word;
  struct p25_ldu ldu;
  struct p25_pdu packet;     // packet data assembler

  // timing search
  bool retime,midpoint;
  bool sync_accepted_here;
  bool pending_candidate;
  uint64_t pending_end;
  uint64_t window_end;        // timing loop output that ended the window just evaluated
  float complex last_mid;
  uint64_t last_mid_output;
  float complex mid_diff[2 * WINDOW];
  float complex mid_unit[2 * WINDOW];
  int mid_pos,mid_valid;
  float complex sync_ref[SYNC]; // e^-j(ideal phase) of each sync dibit

  struct p25p1_stats stats;
  p25_frame_handler handler;
  void *handler_arg;
  p25_dibit_tap tap;
  void *tap_arg;
};

static int unit_size(int unit){
  switch(unit){
  case P25_DUID_HDU:
    return 648 + 10;
  case P25_DUID_TDU:
    return 28;
  case P25_DUID_LDU1:
  case P25_DUID_LDU2:
    return 1568;
  case 6: // VSELP voice, obsolete
  case 9:
    return 1680;
  case P25_DUID_TDULC:
    return 308;
  case P25_DUID_TSDU:
  case P25_DUID_PDU:
  case UNIT_TSBK2:
  case UNIT_TSBK3:
  case UNIT_PDU_DATA:
    return 196;
  default:
    return -1;
  }
}
static bool unit_trailing_status(int unit){
  return unit == P25_DUID_HDU || unit == P25_DUID_TDU || unit == P25_DUID_LDU1 || unit == P25_DUID_LDU2 || unit == P25_DUID_TDULC;
}
static inline bool searching(struct p25p1 const *p){
  return !p->assembling && p->trailing == 0;
}
static inline bool sync_locked(struct p25p1 const *p){
  return p->consecutive_syncs >= 3;
}

// The NAC a channel keeps decoding: up to three, the most observed one dominant once seen three
// times; a fourth evicts the least recently seen
static void observe_nac(struct p25p1 *p,uint16_t nac){
  p->nac_clock++;
  for(int i=0; i < 3; i++){
    if(p->nacs[i].count != 0 && p->nacs[i].nac == nac){
      p->nacs[i].count++;
      p->nacs[i].last_seen = p->nac_clock;
      return;
    }
  }
  struct nac_entry *slot = &p->nacs[0];
  for(int i=0; i < 3; i++){
    if(p->nacs[i].count == 0){
      slot = &p->nacs[i];
      break;
    }
    if(p->nacs[i].last_seen < slot->last_seen)
      slot = &p->nacs[i];
  }
  slot->nac = nac;
  slot->count = 1;
  slot->last_seen = p->nac_clock;
}
static int dominant_nac(struct p25p1 const *p){
  struct nac_entry const *best = NULL;
  for(int i=0; i < 3; i++)
    if(p->nacs[i].count != 0 && (best == NULL || p->nacs[i].count > best->count))
      best = &p->nacs[i];
  return (best == NULL || best->count < 3) ? -1 : best->nac;
}

// Frame sync changes the loops: narrow on the third sync since the last loss, wide again on loss.
// The frequency corner changes at once; the timing loop's from the next block
static void sync_acquired(struct p25p1 *p){
  if(p->tracking)
    return;
  p->tracking = true;
  p->tracking_since = p->dibit_clock;
  set_freqtrack_corner(&p->afc,Afc_track_corner);
  if(p->nlock_changes < (int)(sizeof p->lock_changes / sizeof p->lock_changes[0]))
    p->lock_changes[p->nlock_changes++] = +1;
}
static void sync_lost(struct p25p1 *p){
  p->stats.sync_losses++;
  p->tracking = false;
  p->settled = false;
  set_freqtrack_corner(&p->afc,Afc_acquire_corner);
  if(p->nlock_changes < (int)(sizeof p->lock_changes / sizeof p->lock_changes[0]))
    p->lock_changes[p->nlock_changes++] = -1;
}

// Decode the NID in a window (oldest dibit first): 32 dibits after the sync, less the status
// symbol. Errors only first, then with the doubtful bit of each weak dibit erased. If that fails,
// and allow_known is set, once more with the channel's established NAC in place of the 12
// received NAC bits. Returns false if nothing decodes
static bool decode_nid(struct p25p1 *p,struct wdibit const *w,bool allow_known,int *nac,int *duid,bool *recovered){
  uint8_t bits[64];
  float conf[32];
  bool ambiguous[32];
  int n = 0;
  for(int i=SYNC; i < WINDOW; i++){
    if(i == STATUS_INTERVAL)
      continue;
    bits[2*n] = (w[i].dibit >> 1) & 1;
    bits[2*n+1] = w[i].dibit & 1;
    conf[n] = w[i].confidence;
    // Near +-90 degrees only the lsb is in doubt, near 0 / 180 only the msb
    ambiguous[n] = fabsf(w[i].s) > fabsf(w[i].c);
    n++;
  }
  *recovered = false;
  if(bch_63_16_decode_soft(bits,conf,ambiguous,BCH_NID_ERASURE_THRESHOLD) < 0){
    // Only on a channel carrying a trunking block stream (one passed its CRC within the last
    // second), and never for a re-timed window: forcing 12 bits leaves the code's whole radius
    // free to "correct" a random word's other 51
    if(!allow_known || p->evaluating_replacement)
      return false;
    if(!p->have_tsbk || p->dibit_clock - p->last_tsbk_dibit > SECOND_CHANCE_DIBITS)
      return false;
    int const known = dominant_nac(p);
    if(known < 0)
      return false;
    for(int i=0; i < 12; i++)
      bits[i] = (known >> (11 - i)) & 1;
    if(bch_63_16_decode_soft(bits,conf,ambiguous,BCH_NID_ERASURE_THRESHOLD) < 0)
      return false;
    int got = 0;
    for(int i=0; i < 12; i++)
      got = (got << 1) | bits[i];
    if(got != known)
      return false;
    // Only for data units whose payload has its own CRC: a terminator or voice unit from noise
    // would end a call or put noise into it
    int const d = bits[12] << 3 | bits[13] << 2 | bits[14] << 1 | bits[15];
    if(d != P25_DUID_TSDU && d != P25_DUID_PDU)
      return false;
    *recovered = true;
  }
  int v = 0;
  for(int i=0; i < 12; i++)
    v = (v << 1) | bits[i];
  *nac = v;
  *duid = bits[12] << 3 | bits[13] << 2 | bits[14] << 1 | bits[15];
  return true;
}
static float window_correlation(struct p25p1 const *p,struct wdibit const *w){
  float corr = 0;
  for(int i=0; i < SYNC; i++)
    corr += w[i].c * p->sync_ref_c[i] + w[i].s * p->sync_ref_s[i];
  return corr;
}
// Decide on the current sync window. Returns true if a data unit starts with the next dibit
static bool evaluate_window(struct p25p1 *p,bool is_searching){
  struct wdibit const * const w = p->ring + p->ring_pos;
  float const corr = window_correlation(p,w);
  p->last_correlation = corr;
  // Also try where the next data unit's NID would end if it followed the last one directly
  if(!(corr > Weak_sync || (is_searching && p->searched == WINDOW)))
    return false;
  int nac,duid;
  bool recovered;
  if(!decode_nid(p,w,true,&nac,&duid,&recovered)){
    p->stats.nid_failures++;
    return false;
  }
  // Never abandon a data unit in progress for one that cannot be assembled
  if(!is_searching && unit_size(duid) <= 0)
    return false;
  bool weak = false;
  if(corr > Strong_sync){
    p->stats.syncs++;
    p->nac = (uint16_t)nac;
  } else if(corr > Weak_sync && nac == p->nac){
    p->stats.weak_syncs++;
    weak = true;
  } else
    return false;
  observe_nac(p,(uint16_t)nac);
  if(recovered)
    p->stats.recovered_nids++;
  if(!is_searching){
    // A sync arrived before the data unit being assembled was complete: drop the partial one
    if(p->assembling)
      p->stats.abandoned++;
    p->assembling = false;
    p->trailing = 0;
    p25_pdu_reset(&p->packet);
  }
  if(++p->consecutive_syncs == 3)
    sync_acquired(p);
  p->unit = duid;
  p->nbits = 0;
  p->tsbk_block = 0;
  p->frame_weak = weak;
  p->frame_recovered = recovered;
  p->frame_correlation = corr;
  p->expected = unit_size(duid);
  if(p->expected > 0){
    p->assembling = true;
    p->status_counter = AFTER_NID;
  } else {
    p->assembling = false;
    p->searched = 0;
  }
  p->sync_accepted_here = true;
  return true;
}
// While searching: offer a window (oldest first), e.g. the span just evaluated sampled at other
// timing, in place of the sync window just evaluated. It must be at least a weak sync whose NID
// decodes plainly to the channel's NAC, established by a strong sync of its own: a timing search
// maximizes the correlation over many timings, so on noise it reaches the strong threshold far
// more often than one window does. If it is taken, a data unit starts with the next dibit
static bool evaluate_replacement(struct p25p1 *p,struct softdibit const *window){
  if(!searching(p) || p->stats.syncs == 0)
    return false;
  struct wdibit w[WINDOW];
  for(int i=0; i < WINDOW; i++){
    w[i].dibit = window[i].dibit;
    w[i].confidence = window[i].confidence;
    w[i].c = cosf(window[i].phase);
    w[i].s = sinf(window[i].phase);
  }
  int nac,duid;
  bool recovered;
  p->evaluating_replacement = true;
  bool const nid_ok = decode_nid(p,w,false,&nac,&duid,&recovered);
  p->evaluating_replacement = false;
  if(!nid_ok || window_correlation(p,w) <= Weak_sync || nac != p->nac || unit_size(duid) <= 0)
    return false;
  struct wdibit saved[2 * WINDOW];
  memcpy(saved,p->ring,sizeof saved);
  float const saved_correlation = p->last_correlation;
  for(int i=0; i < WINDOW; i++){
    int const r = (p->ring_pos + i) % WINDOW;
    p->ring[r] = p->ring[r + WINDOW] = w[i];
  }
  p->evaluating_replacement = true;
  bool const started = evaluate_window(p,true);
  p->evaluating_replacement = false;
  if(started)
    return true;
  memcpy(p->ring,saved,sizeof saved); // decided otherwise after all: put the window back
  p->last_correlation = saved_correlation;
  return false;
}
static void emit(struct p25p1 *p,struct p25_frame *f){
  if(p->handler == NULL)
    return;
  f->nac = p->nac;
  f->correlation = p->frame_correlation;
  f->weak_sync = p->frame_weak;
  f->recovered_nid = p->frame_recovered;
  f->dibit = p->dibit_clock;
  p->handler(p->handler_arg,f);
}
static void count_word(struct p25p1 *p,struct p25_word const *w){
  if(w->ok)
    p->stats.word_ok++;
  else
    p->stats.word_bad++;
}
// One rate 1/2 trellis block of trunking signalling: deinterleave, soft Viterbi on the received
// phases, CRC. Returns the CRC result: 0 good, 1 good after one bit, -1 bad
static int decode_block(struct p25p1 *p,uint8_t out[96]){
  float phases[98];
  p25_deinterleave_dibit_floats(phases,p->phase);
  trellis_12_decode_soft(out,phases,49);
  // No single-bit repair on a NID that was itself forced: one guess on top of another
  return crc_ccitt80_check(out,p->crc_correction && !p->frame_recovered);
}
// A complete data unit. Returns true if another block of the same data unit follows
static bool dispatch(struct p25p1 *p){
  struct p25_frame f = { .duid = p->unit, .nbits = p->nbits, .bits = p->bits, .confidence = p->confidence, .phase = p->phase };
  switch(p->unit){
  case P25_DUID_TSDU:
  case UNIT_TSBK2:
  case UNIT_TSBK3:
    {
      uint8_t block[96];
      int const crc = decode_block(p,block);
      if(crc == 0)
	p->stats.tsbk_ok++;
      else if(crc == 1)
	p->stats.tsbk_fixed++;
      else
	p->stats.tsbk_bad++;
      if(crc >= 0){
	p->last_tsbk_dibit = p->dibit_clock;
	p->have_tsbk = true;
      }
      f = (struct p25_frame){ .duid = P25_DUID_TSDU, .block = p->tsbk_block, .nbits = 96, .bits = block, .crc = crc };
      emit(p,&f);
      // The first bit of a good block says whether it is the last. A block that fails its CRC
      // does not say, so carry on: up to three blocks
      bool const last = crc >= 0 && block[0] != 0;
      if(last || p->unit == UNIT_TSBK3)
	return false;
      p->unit = p->unit == P25_DUID_TSDU ? UNIT_TSBK2 : UNIT_TSBK3;
      p->tsbk_block++;
      return true;
    }
  case P25_DUID_PDU:
  case UNIT_PDU_DATA:
    {
      // A header announcing some number of data blocks, then the blocks, all under one frame sync
      struct p25_block block;
      int r;
      if(p->unit == P25_DUID_PDU)
	r = p25_pdu_header(&p->packet,&block,p->bits,p->phase,p->crc_correction && !p->frame_recovered);
      else
	r = p25_pdu_block(&p->packet,&block,p->bits,p->phase);
      if(r == 0){
	p->unit = UNIT_PDU_DATA;
	return true;
      }
      p->stats.pdu++;
      f = (struct p25_frame){ .duid = P25_DUID_PDU, .nbits = block.nbits, .bits = block.bits, .crc = r > 0 ? block.crc : -1,
			      .pdu = r > 0 ? &p->packet : NULL };
      emit(p,&f);
      return false;
    }
  case P25_DUID_HDU:
    p->stats.hdu++;
    p25_hdu_decode(&p->word,p->bits);
    count_word(p,&p->word);
    f.word = &p->word;
    break;
  case P25_DUID_LDU1:
  case P25_DUID_LDU2:
    if(p->unit == P25_DUID_LDU1)
      p->stats.ldu1++;
    else
      p->stats.ldu2++;
    p25_ldu_decode(&p->ldu,p->unit,p->bits,p->confidence);
    count_word(p,&p->ldu.word);
    for(int i=0; i < P25_IMBE_FRAMES; i++){
      p->stats.voice_frames++;
      p->stats.voice_errors += (uint64_t)p->ldu.voice[i].total;
    }
    f.ldu = &p->ldu;
    break;
  case P25_DUID_TDU:
    p->stats.tdu++;
    break;
  case P25_DUID_TDULC:
    p->stats.tdulc++;
    p25_tdulc_decode(&p->word,p->bits);
    count_word(p,&p->word);
    f.word = &p->word;
    break;
  default:
    p->stats.other++;
    break;
  }
  emit(p,&f);
  return false;
}
// One dibit into the framer. The sync correlator sees every dibit, also while a data unit is
// being assembled: a sync whose NID decodes there ends the unit in progress (e.g. a trunking
// data unit whose last-block bit was lost) and starts the new one
static void frame_dibit(struct p25p1 *p,struct softdibit const *sd){
  p->dibit_clock++;
  p->stats.dibits++;
  bool const is_searching = searching(p);
  struct wdibit const w = { .dibit = sd->dibit, .confidence = sd->confidence, .c = cosf(sd->phase), .s = sinf(sd->phase) };
  p->ring[p->ring_pos] = p->ring[p->ring_pos + WINDOW] = w;
  if(++p->ring_pos == WINDOW)
    p->ring_pos = 0;
  if(is_searching)
    p->searched++;
  if(is_searching && p->searched >= LOSS_DIBITS){
    p->assembling = false;
    p->nbits = 0;
    p->consecutive_syncs = 0;
    p->searched = 0;
    sync_lost(p);
  }
  if(evaluate_window(p,is_searching) || is_searching)
    return;
  if(!p->assembling){
    p->trailing--; // absorbing the status symbol after a data unit
    return;
  }
  if(++p->status_counter == STATUS_INTERVAL + 1){
    p->status_counter = 0; // a status symbol: skip it
    return;
  }
  if(p->nbits + 2 <= MAX_BITS){
    p->bits[p->nbits] = (sd->dibit >> 1) & 1;
    p->bits[p->nbits + 1] = sd->dibit & 1;
    p->confidence[p->nbits] = p->confidence[p->nbits + 1] = sd->confidence;
    p->phase[p->nbits / 2] = sd->phase;
    p->nbits += 2;
  }
  if(p->nbits < p->expected)
    return;
  p->trailing = unit_trailing_status(p->unit) ? 1 : 0;
  if(dispatch(p)){
    p->nbits = 0;
    p->expected = unit_size(p->unit);
  } else {
    p->searched = 0;
    p->assembling = false;
  }
}

// ---- timing search around near-miss syncs ----

// The first 'count' dibits of the window ending at timing loop output 'window_end' (every other
// output back from it), sampled 'arms' interpolator steps later, as one-symbol differentials
static bool differentials_at(struct p25p1 const *p,uint64_t window_end,int arms,float complex *z,int count){
  if(window_end < 2 * (uint64_t)WINDOW)
    return false;
  uint64_t const first = window_end - 2 * (uint64_t)WINDOW;
  float complex previous,current;
  if(!symsync_near(&p->sync,first,arms,&previous))
    return false;
  for(int i=0; i < count; i++){
    if(!symsync_near(&p->sync,first + 2 * (uint64_t)(i + 1),arms,&current))
      return false;
    z[i] = current * conjf(previous);
    previous = current;
  }
  return true;
}
// The sync correlation (the 24 sync dibits only) at that timing
static bool sync_score(struct p25p1 const *p,uint64_t window_end,int arms,float *score){
  float complex z[SYNC];
  if(!differentials_at(p,window_end,arms,z,SYNC))
    return false;
  float sum = 0;
  for(int i=0; i < SYNC; i++){
    float const mag = cabsf(z[i]);
    if(mag > 1e-20f)
      sum += crealf(z[i] * p->sync_ref[i]) / mag;
  }
  *score = sum;
  return true;
}
static bool window_at(struct p25p1 const *p,uint64_t window_end,int arms,struct softdibit *window){
  float complex z[WINDOW];
  if(!differentials_at(p,window_end,arms,z,WINDOW))
    return false;
  for(int i=0; i < WINDOW; i++)
    window[i] = make_softdibit(z[i]);
  return true;
}
// Hill-climb of the sync correlation over timing around the window ending at 'window_end':
// from 1/8 symbol (1/16 once locked) down to one interpolator step
struct climb {
  bool ok;
  int offset; // interpolator steps, later positive
  float centre,best;
};
static struct climb climb_timing(struct p25p1 const *p,uint64_t window_end){
  struct climb c = { false, 0, 0, 0 };
  float const arms_per_symbol = symsync_arms_per_symbol(&p->sync);
  if(!sync_score(p,window_end,0,&c.centre))
    return c;
  int const max_arms = (int)(Max_retime * arms_per_symbol);
  int step = (int)(arms_per_symbol / (sync_locked(p) ? 16.0f : 8.0f));
  if(step < 1)
    step = 1;
  int offset = 0;
  float best = c.centre,left,right;
  if(!sync_score(p,window_end,-step,&left))
    left = -1e9f;
  if(!sync_score(p,window_end,step,&right))
    right = -1e9f;
  while(step >= 1){
    if(left > right && left > best && offset - step >= -max_arms){
      offset -= step;
      right = best;
      best = left;
      if(!sync_score(p,window_end,offset - step,&left))
	left = -1e9f;
    } else if(right > left && right > best && offset + step <= max_arms){
      offset += step;
      left = best;
      best = right;
      if(!sync_score(p,window_end,offset + step,&right))
	right = -1e9f;
    } else {
      step /= 2;
      if(step >= 1){
	if(!sync_score(p,window_end,offset - step,&left))
	  left = -1e9f;
	if(!sync_score(p,window_end,offset + step,&right))
	  right = -1e9f;
      }
    }
  }
  c.ok = true;
  c.offset = offset;
  c.best = best;
  return c;
}
static void nudge(struct p25p1 *p,int arms){
  nudge_symsync(&p->sync,(float)arms / symsync_arms_per_symbol(&p->sync));
}
// A window the framer did not accept but whose correlation came close: the same window at the
// best nearby timing goes to the framer's own decision; if it starts a data unit, sample there
// from now on (the resampler's phase only: not the loop's state, not the frequency)
static void retime_candidate(struct p25p1 *p,uint64_t window_end){
  if(!searching(p))
    return;
  struct climb const c = climb_timing(p,window_end);
  if(!c.ok || c.offset == 0 || c.best <= c.centre || c.best <= Offer_sync)
    return;
  struct softdibit window[WINDOW];
  if(!window_at(p,window_end,c.offset,window))
    return;
  if(!evaluate_replacement(p,window))
    return;
  p->stats.retimed++;
  nudge(p,c.offset);
}
// While searching and until frame sync is held, also correlate the timing detector's midpoints,
// half a symbol away: a sync only they see starts the data unit and slips the timing half a
// symbol onto them
static void check_midpoint_sync(struct p25p1 *p,float complex symbol){
  if(p->mid_valid < WINDOW)
    return;
  float complex const * const unit = p->mid_unit + p->mid_pos;
  float corr = 0;
  for(int i=0; i < SYNC; i++)
    corr += crealf(unit[i] * p->sync_ref[i]);
  float const threshold = p->retime ? Candidate_sync : Midpoint_sync;
  if(corr <= threshold || corr <= p->last_correlation)
    return;
  struct softdibit window[WINDOW];
  int offset = 0;
  if(p->retime){
    struct climb const c = climb_timing(p,p->last_mid_output);
    if(!c.ok || c.best <= Offer_sync || !window_at(p,p->last_mid_output,c.offset,window))
      return;
    offset = c.offset;
  } else {
    float complex const * const z = p->mid_diff + p->mid_pos;
    for(int i=0; i < WINDOW; i++)
      window[i] = make_softdibit(z[i]);
  }
  p->window_end = p->last_mid_output;
  if(!evaluate_replacement(p,window))
    return;
  // The data unit continues on the midpoints: the next midpoint is its first dibit
  p->pending_candidate = false;
  slip_symsync(&p->sync);
  p->prev_symbol = p->last_mid;
  p->last_mid = symbol; // the symbols are the midpoints now
  p->mid_valid = 0;
  p->stats.midpoint_syncs++;
  if(offset != 0)
    nudge(p,offset);
}

// ---- receive chain ----

static void on_midpoint(struct p25p1 *p,float complex y,uint64_t output){
  float complex const z = y * conjf(p->last_mid);
  float const mag = cabsf(z);
  float complex const unit = mag > 1e-20f ? z / mag : 0;
  p->mid_diff[p->mid_pos] = p->mid_diff[p->mid_pos + WINDOW] = z;
  p->mid_unit[p->mid_pos] = p->mid_unit[p->mid_pos + WINDOW] = unit;
  if(++p->mid_pos == WINDOW)
    p->mid_pos = 0;
  if(p->mid_valid < WINDOW)
    p->mid_valid++;
  p->last_mid = y;
  p->last_mid_output = output;
  // A near miss at the last symbol is re-timed now, when the samples a later timing needs are in
  if(p->pending_candidate){
    p->pending_candidate = false;
    retime_candidate(p,p->pending_end);
  }
}
// Called by the timing loop for every interpolated sample: symbols and the midpoints between them
static void sync_output(void *arg,float complex y,bool is_symbol){
  struct p25p1 * const p = arg;
  uint64_t const output = p->sync.outputs_out - 1;
  if(!is_symbol){
    on_midpoint(p,y,output);
    return;
  }
  float complex const z = y * conjf(p->prev_symbol);
  p->prev_symbol = y;
  struct softdibit const sd = make_softdibit(z);
  // Phase error against the decision: +/-45 degrees at most, so +/-600 Hz
  p->dd_error += sd.phase - Nominal_phase[sd.dibit];
  p->dd_symbols++;
  if(p->tap != NULL)
    p->tap(p->tap_arg,&sd);
  p->window_end = output;
  p->sync_accepted_here = false;
  bool const was_searching = searching(p);
  frame_dibit(p,&sd);
  if(!p->sync_accepted_here && was_searching){
    if(p->retime && p->last_correlation > Candidate_sync){
      p->pending_candidate = true;
      p->pending_end = output;
    }
    // Midpoints only while acquiring: once frame sync is held the timing is the loop's
    if(p->midpoint && !sync_locked(p))
      check_midpoint_sync(p,y);
  }
}

struct p25p1 *create_p25p1(double samprate){
  if(samprate < 4 * P25_SYMRATE) // the loops want at least 4 samples per symbol
    return NULL;
  struct p25p1 * const p = calloc(1,sizeof *p);
  if(p == NULL)
    return NULL;
  p->samprate = samprate;
  p->prev_symbol = 1;
  p->last_mid = 1;
  p->decision_directed = true;
  p->crc_correction = true;
  p->retime = true;
  p->midpoint = true;
  p->unit = UNIT_NONE;
  p->settled_bw = Settled_bw;
  p->settle_dibits = (uint64_t)(Settle_time * P25_SYMRATE);
  for(int i=0; i < SYNC; i++){
    float const ideal = Nominal_phase[Sync_pattern[i]];
    p->sync_ref_c[i] = cosf(ideal);
    p->sync_ref_s[i] = sinf(ideal);
    p->sync_ref[i] = cosf(ideal) - I * sinf(ideal);
  }
  // Start the window as if every dibit were certain, so the first few (unknown) positions
  // behave like hard decisions
  for(int i=0; i < 2 * WINDOW; i++)
    p->ring[i].confidence = 1;
  int ntaps = (int)lrint(Rx_span * samprate);
  ntaps |= 1; // odd, so the filter has a centre tap
  init_level(&p->level,samprate,Level_time);
  init_freqtrack(&p->afc,samprate,Afc_acquire_corner);
  if(init_rxfilter(&p->rxf,samprate,Rx_cutoff,ntaps,Rx_rolloff) != 0
     || init_symsync(&p->sync,samprate,P25_SYMRATE,Interp_phases,Acquire_bw,Track_bw,Loop_damping,Error_gain,Rate_limit) != 0){
    delete_p25p1(p);
    return NULL;
  }
  return p;
}
void delete_p25p1(struct p25p1 *p){
  if(p == NULL)
    return;
  free_rxfilter(&p->rxf);
  free_symsync(&p->sync);
  free(p->scratch);
  free(p);
}
void p25p1_set_frame_handler(struct p25p1 *p,p25_frame_handler handler,void *arg){
  p->handler = handler;
  p->handler_arg = arg;
}
void p25p1_set_dibit_tap(struct p25p1 *p,p25_dibit_tap tap,void *arg){
  p->tap = tap;
  p->tap_arg = arg;
}
void p25p1_set_decision_directed(struct p25p1 *p,bool enable){
  p->decision_directed = enable;
}
void p25p1_set_crc_correction(struct p25p1 *p,bool enable){
  p->crc_correction = enable;
}
void p25p1_set_sync_search(struct p25p1 *p,bool retime,bool midpoint){
  p->retime = retime;
  p->midpoint = midpoint;
}
void p25p1_set_track_bandwidth(struct p25p1 *p,float track,float settled,float settle_time){
  if(track >= 0)
    p->sync.track_bw = track;
  if(settled >= 0)
    p->settled_bw = settled;
  if(settle_time >= 0)
    p->settle_dibits = (uint64_t)(settle_time * P25_SYMRATE);
}
void p25p1_seed_frequency(struct p25p1 *p,float offset){
  seed_freqtrack(&p->afc,offset);
}
float p25p1_frequency_offset(struct p25p1 const *p){
  return p->afc.estimate;
}
void p25p1_get_stats(struct p25p1 const *p,struct p25p1_stats *stats){
  *stats = p->stats;
  stats->locked = sync_locked(p);
  stats->frequency_offset = p->afc.estimate;
  stats->timing_error = p->sync.error_ema;
}
void p25p1_dibit(struct p25p1 *p,struct softdibit const *sd){
  frame_dibit(p,sd);
}
void p25p1_samples(struct p25p1 *p,float complex const *iq,int count){
  assert(p != NULL);
  if(count <= 0)
    return;
  if(count > p->scratch_len){
    float complex * const s = realloc(p->scratch,(size_t)count * sizeof *s);
    if(s == NULL)
      return;
    p->scratch = s;
    p->scratch_len = count;
  }
  float complex * const buf = p->scratch;
  memcpy(buf,iq,(size_t)count * sizeof *buf);
  if(!p->primed){
    // From its default the level estimate would take a tenth of a second to reach a weak stream's level
    prime_level(&p->level,buf,count);
    p->primed = true;
  }
  run_level(&p->level,buf,count);
  // Frequency: correct with the estimate from the previous block, then estimate the residual.
  // Acquiring: from the lag-one products of the receive-filtered block. Unfiltered, noise away
  // from the signal pulls the estimate toward the centre of the stream; the unfiltered block still
  // supplies the coherence test and a large residual.
  // Tracking: from the decided symbols. The lag-one estimate is the mean frequency, and the mean
  // frequency of a 4-level signal moves with the data: a control channel sends more -1 and -3 than
  // +1 and +3 and reads 50 to 60 Hz low. The phase error against each decision has no such bias.
  // It is good to +/-600 Hz and repeats every 1200 Hz, so it is used only while frame sync is held
  correct_freqtrack(&p->afc,buf,count);
  measure_freqtrack(&p->afc,buf,count);
  run_rxfilter(&p->rxf,buf,count);
  float residual = 0;
  bool valid = freqtrack_residual(&p->afc,buf,count,&residual);
  bool const was_tracking = p->tracking;
  p->dd_error = 0;
  p->dd_symbols = 0;
  run_symsync(&p->sync,buf,count,sync_output,p);
  if(was_tracking && p->tracking && p->decision_directed && p->dd_symbols > 0){
    residual = (float)(p->dd_error / p->dd_symbols * P25_SYMRATE / (2 * M_PI));
    valid = true;
  }
  update_freqtrack(&p->afc,valid,residual,count);
  // The timing loop's bandwidth follows frame sync, from the next block
  for(int i=0; i < p->nlock_changes; i++){
    if(p->lock_changes[i] > 0){
      lock_symsync(&p->sync,true);
    } else {
      lock_symsync(&p->sync,false);
      reset_symsync_rate(&p->sync); // drop the rate estimate noise has walked
    }
  }
  p->nlock_changes = 0;
  if(p->tracking && !p->settled && p->sync.locked && p->dibit_clock - p->tracking_since >= p->settle_dibits){
    p->settled = true;
    set_symsync_bandwidth(&p->sync,p->settled_bw);
  }
}
