// Error correction and checks for DMR (ETSI TS 102 361-1 annex B): the Hamming family, Golay(20,8),
// QR(16,7), the block product codes, RS(12,9) over GF(256), the CRCs and checksums with their data
// type masks, and the rate 3/4 trellis (see dmrfec.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dfec.h"
#include "dmrfec.h"

// Theory of operation
//
// Where the codes are. A DMR burst is 264 bits. A data burst carries 196 bits of BPTC(196,96) (or
// of the rate 3/4 trellis) in bits 0-97 and 166-263, around a 20-bit slot type in Golay(20,8) at
// 98-107 and 156-165, which is around the 48-bit sync. A voice burst B-F has, in place of the sync,
// a 16-bit EMB in QR(16,7) at 108-115 and 148-155 around 32 bits of embedded signalling at 116-147:
// one quarter of an embedded LC in BPTC(128,77), or in burst F a single-burst (32,11) word. Between
// bursts a base station sends a 24-bit CACH: a 7-bit TACT in Hamming(7,4) and 17 bits of a Short
// LC in BPTC(68,36). The checks come after the codes: CRC-CCITT on CSBKs and headers, RS(12,9) on
// a full LC, CRC-8 on a Short LC, a 5-bit checksum on an embedded LC.
//
// Soft decisions. Each bit may come with a confidence from 0 to 1. A decoder looks for the codeword
// whose disagreeing bits have the least total confidence; that total, divided by the mean
// confidence of the word, is "weighted errors": equal to the number of changed bits when all
// confidences are equal (hard decisions), and smaller when the changed bits were the doubtful
// ones. "Margin" is how much worse, in the same units, the best alternative fits. A result is
// accepted when its weighted errors are within a limit and its margin is at least 0.5. A bit with
// no information still counts 0.001, so a word of zero confidences decodes as a hard one rather
// than as a tie between all codewords.
//
// Hamming codes. Five systematic codes, each described by the parity bits each data bit
// contributes to (also that bit's syndrome; a parity bit's own syndrome is its single bit):
//   (7,4,3) and (15,11,3) are perfect: each of their 7 and 15 nonzero syndromes is one bit's, so a
//     hard decode never fails, and two errors always decode to a wrong codeword;
//   (13,9,3) and (17,12,3) are shortened: 2 of 15 and 14 of 31 nonzero syndromes are no single
//     bit's, and a word with one of those is uncorrectable;
//   (16,11,4) adds a parity bit to (15,11): the 16 single-bit syndromes have odd weight, so the 15
//     even ones, which two errors make, are detected.
// The soft decode is a Chase search: flip each of the 2^4 subsets of the four least reliable bits
// (the caller may choose 0 to 5), hard decode each result, and keep the codeword whose disagreeing
// bits weigh least. It corrects one error anywhere plus errors among the four weakest bits.
//
// Small codes by exhaustion. The TACT (16 codewords), the EMB (128), the slot type (256) and the
// single-burst code (2,048) are decoded by measuring the received word against every codeword:
// maximum likelihood, with or without confidences. Their tables are built here from the codes'
// definitions.
//   Golay(20,8,8): the Golay(24,12,8) code of dfec.c (generator x^11 + x^10 + x^6 + x^5 + x^4 +
//     x^2 + 1, plus overall parity) shortened by four data bits. golay24_decode() there is a hard
//     bounded-distance decoder; the exhaustive search here takes confidences and so corrects more
//     than three errors when they fall on doubtful bits. ETSI calls it Golay(20,8,7), the distance
//     without the parity bit.
//   QR(16,7,6): the (17,9) quadratic residue code (generator x^8 + x^5 + x^4 + x^3 + 1, a factor
//     of x^17 + 1) shortened by two data bits, plus overall parity. Do not use the 128 words of
//     sdrtrunk's EMB.java as it was at a0533156: for colour codes 8-15 they differ from this code by
//     0x0060 and, as a set, have minimum distance 4 (fixed upstream by 26a24fc6, #2645).
//   (32,11): one Hamming(16,11,4) row sent twice (its complement the second time for reverse
//     channel signalling), distance 8.
// How often a random word passes, by the limit. Hard decisions, counted (the codewords times the
// words within the limit of each, over all words); and with confidences, measured on 100,000
// words of Gaussian noise (bit = sign, confidence = |x| up to 1):
//     Golay(20,8) limit 0, 1, 2, 3:  0.024%, 0.5%, 5.2%, 33%   (256 x 1, 21, 211, 1351 of 2^20)
//                 with confidences:  0.017%, 1.4%, 11%, 42%
//     QR(16,7)    limit 0, 1, 2:     0.2%, 3.3%, 27%           (128 x 1, 17, 137 of 2^16)
//                 with confidences:  0.18%, 6.1%, 33%
//     TACT        limit 0, 1:        12.5%, 100%                (16 x 1, 8 of 2^7)
// So a burst sink confirming a weak sync with the slot type or EMB should use a limit of 0 or 1
// and also match the colour code; the full radius (3, 2) is for bursts whose framing is known.
//
// Block product codes. BPTC(196,96) is a 13 x 15 matrix whose 9 data rows are Hamming(15,11) and
// whose columns are Hamming(13,9): distance 3 x 3 = 9. BPTC(68,36) is three Hamming(17,12) rows and
// a row of column parity (distance 3 x 2 = 6); BPTC(128,77) seven Hamming(16,11,4) rows and a row of
// column parity (4 x 2 = 8). The matrices are interleaved: bit i of the matrix (row by row) is sent
// at (181 i) mod 196 (bit 0 of the 196 being the reserved bit R(3), outside the code), 4 i mod 67
// and 8 i mod 127 (the last bit of each last), so that the 68 and 128 bit codes go out column by
// column.
// They are decoded as block turbo codes (after Pyndiah, "Near-optimum decoding of product codes:
// block turbo codes", IEEE Trans. Comm. 1998), in 12 half-iterations alternating rows and columns.
// Each line is decoded by a Chase search over its four least reliable values; for each bit, the
// difference between the best codeword and the best one deciding that bit the other way is its
// new soft value, and what that adds to the received value (the extrinsic part) is passed, scaled
// by alpha (0, 0.2, 0.3, 0.5, 0.7, 0.9, 1, 1 by half-iteration), to the other direction. A bit no
// candidate contradicts gets beta (0.2, 0.4, 0.6, 0.8, 1, then 1). A parity column's extrinsic
// value is the parity of the other bits, as reliable as the least reliable of them. The decode
// stops as soon as every row and column checks. If it never does, a hard decoder is tried on the
// bits as received: for Hamming columns, single-error correction down the columns and along the
// rows until nothing changes (at most 6 passes); for parity columns, rows corrected and then, if
// the columns fail, one row rebuilt as the sum of the others, accepted within 2 (BPTC(68,36)) or
// 3 (BPTC(128,77)) bits of what was received. Last, the codeword reached is compared with its
// nearest neighbours (itself plus a lowest-weight codeword of the product code: a lowest-weight
// row codeword placed in the rows of a lowest-weight column codeword) and moved to one that fits
// the received word better, up to 16 times; how much worse the best neighbour fits is the margin.
// Any word within (distance - 1) / 2 errors of a codeword (4, 2, 3) decodes to it. The limits on
// weighted errors (11, 3, 4) matter because an iterative decoder often walks noise to some
// codeword. Measured on 100,000 words of noise, random bits / Gaussian values with confidences:
//                    reaches a codeword   accepted within the limit
//     BPTC(196,96)   25% / 23%            0 / 4     (24 / 30 bits changed on average)
//     BPTC(68,36)    42% / 64%            1 / 200
//     BPTC(128,77)   35% / 36%            0 / 11
// The limits are tight for the Short LC and embedded LC because the checks that follow are weak
// (1 wrong message in 256 and in 31 passes).
// The check after the code (CRC, RS(12,9), CRC-8, checksum) is still needed: ok alone does not
// make a message valid. This single-burst decoder decodes the whole 32 bits (sdrtrunk's at a0533156
// corrected only its first row; it now decodes both).
//
// RS(12,9). The 96 bits of a voice LC header or terminator are 12 octets: 9 of LC and 3 of parity.
// GF(256) is the polynomials over GF(2) modulo x^8 + x^4 + x^3 + x^2 + 1 (0x11D); the generator is
// (x + a)(x + a^2)(x + a^3) and octet 0 the highest power. Each parity octet is sent XORed with a
// mask naming the data type: 0x96 for a voice LC header, 0x99 for a terminator. Distance 4: one
// wrong octet is corrected, two are detected. One error e at x^p gives syndromes s1 = eX, s2 = eX^2,
// s3 = eX^3 with X = a^p, so all three are nonzero and s2^2 = s1 s3; then X = s2 / s1 and
// e = s1^2 / s2. Of random words 1 in 2^24 has zero syndromes; with the one-octet correction
// 3,061 in 2^24 decode (1 in 5,481), so a caller for which a false LC is costly can refuse
// corrections. sdrtrunk has this check inverted (valid = residual != 0) and accepts a correction
// of the first root of a two-root locator; neither is copied.
//
// CRCs. All are register divisions msb first with a zero preset (crc_remainder() in dfec.c).
// CRC-CCITT is P25's (crc_ccitt() in dfec.c, inverted) XORed with the data type's mask: 0x6969 PI
// header, 0xA5A5 CSBK, 0xAAAA MBC header, 0xCCCC data header, 0x3333 unified single block, none on
// the CRC over MBC continuation blocks. A check passes only on an exact match (sdrtrunk also
// passes a residual of 0xFFFF, which makes a mask and its complement the same; that is also why
// it has 0x9696 for the PI header, which with the complement applied would fail every one). The
// Short LC's CRC-8 (x^8 + x^2 + x + 1) is neither inverted nor masked; the embedded LC's 5-bit
// checksum is the sum of its nine octets modulo 31. Nothing here corrects bits with a CRC.
// Settled against captures (ok-dmrlib's on-air vectors) and the standard: CRC-9 over the data then
// the serial number, the serial number "the last seven bits" (TS 102 361-1 B.3.10), masked per data
// type (table B.21); CRC-32 with pairs of octets swapped, no preset, not inverted, stored least
// significant octet first (B.3.9 is ambiguous; figure B.8C and the captures decide it; DSD-FME
// agrees); CRC-7 masked with 0x7A (table B.21).
//
// Rate 3/4 trellis. 144 bits are 48 tribits and a flushing zero tribit; each, with the previous
// one as the state (starting at 0), selects a constellation point, two 4-level symbols (dibits),
// from the same table as P25's rate 3/4 trellis (Trellis_34 in dfec.c). The 98 dibits are
// interleaved as P25's are: received points 0-12 are trellis points 0, 4, .. 48, 13-24 are 1, 5,
// .. 45, 25-36 are 2, 6, .. 46 and 37-48 are 3, 7, .. 47. The metric is not P25's (phase) or
// sdrtrunk's (the Hamming distance of the bits): a dibit is a level, 01 +3, 00 +1, 10 -1, 11 -3, its
// first bit the sign and its second "outer", and reading it as another costs, by the levels moved,
// 1 step: the confidence of the one bit that differs; 2 steps: both; 3 steps (+3 to -3, which differ
// only in the sign bit): sign + 2 x outer. With no confidences that is the number of levels moved,
// which suits 4FSK better than the Hamming distance (which makes +3 to -3 as cheap as +3 to +1).
// A Viterbi decoder over the 8 states with a traceback table finds the least-cost path ending in
// state 0. The code has no check of its own: every one of the 2^144 messages is a codeword and with
// 52 redundant bits a random word is not far from one (on 100,000 noise words the path was 14.2
// level steps away on average, or 8.8 weighted with Gaussian confidences), so ok (within 5 with
// confidences, 9 without) says little: it passed 0.14% of random words and 0.55% with confidences.
// A block's CRC-9, or the packet's CRC-32, decides.

// ---------------------------------------------------------------------------
// Shared pieces

enum {
  MAX_LINE = 17,          // longest row or column of a product code
  MAX_CELLS = 13 * 15,    // largest product matrix
  CHASE_MAX = 1 << DMR_CHASE_MAX_TEST_BITS,
  TURBO_TEST_BITS = 4,
  TURBO_HALF_ITERATIONS = 12,
};
static float const Min_reliability = 1.0e-3f;
static float const Infinity = 1.0e30f;

static inline uint32_t get_field(uint8_t const *bits,int n){
  uint32_t v = 0;
  for(int i = 0; i < n; i++)
    v = (v << 1) | (bits[i] & 1);
  return v;
}
static inline void put_field(uint32_t v,int n,uint8_t *bits){
  for(int i = 0; i < n; i++)
    bits[i] = (v >> (n - 1 - i)) & 1;
}

// Confidence i as a reliability in [Min_reliability, 1]: NULL gives 1, NaN and negatives the floor
static inline float reliability(float const *confidence,int i){
  if(confidence == NULL)
    return 1.0f;
  float const c = confidence[i];
  if(!(c > Min_reliability))
    return Min_reliability;
  return c < 1.0f ? c : 1.0f;
}

// Maximum likelihood over count codewords of n bits (bit n-1 first sent); data = codeword >> data_shift
static struct dmr_soft ml_decode(uint32_t const *codewords,int count,int n,int data_shift,uint8_t const *bits,
                                 float const *confidence,float max_weighted_errors){
  float rel[32]; // by bit position in the word
  float total = 0;
  uint32_t word = 0;
  for(int i = 0; i < n; i++){
    word = (word << 1) | (bits[i] & 1);
    rel[n - 1 - i] = reliability(confidence,i);
    total += rel[n - 1 - i];
  }
  float const mean = total / (float)n;

  float best = Infinity, second = Infinity;
  int best_index = 0;
  for(int c = 0; c < count; c++){
    uint32_t diff = codewords[c] ^ word;
    float cost = 0;
    while(diff != 0){
      cost += rel[__builtin_ctz(diff)];
      diff &= diff - 1;
    }
    if(cost < best){
      second = best;
      best = cost;
      best_index = c;
    } else if(cost < second)
      second = cost;
  }
  struct dmr_soft r;
  r.codeword = codewords[best_index];
  r.data = r.codeword >> data_shift;
  r.errors = __builtin_popcount(r.codeword ^ word);
  r.weighted_errors = best / mean;
  r.margin = count > 1 ? (second - best) / mean : 0.0f;
  r.valid = r.weighted_errors <= max_weighted_errors + 1.0e-4f && r.margin >= DMR_MIN_SOFT_MARGIN;
  return r;
}

// ---------------------------------------------------------------------------
// Hamming codes
// The generator matrices of TS 102 361-1 annex B as sdrtrunk holds them (GPL-3, Dennis Sheirer,
// github.com/DSheirer/sdrtrunk: edac/Hamming13.java, Hamming15.java, Hamming16.java, Hamming17.java,
// module/decode/dmr/message/CACH.java); they agree with OP25's parity equations (GPL-3, Max H. Parke
// KA1RBI et al., op25_repeater/lib/hamming.cc, dmr_const.h). Not copied from sdrtrunk: its CACH
// table marking every TACT with LCSS = 0 invalid, and its special cases in Hamming16/17

struct dmr_hamming const Dmr_hamming_7_4 = {7, 4, {0x5, 0x7, 0x6, 0x3}};
struct dmr_hamming const Dmr_hamming_13_9 = {13, 9, {0xF, 0xE, 0x7, 0xA, 0x5, 0xB, 0xC, 0x6, 0x3}};
struct dmr_hamming const Dmr_hamming_15_11 = {15, 11, {0x9, 0xD, 0xF, 0xE, 0x7, 0xA, 0x5, 0xB, 0xC, 0x6, 0x3}};
struct dmr_hamming const Dmr_hamming_16_11 = {16, 11,
  {0x13, 0x1A, 0x1F, 0x1C, 0x0E, 0x15, 0x0B, 0x16, 0x19, 0x0D, 0x07}};
struct dmr_hamming const Dmr_hamming_17_12 = {17, 12,
  {0x1B, 0x1F, 0x1D, 0x1C, 0x0E, 0x07, 0x11, 0x1A, 0x0D, 0x14, 0x0A, 0x05}};

uint32_t dmr_hamming_parity(struct dmr_hamming const *code,uint32_t data){
  assert(code != NULL);
  uint32_t p = 0;
  for(int i = 0; i < code->k; i++){
    if((data >> (code->k - 1 - i)) & 1)
      p ^= code->contribution[i];
  }
  return p;
}
uint32_t dmr_hamming_encode_word(struct dmr_hamming const *code,uint32_t data){
  return (data << (code->n - code->k)) | dmr_hamming_parity(code,data);
}
uint32_t dmr_hamming_syndrome(struct dmr_hamming const *code,uint32_t word){
  int const r = code->n - code->k;
  return dmr_hamming_parity(code,word >> r) ^ (word & ((1u << r) - 1));
}
// The position (0 = first sent) of the single error with this syndrome, or -1
static int error_position(struct dmr_hamming const *code,uint32_t syndrome){
  if(syndrome == 0)
    return -1;
  for(int i = 0; i < code->k; i++){
    if(code->contribution[i] == syndrome)
      return i;
  }
  int const r = code->n - code->k;
  for(int j = 0; j < r; j++){
    if(syndrome == (1u << (r - 1 - j)))
      return code->k + j;
  }
  return -1;
}
int dmr_hamming_correct_word(struct dmr_hamming const *code,uint32_t *word){
  assert(code != NULL && word != NULL);
  uint32_t const s = dmr_hamming_syndrome(code,*word);
  if(s == 0)
    return 0;
  int const pos = error_position(code,s);
  if(pos < 0)
    return -1;
  *word ^= 1u << (code->n - 1 - pos);
  return 1;
}
void dmr_hamming_encode(struct dmr_hamming const *code,uint8_t *bits){
  assert(code != NULL && bits != NULL);
  put_field(dmr_hamming_parity(code,get_field(bits,code->k)),code->n - code->k,bits + code->k);
}
bool dmr_hamming_check(struct dmr_hamming const *code,uint8_t const *bits){
  assert(code != NULL && bits != NULL);
  return dmr_hamming_syndrome(code,get_field(bits,code->n)) == 0;
}
int dmr_hamming_decode(struct dmr_hamming const *code,uint8_t *bits){
  assert(code != NULL && bits != NULL);
  uint32_t word = get_field(bits,code->n);
  int const r = dmr_hamming_correct_word(code,&word);
  if(r > 0)
    put_field(word,code->n,bits);
  return r;
}

// The distinct codewords a Chase search reached, each with its weighted distance from the word
struct chase_list {
  int count;
  uint32_t word[CHASE_MAX];
  float cost[CHASE_MAX];
};
static int chase_best(struct chase_list const *list){
  int b = -1;
  for(int i = 0; i < list->count; i++){
    if(b < 0 || list->cost[i] < list->cost[b])
      b = i;
  }
  return b;
}
// Flip every subset of the test_bits least reliable bits of word (rel[i]: the bit sent i-th; ties
// to the earlier bit), hard decode each, collect the distinct codewords
static void chase_candidates(struct dmr_hamming const *code,uint32_t word,float const *rel,int test_bits,
                             struct chase_list *out){
  int const n = code->n;
  if(test_bits > DMR_CHASE_MAX_TEST_BITS)
    test_bits = DMR_CHASE_MAX_TEST_BITS;
  if(test_bits > n)
    test_bits = n;
  if(test_bits < 0)
    test_bits = 0;

  int weakest[DMR_CHASE_MAX_TEST_BITS] = {0};
  uint32_t taken = 0;
  for(int t = 0; t < test_bits; t++){
    int pick = -1;
    for(int i = 0; i < n; i++){
      if((taken >> i) & 1)
        continue;
      if(pick < 0 || rel[i] < rel[pick])
        pick = i;
    }
    weakest[t] = pick;
    taken |= 1u << pick;
  }
  out->count = 0;
  for(int pattern = 0; pattern < (1 << test_bits); pattern++){
    uint32_t candidate = word;
    for(int t = 0; t < test_bits; t++){
      if((pattern >> t) & 1)
        candidate ^= 1u << (n - 1 - weakest[t]);
    }
    if(dmr_hamming_correct_word(code,&candidate) < 0)
      continue;
    bool seen = false;
    for(int i = 0; i < out->count && !seen; i++)
      seen = out->word[i] == candidate;
    if(seen)
      continue;
    float cost = 0;
    uint32_t diff = candidate ^ word;
    while(diff != 0){
      cost += rel[n - 1 - __builtin_ctz(diff)];
      diff &= diff - 1;
    }
    out->word[out->count] = candidate;
    out->cost[out->count] = cost;
    out->count++;
  }
}

int dmr_hamming_decode_soft(struct dmr_hamming const *code,uint8_t *bits,float const *confidence,int test_bits,
                            float *soft_distance){
  assert(code != NULL && bits != NULL);
  float rel[32];
  for(int i = 0; i < code->n; i++)
    rel[i] = reliability(confidence,i);
  uint32_t const word = get_field(bits,code->n);
  struct chase_list list;
  chase_candidates(code,word,rel,confidence == NULL ? 0 : test_bits,&list);
  int const b = chase_best(&list);
  if(b < 0)
    return -1;
  int const corrected = __builtin_popcount(list.word[b] ^ word);
  if(soft_distance != NULL)
    *soft_distance = list.cost[b];
  if(corrected > 0)
    put_field(list.word[b],code->n,bits);
  return corrected;
}

// ---------------------------------------------------------------------------
// The codeword tables of the small codes, built once from their definitions

static uint32_t Tact_words[16];
static uint32_t Golay20_words[256];
static uint32_t Qr16_words[128];
static uint32_t Single_burst_words[2048];

// GF(256), x^8 + x^4 + x^3 + x^2 + 1
static uint8_t Gf_exp[510]; // a^i, repeated so a sum of two logs needs no modulo
static uint8_t Gf_log[256];
static uint8_t Rs_gen[3];   // x^3 + Rs_gen[2] x^2 + Rs_gen[1] x + Rs_gen[0]

// Rate 3/4 trellis: the dibit received k-th is dibit Trellis34_order[k] of the encoder's
static uint8_t Trellis34_order[98];

// Lowest-weight codewords of a product code: see the theory of operation
struct neighbours {
  int row_count;
  int row_weight;
  uint32_t row_word[160];       // lowest-weight row codewords, bit cols-1 = column 0
  uint8_t row_columns[160][4];  // the columns each one has set
  int col_count;
  uint32_t col_word[32];        // lowest-weight column codewords, bit rows-1 = row 0
};
struct product_code {
  int rows;
  int cols;
  struct dmr_hamming const *row_code;
  struct dmr_hamming const *col_code; // NULL: even parity columns
};
static struct product_code const Product_196 = {13, 15, &Dmr_hamming_15_11, &Dmr_hamming_13_9};
static struct product_code const Product_68 = {4, 17, &Dmr_hamming_17_12, NULL};
static struct product_code const Product_128 = {8, 16, &Dmr_hamming_16_11, NULL};
static struct neighbours Neighbours_196, Neighbours_68, Neighbours_128;

static uint32_t golay20_encode(uint32_t data8);
static uint32_t qr16_encode(uint32_t data7);

static int lowest_weight_words(struct dmr_hamming const *code,uint32_t *out,int capacity){
  int lowest = code->n + 1;
  for(uint32_t d = 1; d < (1u << code->k); d++){
    int const w = __builtin_popcount(dmr_hamming_encode_word(code,d));
    if(w < lowest)
      lowest = w;
  }
  int count = 0;
  for(uint32_t d = 1; d < (1u << code->k); d++){
    uint32_t const word = dmr_hamming_encode_word(code,d);
    if(__builtin_popcount(word) == lowest && count < capacity)
      out[count++] = word; // never full: 35, 23 and 140 row words, 22 column words
  }
  return count;
}
static void init_neighbours(struct neighbours *nb,struct product_code const *pc){
  memset(nb,0,sizeof *nb);
  nb->row_count = lowest_weight_words(pc->row_code,nb->row_word,160);
  nb->row_weight = __builtin_popcount(nb->row_word[0]);
  assert(nb->row_weight <= 4);
  for(int a = 0; a < nb->row_count; a++){
    int k = 0;
    for(int c = 0; c < pc->cols && k < 4; c++){
      if((nb->row_word[a] >> (pc->cols - 1 - c)) & 1)
        nb->row_columns[a][k++] = c;
    }
  }
  if(pc->col_code != NULL)
    nb->col_count = lowest_weight_words(pc->col_code,nb->col_word,32);
  else {
    for(int a = 0; a < pc->rows; a++)
      for(int b = a + 1; b < pc->rows; b++)
        nb->col_word[nb->col_count++] = (1u << a) | (1u << b);
  }
}

static void init_tables(void){
  for(uint32_t d = 0; d < 16; d++)
    Tact_words[d] = dmr_hamming_encode_word(&Dmr_hamming_7_4,d);
  for(uint32_t d = 0; d < 256; d++)
    Golay20_words[d] = golay20_encode(d);
  for(uint32_t d = 0; d < 128; d++)
    Qr16_words[d] = qr16_encode(d);
  for(uint32_t d = 0; d < 2048; d++){
    uint32_t const row = dmr_hamming_encode_word(&Dmr_hamming_16_11,d);
    Single_burst_words[d] = (row << 16) | row;
  }
  uint32_t x = 1;
  for(int i = 0; i < 255; i++){
    Gf_exp[i] = Gf_exp[i + 255] = x;
    Gf_log[x] = i;
    x <<= 1;
    if(x & 0x100)
      x ^= 0x11D;
  }
  // Generator, one root at a time; p[i] the coefficient of x^i
  uint8_t p[4] = {1, 0, 0, 0};
  for(int root = 1; root <= 3; root++){
    uint8_t const a = Gf_exp[root];
    for(int i = 3; i > 0; i--)
      p[i] = p[i-1] ^ (p[i] == 0 ? 0 : Gf_exp[Gf_log[p[i]] + Gf_log[a]]);
    p[0] = p[0] == 0 ? 0 : Gf_exp[Gf_log[p[0]] + Gf_log[a]];
  }
  Rs_gen[0] = p[0];
  Rs_gen[1] = p[1];
  Rs_gen[2] = p[2];
  for(int k = 0; k < 98; k++){
    int const j = k / 2; // received point
    int point;
    if(j < 13)
      point = 4 * j;
    else
      point = 4 * ((j - 13) % 12) + 1 + (j - 13) / 12;
    Trellis34_order[k] = 2 * point + (k & 1);
  }
  init_neighbours(&Neighbours_196,&Product_196);
  init_neighbours(&Neighbours_68,&Product_68);
  init_neighbours(&Neighbours_128,&Product_128);
}
static pthread_once_t Once = PTHREAD_ONCE_INIT;
static inline void init(void){
  pthread_once(&Once,init_tables);
}

// ---------------------------------------------------------------------------
// CACH and TACT
// Bit positions as sdrtrunk CACH.java and OP25 dmr_const.h (cach_tact_bits, cach_payload_bits)

static int const Cach_tact_bits[7] = {0, 4, 8, 12, 14, 18, 22};
static int const Cach_payload_bits[17] = {1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 15, 16, 17, 19, 20, 21, 23};

void dmr_cach_split(uint8_t const cach[24],float const confidence24[24],uint8_t tact[7],float tact_confidence[7],
                    uint8_t payload[17],float payload_confidence[17]){
  assert(cach != NULL);
  for(int i = 0; i < 7; i++){
    if(tact != NULL)
      tact[i] = cach[Cach_tact_bits[i]] & 1;
    if(tact_confidence != NULL)
      tact_confidence[i] = confidence24 != NULL ? confidence24[Cach_tact_bits[i]] : 1.0f;
  }
  for(int i = 0; i < 17; i++){
    if(payload != NULL)
      payload[i] = cach[Cach_payload_bits[i]] & 1;
    if(payload_confidence != NULL)
      payload_confidence[i] = confidence24 != NULL ? confidence24[Cach_payload_bits[i]] : 1.0f;
  }
}
void dmr_cach_join(uint8_t const tact[7],uint8_t const payload[17],uint8_t cach[24]){
  assert(tact != NULL && payload != NULL && cach != NULL);
  for(int i = 0; i < 7; i++)
    cach[Cach_tact_bits[i]] = tact[i] & 1;
  for(int i = 0; i < 17; i++)
    cach[Cach_payload_bits[i]] = payload[i] & 1;
}
uint32_t dmr_tact_encode(uint32_t data4){
  return dmr_hamming_encode_word(&Dmr_hamming_7_4,data4 & 0xf);
}
struct dmr_soft dmr_tact_decode(uint8_t const tact[7],float const confidence[7],float max_weighted_errors){
  assert(tact != NULL);
  init();
  return ml_decode(Tact_words,16,7,3,tact,confidence,max_weighted_errors);
}

// ---------------------------------------------------------------------------
// Golay(20,8,8), the slot type

static uint32_t golay20_encode(uint32_t data8){
  data8 &= 0xff;
  uint32_t rem = data8 << 11; // data x^11 modulo the Golay(23,12) generator
  for(int bit = 18; bit >= 11; bit--){
    if((rem >> bit) & 1)
      rem ^= 0xC75u << (bit - 11);
  }
  uint32_t const word19 = (data8 << 11) | rem;
  return (word19 << 1) | (__builtin_popcount(word19) & 1);
}
uint32_t dmr_golay20_encode(uint32_t data8){
  return golay20_encode(data8);
}
void dmr_golay20_encode_bits(uint32_t data8,uint8_t bits[20]){
  assert(bits != NULL);
  put_field(golay20_encode(data8),20,bits);
}
void dmr_slot_type_from_burst(uint8_t const burst[264],float const confidence264[264],uint8_t bits[20],
                              float confidence20[20]){
  assert(burst != NULL && bits != NULL);
  for(int i = 0; i < 10; i++){
    bits[i] = burst[98 + i] & 1;
    bits[10 + i] = burst[156 + i] & 1;
    if(confidence264 != NULL && confidence20 != NULL){
      confidence20[i] = confidence264[98 + i];
      confidence20[10 + i] = confidence264[156 + i];
    }
  }
}
struct dmr_soft dmr_golay20_decode(uint8_t const bits[20],float const confidence[20],float max_weighted_errors){
  assert(bits != NULL);
  init();
  return ml_decode(Golay20_words,256,20,12,bits,confidence,max_weighted_errors);
}

// ---------------------------------------------------------------------------
// QR(16,7,6), the EMB

static uint32_t qr16_encode(uint32_t data7){
  data7 &= 0x7f;
  uint32_t rem = data7 << 8; // data x^8 modulo the (15,7) generator
  for(int bit = 14; bit >= 8; bit--){
    if((rem >> bit) & 1)
      rem ^= 0x139u << (bit - 8);
  }
  uint32_t const word15 = (data7 << 8) | rem;
  return (word15 << 1) | (__builtin_popcount(word15) & 1);
}
uint32_t dmr_qr16_encode(uint32_t data7){
  return qr16_encode(data7);
}
void dmr_qr16_encode_bits(uint32_t data7,uint8_t bits[16]){
  assert(bits != NULL);
  put_field(qr16_encode(data7),16,bits);
}
void dmr_emb_from_burst(uint8_t const burst[264],float const confidence264[264],uint8_t bits[16],
                        float confidence16[16]){
  assert(burst != NULL && bits != NULL);
  for(int i = 0; i < 8; i++){
    bits[i] = burst[108 + i] & 1;
    bits[8 + i] = burst[148 + i] & 1;
    if(confidence264 != NULL && confidence16 != NULL){
      confidence16[i] = confidence264[108 + i];
      confidence16[8 + i] = confidence264[148 + i];
    }
  }
}
struct dmr_soft dmr_qr16_decode(uint8_t const bits[16],float const confidence[16],float max_weighted_errors){
  assert(bits != NULL);
  init();
  return ml_decode(Qr16_words,128,16,9,bits,confidence,max_weighted_errors);
}

// ---------------------------------------------------------------------------
// Block product codes
// Layouts and interleaves as sdrtrunk (GPL-3, module/decode/dmr/bptc/BPTC_196_96.java,
// BPTC_68_36.java, BPTC_128_77.java, BPTC_16_2.java) and OP25 (GPL-3, op25_repeater/lib/
// bptc19696.cc, dmr_cai.cc, dmr_slot.cc, dmr_bs_tx_bb_impl.cc), which agree. The decoder is not theirs.
// Soft values: positive = 0, negative = 1, magnitude = reliability

static float const Turbo_alpha[8] = {0.0f, 0.2f, 0.3f, 0.5f, 0.7f, 0.9f, 1.0f, 1.0f};
static float const Turbo_beta[8] = {0.2f, 0.4f, 0.6f, 0.8f, 1.0f, 1.0f, 1.0f, 1.0f};

static uint32_t gather(uint8_t const *m,int stride,int n){
  uint32_t w = 0;
  for(int i = 0; i < n; i++)
    w = (w << 1) | (m[i * stride] & 1);
  return w;
}
static void scatter(uint32_t w,uint8_t *m,int stride,int n){
  for(int i = 0; i < n; i++)
    m[i * stride] = (w >> (n - 1 - i)) & 1;
}
static bool product_check(struct product_code const *pc,uint8_t const *m){
  for(int r = 0; r < pc->rows; r++){
    if(dmr_hamming_syndrome(pc->row_code,gather(m + r * pc->cols,1,pc->cols)) != 0)
      return false;
  }
  for(int c = 0; c < pc->cols; c++){
    uint32_t const w = gather(m + c,pc->cols,pc->rows);
    if(pc->col_code != NULL){
      if(dmr_hamming_syndrome(pc->col_code,w) != 0)
        return false;
    } else if(__builtin_popcount(w) & 1)
      return false;
  }
  return true;
}
// Soft in, soft out decode of one Hamming line of n values stride apart: extrinsic values and
// decided bits written at the same spacing
static void hamming_siso(struct dmr_hamming const *code,float const *in,int stride,float beta,
                         float *extrinsic,uint8_t *decided){
  int const n = code->n;
  float value[MAX_LINE];
  float rel[MAX_LINE] = {0}; // initialised for gcc 14's -Wmaybe-uninitialized
  uint32_t word = 0;
  for(int i = 0; i < n; i++){
    value[i] = in[i * stride];
    rel[i] = fabsf(value[i]);
    word = (word << 1) | (value[i] < 0.0f ? 1 : 0);
  }
  struct chase_list list;
  chase_candidates(code,word,rel,TURBO_TEST_BITS,&list);
  int const b = chase_best(&list);
  if(b < 0){
    for(int i = 0; i < n; i++){
      extrinsic[i * stride] = 0;
      decided[i * stride] = (word >> (n - 1 - i)) & 1;
    }
    return;
  }
  uint32_t const best = list.word[b];
  float const best_cost = list.cost[b];
  for(int i = 0; i < n; i++){
    uint32_t const mask = 1u << (n - 1 - i);
    float const sign = (best & mask) ? -1.0f : 1.0f;
    float rival = -1.0f; // the cheapest candidate deciding this bit the other way
    for(int c = 0; c < list.count; c++){
      if(((list.word[c] ^ best) & mask) == 0)
        continue;
      if(rival < 0.0f || list.cost[c] < rival)
        rival = list.cost[c];
    }
    if(rival >= 0.0f)
      extrinsic[i * stride] = (rival - best_cost) * sign - value[i];
    else
      extrinsic[i * stride] = beta * sign;
    decided[i * stride] = (best & mask) ? 1 : 0;
  }
}
// Soft in, soft out decode of an even parity line
static void parity_siso(int n,float const *in,int stride,float *extrinsic,uint8_t *decided){
  float min1 = Infinity, min2 = Infinity;
  int min_at = -1;
  int negatives = 0;
  for(int i = 0; i < n; i++){
    float const v = in[i * stride];
    float const a = fabsf(v);
    if(v < 0.0f)
      negatives++;
    if(a < min1){
      min2 = min1;
      min1 = a;
      min_at = i;
    } else if(a < min2)
      min2 = a;
  }
  for(int i = 0; i < n; i++){
    float const v = in[i * stride];
    int const others_negative = negatives - (v < 0.0f ? 1 : 0);
    float const sign = (others_negative & 1) ? -1.0f : 1.0f;
    float const e = sign * (i == min_at ? min2 : min1);
    extrinsic[i * stride] = e;
    decided[i * stride] = (v + e) < 0.0f ? 1 : 0;
  }
}
// Iterative soft decode. channel[]: soft values with mean magnitude near 1. True, with the codeword
// in decided[], when every row and column checks
static bool product_decode_soft(struct product_code const *pc,float const *channel,uint8_t *decided){
  int const cells = pc->rows * pc->cols;
  float extrinsic[MAX_CELLS];
  float next[MAX_CELLS];
  float in[MAX_CELLS];
  for(int i = 0; i < cells; i++)
    extrinsic[i] = 0;
  for(int half = 0; half < TURBO_HALF_ITERATIONS; half++){
    float const alpha = Turbo_alpha[half < 8 ? half : 7];
    float const beta = Turbo_beta[half < 8 ? half : 7];
    for(int i = 0; i < cells; i++)
      in[i] = channel[i] + alpha * extrinsic[i];
    if((half & 1) == 0){
      for(int r = 0; r < pc->rows; r++)
        hamming_siso(pc->row_code,in + r * pc->cols,1,beta,next + r * pc->cols,decided + r * pc->cols);
    } else {
      for(int c = 0; c < pc->cols; c++){
        if(pc->col_code != NULL)
          hamming_siso(pc->col_code,in + c,pc->cols,beta,next + c,decided + c);
        else
          parity_siso(pc->rows,in + c,pc->cols,next + c,decided + c);
      }
    }
    for(int i = 0; i < cells; i++)
      extrinsic[i] = next[i];
    if(product_check(pc,decided))
      return true;
  }
  return false;
}
// Hard decode in place (see the theory of operation); true when every row and column checks
static bool product_decode_hard(struct product_code const *pc,uint8_t *m,int max_rebuild_errors){
  int const cells = pc->rows * pc->cols;
  if(pc->col_code != NULL){
    for(int pass = 0; pass < 6; pass++){
      bool changed = false;
      for(int c = 0; c < pc->cols; c++){
        uint32_t w = gather(m + c,pc->cols,pc->rows);
        if(dmr_hamming_correct_word(pc->col_code,&w) > 0){
          scatter(w,m + c,pc->cols,pc->rows);
          changed = true;
        }
      }
      for(int r = 0; r < pc->rows; r++){
        uint32_t w = gather(m + r * pc->cols,1,pc->cols);
        if(dmr_hamming_correct_word(pc->row_code,&w) > 0){
          scatter(w,m + r * pc->cols,1,pc->cols);
          changed = true;
        }
      }
      if(!changed)
        break;
    }
    return product_check(pc,m);
  }
  uint8_t received[MAX_CELLS];
  for(int i = 0; i < cells; i++)
    received[i] = m[i] & 1;
  uint32_t row[8];
  bool row_ok[8];
  assert(pc->rows <= 8);
  for(int r = 0; r < pc->rows; r++){
    row[r] = gather(m + r * pc->cols,1,pc->cols);
    row_ok[r] = dmr_hamming_correct_word(pc->row_code,&row[r]) >= 0;
    scatter(row[r],m + r * pc->cols,1,pc->cols);
  }
  if(product_check(pc,m))
    return true;

  int best_row = -1, best_distance = 0;
  uint32_t best_word = 0;
  for(int r = 0; r < pc->rows; r++){
    bool others_ok = true;
    uint32_t sum = 0;
    int distance = 0;
    for(int o = 0; o < pc->rows; o++){
      if(o == r)
        continue;
      others_ok = others_ok && row_ok[o];
      sum ^= row[o];
      distance += __builtin_popcount(row[o] ^ gather(received + o * pc->cols,1,pc->cols));
    }
    if(!others_ok)
      continue;
    distance += __builtin_popcount(sum ^ gather(received + r * pc->cols,1,pc->cols));
    if(best_row < 0 || distance < best_distance){
      best_row = r;
      best_distance = distance;
      best_word = sum;
    }
  }
  if(best_row < 0 || best_distance > max_rebuild_errors){
    for(int i = 0; i < cells; i++)
      m[i] = received[i];
    return false;
  }
  scatter(best_word,m + best_row * pc->cols,1,pc->cols);
  return product_check(pc,m);
}
// How much worse (summed reliability) the nearest neighbour of codeword[] fits received[];
// negative if one fits better, which *flip_rows / *flip_cols then name
static float neighbour_margin(struct product_code const *pc,struct neighbours const *nb,uint8_t const *codeword,
                              uint8_t const *received,float const *rel,uint32_t *flip_rows,uint32_t *flip_cols){
  float change[MAX_CELLS]; // what flipping a cell adds to the distance
  for(int i = 0; i < pc->rows * pc->cols; i++)
    change[i] = codeword[i] == received[i] ? rel[i] : -rel[i];
  float lowest = Infinity;
  for(int b = 0; b < nb->col_count; b++){
    float column_sum[MAX_LINE];
    for(int c = 0; c < pc->cols; c++)
      column_sum[c] = 0;
    for(int r = 0; r < pc->rows; r++){
      if(((nb->col_word[b] >> (pc->rows - 1 - r)) & 1) == 0)
        continue;
      for(int c = 0; c < pc->cols; c++)
        column_sum[c] += change[r * pc->cols + c];
    }
    for(int a = 0; a < nb->row_count; a++){
      float delta = 0;
      for(int k = 0; k < nb->row_weight; k++)
        delta += column_sum[nb->row_columns[a][k]];
      if(delta < lowest){
        lowest = delta;
        *flip_rows = nb->col_word[b];
        *flip_cols = nb->row_word[a];
      }
    }
  }
  return lowest;
}
// Decode a product matrix (row-major) in place: soft, then hard if that reaches no codeword, then
// toward a better-fitting neighbour. True if a codeword was reached; else bits[] is left as
// received. d gets the counts (all zero when no codeword was reached); its ok is not set here
static bool product_decode(struct dmr_bptc *d,struct product_code const *pc,struct neighbours const *nb,uint8_t *bits,
                           float const *confidence,int hard_radius){
  int const cells = pc->rows * pc->cols;
  uint8_t received[MAX_CELLS];
  float rel[MAX_CELLS];
  float channel[MAX_CELLS];
  float total = 0;
  for(int i = 0; i < cells; i++){
    received[i] = bits[i] & 1;
    rel[i] = reliability(confidence,i);
    total += rel[i];
  }
  float const mean = total / (float)cells;
  for(int i = 0; i < cells; i++)
    channel[i] = (received[i] ? -rel[i] : rel[i]) / mean;

  memset(d,0,sizeof *d);
  uint8_t candidate[MAX_CELLS];
  bool found = product_decode_soft(pc,channel,candidate);
  if(!found){
    for(int i = 0; i < cells; i++)
      candidate[i] = received[i];
    found = product_decode_hard(pc,candidate,hard_radius);
  }
  if(!found){
    for(int i = 0; i < cells; i++)
      bits[i] = received[i];
    return false;
  }
  float margin = 0;
  for(int step = 0; step < 16; step++){
    uint32_t flip_rows = 0, flip_cols = 0;
    margin = neighbour_margin(pc,nb,candidate,received,rel,&flip_rows,&flip_cols);
    if(margin >= 0.0f)
      break;
    for(int r = 0; r < pc->rows; r++){
      if(((flip_rows >> (pc->rows - 1 - r)) & 1) == 0)
        continue;
      for(int c = 0; c < pc->cols; c++){
        if((flip_cols >> (pc->cols - 1 - c)) & 1)
          candidate[r * pc->cols + c] ^= 1;
      }
    }
  }
  float cost = 0;
  for(int i = 0; i < cells; i++){
    bits[i] = candidate[i];
    if(candidate[i] != received[i]){
      d->corrected++;
      cost += rel[i];
    }
  }
  d->weighted_errors = cost / mean;
  d->margin = margin > 0.0f ? margin / mean : 0.0f;
  return true;
}
// The acceptance rule of the three product codes
static bool product_accept(struct dmr_bptc *d,bool found,float max_weighted_errors){
  d->ok = found && d->weighted_errors <= max_weighted_errors + 1.0e-4f && d->margin >= DMR_MIN_SOFT_MARGIN;
  return d->ok;
}

// BPTC(196,96)
void dmr_bptc196_from_burst(uint8_t const burst[264],float const confidence264[264],uint8_t bits[196],
                            float confidence196[196]){
  assert(burst != NULL && bits != NULL);
  for(int i = 0; i < 98; i++){
    bits[i] = burst[i] & 1;
    bits[98 + i] = burst[166 + i] & 1;
  }
  if(confidence264 != NULL && confidence196 != NULL){
    for(int i = 0; i < 98; i++){
      confidence196[i] = confidence264[i];
      confidence196[98 + i] = confidence264[166 + i];
    }
  }
}
void dmr_bptc196_to_burst(uint8_t const bits[196],uint8_t burst[264]){
  assert(bits != NULL && burst != NULL);
  for(int i = 0; i < 98; i++){
    burst[i] = bits[i] & 1;
    burst[166 + i] = bits[98 + i] & 1;
  }
}
bool dmr_bptc196_decode(struct dmr_bptc *result,uint8_t info[96],uint8_t reserved[4],uint8_t const bits[196],
                        float const confidence[196],float max_weighted_errors){
  assert(info != NULL && bits != NULL);
  init();
  // Matrix bit i was sent at (181 i) mod 196; bit 0 is R(3), the 13 x 15 matrix follows
  uint8_t m[195];
  float conf[195];
  for(int i = 1; i < 196; i++){
    int const at = (i * 181) % 196;
    m[i-1] = bits[at] & 1;
    conf[i-1] = confidence != NULL ? confidence[at] : 1.0f;
  }
  struct dmr_bptc d;
  bool const found = product_decode(&d,&Product_196,&Neighbours_196,m,confidence != NULL ? conf : NULL,4);
  product_accept(&d,found,max_weighted_errors);
  if(reserved != NULL){
    reserved[0] = bits[0] & 1;
    reserved[1] = m[0];
    reserved[2] = m[1];
    reserved[3] = m[2];
  }
  uint8_t *out = info;
  for(int c = 3; c < 11; c++)
    *out++ = m[c];
  for(int row = 1; row < 9; row++)
    for(int c = 0; c < 11; c++)
      *out++ = m[row * 15 + c];
  if(result != NULL)
    *result = d;
  return d.ok;
}
void dmr_bptc196_encode(uint8_t const info[96],uint8_t bits[196],uint8_t const reserved[4]){
  assert(info != NULL && bits != NULL);
  uint8_t m[195] = {0};
  if(reserved != NULL){
    m[0] = reserved[1] & 1;
    m[1] = reserved[2] & 1;
    m[2] = reserved[3] & 1;
  }
  int in = 0;
  for(int c = 3; c < 11; c++)
    m[c] = info[in++] & 1;
  for(int row = 1; row < 9; row++)
    for(int c = 0; c < 11; c++)
      m[row * 15 + c] = info[in++] & 1;
  for(int row = 0; row < 9; row++)
    dmr_hamming_encode(&Dmr_hamming_15_11,m + row * 15);
  for(int c = 0; c < 15; c++){
    uint32_t const parity = dmr_hamming_parity(&Dmr_hamming_13_9,gather(m + c,15,9));
    scatter(parity,m + 9 * 15 + c,15,4);
  }
  bits[0] = reserved != NULL ? (reserved[0] & 1) : 0;
  for(int i = 1; i < 196; i++)
    bits[(i * 181) % 196] = m[i-1];
}

// BPTC(68,36), Short LC: matrix bit i (row * 17 + column) was sent at 4 i mod 67, bit 67 at 67
bool dmr_bptc68_decode(struct dmr_bptc *result,uint8_t info[36],uint8_t const bits[68],float const confidence[68],
                       float max_weighted_errors){
  assert(info != NULL && bits != NULL);
  init();
  uint8_t m[68];
  float conf[68];
  for(int i = 0; i < 68; i++){
    int const at = i < 67 ? (i * 4) % 67 : 67;
    m[i] = bits[at] & 1;
    conf[i] = confidence != NULL ? confidence[at] : 1.0f;
  }
  struct dmr_bptc d;
  bool const found = product_decode(&d,&Product_68,&Neighbours_68,m,confidence != NULL ? conf : NULL,2);
  product_accept(&d,found,max_weighted_errors);
  uint8_t *out = info;
  for(int row = 0; row < 3; row++)
    for(int c = 0; c < 12; c++)
      *out++ = m[row * 17 + c];
  if(result != NULL)
    *result = d;
  return d.ok;
}
void dmr_bptc68_encode(uint8_t const info[36],uint8_t bits[68]){
  assert(info != NULL && bits != NULL);
  uint8_t m[68] = {0};
  for(int row = 0; row < 3; row++){
    for(int c = 0; c < 12; c++)
      m[row * 17 + c] = info[row * 12 + c] & 1;
    dmr_hamming_encode(&Dmr_hamming_17_12,m + row * 17);
  }
  for(int c = 0; c < 17; c++)
    m[51 + c] = m[c] ^ m[17 + c] ^ m[34 + c];
  for(int i = 0; i < 68; i++)
    bits[i < 67 ? (i * 4) % 67 : 67] = m[i];
}

// BPTC(128,77), embedded LC: matrix bit i (row * 16 + column) was sent at 8 i mod 127, bit 127 at 127.
// Rows 0-1 carry 11 LC bits, rows 2-6 10 LC bits and, in column 10, one checksum bit (msb in row 2)
void dmr_embedded_from_burst(uint8_t const burst[264],float const confidence264[264],uint8_t bits[32],
                             float confidence32[32]){
  assert(burst != NULL && bits != NULL);
  for(int i = 0; i < 32; i++){
    bits[i] = burst[116 + i] & 1;
    if(confidence264 != NULL && confidence32 != NULL)
      confidence32[i] = confidence264[116 + i];
  }
}
bool dmr_bptc128_decode(struct dmr_bptc *result,uint8_t info[77],uint8_t const bits[128],float const confidence[128],
                        float max_weighted_errors){
  assert(info != NULL && bits != NULL);
  init();
  uint8_t m[128];
  float conf[128];
  for(int i = 0; i < 128; i++){
    int const at = i < 127 ? (i * 8) % 127 : 127;
    m[i] = bits[at] & 1;
    conf[i] = confidence != NULL ? confidence[at] : 1.0f;
  }
  struct dmr_bptc d;
  bool const found = product_decode(&d,&Product_128,&Neighbours_128,m,confidence != NULL ? conf : NULL,3);
  product_accept(&d,found,max_weighted_errors);
  uint8_t *out = info;
  for(int row = 0; row < 2; row++)
    for(int c = 0; c < 11; c++)
      *out++ = m[row * 16 + c];
  for(int row = 2; row < 7; row++)
    for(int c = 0; c < 10; c++)
      *out++ = m[row * 16 + c];
  for(int row = 2; row < 7; row++)
    *out++ = m[row * 16 + 10];
  if(result != NULL)
    *result = d;
  return d.ok;
}
void dmr_bptc128_encode(uint8_t const info[77],uint8_t bits[128]){
  assert(info != NULL && bits != NULL);
  uint8_t m[128] = {0};
  int in = 0;
  for(int row = 0; row < 2; row++)
    for(int c = 0; c < 11; c++)
      m[row * 16 + c] = info[in++] & 1;
  for(int row = 2; row < 7; row++)
    for(int c = 0; c < 10; c++)
      m[row * 16 + c] = info[in++] & 1;
  for(int row = 2; row < 7; row++)
    m[row * 16 + 10] = info[in++] & 1;
  for(int row = 0; row < 7; row++)
    dmr_hamming_encode(&Dmr_hamming_16_11,m + row * 16);
  for(int c = 0; c < 16; c++){
    uint8_t parity = 0;
    for(int row = 0; row < 7; row++)
      parity ^= m[row * 16 + c];
    m[112 + c] = parity;
  }
  for(int i = 0; i < 128; i++)
    bits[i < 127 ? (i * 8) % 127 : 127] = m[i];
}

// Single-burst (32,11): where each of the 32 bits as sent goes in the 2 x 16 matrix (row * 16 +
// column). Row 0 column k is sent at 2k, row 1 column k at (2k + 17) mod 32
static int const Single_burst_place[32] = {
  0, 24, 1, 25, 2, 26, 3, 27, 4, 28, 5, 29, 6, 30, 7, 31,
  8, 16, 9, 17, 10, 18, 11, 19, 12, 20, 13, 21, 14, 22, 15, 23
};
struct dmr_soft dmr_single_burst_decode(uint8_t const bits[32],float const confidence[32],bool reverse_channel,
                                        float max_weighted_errors){
  assert(bits != NULL);
  init();
  uint8_t m[32];
  float conf[32];
  for(int i = 0; i < 32; i++){
    int const at = Single_burst_place[i];
    m[at] = bits[i] & 1;
    if(reverse_channel && at >= 16)
      m[at] ^= 1;
    conf[at] = confidence != NULL ? confidence[i] : 1.0f;
  }
  return ml_decode(Single_burst_words,2048,32,21,m,confidence != NULL ? conf : NULL,max_weighted_errors);
}
void dmr_single_burst_encode(uint32_t data11,uint8_t bits[32],bool reverse_channel){
  assert(bits != NULL);
  init();
  uint32_t word = Single_burst_words[data11 & 0x7ff];
  if(reverse_channel)
    word ^= 0xffff;
  for(int i = 0; i < 32; i++)
    bits[i] = (word >> (31 - Single_burst_place[i])) & 1;
}

// ---------------------------------------------------------------------------
// RS(12,9) over GF(256)
// Field, generator and octet order as sdrtrunk (GPL-3, edac/RS_12_9_DMR.java) and OP25 (GPL-3,
// op25_repeater/lib/dmr_slot.cc); tables computed here

static inline uint8_t gf_mul(uint8_t a,uint8_t b){
  return (a == 0 || b == 0) ? 0 : Gf_exp[Gf_log[a] + Gf_log[b]];
}
static inline uint8_t gf_div(uint8_t a,uint8_t b){ // b != 0
  return a == 0 ? 0 : Gf_exp[Gf_log[a] + 255 - Gf_log[b]];
}
void dmr_rs129_parity(uint8_t const lc[9],uint8_t parity[3]){
  assert(lc != NULL && parity != NULL);
  init();
  uint8_t r[3] = {0, 0, 0}; // r[0] the coefficient of x^2
  for(int i = 0; i < 9; i++){
    uint8_t const feedback = lc[i] ^ r[0];
    r[0] = r[1] ^ gf_mul(Rs_gen[2],feedback);
    r[1] = r[2] ^ gf_mul(Rs_gen[1],feedback);
    r[2] = gf_mul(Rs_gen[0],feedback);
  }
  parity[0] = r[0];
  parity[1] = r[1];
  parity[2] = r[2];
}
void dmr_rs129_encode(uint8_t lc[12],uint8_t mask){
  assert(lc != NULL);
  dmr_rs129_parity(lc,lc + 9);
  for(int i = 9; i < 12; i++)
    lc[i] ^= mask;
}
uint32_t dmr_rs129_observed_mask(uint8_t const lc[12]){
  assert(lc != NULL);
  uint8_t parity[3];
  dmr_rs129_parity(lc,parity);
  return ((uint32_t)(parity[0] ^ lc[9]) << 16) | ((uint32_t)(parity[1] ^ lc[10]) << 8) | (parity[2] ^ lc[11]);
}
int dmr_rs129_decode(uint8_t lc[12],uint8_t mask,bool correct,int *position,int *bit_errors){
  assert(lc != NULL);
  init();
  if(position != NULL)
    *position = -1;
  if(bit_errors != NULL)
    *bit_errors = 0;
  uint8_t c[12];
  for(int i = 0; i < 12; i++)
    c[i] = lc[i] ^ (i >= 9 ? mask : 0);
  uint8_t s[3] = {0, 0, 0}; // s[j] = c(a^(j+1))
  for(int j = 0; j < 3; j++){
    uint8_t const a = Gf_exp[j + 1];
    for(int i = 0; i < 12; i++)
      s[j] = gf_mul(s[j],a) ^ c[i];
  }
  if(s[0] == 0 && s[1] == 0 && s[2] == 0)
    return 0;
  if(!correct)
    return -1;
  if(s[0] == 0 || s[1] == 0 || s[2] == 0)
    return -1;
  if(gf_mul(s[1],s[1]) != gf_mul(s[0],s[2]))
    return -1;
  int const power = Gf_log[gf_div(s[1],s[0])];
  if(power > 11)
    return -1; // outside the shortened codeword
  uint8_t const error = gf_div(gf_mul(s[0],s[0]),s[1]);
  int const p = 11 - power;
  lc[p] ^= error;
  if(position != NULL)
    *position = p;
  if(bit_errors != NULL)
    *bit_errors = __builtin_popcount(error);
  return 1;
}
static void bits_to_octets(uint8_t const *bits,int noctets,uint8_t *octets){
  for(int i = 0; i < noctets; i++)
    octets[i] = get_field(bits + 8 * i,8);
}
void dmr_rs129_encode_bits(uint8_t bits[96],uint8_t mask){
  assert(bits != NULL);
  uint8_t lc[12];
  bits_to_octets(bits,9,lc);
  dmr_rs129_encode(lc,mask);
  for(int i = 9; i < 12; i++)
    put_field(lc[i],8,bits + 8 * i);
}
int dmr_rs129_decode_bits(uint8_t bits[96],uint8_t mask,bool correct,int *position,int *bit_errors){
  assert(bits != NULL);
  uint8_t lc[12];
  bits_to_octets(bits,12,lc);
  int p = -1;
  int const r = dmr_rs129_decode(lc,mask,correct,&p,bit_errors);
  if(r > 0)
    put_field(lc[p],8,bits + 8 * p);
  if(position != NULL)
    *position = p;
  return r;
}

// ---------------------------------------------------------------------------
// CRCs and checksums. Masks as TS 102 361-1 table B.21, the way OP25 (dmr_slot.h) and sdrtrunk
// (USBData.java for 0x3333) have them

uint16_t dmr_crc_ccitt(uint8_t const *bits,int ndata,uint16_t mask){
  return crc_ccitt(bits,ndata) ^ mask;
}
void dmr_crc_ccitt_append(uint8_t *bits,int ndata,uint16_t mask){
  put_field(dmr_crc_ccitt(bits,ndata,mask),16,bits + ndata);
}
bool dmr_crc_ccitt_check(uint8_t const *bits,int ntotal,uint16_t mask){
  assert(ntotal >= 16);
  return dmr_crc_ccitt(bits,ntotal - 16,mask) == get_field(bits + ntotal - 16,16);
}
uint16_t dmr_crc_ccitt_observed_mask(uint8_t const *bits,int ntotal){
  assert(ntotal >= 16);
  return dmr_crc_ccitt(bits,ntotal - 16,0) ^ get_field(bits + ntotal - 16,16);
}

uint8_t dmr_slc_crc(uint8_t const bits[28]){
  return crc_remainder(bits,28,0x07,8,0);
}
void dmr_slc_crc_append(uint8_t info[36]){
  put_field(dmr_slc_crc(info),8,info + 28);
}
bool dmr_slc_crc_check(uint8_t const info[36]){
  return dmr_slc_crc(info) == get_field(info + 28,8);
}

uint8_t dmr_elc_checksum(uint8_t const lc[72]){
  assert(lc != NULL);
  uint32_t sum = 0;
  for(int i = 0; i < 9; i++)
    sum += get_field(lc + 8 * i,8);
  return sum % 31;
}
void dmr_elc_checksum_append(uint8_t info[77]){
  put_field(dmr_elc_checksum(info),5,info + 72);
}
bool dmr_elc_checksum_check(uint8_t const info[77]){
  return dmr_elc_checksum(info) == get_field(info + 72,5);
}

// CRC-9 (TS 102 361-1 B.3.10): data then the serial number, inverted, masked per data type (table
// B.21); DSD-FME (dmr_dburst.c, ComputeCrc9Bit) agrees and ok-dmrlib's on-air vectors pass (the
// serial number first fails them). The serial-first order stays offered for tests
uint16_t dmr_crc9(uint8_t const *data,int ndata,uint8_t serial,uint16_t mask,bool serial_first){
  uint8_t serial_bits[7];
  put_field(serial,7,serial_bits);
  uint32_t reg;
  if(serial_first){
    reg = crc_remainder(serial_bits,7,0x059,9,0);
    reg = crc_remainder(data,ndata,0x059,9,reg);
  } else {
    reg = crc_remainder(data,ndata,0x059,9,0);
    reg = crc_remainder(serial_bits,7,0x059,9,reg);
  }
  return (reg ^ 0x1ff ^ mask) & 0x1ff;
}
// CRC-32 (TS 102 361-1 B.3.9): the octet order, which B.3.9 leaves ambiguous, as figure B.8C shows
// it, DSD-FME (ComputeCrc32Bit) does it and ok-dmrlib's on-air vectors confirm
uint32_t dmr_crc32_bits(uint8_t const *bits,int n){
  return crc_remainder(bits,n,0x04C11DB7,32,0);
}
uint32_t dmr_packet_crc32(uint8_t const *octets,int noctets){
  assert(octets != NULL || noctets == 0);
  uint32_t reg = 0;
  uint8_t bits[16];
  for(int i = 0; i + 1 < noctets; i += 2){
    put_field(octets[i+1],8,bits);
    put_field(octets[i],8,bits + 8);
    reg = crc_remainder(bits,16,0x04C11DB7,32,reg);
  }
  return reg;
}
bool dmr_packet_crc32_check(uint8_t const *octets,int noctets){
  if(noctets < 6)
    return false;
  uint8_t const *c = octets + noctets - 4;
  uint32_t const stored = (uint32_t)c[0] | ((uint32_t)c[1] << 8) | ((uint32_t)c[2] << 16) | ((uint32_t)c[3] << 24);
  return dmr_packet_crc32(octets,noctets - 4) == stored;
}
// CRC-7 (TS 102 361-1 B.3.13): polynomial and zero preset as OP25 (crc16.h crc7) and ok-dmrlib; the
// reverse channel mask 0x7A is table B.21's
uint8_t dmr_crc7(uint8_t const *bits,int n,uint8_t mask){
  return (crc_remainder(bits,n,0x27,7,0) ^ mask) & 0x7f;
}

// ---------------------------------------------------------------------------
// Rate 3/4 trellis

// The level index of a dibit: 11 (-3) 0, 10 (-1) 1, 00 (+1) 2, 01 (+3) 3
static int const Dibit_level[4] = {2, 3, 1, 0};

// The cost of taking a received dibit (bit reliabilities sign, outer) as each of the four
static void dibit_costs(unsigned received,float sign,float outer,float cost[4]){
  int const from = Dibit_level[received];
  for(unsigned d = 0; d < 4; d++){
    int const to = Dibit_level[d];
    int const steps = from > to ? from - to : to - from;
    float c = 0;
    if(steps == 1)
      c = ((received ^ d) & 2) ? sign : outer;
    else if(steps == 2)
      c = sign + outer;
    else if(steps == 3)
      c = sign + 2.0f * outer;
    cost[d] = c;
  }
}

void dmr_trellis34_encode(uint8_t const info[144],uint8_t bits[196]){
  assert(info != NULL && bits != NULL);
  init();
  uint8_t ordered[196];
  unsigned state = 0;
  for(int i = 0; i < 49; i++){
    unsigned const tribit = i < 48 ? get_field(info + 3 * i,3) : 0;
    put_field(Trellis_34[state][tribit],4,ordered + 4 * i);
    state = tribit;
  }
  for(int k = 0; k < 98; k++){
    int const d = Trellis34_order[k];
    bits[2*k] = ordered[2*d];
    bits[2*k + 1] = ordered[2*d + 1];
  }
}

bool dmr_trellis34_decode(struct dmr_trellis34 *result,uint8_t info[144],uint8_t const bits[196],
                          float const confidence[196],float max_weighted_errors){
  assert(info != NULL && bits != NULL);
  init();
  // Deinterleave into encoder order, with each dibit's costs
  uint8_t dibit[98];
  float cost[98][4];
  float total = 0;
  float least = 1.0f, most = 0.0f;
  for(int k = 0; k < 98; k++){
    int const d = Trellis34_order[k];
    unsigned const value = ((bits[2*k] & 1) << 1) | (bits[2*k + 1] & 1);
    float const sign = reliability(confidence,2*k);
    float const outer = reliability(confidence,2*k + 1);
    dibit[d] = value;
    dibit_costs(value,sign,outer,cost[d]);
    total += sign + outer;
    least = sign < least ? sign : least;
    least = outer < least ? outer : least;
    most = sign > most ? sign : most;
    most = outer > most ? outer : most;
  }
  float const mean = total / 196.0f;
  if(max_weighted_errors < 0.0f)
    max_weighted_errors = most - least < 1.0e-3f ? DMR_TRELLIS34_MAX_ERRORS_HARD : DMR_TRELLIS34_MAX_ERRORS_SOFT;

  // previous[t][s]: the state before step t on the best path into s; closeness[t][s]: how much
  // worse the runner-up into s was
  float metric[8];
  for(int s = 0; s < 8; s++)
    metric[s] = Infinity;
  metric[0] = 0;
  uint8_t previous[49][8];
  float closeness[49][8];
  for(int t = 0; t < 49; t++){
    float branch[16];
    for(unsigned p = 0; p < 16; p++)
      branch[p] = cost[2*t][p >> 2] + cost[2*t + 1][p & 3];
    int const inputs = t < 48 ? 8 : 1; // the last point carries the flushing tribit 0
    float next[8];
    for(int s = 0; s < 8; s++)
      next[s] = Infinity;
    for(int in = 0; in < inputs; in++){
      float best = Infinity, second = Infinity;
      int best_from = 0;
      for(int from = 0; from < 8; from++){
        if(metric[from] >= Infinity)
          continue;
        float const m = metric[from] + branch[Trellis_34[from][in]];
        if(m < best){
          second = best;
          best = m;
          best_from = from;
        } else if(m < second)
          second = m;
      }
      next[in] = best;
      previous[t][in] = best_from;
      closeness[t][in] = second >= Infinity ? Infinity : second - best;
    }
    for(int s = 0; s < 8; s++){
      metric[s] = next[s];
      if(s >= inputs){
        previous[t][s] = 0;
        closeness[t][s] = Infinity;
      }
    }
  }
  // Trace back from state 0
  struct dmr_trellis34 r;
  memset(&r,0,sizeof r);
  float margin = Infinity;
  int state = 0;
  for(int t = 48; t >= 0; t--){
    int const from = previous[t][state];
    if(closeness[t][state] < margin)
      margin = closeness[t][state];
    unsigned const sent = Trellis_34[from][state];
    unsigned const got = ((unsigned)dibit[2*t] << 2) | dibit[2*t + 1];
    if(sent != got){
      r.corrected_points++;
      r.bit_errors += __builtin_popcount(sent ^ got);
    }
    if(t < 48)
      put_field(state,3,info + 3 * t);
    state = from;
  }
  r.weighted_errors = metric[0] / mean;
  r.margin = margin >= Infinity ? 0.0f : margin / mean;
  r.ok = r.weighted_errors <= max_weighted_errors + 1.0e-4f;
  if(result != NULL)
    *result = r;
  return r.ok;
}
