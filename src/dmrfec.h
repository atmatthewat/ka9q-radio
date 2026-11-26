// Error correction and checks for DMR (ETSI TS 102 361-1 annex B): the Hamming family, Golay(20,8),
// QR(16,7), the block product codes BPTC(196,96), (68,36), (128,77) and the single-burst (32,11) code,
// RS(12,9) over GF(256), the CRCs and checksums with their data type masks, and the rate 3/4 trellis.
// dmrfec.c has the theory of operation
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRFEC_H
#define _DMRFEC_H 1

#include <stdbool.h>
#include <stdint.h>

// Conventions, unless stated otherwise:
// Bits are one per uint8_t (only the low bit is read), index 0 first transmitted; a field packed
// into an integer has its first transmitted bit most significant.
// A confidence array runs parallel to a bit array: float 0 (no information) to 1 (certain).
// A NULL confidence pointer means every bit is equally reliable (hard decisions).
// Decoders that take a limit ("max_weighted_errors") count errors in units of the word's mean
// confidence, which equals the plain count of changed bits when there are no confidences.

// What a soft decode of a small block code found. Every field is filled whether or not
// valid is set, so a caller can apply a stricter rule of its own
struct dmr_soft {
  uint32_t data;          // information bits of the chosen codeword
  uint32_t codeword;      // the chosen codeword
  int errors;             // received bits that disagree with it
  float weighted_errors;  // the disagreeing bits' confidences summed, over the mean confidence
  float margin;           // the runner-up's weighted_errors minus the winner's
  bool valid;             // weighted_errors <= the limit and margin >= DMR_MIN_SOFT_MARGIN
};
#define DMR_MIN_SOFT_MARGIN 0.5f

// Hamming codes, systematic: k data bits, then n - k parity bits
struct dmr_hamming {
  int n;
  int k;
  // contribution[i]: the parity bits (first sent most significant) data bit i (0 = first sent)
  // is part of, which is also the syndrome of an error in data bit i
  uint8_t contribution[12];
};
extern struct dmr_hamming const Dmr_hamming_7_4;    // CACH TACT
extern struct dmr_hamming const Dmr_hamming_13_9;   // BPTC(196,96) columns
extern struct dmr_hamming const Dmr_hamming_15_11;  // BPTC(196,96) rows
extern struct dmr_hamming const Dmr_hamming_16_11;  // embedded LC rows, single-burst code (distance 4)
extern struct dmr_hamming const Dmr_hamming_17_12;  // Short LC rows

uint32_t dmr_hamming_parity(struct dmr_hamming const *code,uint32_t data);
uint32_t dmr_hamming_encode_word(struct dmr_hamming const *code,uint32_t data); // n-bit codeword
uint32_t dmr_hamming_syndrome(struct dmr_hamming const *code,uint32_t word);
// Hard decode of an n-bit word in place: 0 clean, 1 one bit fixed, -1 uncorrectable (unchanged)
int dmr_hamming_correct_word(struct dmr_hamming const *code,uint32_t *word);
void dmr_hamming_encode(struct dmr_hamming const *code,uint8_t *bits);  // fills bits[k..n-1]
bool dmr_hamming_check(struct dmr_hamming const *code,uint8_t const *bits);
int dmr_hamming_decode(struct dmr_hamming const *code,uint8_t *bits);    // 0, 1 or -1, in place
// Soft (Chase) decode in place: of the codewords reached by flipping each subset of the test_bits
// (at most 5) least reliable bits and hard decoding, the one whose disagreeing bits have the least
// total confidence. Returns the bits changed, or -1 (bits unchanged). *soft_distance (may be NULL)
// gets the changed bits' confidences summed. NULL confidence gives the hard decode
enum { DMR_CHASE_TEST_BITS = 4, DMR_CHASE_MAX_TEST_BITS = 5 };
int dmr_hamming_decode_soft(struct dmr_hamming const *code,uint8_t *bits,float const *confidence,
                            int test_bits,float *soft_distance);

// CACH: 7 TACT bits and a 17-bit Short LC fragment interleaved in 24 bits. Any pointer but cach
// may be NULL; a NULL confidence24 gives confidences of 1
void dmr_cach_split(uint8_t const cach[24],float const confidence24[24],uint8_t tact[7],float tact_confidence[7],
                    uint8_t payload[17],float payload_confidence[17]);
void dmr_cach_join(uint8_t const tact[7],uint8_t const payload[17],uint8_t cach[24]);
// TACT: data = AT (8), TC (4), LCSS (3), in Hamming(7,4). Soft maximum likelihood decode; the code
// is perfect, so as a sync check pass max_weighted_errors = 0 (1 random word in 8 passes)
uint32_t dmr_tact_encode(uint32_t data4);
#define DMR_TACT_MAX_ERRORS 1.0f
struct dmr_soft dmr_tact_decode(uint8_t const tact[7],float const confidence[7],float max_weighted_errors);

// Slot type of a data burst: data = (colour code << 4) | data type, in Golay(20,8,8);
// sent at burst bits 98-107 and 156-165
uint32_t dmr_golay20_encode(uint32_t data8);
void dmr_golay20_encode_bits(uint32_t data8,uint8_t bits[20]);
void dmr_slot_type_from_burst(uint8_t const burst[264],float const confidence264[264],uint8_t bits[20],
                              float confidence20[20]);
#define DMR_GOLAY20_MAX_ERRORS 3.0f
struct dmr_soft dmr_golay20_decode(uint8_t const bits[20],float const confidence[20],float max_weighted_errors);

// EMB of voice bursts B-F: data = (colour code << 3) | (PI << 2) | LCSS, in QR(16,7,6)
// (PI is ETSI's pre-emption and power control indicator, not a privacy flag: PI = 1, the embedded field
// carries reverse channel information for the other logical channel);
// sent at burst bits 108-115 and 148-155
uint32_t dmr_qr16_encode(uint32_t data7);
void dmr_qr16_encode_bits(uint32_t data7,uint8_t bits[16]);
void dmr_emb_from_burst(uint8_t const burst[264],float const confidence264[264],uint8_t bits[16],
                        float confidence16[16]);
#define DMR_QR16_MAX_ERRORS 2.0f
struct dmr_soft dmr_qr16_decode(uint8_t const bits[16],float const confidence[16],float max_weighted_errors);

// Result of a block product code decode: BPTC(196,96), (68,36), (128,77)
struct dmr_bptc {
  bool ok;                // a codeword was reached within the limit and with margin >= DMR_MIN_SOFT_MARGIN
  int corrected;          // bits changed
  float weighted_errors;  // the changed bits' confidences summed, over the mean confidence
  float margin;           // the nearest other codeword's weighted_errors minus this one's
};
// The 196 BPTC bits of a data burst: burst bits 0-97 and 166-263
void dmr_bptc196_from_burst(uint8_t const burst[264],float const confidence264[264],uint8_t bits[196],
                            float confidence196[196]);
void dmr_bptc196_to_burst(uint8_t const bits[196],uint8_t burst[264]);
// BPTC(196,96): info[] gets the 96 information bits, reserved[] (may be NULL) R(3), R(2), R(1), R(0)
// (R(3) is outside the code). Both are filled even when the decode is refused (then they are the
// refused codeword's, or the bits as received), so look at the return. result may be NULL.
// Returns result->ok
#define DMR_BPTC196_MAX_ERRORS 11.0f
bool dmr_bptc196_decode(struct dmr_bptc *result,uint8_t info[96],uint8_t reserved[4],uint8_t const bits[196],
                        float const confidence[196],float max_weighted_errors);
void dmr_bptc196_encode(uint8_t const info[96],uint8_t bits[196],uint8_t const reserved[4]); // reserved may be NULL
// BPTC(68,36), Short LC: bits[] the four 17-bit CACH fragments in order received (first fragment
// first); info[] the 36 bits SLCO (4), data (24), CRC-8 (8), the CRC not checked here
#define DMR_BPTC68_MAX_ERRORS 3.0f
bool dmr_bptc68_decode(struct dmr_bptc *result,uint8_t info[36],uint8_t const bits[68],float const confidence[68],
                       float max_weighted_errors);
void dmr_bptc68_encode(uint8_t const info[36],uint8_t bits[68]);
// BPTC(128,77), embedded LC: bits[] the four 32-bit fragments of voice bursts B-E in order; info[]
// the 72 LC bits and the 5-bit checksum (not checked here)
void dmr_embedded_from_burst(uint8_t const burst[264],float const confidence264[264],uint8_t bits[32],
                             float confidence32[32]);
#define DMR_BPTC128_MAX_ERRORS 4.0f
bool dmr_bptc128_decode(struct dmr_bptc *result,uint8_t info[77],uint8_t const bits[128],float const confidence[128],
                        float max_weighted_errors);
void dmr_bptc128_encode(uint8_t const info[77],uint8_t bits[128]);
// Single-burst embedded signalling (voice burst F with EMB LCSS = 0): 11 bits in 32. reverse_channel
// selects the form whose second row is the complement of the first (EMB PI = 1)
#define DMR_SINGLE_BURST_MAX_ERRORS 3.0f
struct dmr_soft dmr_single_burst_decode(uint8_t const bits[32],float const confidence[32],bool reverse_channel,
                                        float max_weighted_errors);
void dmr_single_burst_encode(uint32_t data11,uint8_t bits[32],bool reverse_channel);

// RS(12,9) over GF(256): the full LC of a voice LC header or terminator with LC, 9 octets of LC and
// 3 of parity XORed with the data type's mask
#define DMR_RS_MASK_VOICE_LC_HEADER 0x96
#define DMR_RS_MASK_TERMINATOR 0x99
void dmr_rs129_parity(uint8_t const lc[9],uint8_t parity[3]);  // unmasked
void dmr_rs129_encode(uint8_t lc[12],uint8_t mask);            // fills lc[9..11]
// The mask the parity appears to carry, as 0xAABBCC (0x969696 for an undamaged voice LC header).
// For learning what a non-standard system uses; it does not make an LC valid
uint32_t dmr_rs129_observed_mask(uint8_t const lc[12]);
// Check lc[] and, if correct, repair one wrong octet in place. The mask is removed for the check
// only. Returns the octets corrected (0 or 1) or -1 (not a codeword; lc[] unchanged).
// *position (0-11, else -1) and *bit_errors (bits changed in it) may be NULL
int dmr_rs129_decode(uint8_t lc[12],uint8_t mask,bool correct,int *position,int *bit_errors);
// The same on the 96 information bits of a BPTC(196,96) decode
void dmr_rs129_encode_bits(uint8_t bits[96],uint8_t mask);
int dmr_rs129_decode_bits(uint8_t bits[96],uint8_t mask,bool correct,int *position,int *bit_errors);

// CRC-CCITT as DMR sends it: inverted, then XORed with the data type's mask
#define DMR_CRC_MASK_PI_HEADER 0x6969
#define DMR_CRC_MASK_CSBK 0xA5A5
#define DMR_CRC_MASK_MBC_HEADER 0xAAAA
#define DMR_CRC_MASK_DATA_HEADER 0xCCCC
#define DMR_CRC_MASK_USB 0x3333   // unified single block
#define DMR_CRC_MASK_NONE 0x0000  // MBC continuation blocks
uint16_t dmr_crc_ccitt(uint8_t const *bits,int ndata,uint16_t mask);
void dmr_crc_ccitt_append(uint8_t *bits,int ndata,uint16_t mask);         // into bits[ndata..ndata+15]
bool dmr_crc_ccitt_check(uint8_t const *bits,int ntotal,uint16_t mask);   // last 16 of ntotal bits
uint16_t dmr_crc_ccitt_observed_mask(uint8_t const *bits,int ntotal);
// Short LC CRC-8 over the first 28 of its 36 bits: x^8 + x^2 + x + 1, not inverted, no mask
uint8_t dmr_slc_crc(uint8_t const bits[28]);
void dmr_slc_crc_append(uint8_t info[36]);
bool dmr_slc_crc_check(uint8_t const info[36]);
// Embedded LC checksum: the sum of the nine LC octets modulo 31, in bits 72-76 of the 77
uint8_t dmr_elc_checksum(uint8_t const lc[72]);
void dmr_elc_checksum_append(uint8_t info[77]);
bool dmr_elc_checksum_check(uint8_t const info[77]);
// CRC-9 of a confirmed data block (x^9 + x^6 + x^4 + x^3 + 1, inverted, masked): its ndata data bits
// and 7-bit serial number, data first unless serial_first. UNCONFIRMED (see dmrfec.c)
#define DMR_CRC9_MASK_RATE12 0x0F0
#define DMR_CRC9_MASK_RATE34 0x1FF
#define DMR_CRC9_MASK_RATE1 0x10F
uint16_t dmr_crc9(uint8_t const *data,int ndata,uint8_t serial,uint16_t mask,bool serial_first);
// CRC-32 of packet data. UNCONFIRMED (see dmrfec.c)
uint32_t dmr_crc32_bits(uint8_t const *bits,int n);                       // plain division
uint32_t dmr_packet_crc32(uint8_t const *octets,int noctets);             // noctets even
bool dmr_packet_crc32_check(uint8_t const *octets,int noctets);           // last 4 octets, lsb first
// CRC-7 of reverse channel signalling (x^7 + x^5 + x^2 + x + 1). The mask is UNCONFIRMED
#define DMR_CRC7_MASK_REVERSE_CHANNEL 0x7A
uint8_t dmr_crc7(uint8_t const *bits,int n,uint8_t mask);

// Rate 3/4 trellis: 144 bits (18 octets) in the 196 bits of a rate 3/4 data burst
struct dmr_trellis34 {
  bool ok;                // weighted_errors <= the limit; little is worth resting on it (dmrfec.c)
  int corrected_points;   // constellation points (of 49) received other than the path's
  int bit_errors;         // received bits (of 196) other than the path's
  float weighted_errors;  // the path metric over the mean confidence (level steps, hard)
  float margin;           // the closest decision along the path, same units
};
#define DMR_TRELLIS34_MAX_ERRORS_SOFT 5.0f
#define DMR_TRELLIS34_MAX_ERRORS_HARD 9.0f
#define DMR_TRELLIS34_AUTO_LIMIT (-1.0f)   // choose by whether the confidences differ
void dmr_trellis34_encode(uint8_t const info[144],uint8_t bits[196]);
// info[] always gets the path's 144 bits; result may be NULL. Returns result->ok
bool dmr_trellis34_decode(struct dmr_trellis34 *result,uint8_t info[144],uint8_t const bits[196],
                          float const confidence[196],float max_weighted_errors);

#endif
