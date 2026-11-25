// DMR packet data (ETSI TS 102 361-1 clause 8.2 / 9.2, TS 102 361-3, TS 102 361-4 for UDT): data
// headers, unified single block data, data blocks at rate 1/2, 3/4 and 1, the packet CRCs, and the
// reassembly of packets on both timeslots of a carrier. What a packet carries is dmrdataapp.h's.
// dmrdata.c has the theory of operation
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRDATA_H
#define _DMRDATA_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmr.h"
#include "dmrmsg.h"

// Conventions as dmrmsg.h: bits one per uint8_t, index 0 first sent; a field packed into an integer has
// its first sent bit most significant. Octets: bit 0 is the top bit of octet 0.

enum {
  DMR_DATA_MAX_BLOCKS = 127,                      // blocks to follow is 7 bits
  DMR_DATA_MAX_OCTETS = DMR_DATA_MAX_BLOCKS * 24, // every block of a packet at rate 1
  DMR_DATA_DESCRIBE_MAX = 512,                    // a describe() line of this file or dmrdataapp.h fits
};

// Data packet format, bits 4-7 of a header (sdrtrunk DataPacketFormat.java; TS 102 361-1 table 9.30)
enum {
  DMR_DPF_UDT = 0,
  DMR_DPF_RESPONSE = 1,
  DMR_DPF_UNCONFIRMED = 2,
  DMR_DPF_CONFIRMED = 3,
  DMR_DPF_DEFINED_SHORT_DATA = 13,
  DMR_DPF_RAW_OR_STATUS_SHORT_DATA = 14,
  DMR_DPF_PROPRIETARY = 15,
};

// Service access points (sdrtrunk ServiceAccessPoint.java; TS 102 361-1 table 9.31)
enum {
  DMR_SAP_UDT = 0,
  DMR_SAP_MOTOROLA_MNIS = 1,     // reserved in ETSI: what Motorola's MNIS proprietary header uses
  DMR_SAP_TCP_IP_COMPRESSION = 2,
  DMR_SAP_UDP_IP_COMPRESSION = 3,
  DMR_SAP_IP_PACKET = 4,
  DMR_SAP_ARP = 5,
  DMR_SAP_PROPRIETARY = 9,
  DMR_SAP_SHORT_DATA = 10,
};
char const *dmr_sap_name(uint8_t sap);

// Response class, bits 72-73 of a response header (TS 102 361-1 table 8.3)
enum { DMR_RESPONSE_ACK = 0, DMR_RESPONSE_NACK = 1, DMR_RESPONSE_SACK = 2 };

// ---------------- Data headers ----------------

enum dmr_data_header_kind {
  DMR_DH_INVALID = 0,          // BPTC or CRC failed, or a reserved packet format
  DMR_DH_UNCONFIRMED,
  DMR_DH_CONFIRMED,
  DMR_DH_RESPONSE,
  DMR_DH_DEFINED_SHORT_DATA,
  DMR_DH_RAW_SHORT_DATA,
  DMR_DH_STATUS_PRECODED,      // raw / status short data with no appended blocks
  DMR_DH_UDT,
  DMR_DH_PROPRIETARY,          // a vendor header that is none of the three below
  DMR_DH_MOTOROLA_ENCRYPTION,
  DMR_DH_MOTOROLA_MNIS,
  DMR_DH_HYTERA_ENCRYPTION,
};
char const *dmr_data_header_kind_name(enum dmr_data_header_kind k);

// One data header. Which fields mean something depends on kind; the rest stay 0
struct dmr_data_header {
  // Framing and checks
  bool valid;                  // fec_ok && crc_ok, and a known packet format
  bool fec_ok;                 // the BPTC(196,96) decode was accepted
  bool crc_ok;                 // CRC-CCITT, mask 0xCCCC
  int fec_corrected;
  uint16_t crc_observed_mask;  // the mask that would make the CRC pass (0xCCCC when it does)
  uint8_t slot;
  uint8_t color_code;
  uint64_t timestamp_us;
  uint8_t octets[12];          // the 96 bits as decoded, CRC included

  enum dmr_data_header_kind kind;
  uint8_t dpf;                 // data packet format
  uint8_t sap;

  // Every kind but the proprietary ones
  bool group;                  // the destination is a talkgroup
  bool response_requested;
  uint32_t destination;
  uint32_t source;
  // The blocks that follow this header in the packet. A proprietary second header is one of them
  // (sdrtrunk PacketSequence.isComplete, OP25 d_pdp_bf--). Short data: its appended blocks; UDT: UAB + 1
  uint8_t blocks_to_follow;

  // Unconfirmed and confirmed
  uint8_t pad_octets;
  bool full_message;           // F. Also short data
  uint8_t fragment_seq;        // FSN
  bool resync;                 // S: confirmed
  uint8_t send_seq;            // N(S): confirmed

  // Response
  uint8_t response_class;      // DMR_RESPONSE_*
  uint8_t response_type;
  uint8_t response_status;

  // Short data
  uint8_t source_port;         // raw, status
  uint8_t destination_port;
  uint8_t defined_format;      // DD format: defined short data
  uint8_t bit_padding;         // pad BITS at the end of the data: raw, defined
  bool sarq;                   // SARQ (bit 70): raw, defined (TS 102 361-1 9.3.37)
  uint16_t status;             // status / precoded, 10 bits

  // UDT
  uint8_t udt_format;
  uint8_t udt_pad_nibbles;
  uint8_t udt_opcode;
  bool udt_supplementary;
  bool udt_protect;

  // Proprietary kinds
  uint8_t mfid;
  uint8_t vendor_data[8];      // bits 16-79
  // Motorola / Hytera encryption header
  bool marks_encrypted;        // a packet this header is part of is encrypted
  uint8_t algorithm;
  uint8_t key_id;
  uint32_t iv;
  // Motorola MNIS
  uint8_t mnis_message_type;
  uint8_t mnis_application_type; // 0x01 MNIS LRRP, 0x11 LRRP, 0x33 ARS, 0x88 XCMP
  uint16_t mnis_packet_number;
  uint8_t mnis_prefix[3];      // sdrtrunk puts these three octets in front of the packet
};
static inline bool dmr_data_header_is_proprietary(struct dmr_data_header const *h){
  return h->dpf == DMR_DPF_PROPRIETARY && h->kind != DMR_DH_INVALID;
}
// The blocks that follow carry a DBSN and a CRC-9: a confirmed packet (DPF 0011), or raw / defined
// short data with A = 1 (TS 102 361-3 6.0, 6.1.2, 6.2.2)
static inline bool dmr_data_header_uses_confirmed_blocks(struct dmr_data_header const *h){
  return h->kind == DMR_DH_CONFIRMED
    || ((h->kind == DMR_DH_RAW_SHORT_DATA || h->kind == DMR_DH_DEFINED_SHORT_DATA) && h->response_requested);
}
// Parse the 96 information bits of a data header. With fec_ok false, or a failed CRC, the result is not
// valid and carries no fields, only its octets (slot, colour code and time are the caller's to set)
void dmr_data_header_parse(struct dmr_data_header *h,uint8_t const info96[96],bool fec_ok);
// The same from what dmrmsg decoded for a data header burst (d->data_type DMR_DT_DATA_HEADER)
void dmr_data_header_from_burst(struct dmr_data_header *h,struct dmr_burst const *b,struct dmr_data_burst const *d);
// "[DMR data] slot=1 header confirmed src=.. dst=TG .. sap=4(IP) blocks=3 pad=..". Prints the header's
// raw octets for a proprietary or invalid one. Returns the length written, as dmrmsg's describe()s
int dmr_data_header_describe(char *buf,size_t size,struct dmr_data_header const *h);
// What a response header says: "ACK packet N(S)=3 received", "NACK packet CRC failed (status 2)", ...
int dmr_data_response_describe(char *buf,size_t size,uint8_t response_class,uint8_t type,uint8_t status);

// ---------------- Unified single block data (data type 11) ----------------

// One BPTC(196,96) burst, CRC-CCITT with mask 0x3333 (sdrtrunk USBData.java; TS 102 361-1 8.2.3.1)
struct dmr_usbd {
  bool valid;
  bool fec_ok;
  bool crc_ok;
  uint8_t slot;
  uint8_t color_code;
  uint64_t timestamp_us;
  uint8_t service_type;        // bits 0-3
  uint32_t target;             // bits 56-79 (a destination for service type 0 only)
  uint8_t octets[12];
};
void dmr_usbd_from_burst(struct dmr_usbd *u,struct dmr_burst const *b,struct dmr_data_burst const *d);
int dmr_usbd_describe(char *buf,size_t size,struct dmr_usbd const *u);

// ---------------- The packet CRCs (dmrdata.c says what they rest on) ----------------

enum dmr_data_rate { DMR_DATA_RATE_12 = 0, DMR_DATA_RATE_34 = 1, DMR_DATA_RATE_1 = 2 };
char const *dmr_data_rate_name(enum dmr_data_rate r);   // "1/2", "3/4", "1"
// The rate a data type names; false if it is not a data block
bool dmr_data_rate_of(enum dmr_data_type t,enum dmr_data_rate *rate);
static inline int dmr_data_block_octets(enum dmr_data_rate r){
  return r == DMR_DATA_RATE_12 ? 12 : r == DMR_DATA_RATE_34 ? 18 : 24;
}
// Data octets of a block: all of it, or all but the serial number and CRC-9
static inline int dmr_data_block_payload_octets(enum dmr_data_rate r,bool confirmed){
  return dmr_data_block_octets(r) - (confirmed ? 2 : 0);
}

// Every convention of the data CRCs, all ETSI's (the CRC-32 octet order is the ambiguous one).
// dmr_data_crc_convention_init() gives the defaults; another is a run time choice
struct dmr_data_crc_convention {
  bool crc9_serial_first;      // false: data bits, then the serial number
  bool crc9_complement;
  uint16_t crc9_mask[3];       // by enum dmr_data_rate: 0x0F0, 0x1FF, 0x10F
  bool crc32_swap_octet_pairs;
  bool crc32_complement;
  bool crc32_lsb_first;        // the first CRC octet sent is the least significant
  uint16_t udt_crc_mask;       // UDT appended data CRC-16: 0x0000
};
void dmr_data_crc_convention_init(struct dmr_data_crc_convention *c);
// The 9 CRC bits a confirmed block of this rate carries. c may be NULL (the defaults)
uint16_t dmr_data_crc9(uint8_t const *data_bits,int ndata,uint8_t serial,enum dmr_data_rate rate,
                       struct dmr_data_crc_convention const *c);
// Stored CRC-9 XOR the plain remainder, for one ordering: constant over undamaged blocks of one rate
// when the ordering is right
uint16_t dmr_data_crc9_observed(uint8_t const *data_bits,int ndata,uint8_t serial,uint16_t stored,bool serial_first);
// The remainder of the octets x^32, the octets taken in pairs with each pair swapped or as they are
uint32_t dmr_data_crc32_remainder(uint8_t const *octets,int noctets,bool swap_pairs);
uint32_t dmr_data_crc32(uint8_t const *octets,int noctets,struct dmr_data_crc_convention const *c);
uint32_t dmr_data_crc32_stored(uint8_t const crc4[4],struct dmr_data_crc_convention const *c);
// For settling the conventions on a capture: stored XOR remainder for the four readings of a packet
// (noctets includes the four CRC octets). The right reading gives 0 for every undamaged packet
struct dmr_crc32_observed {
  uint32_t swapped_lsb_first;  // the default convention
  uint32_t swapped_msb_first;
  uint32_t straight_lsb_first;
  uint32_t straight_msb_first;
};
void dmr_data_crc32_observed(struct dmr_crc32_observed *o,uint8_t const *octets,int noctets);

// ---------------- Data blocks ----------------

struct dmr_data_block {
  enum dmr_data_rate rate;
  // The channel decode was accepted: BPTC ok, trellis ok; always true for rate 1 (it has no code)
  bool fec_ok;
  int corrected;               // bits (rate 1/2) or constellation points (rate 3/4) changed
  float weighted_errors;
  int octet_count;             // 12 / 18 / 24
  uint8_t bits[192];
  uint8_t octets[24];
  // The block read as a confirmed-data block: meaningful only when the packet's header says so
  uint8_t serial;              // DBSN, bits 0-6
  uint16_t crc9_stored;        // bits 7-15
  bool crc9_ok;
  uint16_t crc9_observed_data_first;
  uint16_t crc9_observed_serial_first;
};
// Decode a data block from what dmrmsg decoded for its burst: d->info and the BPTC result for rate 1/2,
// d->payload (and its confidences, for the trellis) for rate 3/4 and 1. c may be NULL (the defaults)
void dmr_data_block_decode(struct dmr_data_block *blk,enum dmr_data_rate rate,struct dmr_data_burst const *d,
                           struct dmr_data_crc_convention const *c);

// ---------------- Packets ----------------

enum dmr_packet_end {
  DMR_PACKET_ALL_BLOCKS = 0,   // the last block's place was reached
  DMR_PACKET_NEW_HEADER,       // another header started before that
  DMR_PACKET_INTERRUPTED,      // a burst that is not packet data arrived on the slot
  DMR_PACKET_TIMEOUT,
  DMR_PACKET_FLUSH,
};
char const *dmr_packet_end_name(enum dmr_packet_end e);

// One block position of a packet
struct dmr_data_packet_block {
  bool received;               // a data block burst arrived for this place
  enum dmr_data_rate rate;
  bool fec_ok;
  // Confirmed packets only
  bool crc9_ok;
  uint8_t serial;
  uint16_t crc9_observed_data_first;
  uint16_t crc9_observed_serial_first;
};

struct dmr_data_message;       // dmrdataapp.h

struct dmr_data_packet {
  uint8_t slot;
  uint8_t color_code;
  struct dmr_data_header header;         // the first header
  bool has_second_header;
  struct dmr_data_header second_header;  // the proprietary header that followed it

  uint32_t source;
  uint32_t destination;
  bool group;
  uint8_t sap;
  bool confirmed;              // the blocks carry DBSN and CRC-9

  // Every block arrived, every confirmed block's CRC-9 passed, and the packet CRC passed
  bool complete;
  enum dmr_packet_end end;
  int blocks_expected;
  int blocks_received;
  int blocks_good;             // received, and (confirmed) the CRC-9 passed
  int blocks_fec_refused;      // received, but the channel decoder judged the burst too far from a codeword
  int duplicate_blocks;        // retries of a serial number already held
  struct dmr_data_packet_block blocks[DMR_DATA_MAX_BLOCKS];  // blocks_expected of them

  // The packet check: CRC-32, or for a UDT the CRC-16. Checked only when every block arrived
  bool crc_checked;
  bool crc_ok;
  uint32_t crc_stored;
  uint32_t crc_computed;
  struct dmr_crc32_observed crc32_observed; // not for a UDT
  uint16_t udt_crc_observed_mask;           // UDT: the CRC-CCITT mask that would make it pass

  // The data. payload_trimmed: the pad and the CRC have been removed and payload_bits is the length the
  // header gives (short data and UDT pad in bits and nibbles). Otherwise (a block missing, or an
  // encrypted packet) payload is every block's data octets in place, pad and CRC included, missing
  // blocks zero-filled
  uint8_t payload[DMR_DATA_MAX_OCTETS];
  size_t payload_length;
  size_t payload_bits;
  bool payload_trimmed;
  // Every block's data octets in place, pad and packet CRC included, whether or not payload was trimmed
  uint8_t raw_payload[DMR_DATA_MAX_OCTETS];
  size_t raw_payload_length;

  bool encrypted;
  uint8_t encryption_mfid;
  uint8_t algorithm;
  uint8_t key_id;
  uint32_t iv;

  bool retransmission;         // repeats the previous complete confirmed packet
  uint64_t first_timestamp_us; // of the header
  uint64_t last_timestamp_us;  // of the last burst used

  // What the packet carries (dmrdataapp.h), classified by the assembler before the packet is handed on;
  // it points into the assembler and is valid only during the callback. NULL in a packet not from one
  struct dmr_data_message const *app;
};
// "[DMR data] slot=1 packet confirmed rate=1/2 src=.. dst=.. sap=4(IP) blocks=3/3 good=3 dup=0
// end=all-blocks COMPLETE len=57 crc=ok ...": assembly and the CRC evidence, never a payload octet.
// What the packet carries is dmr_data_app_describe() (dmrdataapp.h)
int dmr_data_packet_describe(char *buf,size_t size,struct dmr_data_packet const *p);

// ---------------- The assembler: one per carrier ----------------

struct dmr_data_config {
  int timeout_bursts;                // slot periods (60 ms each) without a burst of the slot: 6
  uint64_t retransmission_window_us; // 30 s
  struct dmr_data_crc_convention crc;
  bool classify;                     // classify each packet (packet->app): true
};
void dmr_data_config_init(struct dmr_data_config *c);

// Called on the caller's thread, from within dmr_data_on_burst() and the flushes. Any may be NULL
struct dmr_data_handlers {
  void *arg;
  void (*on_header)(void *arg,struct dmr_data_header const *h);   // every data header burst: check h->valid
  void (*on_packet)(void *arg,struct dmr_data_packet const *p);   // every packet that ended: check p->complete
  void (*on_usbd)(void *arg,struct dmr_usbd const *u);            // every unified single block burst
};

struct dmr_data_stats {
  uint64_t headers;            // valid headers
  uint64_t header_failures;    // data header bursts whose BPTC or CRC failed
  uint64_t orphan_headers;     // proprietary headers with no packet to belong to
  uint64_t repeated_headers;
  uint64_t blocks;             // data block bursts used
  uint64_t block_fec_failures;
  uint64_t crc9_failures;
  uint64_t duplicate_blocks;
  uint64_t orphan_blocks;      // data block bursts with no packet open
  uint64_t packets_complete;
  uint64_t packets_incomplete;
  uint64_t packet_crc_failures; // every block arrived but the packet CRC failed
  uint64_t timeouts;
  uint64_t unified_single_blocks;
};

struct dmr_data_assembler;
// h and config may be NULL (no callbacks; the defaults). Both are copied
struct dmr_data_assembler *dmr_data_create(struct dmr_data_handlers const *h,struct dmr_data_config const *config);
void dmr_data_destroy(struct dmr_data_assembler *a);
// Feed EVERY burst of the carrier, both slots, in order, with what dmr_msg_decode() made of it
// (m may be NULL: the data burst is then decoded here). The bursts that are not data matter: they end
// a packet, and the other slot's clock notices a slot gone quiet
void dmr_data_on_burst(struct dmr_data_assembler *a,struct dmr_burst const *b,struct dmr_burst_messages const *m);
// Deliver every open packet as it stands (incomplete, end flush). Clocks and the last packet are kept
void dmr_data_flush(struct dmr_data_assembler *a);
// The sink lost frame sync: flush, then drop every slot's state
void dmr_data_sync_lost(struct dmr_data_assembler *a);
// Flush one slot (0 = bursts whose slot is not known, 1, 2), then drop its state
void dmr_data_reset_slot(struct dmr_data_assembler *a,int slot);
// Drop every slot's state without delivering anything (a retune)
void dmr_data_reset(struct dmr_data_assembler *a);
bool dmr_data_packet_open(struct dmr_data_assembler const *a);
struct dmr_data_stats const *dmr_data_get_stats(struct dmr_data_assembler const *a,int slot);

#endif
