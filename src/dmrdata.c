// DMR packet data (see dmrdata.h): data headers, unified single block data, data blocks, the packet
// CRCs and the reassembly of packets on both timeslots of a carrier
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dfec.h"
#include "dmrfec.h"
#include "dmrdata.h"
#include "dmrdataapp.h"

// Theory of operation
//
// Input. Every burst of the carrier, in order, with what dmr_msg_decode() made of it: for a data header,
// a rate 1/2 block or a unified single block the 96 information bits BPTC(196,96) delivered and whether
// the decode was accepted (dmrmsg hands them on unchecked: the checks are this file's); for rate 3/4 and
// rate 1 the 196 bits of the burst's information field with their confidences. Nothing here decodes a
// BPTC word again.
//
// Data headers (TS 102 361-1 clause 8.2.1 / 9.2, TS 102 361-4 for UDT): 96 bits, CRC-CCITT with mask
// 0xCCCC over the first 80. A header whose BPTC decode or CRC fails is never parsed: valid is false and
// it keeps only its raw octets, for a log line; nothing corrects a header from its CRC. The field
// positions are sdrtrunk's (GPL-3, Dennis Sheirer, github.com/DSheirer/sdrtrunk, module/decode/dmr/
// message/data/header/: DataHeader, PacketSequenceHeader, OctetDataHeader, ConfirmedDataHeader,
// ResponseDataHeader, ShortDataHeader, RawShortDataHeader, StatusDataHeader, DefinedShortDataHeader,
// UDTHeader, ProprietaryDataHeader, motorola/MotorolaDataEncryptionHeader, motorola/
// MNISProprietaryDataHeader, hytera/HyteraDataEncryptionHeader; message/type/ResponseStatus) and, for
// the common fields, OP25's (GPL-3, lib/dmr_slot.cc decode_pdp_header). Every one matches TS 102 361-1
// figures 8.2-8.10 and tables 9.10-9.17D. Where the two sources differ, or sdrtrunk is alone:
//   - Pad octet count: sdrtrunk reads 5 bits {3, 12..15}, OP25 the low 4 (12..15). Five is right
//     (TS 102 361-1 figures 8.3 / 8.4, 9.3.22).
//   - UDT format: 4 bits (12..15, table 9.51), not sdrtrunk's 5. Bits 2 and 3 of octet 0 are not
//     reserved (outbound Emergency and UDT_Option_Flag, inbound reserved and UDT_DIV); not parsed.
//   - UDT appended blocks: the 2-bit UAB field counts from one (0 = one block, TS 102 361-4 table 7.66).
//   - Short data bit 70 (raw and defined) is SARQ (TS 102 361-1 9.3.37), sdrtrunk's "resync". With A
//     it selects the service (TS 102 361-3 table 6.5).
//   - Short data with A = 1 and appended blocks is CONFIRMED data: its blocks carry a DBSN and a CRC-9
//     (TS 102 361-3 6.0, 6.1.2, 6.2.2): dmr_data_header_uses_confirmed_blocks().
//   - The Motorola encryption and MNIS headers and the Hytera encryption header are sdrtrunk's own
//     reverse engineering, with no second source; which of them marks a packet encrypted is sdrtrunk's
//     rule (PacketSequence.isEncrypted): a Motorola (MFID 0x10 or 0x06) header on any SAP but 1, or a
//     Hytera (0x68) one whose algorithm is not 0.
// The response status of an ACK and the NACKs is NI, the N(S) of the packet concerned (TS 102 361-3
// table 5.7), not a block count.
//
// Unified single block data (data type 11): 96 bits, CRC-CCITT with mask 0x3333; service type bits 0-3,
// bits 56-79 the destination of a Tier III LIP poll request (service type 0) and otherwise used
// otherwise (sdrtrunk USBData.java; TS 102 361-1 8.2.3.1, TS 102 361-4 tables 6.77 / 6.79).
//
// Blocks (TS 102 361-1 8.2.2, table 8.1; sdrtrunk DataBlock*.java, OP25 decode_pdp_12data / 34data):
//   rate 1/2   BPTC(196,96)  ->  96 bits = 12 octets
//   rate 3/4   the trellis   -> 144 bits = 18 octets
//   rate 1     no code       -> 192 bits = 24 octets: information field bits 0-95 and 100-195, the four
//                                bits between being pad (TS 102 361-1 B.2.5, table B.10B); not checked
// A block of a confirmed packet starts with a 7-bit serial number (DBSN) and a CRC-9 over the rest of the
// block and the serial number, leaving 10 / 16 / 22 data octets.
//
// The CRCs (TS 102 361-1 annex B.3). sdrtrunk and OP25 check none of them for DMR.
//   CRC-9   x^9 + x^6 + x^4 + x^3 + 1 over the block's data bits in the order sent, then the serial
//           number; complemented; XOR the data type's mask: rate 1/2 0x0F0, 3/4 0x1FF, 1 0x10F (B.3.10,
//           table B.21). sdrtrunk's unused checkCRC9 has the serial number first, P25's order.
//   CRC-32  0x04C11DB7 over the packet's octets before the CRC (user data and pad; for confirmed data
//           without serial numbers and CRC-9s), taken two at a time with each pair swapped; no preset, no
//           complement (B.3.9, equation B.22). The order of the four CRC octets on air is AMBIGUOUS in
//           ETSI itself: B.3.9's x-terms put x^31..x^24 in the first octet sent, while the same
//           paragraph's "less significant octets first" and figure B.8C's labels put x^7..x^0 there.
//           Least significant first (as dmrshark) is the default; crc32_observed keeps the evidence.
//   UDT     CRC-CCITT over the appended blocks before their last 16 bits, complemented, no mask
//           (table 9.17E, B.3.8).
// How a capture settles them: dmr_data_crc9_observed() and dmr_data_crc32_observed() give "stored XOR
// plain remainder" for each candidate ordering. For the right one that is the same for every undamaged
// block (0x10F / 0x000 / 0x0F0 by rate, with the masks above) or packet (0); for a wrong one it differs
// every time. Every packet carries them and its describe() prints them. Every convention is in struct
// dmr_data_crc_convention, so another is a configuration change.
//
// Reassembly, one state per timeslot (0 = slot not known, 1, 2). A header with blocks to follow = N is
// followed by N bursts on the same slot. The first may be a second, proprietary header (Motorola or Hytera
// encryption parameters, Motorola MNIS), which counts as one of the N (sdrtrunk PacketSequence.isComplete,
// OP25 decode_pdp_header); the rest are data blocks. The last four octets of the last block are the
// packet's CRC-32, with the pad octets the header counts just before it (OP25 dmr_slot.cc:
// size - (poc + 4)); a UDT's appended blocks end in a CRC-16 instead.
//
// What decides. The header CRC (a header that fails is never used), each confirmed block's CRC-9 and the
// packet CRC. complete is true only when every block arrived, every confirmed block's CRC-9 passed and
// the packet CRC passed; anything else is delivered with complete false, what arrived in place and the
// missing blocks zero-filled. The channel decoders' verdicts (BPTC ok, trellis ok) are kept per block and
// counted (blocks_fec_refused) but do not decide: a block they doubt whose CRCs pass is right, one they
// accept whose CRC fails is not.
//
// Where a block goes. Unconfirmed blocks have no number, so a block's place is the number of slot
// periods since the header, from the bursts' dibit_clock (a burst the receiver never framed leaves a gap
// of 288 dibits and the block after it still lands in its place). Without a usable clock (one that does
// not advance) the place is the order of arrival. A confirmed block whose CRC-9 passes names its own
// place by its serial number; a second good copy of a serial number already held is a retry and is
// dropped (duplicate_blocks). A complete confirmed packet that repeats the previous one (same source,
// destination, N(S), FSN and CRC-32, within retransmission_window_us) is delivered with retransmission
// set: the sender did not hear the acknowledgement.
//
// A packet ends when every block is in and good; the last place has passed; a new (non-proprietary)
// header arrives; a burst that is not a header or a data block arrives on the slot; no burst of the slot
// has come for timeout_bursts periods (seen on this slot's next burst or on the other slot's clock); or
// on a flush.
//
// Encryption. A packet whose second header marks it encrypted is delivered with encrypted set, the
// algorithm, key ID and IV from that header, and its block octets exactly as received: pad and CRC are
// not removed, and nothing here or in dmrdataapp.c looks inside it. Whether the CRC-32 of an encrypted
// packet covers the ciphertext is not known, so an encrypted packet that arrived whole may still show
// crc_ok false and complete false: judge those by blocks_received == blocks_expected (and blocks_good).
//
// Not done: merging a selective retry (a later header resending only the blocks a SACK asked for, with
// F = 0 and their original DBSNs, TS 102 361-3 5.4.0) into the packet it repairs; joining the fragments
// of a message sent as several packets (FSN); the response data block's retry flags (figure 8.17); data
// type 13 (sdrtrunk's DATA_ENC_HEADER, reserved in TS 102 361-1 table 9.22), not handled as a header.

// ---------------- Bits and text ----------------

static uint32_t bits_to_uint(uint8_t const *bits,int n){
  uint32_t v = 0;
  for(int i=0; i < n; i++)
    v = (v << 1) | (bits[i] & 1u);
  return v;
}
static void uint_to_bits(uint32_t v,int n,uint8_t *bits){
  for(int i=0; i < n; i++)
    bits[i] = (uint8_t)((v >> (n - 1 - i)) & 1u);
}
static void bits_to_bytes(uint8_t const *bits,int nbytes,uint8_t *bytes){
  for(int i=0; i < nbytes; i++)
    bytes[i] = (uint8_t)bits_to_uint(bits + 8 * i,8);
}
static void bytes_to_bits(uint8_t const *bytes,int nbytes,uint8_t *bits){
  for(int i=0; i < nbytes; i++)
    uint_to_bits(bytes[i],8,bits + 8 * i);
}
// Bits {high_first .. high_first + high - 1, 12, 13, 14, 15}
static uint32_t split_field(uint8_t const *b,int high_first,int high){
  return (bits_to_uint(b + high_first,high) << 4) | bits_to_uint(b + 12,4);
}

static void append(char *buf,size_t size,size_t *len,char const *fmt,...) __attribute__((format(printf,4,5)));
static void append(char *buf,size_t size,size_t *len,char const *fmt,...){
  if(*len >= size)
    return;
  va_list ap;
  va_start(ap,fmt);
  int const n = vsnprintf(buf + *len,size - *len,fmt,ap);
  va_end(ap);
  if(n > 0)
    *len += (size_t)n < size - *len ? (size_t)n : size - *len - 1;
}
static int finish(char *buf,size_t size,size_t len){
  if(size > 0 && len == 0)
    buf[0] = '\0';
  return (int)len;
}
static void hex_octets(char *buf,size_t size,size_t *len,uint8_t const *octets,int count){
  for(int i=0; i < count; i++)
    append(buf,size,len,"%02X",(unsigned)octets[i]);
}

// ---------------- Names ----------------

char const *dmr_sap_name(uint8_t sap){
  switch(sap){
  case DMR_SAP_UDT: return "UDT";
  case DMR_SAP_MOTOROLA_MNIS: return "MNIS";
  case DMR_SAP_TCP_IP_COMPRESSION: return "TCP/IP-compressed";
  case DMR_SAP_UDP_IP_COMPRESSION: return "UDP/IP-compressed";
  case DMR_SAP_IP_PACKET: return "IP";
  case DMR_SAP_ARP: return "ARP";
  case DMR_SAP_PROPRIETARY: return "proprietary";
  case DMR_SAP_SHORT_DATA: return "short-data";
  default: return "reserved";
  }
}

char const *dmr_data_header_kind_name(enum dmr_data_header_kind k){
  switch(k){
  case DMR_DH_UNCONFIRMED: return "unconfirmed";
  case DMR_DH_CONFIRMED: return "confirmed";
  case DMR_DH_RESPONSE: return "response";
  case DMR_DH_DEFINED_SHORT_DATA: return "defined-short-data";
  case DMR_DH_RAW_SHORT_DATA: return "raw-short-data";
  case DMR_DH_STATUS_PRECODED: return "status-precoded";
  case DMR_DH_UDT: return "udt";
  case DMR_DH_PROPRIETARY: return "proprietary";
  case DMR_DH_MOTOROLA_ENCRYPTION: return "motorola-encryption";
  case DMR_DH_MOTOROLA_MNIS: return "motorola-mnis";
  case DMR_DH_HYTERA_ENCRYPTION: return "hytera-encryption";
  default: return "invalid";
  }
}

char const *dmr_data_rate_name(enum dmr_data_rate r){
  return r == DMR_DATA_RATE_12 ? "1/2" : r == DMR_DATA_RATE_34 ? "3/4" : "1";
}

bool dmr_data_rate_of(enum dmr_data_type t,enum dmr_data_rate *rate){
  switch(t){
  case DMR_DT_RATE12_DATA: *rate = DMR_DATA_RATE_12; return true;
  case DMR_DT_RATE34_DATA: *rate = DMR_DATA_RATE_34; return true;
  case DMR_DT_RATE1_DATA: *rate = DMR_DATA_RATE_1; return true;
  default: return false;
  }
}

char const *dmr_packet_end_name(enum dmr_packet_end e){
  switch(e){
  case DMR_PACKET_ALL_BLOCKS: return "all-blocks";
  case DMR_PACKET_NEW_HEADER: return "new-header";
  case DMR_PACKET_INTERRUPTED: return "interrupted";
  case DMR_PACKET_TIMEOUT: return "timeout";
  default: return "flush";
  }
}

// ---------------- Data headers ----------------

void dmr_data_header_parse(struct dmr_data_header *h,uint8_t const info96[96],bool fec_ok){
  assert(h != NULL && info96 != NULL);
  memset(h,0,sizeof *h);
  bits_to_bytes(info96,12,h->octets);
  h->fec_ok = fec_ok;
  h->crc_observed_mask = dmr_crc_ccitt_observed_mask(info96,96);
  h->crc_ok = dmr_crc_ccitt_check(info96,96,DMR_CRC_MASK_DATA_HEADER);
  if(!h->fec_ok || !h->crc_ok)
    return;

  uint8_t const *b = info96;
  h->dpf = (uint8_t)bits_to_uint(b + 4,4);

  if(h->dpf == DMR_DPF_PROPRIETARY){
    h->sap = (uint8_t)bits_to_uint(b,4);
    h->mfid = (uint8_t)bits_to_uint(b + 8,8);
    bits_to_bytes(b + 16,8,h->vendor_data);
    h->kind = DMR_DH_PROPRIETARY;
    if(h->mfid == DMR_FID_MOTOROLA || h->mfid == DMR_FID_CONNECT_PLUS){
      if(h->sap == DMR_SAP_MOTOROLA_MNIS){
        h->kind = DMR_DH_MOTOROLA_MNIS;
        h->mnis_message_type = (uint8_t)bits_to_uint(b + 24,8);
        h->mnis_application_type = (uint8_t)bits_to_uint(b + 32,8);
        h->mnis_packet_number = (uint16_t)bits_to_uint(b + 40,16);
        bits_to_bytes(b + 56,3,h->mnis_prefix);
      } else {
        h->kind = DMR_DH_MOTOROLA_ENCRYPTION;
        h->algorithm = (uint8_t)bits_to_uint(b + 16,8);
        h->key_id = (uint8_t)bits_to_uint(b + 24,8);
        h->iv = bits_to_uint(b + 48,32);
        h->marks_encrypted = true;
      }
    } else if(h->mfid == DMR_FID_HYTERA_68){
      h->kind = DMR_DH_HYTERA_ENCRYPTION;
      h->algorithm = (uint8_t)bits_to_uint(b + 16,8);
      h->key_id = (uint8_t)bits_to_uint(b + 24,8);
      h->iv = bits_to_uint(b + 32,32);
      h->marks_encrypted = h->algorithm != 0;
    }
    h->valid = true;
    return;
  }

  h->group = b[0] != 0;
  h->response_requested = b[1] != 0;
  h->sap = (uint8_t)bits_to_uint(b + 8,4);
  h->destination = bits_to_uint(b + 16,24);
  h->source = bits_to_uint(b + 40,24);

  switch(h->dpf){
  case DMR_DPF_UNCONFIRMED:
  case DMR_DPF_CONFIRMED:
    h->kind = h->dpf == DMR_DPF_CONFIRMED ? DMR_DH_CONFIRMED : DMR_DH_UNCONFIRMED;
    h->pad_octets = (uint8_t)split_field(b,3,1);
    h->full_message = b[64] != 0;
    h->blocks_to_follow = (uint8_t)bits_to_uint(b + 65,7);
    h->fragment_seq = (uint8_t)bits_to_uint(b + 76,4);
    if(h->dpf == DMR_DPF_CONFIRMED){
      h->resync = b[72] != 0;
      h->send_seq = (uint8_t)bits_to_uint(b + 73,3);
    }
    break;
  case DMR_DPF_RESPONSE:
    h->kind = DMR_DH_RESPONSE;
    h->response_requested = false;
    h->blocks_to_follow = (uint8_t)bits_to_uint(b + 65,7);
    h->response_class = (uint8_t)bits_to_uint(b + 72,2);
    h->response_type = (uint8_t)bits_to_uint(b + 74,3);
    h->response_status = (uint8_t)bits_to_uint(b + 77,3);
    break;
  case DMR_DPF_DEFINED_SHORT_DATA:
    h->kind = DMR_DH_DEFINED_SHORT_DATA;
    h->blocks_to_follow = (uint8_t)split_field(b,2,2);
    h->defined_format = (uint8_t)bits_to_uint(b + 64,6);
    h->sarq = b[70] != 0;
    h->full_message = b[71] != 0;
    h->bit_padding = (uint8_t)bits_to_uint(b + 72,8);
    break;
  case DMR_DPF_RAW_OR_STATUS_SHORT_DATA:
    h->blocks_to_follow = (uint8_t)split_field(b,2,2);
    h->source_port = (uint8_t)bits_to_uint(b + 64,3);
    h->destination_port = (uint8_t)bits_to_uint(b + 67,3);
    if(h->blocks_to_follow == 0){
      h->kind = DMR_DH_STATUS_PRECODED;
      h->status = (uint16_t)bits_to_uint(b + 70,10);
    } else {
      h->kind = DMR_DH_RAW_SHORT_DATA;
      h->sarq = b[70] != 0;
      h->full_message = b[71] != 0;
      h->bit_padding = (uint8_t)bits_to_uint(b + 72,8);
    }
    break;
  case DMR_DPF_UDT:
    h->kind = DMR_DH_UDT;
    h->udt_format = (uint8_t)bits_to_uint(b + 12,4);
    h->udt_pad_nibbles = (uint8_t)bits_to_uint(b + 64,5);
    h->blocks_to_follow = (uint8_t)(bits_to_uint(b + 70,2) + 1u);
    h->udt_supplementary = b[72] != 0;
    h->udt_protect = b[73] != 0;
    h->udt_opcode = (uint8_t)bits_to_uint(b + 74,6);
    break;
  default:
    // A reserved packet format: the CRC passed but there is nothing to read
    h->kind = DMR_DH_INVALID;
    return;
  }
  h->valid = true;
}

void dmr_data_header_from_burst(struct dmr_data_header *h,struct dmr_burst const *b,struct dmr_data_burst const *d){
  assert(h != NULL && b != NULL && d != NULL);
  dmr_data_header_parse(h,d->info,d->bptc_ok);
  h->fec_corrected = d->bptc_corrected;
  h->slot = b->slot;
  h->color_code = b->color_code;
  h->timestamp_us = b->timestamp_us;
}

int dmr_data_response_describe(char *buf,size_t size,uint8_t response_class,uint8_t type,uint8_t status){
  if(response_class == DMR_RESPONSE_ACK)
    return snprintf(buf,size,"ACK packet N(S)=%u received",(unsigned)status);
  if(response_class == DMR_RESPONSE_NACK){
    static char const * const reasons[8] = {
      "illegal format", "packet CRC failed", "recipient memory full", "out of sequence FSN",
      "undeliverable", "packet out of sequence", "invalid user", "reserved"};
    return snprintf(buf,size,"NACK %s (status %u)",reasons[type & 7u],(unsigned)status);
  }
  if(response_class == DMR_RESPONSE_SACK)
    return snprintf(buf,size,"SACK selective retry (type %u, status %u)",(unsigned)type,(unsigned)status);
  return snprintf(buf,size,"reserved class 3 (type %u, status %u)",(unsigned)type,(unsigned)status);
}

int dmr_data_header_describe(char *buf,size_t size,struct dmr_data_header const *h){
  size_t len = 0;
  char raw[24];
  {
    size_t rl = 0;
    hex_octets(raw,sizeof raw,&rl,h->octets,10);
  }
  if(!h->valid){
    append(buf,size,&len,"[DMR data] slot=%u header INVALID (%s%s) crcMask=%04X raw=%s",(unsigned)h->slot,
           h->fec_ok ? "" : "FEC ",h->crc_ok ? "" : "CRC",(unsigned)h->crc_observed_mask,raw);
    return finish(buf,size,len);
  }
  char const *kind = dmr_data_header_kind_name(h->kind);
  if(dmr_data_header_is_proprietary(h)){
    append(buf,size,&len,"[DMR data] slot=%u header %s sap=%u(%s) mfid=%02X",(unsigned)h->slot,kind,
           (unsigned)h->sap,dmr_sap_name(h->sap),(unsigned)h->mfid);
    if(h->kind == DMR_DH_MOTOROLA_ENCRYPTION || h->kind == DMR_DH_HYTERA_ENCRYPTION){
      // The key ID and IV are transmitted in the clear; they identify a key, they are not one
      append(buf,size,&len," %s alg=%02X key=%u iv=%08X",h->marks_encrypted ? "ENCRYPTED" : "clear",
             (unsigned)h->algorithm,(unsigned)h->key_id,(unsigned)h->iv);
    } else if(h->kind == DMR_DH_MOTOROLA_MNIS){
      append(buf,size,&len," app=%02X msg=%02X packet=%u prefix=%02X%02X%02X",(unsigned)h->mnis_application_type,
             (unsigned)h->mnis_message_type,(unsigned)h->mnis_packet_number,(unsigned)h->mnis_prefix[0],
             (unsigned)h->mnis_prefix[1],(unsigned)h->mnis_prefix[2]);
    }
    append(buf,size,&len," raw=%s",raw);
    return finish(buf,size,len);
  }

  append(buf,size,&len,"[DMR data] slot=%u header %s src=%u dst=%s%u sap=%u(%s) blocks=%u",(unsigned)h->slot,kind,
         (unsigned)h->source,h->group ? "TG " : "",(unsigned)h->destination,(unsigned)h->sap,dmr_sap_name(h->sap),
         (unsigned)h->blocks_to_follow);
  switch(h->kind){
  case DMR_DH_UNCONFIRMED:
    append(buf,size,&len," pad=%u fsn=%u%s%s",(unsigned)h->pad_octets,(unsigned)h->fragment_seq,
           h->full_message ? " full" : "",h->response_requested ? " response-requested" : "");
    break;
  case DMR_DH_CONFIRMED:
    append(buf,size,&len," pad=%u fsn=%u ns=%u%s%s%s",(unsigned)h->pad_octets,(unsigned)h->fragment_seq,
           (unsigned)h->send_seq,h->full_message ? " full" : "",h->resync ? " resync" : "",
           h->response_requested ? " response-requested" : "");
    break;
  case DMR_DH_RESPONSE: {
    char response[96];
    dmr_data_response_describe(response,sizeof response,h->response_class,h->response_type,h->response_status);
    append(buf,size,&len," %s",response);
    break;
  }
  case DMR_DH_DEFINED_SHORT_DATA:
    append(buf,size,&len," format=%u bitpad=%u%s%s%s",(unsigned)h->defined_format,(unsigned)h->bit_padding,
           h->full_message ? " full" : "",h->sarq ? " sarq" : "",h->response_requested ? " confirmed" : "");
    break;
  case DMR_DH_RAW_SHORT_DATA:
    append(buf,size,&len," sport=%u dport=%u bitpad=%u%s%s%s",(unsigned)h->source_port,(unsigned)h->destination_port,
           (unsigned)h->bit_padding,h->full_message ? " full" : "",h->sarq ? " sarq" : "",
           h->response_requested ? " confirmed" : "");
    break;
  case DMR_DH_STATUS_PRECODED:
    append(buf,size,&len," sport=%u dport=%u status=%u",(unsigned)h->source_port,(unsigned)h->destination_port,
           (unsigned)h->status);
    break;
  case DMR_DH_UDT:
    append(buf,size,&len," format=%u opcode=%u padnibbles=%u%s%s",(unsigned)h->udt_format,(unsigned)h->udt_opcode,
           (unsigned)h->udt_pad_nibbles,h->udt_supplementary ? " supplementary" : "",h->udt_protect ? " protect" : "");
    break;
  default:
    break;
  }
  return finish(buf,size,len);
}

// ---------------- Unified single block data ----------------

void dmr_usbd_from_burst(struct dmr_usbd *u,struct dmr_burst const *b,struct dmr_data_burst const *d){
  assert(u != NULL && b != NULL && d != NULL);
  memset(u,0,sizeof *u);
  u->slot = b->slot;
  u->color_code = b->color_code;
  u->timestamp_us = b->timestamp_us;
  u->fec_ok = d->bptc_ok;
  u->crc_ok = dmr_crc_ccitt_check(d->info,96,DMR_CRC_MASK_USB);
  bits_to_bytes(d->info,12,u->octets);
  u->valid = u->fec_ok && u->crc_ok;
  if(u->valid){
    u->service_type = (uint8_t)bits_to_uint(d->info,4);
    u->target = bits_to_uint(d->info + 56,24);
  }
}

int dmr_usbd_describe(char *buf,size_t size,struct dmr_usbd const *u){
  size_t len = 0;
  append(buf,size,&len,"[DMR data] slot=%u USBD %s service=%u target=%u raw=",(unsigned)u->slot,
         u->valid ? "ok" : "INVALID",(unsigned)u->service_type,(unsigned)u->target);
  hex_octets(buf,size,&len,u->octets,10);
  return finish(buf,size,len);
}

// ---------------- CRCs ----------------

void dmr_data_crc_convention_init(struct dmr_data_crc_convention *c){
  assert(c != NULL);
  memset(c,0,sizeof *c);
  c->crc9_serial_first = false;
  c->crc9_complement = true;
  c->crc9_mask[DMR_DATA_RATE_12] = DMR_CRC9_MASK_RATE12;
  c->crc9_mask[DMR_DATA_RATE_34] = DMR_CRC9_MASK_RATE34;
  c->crc9_mask[DMR_DATA_RATE_1] = DMR_CRC9_MASK_RATE1;
  c->crc32_swap_octet_pairs = true;
  c->crc32_complement = false;
  c->crc32_lsb_first = true;
  c->udt_crc_mask = 0x0000;
}

static struct dmr_data_crc_convention const *convention_or_default(struct dmr_data_crc_convention const *c,
                                                                     struct dmr_data_crc_convention *storage){
  if(c != NULL)
    return c;
  dmr_data_crc_convention_init(storage);
  return storage;
}

// The plain remainder: dmr_crc9() complements and masks, and a mask of 0x1FF undoes the complement
static uint16_t crc9_remainder(uint8_t const *data_bits,int ndata,uint8_t serial,bool serial_first){
  return dmr_crc9(data_bits,ndata,serial,0x1ff,serial_first);
}

uint16_t dmr_data_crc9(uint8_t const *data_bits,int ndata,uint8_t serial,enum dmr_data_rate rate,
                       struct dmr_data_crc_convention const *c){
  struct dmr_data_crc_convention storage;
  c = convention_or_default(c,&storage);
  uint16_t v = crc9_remainder(data_bits,ndata,serial,c->crc9_serial_first);
  if(c->crc9_complement)
    v ^= 0x1ff;
  return (uint16_t)((v ^ c->crc9_mask[rate]) & 0x1ff);
}

uint16_t dmr_data_crc9_observed(uint8_t const *data_bits,int ndata,uint8_t serial,uint16_t stored,bool serial_first){
  return (uint16_t)((stored ^ crc9_remainder(data_bits,ndata,serial,serial_first)) & 0x1ff);
}

uint32_t dmr_data_crc32_remainder(uint8_t const *octets,int noctets,bool swap_pairs){
  uint32_t reg = 0;
  uint8_t bits[8];
  for(int i=0; i < noctets; i++){
    int at = i;
    if(swap_pairs)
      at = (i % 2 == 0) ? (i + 1 < noctets ? i + 1 : i) : i - 1; // a last odd octet is taken alone
    uint_to_bits(octets[at],8,bits);
    reg = crc_remainder(bits,8,0x04C11DB7,32,reg);
  }
  return reg;
}

uint32_t dmr_data_crc32(uint8_t const *octets,int noctets,struct dmr_data_crc_convention const *c){
  struct dmr_data_crc_convention storage;
  c = convention_or_default(c,&storage);
  // dmr_packet_crc32() is the default reading for an even count
  uint32_t const v = (c->crc32_swap_octet_pairs && noctets % 2 == 0) ? dmr_packet_crc32(octets,noctets)
    : dmr_data_crc32_remainder(octets,noctets,c->crc32_swap_octet_pairs);
  return c->crc32_complement ? ~v : v;
}

static uint32_t lsb_first(uint8_t const c[4]){
  return (uint32_t)c[0] | ((uint32_t)c[1] << 8) | ((uint32_t)c[2] << 16) | ((uint32_t)c[3] << 24);
}
static uint32_t msb_first(uint8_t const c[4]){
  return ((uint32_t)c[0] << 24) | ((uint32_t)c[1] << 16) | ((uint32_t)c[2] << 8) | (uint32_t)c[3];
}

uint32_t dmr_data_crc32_stored(uint8_t const crc4[4],struct dmr_data_crc_convention const *c){
  struct dmr_data_crc_convention storage;
  c = convention_or_default(c,&storage);
  return c->crc32_lsb_first ? lsb_first(crc4) : msb_first(crc4);
}

void dmr_data_crc32_observed(struct dmr_crc32_observed *o,uint8_t const *octets,int noctets){
  memset(o,0,sizeof *o);
  if(noctets < 5)
    return;
  uint8_t const *c = octets + noctets - 4;
  uint32_t const swapped = dmr_data_crc32_remainder(octets,noctets - 4,true);
  uint32_t const straight = dmr_data_crc32_remainder(octets,noctets - 4,false);
  o->swapped_lsb_first = swapped ^ lsb_first(c);
  o->swapped_msb_first = swapped ^ msb_first(c);
  o->straight_lsb_first = straight ^ lsb_first(c);
  o->straight_msb_first = straight ^ msb_first(c);
}

// ---------------- Data blocks ----------------

static void read_confirmed_fields(struct dmr_data_block *blk,struct dmr_data_crc_convention const *c){
  int const data_bits = 8 * blk->octet_count - 16;
  blk->serial = (uint8_t)bits_to_uint(blk->bits,7);
  blk->crc9_stored = (uint16_t)bits_to_uint(blk->bits + 7,9);
  uint8_t const *data = blk->bits + 16;
  blk->crc9_ok = dmr_data_crc9(data,data_bits,blk->serial,blk->rate,c) == blk->crc9_stored;
  blk->crc9_observed_data_first = dmr_data_crc9_observed(data,data_bits,blk->serial,blk->crc9_stored,false);
  blk->crc9_observed_serial_first = dmr_data_crc9_observed(data,data_bits,blk->serial,blk->crc9_stored,true);
}

void dmr_data_block_decode(struct dmr_data_block *blk,enum dmr_data_rate rate,struct dmr_data_burst const *d,
                           struct dmr_data_crc_convention const *c){
  assert(blk != NULL && d != NULL);
  struct dmr_data_crc_convention storage;
  c = convention_or_default(c,&storage);
  memset(blk,0,sizeof *blk);
  blk->rate = rate;
  blk->octet_count = dmr_data_block_octets(rate);
  if(rate == DMR_DATA_RATE_12){
    // dmrmsg ran the BPTC(196,96) decode; info[] is filled even when it was refused
    blk->fec_ok = d->bptc_ok;
    blk->corrected = d->bptc_corrected;
    blk->weighted_errors = d->bptc_weighted_errors;
    memcpy(blk->bits,d->info,96);
  } else if(rate == DMR_DATA_RATE_34){
    struct dmr_trellis34 r;
    dmr_trellis34_decode(&r,blk->bits,d->payload,d->payload_confidence,DMR_TRELLIS34_AUTO_LIMIT);
    blk->fec_ok = r.ok;
    blk->corrected = r.corrected_points;
    blk->weighted_errors = r.weighted_errors;
  } else {
    blk->fec_ok = true;
    for(int i=0; i < 96; i++){
      blk->bits[i] = d->payload[i];
      blk->bits[96 + i] = d->payload[100 + i];
    }
  }
  bits_to_bytes(blk->bits,blk->octet_count,blk->octets);
  read_confirmed_fields(blk,c);
}

// ---------------- Packets ----------------

int dmr_data_packet_describe(char *buf,size_t size,struct dmr_data_packet const *p){
  size_t len = 0;
  enum dmr_data_rate rate = DMR_DATA_RATE_12;
  for(int i=0; i < p->blocks_expected; i++){
    if(p->blocks[i].received){
      rate = p->blocks[i].rate;
      break;
    }
  }
  append(buf,size,&len,"[DMR data] slot=%u packet %s rate=%s src=%u dst=%s%u sap=%u(%s) blocks=%d/%d good=%d dup=%d "
         "end=%s %s len=%zu",(unsigned)p->slot,dmr_data_header_kind_name(p->header.kind),dmr_data_rate_name(rate),
         (unsigned)p->source,p->group ? "TG " : "",(unsigned)p->destination,(unsigned)p->sap,dmr_sap_name(p->sap),
         p->blocks_received,p->blocks_expected,p->blocks_good,p->duplicate_blocks,dmr_packet_end_name(p->end),
         p->complete ? "COMPLETE" : "INCOMPLETE",p->payload_length);
  if(p->crc_checked && p->crc_ok){
    append(buf,size,&len," crc=ok");
  } else if(p->crc_checked && p->header.kind == DMR_DH_UDT){
    append(buf,size,&len," crc=FAIL(udt mask %04X)",(unsigned)p->udt_crc_observed_mask);
  } else if(p->crc_checked){
    // The CRC-32 evidence: stored XOR remainder for the four readings
    append(buf,size,&len," crc=FAIL(stored %08X computed %08X; observed %08X %08X %08X %08X)",(unsigned)p->crc_stored,
           (unsigned)p->crc_computed,(unsigned)p->crc32_observed.swapped_lsb_first,
           (unsigned)p->crc32_observed.swapped_msb_first,(unsigned)p->crc32_observed.straight_lsb_first,
           (unsigned)p->crc32_observed.straight_msb_first);
  } else {
    append(buf,size,&len," crc=unchecked");
  }
  if(p->confirmed){
    // The CRC-9 evidence: "stored XOR remainder" of the first received block, both bit orders
    for(int i=0; i < p->blocks_expected; i++){
      struct dmr_data_packet_block const *b = &p->blocks[i];
      if(!b->received)
        continue;
      append(buf,size,&len," crc9[%s serial=%u data-first=%03X serial-first=%03X]",b->crc9_ok ? "ok" : "FAIL",
             (unsigned)b->serial,(unsigned)b->crc9_observed_data_first,(unsigned)b->crc9_observed_serial_first);
      break;
    }
  }
  if(p->blocks_fec_refused > 0)
    append(buf,size,&len," fec-doubted=%d",p->blocks_fec_refused);
  if(p->encrypted)
    append(buf,size,&len," ENCRYPTED mfid=%02X alg=%02X key=%u iv=%08X",(unsigned)p->encryption_mfid,
           (unsigned)p->algorithm,(unsigned)p->key_id,(unsigned)p->iv);
  if(p->retransmission)
    append(buf,size,&len," retransmission");
  return finish(buf,size,len);
}

// ---------------- The assembler ----------------

void dmr_data_config_init(struct dmr_data_config *c){
  assert(c != NULL);
  memset(c,0,sizeof *c);
  c->timeout_bursts = 6;
  c->retransmission_window_us = 30000000;
  dmr_data_crc_convention_init(&c->crc);
  c->classify = true;
}

// One block position of the open packet
struct place {
  struct dmr_data_packet_block info;
  int octet_count;
  uint8_t octets[24];
};

// One timeslot's reassembly
struct slot_state {
  uint8_t config_slot;         // 1 or 2; 0 = takes every burst it is given (the slot not known)
  struct dmr_data_stats stats;

  uint64_t last_clock;
  bool have_clock;

  // The open packet
  bool open;
  struct dmr_data_header header;
  bool has_second;
  struct dmr_data_header second;
  bool confirmed;
  int block_count;             // data blocks expected
  int cursor;                  // the place the next block burst takes
  bool any_block;
  int duplicates;
  struct place places[DMR_DATA_MAX_BLOCKS];
  uint64_t first_timestamp_us;
  uint64_t last_timestamp_us;
  uint8_t color_code;
  uint8_t slot;

  // The last complete confirmed packet, to recognise a retransmission
  bool have_previous;
  uint32_t previous_source;
  uint32_t previous_destination;
  uint8_t previous_send_seq;
  uint8_t previous_fragment_seq;
  uint32_t previous_crc;
  uint64_t previous_timestamp_us;
};

struct dmr_data_assembler {
  struct dmr_data_handlers handlers;
  struct dmr_data_config config;
  struct slot_state slots[3];
  // Scratch for end_packet(): the packet being handed on, what it carries, the bits of a UDT's blocks
  struct dmr_data_packet packet;
  struct dmr_data_message message;
  uint8_t bits[8 * DMR_DATA_MAX_OCTETS];
};

static void slot_reset(struct slot_state *s){
  s->open = false;
  s->have_clock = false;
  s->have_previous = false;
}

// A place holds a block that passed the check a block has: the CRC-9 of a confirmed block. An
// unconfirmed block has none (the packet CRC covers it). The channel decoder's own judgement (fec_ok) is
// recorded and counted but does not veto a block whose CRC passes: the CRCs are the stronger check, and
// a rate 3/4 decode has no way to be sure of itself (dmrfec.c)
static bool good(struct slot_state const *s,struct place const *p){
  return p->info.received && (!s->confirmed || p->info.crc9_ok);
}

static void end_packet(struct dmr_data_assembler *a,struct slot_state *s,enum dmr_packet_end reason);

static void skip_place(struct dmr_data_assembler *a,struct slot_state *s){
  s->cursor++;
  if(s->cursor >= s->block_count)
    end_packet(a,s,DMR_PACKET_ALL_BLOCKS);
}

static void store(struct slot_state *s,int index,struct dmr_data_block const *blk){
  struct place *p = &s->places[index];
  p->info.received = true;
  p->info.rate = blk->rate;
  p->info.fec_ok = blk->fec_ok;
  p->info.crc9_ok = blk->crc9_ok;
  p->info.serial = blk->serial;
  p->info.crc9_observed_data_first = blk->crc9_observed_data_first;
  p->info.crc9_observed_serial_first = blk->crc9_observed_serial_first;
  p->octet_count = blk->octet_count;
  memcpy(p->octets,blk->octets,sizeof p->octets);
}

static void end_packet(struct dmr_data_assembler *a,struct slot_state *s,enum dmr_packet_end reason){
  s->open = false;

  struct dmr_data_packet *p = &a->packet;
  memset(p,0,sizeof *p);
  p->slot = s->slot;
  p->color_code = s->color_code;
  p->header = s->header;
  p->has_second_header = s->has_second;
  p->second_header = s->second;
  p->source = s->header.source;
  p->destination = s->header.destination;
  p->group = s->header.group;
  p->sap = s->header.sap;
  p->confirmed = s->confirmed;
  p->end = reason;
  p->blocks_expected = s->block_count;
  p->duplicate_blocks = s->duplicates;
  p->first_timestamp_us = s->first_timestamp_us;
  p->last_timestamp_us = s->last_timestamp_us;
  if(s->has_second && s->second.marks_encrypted){
    p->encrypted = true;
    p->encryption_mfid = s->second.mfid;
    p->algorithm = s->second.algorithm;
    p->key_id = s->second.key_id;
    p->iv = s->second.iv;
  }

  // The size of a block that never arrived is taken from one that did
  int fill_octets = 0;
  for(int i=0; i < s->block_count; i++){
    if(s->places[i].info.received){
      fill_octets = s->places[i].octet_count;
      break;
    }
  }
  int const skip = s->confirmed ? 2 : 0;
  bool all_received = true;
  bool all_good = true;
  size_t total = 0;
  for(int i=0; i < s->block_count; i++){
    struct place const *place = &s->places[i];
    p->blocks[i] = place->info;
    if(place->info.received){
      p->blocks_received++;
      if(!place->info.fec_ok)
        p->blocks_fec_refused++;
      memcpy(p->payload + total,place->octets + skip,(size_t)(place->octet_count - skip));
      total += (size_t)(place->octet_count - skip);
    } else {
      all_received = false;
      if(fill_octets > skip){
        memset(p->payload + total,0,(size_t)(fill_octets - skip));
        total += (size_t)(fill_octets - skip);
      }
    }
    if(good(s,place))
      p->blocks_good++;
    else
      all_good = false;
  }
  p->payload_length = total;
  p->payload_bits = 8 * total;

  bool const udt = s->header.kind == DMR_DH_UDT;
  size_t const crc_octets = udt ? 2 : 4;
  if(all_received && total > crc_octets){
    p->crc_checked = true;
    if(udt){
      int const nbits = (int)(8 * total);
      bytes_to_bits(p->payload,(int)total,a->bits);
      p->udt_crc_observed_mask = dmr_crc_ccitt_observed_mask(a->bits,nbits);
      p->crc_stored = bits_to_uint(a->bits + nbits - 16,16);
      p->crc_computed = dmr_crc_ccitt(a->bits,nbits - 16,a->config.crc.udt_crc_mask);
    } else {
      p->crc_stored = dmr_data_crc32_stored(p->payload + total - 4,&a->config.crc);
      p->crc_computed = dmr_data_crc32(p->payload,(int)total - 4,&a->config.crc);
      dmr_data_crc32_observed(&p->crc32_observed,p->payload,(int)total);
    }
    p->crc_ok = p->crc_stored == p->crc_computed;
  }
  p->complete = all_good && (p->crc_checked ? p->crc_ok : s->block_count == 0);

  memcpy(p->raw_payload,p->payload,total);
  p->raw_payload_length = total;
  if(p->crc_checked && !p->encrypted){
    // Remove the CRC and the padding the header counts
    size_t bits = 8 * (total - crc_octets);
    size_t pad = 0;
    switch(s->header.kind){
    case DMR_DH_UNCONFIRMED:
    case DMR_DH_CONFIRMED: pad = 8u * s->header.pad_octets; break;
    case DMR_DH_RAW_SHORT_DATA:
    case DMR_DH_DEFINED_SHORT_DATA: pad = s->header.bit_padding; break;
    case DMR_DH_UDT: pad = 4u * s->header.udt_pad_nibbles; break;
    default: break;
    }
    bits = pad < bits ? bits - pad : 0;
    p->payload_length = (bits + 7) / 8;
    p->payload_bits = bits;
    p->payload_trimmed = true;
  }

  if(p->complete && p->confirmed){
    bool const same = s->have_previous && s->previous_source == p->source && s->previous_destination == p->destination
      && s->previous_send_seq == s->header.send_seq && s->previous_fragment_seq == s->header.fragment_seq
      && s->previous_crc == p->crc_stored && p->first_timestamp_us >= s->previous_timestamp_us
      && p->first_timestamp_us - s->previous_timestamp_us <= a->config.retransmission_window_us;
    p->retransmission = same;
    s->have_previous = true;
    s->previous_source = p->source;
    s->previous_destination = p->destination;
    s->previous_send_seq = s->header.send_seq;
    s->previous_fragment_seq = s->header.fragment_seq;
    s->previous_crc = p->crc_stored;
    s->previous_timestamp_us = p->last_timestamp_us;
  }

  if(p->complete){
    s->stats.packets_complete++;
  } else {
    s->stats.packets_incomplete++;
    if(p->crc_checked && !p->crc_ok)
      s->stats.packet_crc_failures++;
  }
  s->block_count = 0;
  p->app = NULL;
  if(a->config.classify){
    dmr_data_classify(&a->message,p,NULL);
    p->app = &a->message;
  }
  if(a->handlers.on_packet != NULL)
    (*a->handlers.on_packet)(a->handlers.arg,p);
}

static void handle_header(struct dmr_data_assembler *a,struct slot_state *s,struct dmr_burst const *b,
                          struct dmr_data_burst const *d){
  struct dmr_data_header h;
  dmr_data_header_from_burst(&h,b,d);
  if(!h.valid){
    s->stats.header_failures++;
    if(a->handlers.on_header != NULL)
      (*a->handlers.on_header)(a->handlers.arg,&h);
    if(s->open)
      skip_place(a,s);
    return;
  }
  s->stats.headers++;
  if(a->handlers.on_header != NULL)
    (*a->handlers.on_header)(a->handlers.arg,&h);

  if(dmr_data_header_is_proprietary(&h)){
    if(s->open && !s->has_second && !s->any_block && s->cursor == 0){
      s->has_second = true;
      s->second = h;
      s->last_timestamp_us = b->timestamp_us;
      if(s->block_count > 0)
        s->block_count--;   // the second header was one of the blocks to follow
      if(s->block_count == 0)
        end_packet(a,s,DMR_PACKET_ALL_BLOCKS);
    } else {
      s->stats.orphan_headers++;
      if(s->open)
        end_packet(a,s,DMR_PACKET_NEW_HEADER);
    }
    return;
  }

  if(s->open){
    if(!s->any_block && !s->has_second && s->cursor == 0 && memcmp(h.octets,s->header.octets,sizeof h.octets) == 0){
      s->stats.repeated_headers++;  // the same header again before any block
      return;
    }
    end_packet(a,s,DMR_PACKET_NEW_HEADER);
  }
  if(h.blocks_to_follow == 0)
    return;  // a header with nothing after it: status, an ACK

  s->open = true;
  s->header = h;
  s->has_second = false;
  memset(&s->second,0,sizeof s->second);
  s->confirmed = dmr_data_header_uses_confirmed_blocks(&h);
  s->block_count = h.blocks_to_follow;
  s->cursor = 0;
  s->any_block = false;
  s->duplicates = 0;
  memset(s->places,0,sizeof s->places[0] * (size_t)s->block_count);
  s->first_timestamp_us = b->timestamp_us;
  s->last_timestamp_us = b->timestamp_us;
  s->color_code = b->color_code;
  s->slot = b->slot;
}

static void handle_block(struct dmr_data_assembler *a,struct slot_state *s,struct dmr_burst const *b,
                         struct dmr_data_burst const *d,enum dmr_data_rate rate){
  if(!s->open){
    s->stats.orphan_blocks++;
    return;
  }
  struct dmr_data_block blk;
  dmr_data_block_decode(&blk,rate,d,&a->config.crc);
  s->stats.blocks++;
  if(!blk.fec_ok)
    s->stats.block_fec_failures++;
  if(s->confirmed && !blk.crc9_ok)
    s->stats.crc9_failures++;
  s->any_block = true;
  s->last_timestamp_us = b->timestamp_us;

  if(s->confirmed && blk.crc9_ok && blk.serial < s->block_count){
    // The serial number names the place
    int const index = blk.serial;
    if(good(s,&s->places[index])){
      s->duplicates++;
      s->stats.duplicate_blocks++;
    } else {
      store(s,index,&blk);
      if(index >= s->cursor)
        s->cursor = index + 1;
    }
  } else {
    if(s->cursor < s->block_count && !s->places[s->cursor].info.received)
      store(s,s->cursor,&blk);
    s->cursor++;
  }

  bool all_good = true;
  for(int i=0; i < s->block_count; i++)
    all_good = all_good && good(s,&s->places[i]);
  if(all_good || s->cursor >= s->block_count)
    end_packet(a,s,DMR_PACKET_ALL_BLOCKS);
}

static void slot_on_burst(struct dmr_data_assembler *a,struct slot_state *s,struct dmr_burst const *b,
                          struct dmr_data_burst const *d){
  uint64_t const frame = DMR_SLOT_BURST_SPACING_DIBITS;
  if(s->config_slot != 0 && b->slot != s->config_slot){
    // The other slot: only its clock is used, to notice that this slot has gone quiet
    if(s->open && s->have_clock && b->dibit_clock > s->last_clock
       && (b->dibit_clock - s->last_clock) / frame > (uint64_t)a->config.timeout_bursts){
      s->stats.timeouts++;
      end_packet(a,s,DMR_PACKET_TIMEOUT);
    }
    return;
  }

  // Slot periods since the last burst of this slot: 1 = the next one
  uint64_t periods = 1;
  if(s->have_clock && b->dibit_clock > s->last_clock){
    periods = (b->dibit_clock - s->last_clock + frame / 2) / frame;
    if(periods == 0)
      periods = 1;
  }
  s->last_clock = b->dibit_clock;
  s->have_clock = true;
  if(s->open){
    if(periods > (uint64_t)a->config.timeout_bursts){
      s->stats.timeouts++;
      end_packet(a,s,DMR_PACKET_TIMEOUT);
    } else if(periods > 1){
      s->cursor += (int)(periods - 1);  // bursts that never arrived
      if(s->cursor >= s->block_count)
        end_packet(a,s,DMR_PACKET_ALL_BLOCKS);
    }
  }

  if(dmr_is_voice(b->kind) || b->kind == DMR_KIND_REVERSE_CHANNEL){
    if(s->open)
      end_packet(a,s,DMR_PACKET_INTERRUPTED);
    return;
  }
  if(!b->slot_type_valid){
    // A data burst whose type is not known: if a packet is open it takes a block's place
    if(s->open)
      skip_place(a,s);
    return;
  }

  enum dmr_data_rate rate = DMR_DATA_RATE_12;
  if(b->data_type == DMR_DT_DATA_HEADER){
    handle_header(a,s,b,d);
  } else if(dmr_data_rate_of(b->data_type,&rate)){
    handle_block(a,s,b,d,rate);
  } else {
    if(s->open)
      end_packet(a,s,DMR_PACKET_INTERRUPTED);
    if(b->data_type == DMR_DT_USB){
      struct dmr_usbd u;
      dmr_usbd_from_burst(&u,b,d);
      s->stats.unified_single_blocks++;
      if(a->handlers.on_usbd != NULL)
        (*a->handlers.on_usbd)(a->handlers.arg,&u);
    }
  }
}

struct dmr_data_assembler *dmr_data_create(struct dmr_data_handlers const *h,struct dmr_data_config const *config){
  struct dmr_data_assembler *a = calloc(1,sizeof *a);
  if(a == NULL)
    return NULL;
  if(h != NULL)
    a->handlers = *h;
  if(config != NULL)
    a->config = *config;
  else
    dmr_data_config_init(&a->config);
  for(int i=0; i < 3; i++)
    a->slots[i].config_slot = (uint8_t)i;
  return a;
}

void dmr_data_destroy(struct dmr_data_assembler *a){
  free(a);
}

void dmr_data_on_burst(struct dmr_data_assembler *a,struct dmr_burst const *b,struct dmr_burst_messages const *m){
  assert(a != NULL && b != NULL);
  // What dmrmsg made of a data burst; decoded here when the caller has nothing
  struct dmr_data_burst local;
  struct dmr_data_burst const *d = NULL;
  if(b->kind == DMR_KIND_DATA && b->slot_type_valid){
    if(m != NULL && m->has_data){
      d = &m->data;
    } else {
      dmr_data_decode(&local,b,NULL);
      d = &local;
    }
  }
  if(b->slot == 1 || b->slot == 2){
    slot_on_burst(a,&a->slots[1],b,d);
    slot_on_burst(a,&a->slots[2],b,d);
  } else {
    slot_on_burst(a,&a->slots[0],b,d);
  }
}

void dmr_data_flush(struct dmr_data_assembler *a){
  assert(a != NULL);
  for(int i=0; i < 3; i++){
    if(a->slots[i].open)
      end_packet(a,&a->slots[i],DMR_PACKET_FLUSH);
  }
}

void dmr_data_reset(struct dmr_data_assembler *a){
  assert(a != NULL);
  for(int i=0; i < 3; i++)
    slot_reset(&a->slots[i]);
}

void dmr_data_sync_lost(struct dmr_data_assembler *a){
  dmr_data_flush(a);
  dmr_data_reset(a);
}

void dmr_data_reset_slot(struct dmr_data_assembler *a,int slot){
  assert(a != NULL);
  if(slot < 0 || slot > 2)
    return;
  if(a->slots[slot].open)
    end_packet(a,&a->slots[slot],DMR_PACKET_FLUSH);
  slot_reset(&a->slots[slot]);
}

bool dmr_data_packet_open(struct dmr_data_assembler const *a){
  return a->slots[0].open || a->slots[1].open || a->slots[2].open;
}

struct dmr_data_stats const *dmr_data_get_stats(struct dmr_data_assembler const *a,int slot){
  if(slot < 0 || slot > 2)
    return NULL;
  return &a->slots[slot].stats;
}
