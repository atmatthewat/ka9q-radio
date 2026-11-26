// dmrd's packet stream: each packet data packet, and each unified single block, as one datagram of a
// fixed header and the octets it carried (docs/dmrd.md, "Packet stream", is the receiver's view)
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRPACKET_H
#define _DMRPACKET_H 1

#include <stddef.h>
#include <stdint.h>

#include "dmrdata.h"

// The header, all numbers big-endian. Laid out for any digital mode's packets (the protocol octet
// says which; the network code is 16 bits and the message indicator 72 so that a NAC and a P25 MI
// fit), though only dmrd sends it so far
enum {
  DMR_PACKET_PT = 98,                 // RTP payload type: dynamic; 96 is packetd's AX.25, 97 p25d's frames
  DMR_PACKET_VERSION = 1,
  DMR_PACKET_PROTOCOL_DMR = 1,
  DMR_PACKET_RECORD_PACKET = 1,       // a packet: data header(s) and blocks, short data, UDT
  DMR_PACKET_RECORD_SINGLE_BLOCK = 2, // a unified single block (12 octets)
  // Flags (octet 3)
  DMR_PACKET_COMPLETE = 0x01,         // every block arrived and every check passed
  DMR_PACKET_ENCRYPTED = 0x02,        // the octets are ciphertext
  DMR_PACKET_GROUP = 0x04,            // the destination is a talkgroup
  DMR_PACKET_CONFIRMED = 0x08,        // confirmed delivery (the blocks carried serial numbers and CRC-9)
  DMR_PACKET_TRIMMED = 0x10,          // pad and packet CRC removed: the octets are the user data
  DMR_PACKET_CRC_CHECKED = 0x20,      // the packet CRC could be checked (every block arrived) ...
  DMR_PACKET_CRC_OK = 0x40,           // ... and passed
  DMR_PACKET_RETRANSMISSION = 0x80,   // repeats the previous complete confirmed packet
  DMR_PACKET_HEADER = 48,             // the fixed header; the data headers follow it, then the data
  DMR_PACKET_DATA_HEADER = 12,        // one data header as decoded, CRC included
  DMR_PACKET_MAX = DMR_PACKET_HEADER + 2 * DMR_PACKET_DATA_HEADER + DMR_DATA_MAX_OCTETS,
};

// The datagram for a packet that ended (its octets as dmrdata.h delivers them), heard on a carrier
// at frequency_hz. Returns its length, or 0 if size is too small
size_t dmr_packet_encode(uint8_t *buf,size_t size,struct dmr_data_packet const *p,uint32_t frequency_hz);
size_t dmr_packet_encode_single_block(uint8_t *buf,size_t size,struct dmr_usbd const *u,uint32_t frequency_hz);

#endif
