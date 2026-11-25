// dmrd's packet stream: the datagram for a packet or a unified single block (dmrpacket.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
//
// Layout (all numbers big-endian):
//   0      version, 1
//   1      protocol: 1 DMR
//   2      record: 1 packet, 2 unified single block
//   3      flags (DMR_PACKET_*)
//   4      slot (1, 2; 0 not known)
//   5      reserved, 0
//   6-7    network code: the DMR colour code
//   8      format: a packet's data header kind (dmrdata.h enum dmr_data_header_kind); a single block's
//          service type
//   9      SAP (packets; 0 for a single block)
//   10     application (dmrdataapp.h enum dmr_app_kind; 0 when not classified)
//   11     blocks expected, 12 received, 13 good (received and, confirmed, the CRC-9 passed); 255 at most
//   14-17  source (24 bits; 0 for a single block)
//   18-21  destination (24 bits; a single block's target)
//   22-29  time of the first burst, ns since the GPS epoch (radiod's clock)
//   30-33  the carrier's frequency, Hz
//   34     encryption: manufacturer ID of the encryption header (0 if none)
//   35     algorithm
//   36-37  key ID
//   38-46  message indicator, 72 bits: DMR's 32-bit IV in octets 43-46, the rest 0
//   47     reserved, 0
//   48-    the octets: trimmed (flag), the user data; otherwise every block's data octets in place,
//          pad and CRC included, missing blocks zero-filled. Their bit length is the datagram's octets
//          less 48, times 8, except in trimmed short data and UDT, whose last octet may be partly pad:
//          the bit length then is in the format's own fields (and in dmrd's log line)
#include <string.h>

#include "dmrdataapp.h"
#include "dmrpacket.h"

static uint8_t *put16(uint8_t *p,uint32_t v){ p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return p + 2; }
static uint8_t *put32(uint8_t *p,uint32_t v){ p = put16(p,v >> 16); return put16(p,v); }
static uint8_t *put64(uint8_t *p,uint64_t v){ p = put32(p,(uint32_t)(v >> 32)); return put32(p,(uint32_t)v); }
static uint8_t clip(int n){ return (uint8_t)(n < 0 ? 0 : n > 255 ? 255 : n); }

static void header(uint8_t *b,int record,uint8_t flags,uint8_t slot,uint8_t color_code,uint8_t format,uint8_t sap,
                   uint8_t app,uint32_t source,uint32_t destination,uint64_t when_us,uint32_t frequency_hz){
  memset(b,0,DMR_PACKET_HEADER);
  b[0] = DMR_PACKET_VERSION;
  b[1] = DMR_PACKET_PROTOCOL_DMR;
  b[2] = (uint8_t)record;
  b[3] = flags;
  b[4] = slot;
  put16(b + 6,color_code & 0x0f);
  b[8] = format;
  b[9] = sap;
  b[10] = app;
  put32(b + 14,source & 0xffffff);
  put32(b + 18,destination & 0xffffff);
  put64(b + 22,when_us * 1000);
  put32(b + 30,frequency_hz);
}

size_t dmr_packet_encode(uint8_t *buf,size_t size,struct dmr_data_packet const *p,uint32_t frequency_hz){
  size_t const n = p->payload_length <= sizeof p->payload ? p->payload_length : sizeof p->payload;
  if(size < DMR_PACKET_HEADER + n)
    return 0;
  uint8_t flags = 0;
  if(p->complete) flags |= DMR_PACKET_COMPLETE;
  if(p->encrypted) flags |= DMR_PACKET_ENCRYPTED;
  if(p->group) flags |= DMR_PACKET_GROUP;
  if(p->confirmed) flags |= DMR_PACKET_CONFIRMED;
  if(p->payload_trimmed) flags |= DMR_PACKET_TRIMMED;
  if(p->crc_checked) flags |= DMR_PACKET_CRC_CHECKED;
  if(p->crc_checked && p->crc_ok) flags |= DMR_PACKET_CRC_OK;
  if(p->retransmission) flags |= DMR_PACKET_RETRANSMISSION;
  header(buf,DMR_PACKET_RECORD_PACKET,flags,p->slot,p->color_code,(uint8_t)p->header.kind,p->sap & 0x0f,
         p->app != NULL ? (uint8_t)p->app->kind : 0,p->source,p->destination,p->first_timestamp_us,frequency_hz);
  buf[11] = clip(p->blocks_expected);
  buf[12] = clip(p->blocks_received);
  buf[13] = clip(p->blocks_good);
  if(p->encrypted){
    buf[34] = p->encryption_mfid;
    buf[35] = p->algorithm;
    put16(buf + 36,p->key_id);
    put32(buf + 43,p->iv);
  }
  memcpy(buf + DMR_PACKET_HEADER,p->payload,n);
  return DMR_PACKET_HEADER + n;
}

size_t dmr_packet_encode_single_block(uint8_t *buf,size_t size,struct dmr_usbd const *u,uint32_t frequency_hz){
  size_t const n = sizeof u->octets;
  if(size < DMR_PACKET_HEADER + n)
    return 0;
  uint8_t const flags = (u->valid && u->fec_ok && u->crc_ok ? DMR_PACKET_COMPLETE | DMR_PACKET_CRC_CHECKED | DMR_PACKET_CRC_OK : 0)
    | DMR_PACKET_TRIMMED;
  header(buf,DMR_PACKET_RECORD_SINGLE_BLOCK,flags,u->slot,u->color_code,u->service_type,0,0,0,u->target,
         u->timestamp_us,frequency_hz);
  buf[11] = buf[12] = 1;
  buf[13] = u->fec_ok && u->crc_ok ? 1 : 0;
  memcpy(buf + DMR_PACKET_HEADER,u->octets,n);
  return DMR_PACKET_HEADER + n;
}
