// What a reassembled DMR data packet carries (see dmrdataapp.h): IPv4 / UDP, Motorola LRRP, ARS and TMS,
// Hytera tokens, defined short data and UDT text, and the dispatcher over them
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "dmrdata.h"
#include "dmrdataapp.h"

// Theory of operation
//
// Every parser here obeys one rule: a read past the end of the payload, or a value that cannot be, makes
// the whole parse fail; the message then stays named (DMR_APP_IDENTIFIED) with its octets and no fields.
// PARTIAL means the fields given are sound and something after them was not understood. describe()
// names a message and never prints its text, coordinates, a password or payload octets.
//
// IPv4 and UDP. SAP 4 carries an IPv4 datagram: a plain RFC 791 header and RFC 768 UDP header, read as
// sdrtrunk reads them (GPL-3, Dennis Sheirer, github.com/DSheirer/sdrtrunk, module/decode/ip/ipv4/
// IPV4Header.java, ip/udp/UDPHeader.java); here the IPv4 header checksum and the UDP checksum are also
// verified. SAP 3 is the TS 102 361-3 compressed header, which neither sdrtrunk nor OP25 parses: IPv4
// identification (16), SAID (4), DAID (4), one opcode bit and SPID (7), one opcode bit and DPID (7), then a
// 16-bit source port if SPID is 0 and a 16-bit destination port if DPID is 0; SPID / DPID 1 = UDP 5016, 2
// = 5017 (TS 102 361-3 tables 7.14-7.21; the 2-bit header compression opcode is not checked). It is a
// hint until a capture confirms it, and the dispatcher does not use the ports it gives. An encrypted or
// incomplete packet is never split.
//
// Motorola LRRP (UDP 4001, or MNIS application 0x01 / 0x11), from sdrtrunk module/decode/ip/mototrbo/
// lrrp/ (LRRPHeader, LRRPPacket, LRRPPacketType, token/*), the only description there is, with no
// example payloads: type (8), length (8) = the octets that follow, then tokens, each an id octet and a
// payload whose size the id fixes (or, for the request ID, a length octet gives). Where this differs from
// sdrtrunk, each time on the side of saying less: the length octet must equal the octets that follow it;
// a token that runs past the end, a date or time that cannot be, or a heading of 360 degrees or more
// fails the message; an id sdrtrunk does not list stops the parse (PARTIAL, the rest kept; as the first
// token, nothing was understood and the message stays identified), where sdrtrunk steps one octet and
// reads the unknown token's payload as more tokens; token 0x22 is the request's ID (sdrtrunk's
// "IDENTITY"), kept as sent; speed is given raw and at sdrtrunk's 1/100 scale, its unit not known;
// latitude is a sign bit and 31 bits, longitude 32 bits two's complement, sdrtrunk's reading.
//
// Motorola ARS (UDP 4005, or MNIS application 0x33), from sdrtrunk module/decode/ip/mototrbo/ars/:
//   length (16)                          the octets that follow
//   E A P C type(4)                      extension, acknowledge, priority, control / user, PDU type
//   [ E event(2) encoding(5) ]           when the first E is set (registrations)
//   [ . value(7) ]                       the same octet in an acknowledgement: refresh time or reason
//   size (8), device identifier          registrations; the radio ID in ASCII digits
//   size (8), user identifier
//   size (8), password
// Where this differs from sdrtrunk: the length must equal the octets that follow (sdrtrunk has the check
// and never calls it); an identifier whose size runs past the end fails the message (sdrtrunk skips sizes
// of 8 and more without moving past them); sizes of 8 and more are read; a registration may end after
// any identifier; the device identifier must be printable ASCII. The password is carried in the clear on
// the air; it is kept and never put in a log line.
//
// Motorola TMS (UDP 4007). sdrtrunk (mototrbo/tms/TMSHeader, TMSPacket) says only: four header octets,
// then UTF-16 little-endian text to the end. The header read here is NOT from sdrtrunk and has no second
// source; it is the Moto.Net project's TMS layout as recalled, shaped like the ARS header:
//   length (16), E A R C type(4) (0 = message, 0xF = acknowledgement), address size (8) and address,
//   [ E . . seq(5) ] when the first E is set, [ E . . encoding(5) ] when that octet's E is set (4 =
//   UTF-16LE), then the text, commonly starting with CR LF.
// In the common message (length, A0 00 8x 04, text) sdrtrunk's "four octets" are the length and the two
// after it, so it reads the sequence and encoding octets as the first character; the two readings agree
// on everything after. The guards: the length must match, the type must be a message or an
// acknowledgement, the header chain must fit with at most two extension octets, and the text must be
// whole UTF-16 code units with no unpaired surrogate. A leading CR LF and trailing NULs are dropped.
//
// Hytera tokens, from sdrtrunk module/decode/ip/hytera/ (sds/HyteraTokenHeader, HyteraTokenType,
// TmsMessageHeader, RrsMessageHeader, MessageId, SourceId, DestinationId, Encoding, Payload, RrsUnknown;
// sms/HyteraSmsPacket; rrs/HyteraRrsPacket; dmr/message/type/HyteraEncodeFormat), whose own comments call
// the fields unconfirmed. A run of tokens, each a 16-bit opcode and a fixed content or a 16-bit length and
// that many octets: 0x0200 RRS header (one octet, the length as two BCD digits), 0x0201 TMS header (the
// length as four BCD digits, 16 flag bits), 0x0001 message ID, 0x0002 source, 0x0003 destination (32-bit
// numbers; a destination above 0xFFFFFF is an IP address whose low 24 bits are the radio), 0x0101
// encoding, 0x0102 payload, 0x0703 (RRS, unknown, empty). A text message has the TMS header, an encoding
// and a payload; a registration the RRS header and a destination. Where this differs from sdrtrunk: a
// token running past the end or a BCD digit above 9 fails the message; the packet arrives here without
// its pad and CRC, so an unknown opcode stops the parse (PARTIAL); an ID whose content is not four
// octets is not read as a number (PARTIAL); 16-bit text with no byte order mark is big-endian (Java
// "UTF-16"); GBK is named, not transcoded; encoding 5 (NMEA GPS) makes a Hytera location whose payload
// is kept as octets; whether an RRS message registers or de-registers is not known.
//
// Defined short data (DD format, sdrtrunk dmr/message/type/DefinedDataFormat.java, which decodes no text:
// the decoding here is this code's own, from the format names) and UDT (format numbers and readings from
// sdrtrunk UnifiedDataTransportFormat.java and UDTShortMessageService.java: 16-bit Unicode, ISO 7-bit,
// ISO 8-bit, BCD). 7-bit characters are packed most significant bit first with no fill (sdrtrunk
// parseISO7); 16-bit text with no byte order mark is big-endian; a final U+0006 of UDT 16-bit text is
// dropped when it is there (sdrtrunk drops "the dangling 0x0006" always); ISO 8859 parts other than 1
// have no tables here, so octets above 0x7F become U+FFFD and the result is PARTIAL; UDT format 5 (NMEA)
// has no reference for its coding and is named only. The lengths come from the header through the
// assembler (the pad bits or nibbles are already gone). A text that does not fill whole characters, UTF-8
// that is not well formed, or 16-bit text with an unpaired surrogate is not offered as text.
//
// The dispatcher follows sdrtrunk's choice (dmr/message/data/packet/PacketSequenceMessageFactory.java
// by the header's SAP, then the vendor's second header; ip/PacketMessageFactory.java, ipv4/IPV4Packet,
// udp/UDPPacket by IP protocol and UDP port; icmp/ICMPHeader, ICMPTypeCode; mototrbo/xcmp/XCMPHeader,
// XCMPMessageType; cellocator/MCGPHeader for the "MCGP" signature only):
//   UDT header                          format 3 / 4 / 7 / 2: UDT text; 5: UDT location (named only);
//                                       supplementary data and the other formats: UDT (named only)
//   response header with blocks         response (named only)
//   SAP 4, IPv4                         ICMP; UDP by port: 4001 LRRP, 4005 ARS, 4007 TMS, 4004 XCMP,
//                                       4008 telemetry, 4009 OTAP, 4012 battery, 4013 job ticket, "MCGP"
//                                       Cellocator (the last six named only); else UDP / IP other
//   SAP 9 + Motorola MNIS header        application 0x01 / 0x11 LRRP, 0x33 ARS, 0x88 XCMP, else MNIS
//                                       (named only). The message is the header's three prefix octets,
//                                       then the packet (sdrtrunk getPacket)
//   SAP 9 + Hytera header (algorithm 0) that header's SAP 9: Hytera tokens (SMS, location, other); its
//                                       SAP 10: Hytera data (named only)
//   SAP 10                              Hytera tokens saying RRS: Hytera registration; otherwise defined
//                                       short data in a text format: short data text; else short data
//   SAP 2 / 3 (compressed IP), 5 (ARP)  named only
// Beyond sdrtrunk: the source port is tried when the destination port names nothing (a service answers
// from its port); sdrtrunk does that for Cellocator only.
//
// The rules:
//   - An encrypted packet is never parsed: kind encrypted, the octets as received and the encryption
//     header's fields, before anything else is looked at.
//   - An incomplete packet is named from headers that passed their own checks only: the DMR header
//     (CRC), the vendor's second header (CRC), the IPv4 header (checksum). Its UDP ports are used, and the
//     application parsed, only when the UDP checksum is present and passes, since that covers the ports
//     and every octet of the application message: such a packet was received right, and only the packet
//     CRC's convention, not yet confirmed, says otherwise. It is marked incomplete either way. An
//     incomplete packet with no check of its own (MNIS, Hytera, short data, UDT) is not parsed.

// ---------------- Shared pieces ----------------

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
static void hex_octets(char *buf,size_t size,size_t *len,uint8_t const *octets,size_t count){
  for(size_t i=0; i < count; i++)
    append(buf,size,len,"%02X",(unsigned)octets[i]);
}

char const *dmr_app_status_name(enum dmr_app_status s){
  switch(s){
  case DMR_APP_PARSED: return "parsed";
  case DMR_APP_PARTIAL: return "partial";
  default: return "identified";
  }
}

char const *dmr_text_encoding_name(enum dmr_text_encoding e){
  switch(e){
  case DMR_TEXT_BINARY: return "binary";
  case DMR_TEXT_BCD: return "bcd";
  case DMR_TEXT_ISO7: return "iso-7";
  case DMR_TEXT_ISO8859: return "iso-8859";
  case DMR_TEXT_UTF8: return "utf-8";
  case DMR_TEXT_UTF16BE: return "utf-16be";
  case DMR_TEXT_UTF16LE: return "utf-16le";
  case DMR_TEXT_UTF32BE: return "utf-32be";
  case DMR_TEXT_UTF32LE: return "utf-32le";
  case DMR_TEXT_GBK: return "gbk";
  default: return "unknown";
  }
}

// Reads octets in order; a read past the end clears ok and every later read returns 0
struct reader {
  uint8_t const *data;
  size_t size;
  size_t at;
  bool ok;
};
static void reader_init(struct reader *r,uint8_t const *p,size_t n){
  r->data = p;
  r->size = p != NULL ? n : 0;
  r->at = 0;
  r->ok = true;
}
static size_t remaining(struct reader const *r){
  return r->ok ? r->size - r->at : 0;
}
static uint8_t u8(struct reader *r){
  if(!r->ok || r->at >= r->size){
    r->ok = false;
    return 0;
  }
  return r->data[r->at++];
}
static uint16_t be16(struct reader *r){
  uint16_t const high = u8(r);
  return (uint16_t)((high << 8) | u8(r));
}
static uint32_t be24(struct reader *r){
  uint32_t const high = be16(r);
  return (high << 8) | u8(r);
}
static uint32_t be32(struct reader *r){
  uint32_t const high = be16(r);
  return (high << 16) | be16(r);
}
// The next n octets, or NULL (and ok cleared) when fewer remain
static uint8_t const *take(struct reader *r,size_t n){
  if(!r->ok || n > r->size - r->at){
    r->ok = false;
    return NULL;
  }
  uint8_t const *p = r->data + r->at;
  r->at += n;
  return p;
}

static uint16_t get_be16(uint8_t const *p){
  return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t get_be32(uint8_t const *p){
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// ---------------- Text ----------------

static void text_clear(struct dmr_app_text *t){
  t->length = 0;
  t->utf8[0] = '\0';
}
// False when the text is full (it never is for a packet's octets: DMR_APP_TEXT_MAX)
static bool text_byte(struct dmr_app_text *t,uint8_t c){
  if(t->length + 1 >= sizeof t->utf8)
    return false;
  t->utf8[t->length++] = (char)c;
  t->utf8[t->length] = '\0';
  return true;
}
static bool text_utf8(struct dmr_app_text *t,uint32_t cp){
  if(cp < 0x80u)
    return text_byte(t,(uint8_t)cp);
  if(cp < 0x800u)
    return text_byte(t,(uint8_t)(0xC0u | (cp >> 6))) && text_byte(t,(uint8_t)(0x80u | (cp & 0x3Fu)));
  if(cp < 0x10000u)
    return text_byte(t,(uint8_t)(0xE0u | (cp >> 12))) && text_byte(t,(uint8_t)(0x80u | ((cp >> 6) & 0x3Fu)))
      && text_byte(t,(uint8_t)(0x80u | (cp & 0x3Fu)));
  return text_byte(t,(uint8_t)(0xF0u | (cp >> 18))) && text_byte(t,(uint8_t)(0x80u | ((cp >> 12) & 0x3Fu)))
    && text_byte(t,(uint8_t)(0x80u | ((cp >> 6) & 0x3Fu))) && text_byte(t,(uint8_t)(0x80u | (cp & 0x3Fu)));
}
static void text_trim_nuls(struct dmr_app_text *t){
  while(t->length > 0 && t->utf8[t->length - 1] == '\0')
    t->length--;
  t->utf8[t->length] = '\0';
}
size_t dmr_app_text_chars(struct dmr_app_text const *t){
  size_t n = 0;
  for(size_t i=0; i < t->length; i++)
    n += ((uint8_t)t->utf8[i] & 0xC0u) != 0x80u ? 1u : 0u;
  return n;
}

// A code point that may stand in a text: not a surrogate, not beyond U+10FFFF
static bool is_scalar_value(uint32_t cp){
  return cp <= 0x10FFFFu && (cp < 0xD800u || cp > 0xDFFFu);
}

// UTF-16 octets to UTF-8. False for an odd octet count or an unpaired surrogate (the text is then cleared)
static bool utf16_to_utf8(struct dmr_app_text *t,uint8_t const *p,size_t octets,bool little_endian){
  text_clear(t);
  if((octets & 1u) != 0u)
    return false;
  size_t const units = octets / 2;
  for(size_t i=0; i < units; i++){
    uint32_t cp = little_endian ? (uint32_t)((p[2*i+1] << 8) | p[2*i]) : (uint32_t)((p[2*i] << 8) | p[2*i+1]);
    if(cp >= 0xD800u && cp <= 0xDBFFu){
      if(i + 1 >= units)
        goto fail;
      uint32_t const low = little_endian ? (uint32_t)((p[2*i+3] << 8) | p[2*i+2]) : (uint32_t)((p[2*i+2] << 8) | p[2*i+3]);
      if(low < 0xDC00u || low > 0xDFFFu)
        goto fail;
      cp = 0x10000u + ((cp - 0xD800u) << 10) + (low - 0xDC00u);
      i++;
    } else if(cp >= 0xDC00u && cp <= 0xDFFFu){
      goto fail;
    }
    if(!text_utf8(t,cp))
      goto fail;
  }
  return true;
 fail:
  text_clear(t);
  return false;
}

// UTF-16 with an optional byte order mark; big-endian without one (sdrtrunk parseUnicode: Java "UTF-16").
// *little_endian reports what was used. The mark is not part of the text
static bool utf16_with_mark_to_utf8(struct dmr_app_text *t,uint8_t const *p,size_t octets,bool *little_endian){
  *little_endian = false;
  if(octets >= 2 && p[0] == 0xFFu && p[1] == 0xFEu){
    *little_endian = true;
    return utf16_to_utf8(t,p + 2,octets - 2,true);
  }
  if(octets >= 2 && p[0] == 0xFEu && p[1] == 0xFFu)
    return utf16_to_utf8(t,p + 2,octets - 2,false);
  return utf16_to_utf8(t,p,octets,false);
}

static bool utf32_to_utf8(struct dmr_app_text *t,uint8_t const *p,size_t octets,bool little_endian){
  text_clear(t);
  if((octets & 3u) != 0u)
    return false;
  for(size_t i=0; i < octets; i += 4){
    uint32_t const cp = little_endian
      ? ((uint32_t)p[i+3] << 24) | ((uint32_t)p[i+2] << 16) | ((uint32_t)p[i+1] << 8) | p[i]
      : ((uint32_t)p[i] << 24) | ((uint32_t)p[i+1] << 16) | ((uint32_t)p[i+2] << 8) | p[i+3];
    if(!is_scalar_value(cp) || !text_utf8(t,cp)){
      text_clear(t);
      return false;
    }
  }
  return true;
}

// Well-formed UTF-8: no overlong forms, no surrogates, nothing beyond U+10FFFF, no cut-off sequence
static bool utf8_valid(uint8_t const *p,size_t n){
  size_t i = 0;
  while(i < n){
    uint8_t const c = p[i];
    size_t extra = 0;
    uint32_t cp = 0;
    uint32_t least = 0;
    if(c < 0x80u){
      i++;
      continue;
    } else if((c & 0xE0u) == 0xC0u){
      extra = 1;
      cp = c & 0x1Fu;
      least = 0x80u;
    } else if((c & 0xF0u) == 0xE0u){
      extra = 2;
      cp = c & 0x0Fu;
      least = 0x800u;
    } else if((c & 0xF8u) == 0xF0u){
      extra = 3;
      cp = c & 0x07u;
      least = 0x10000u;
    } else {
      return false;
    }
    if(extra > n - i - 1)
      return false;
    for(size_t k=1; k <= extra; k++){
      if((p[i + k] & 0xC0u) != 0x80u)
        return false;
      cp = (cp << 6) | (p[i + k] & 0x3Fu);
    }
    if(cp < least || !is_scalar_value(cp))
      return false;
    i += extra + 1;
  }
  return true;
}

// ISO 8859-1 octets to UTF-8 (every octet is its own code point)
static bool latin1_to_utf8(struct dmr_app_text *t,uint8_t const *p,size_t n){
  text_clear(t);
  for(size_t i=0; i < n; i++){
    if(!text_utf8(t,p[i]))
      return false;
  }
  return true;
}

// count 7-bit characters packed most significant bit first from bit 0 of p (sdrtrunk parseISO7). The
// caller has checked that 7 * count bits are there
static bool iso7_to_utf8(struct dmr_app_text *t,uint8_t const *p,size_t count){
  text_clear(t);
  for(size_t c=0; c < count; c++){
    uint32_t v = 0;
    for(size_t b=0; b < 7; b++){
      size_t const bit = 7 * c + b;
      v = (v << 1) | ((p[bit / 8] >> (7 - bit % 8)) & 1u);
    }
    if(!text_byte(t,(uint8_t)v))
      return false;
  }
  return true;
}

// count 4-bit digits from the high nibble of p[0] on; a value above 9 prints as A-F (sdrtrunk parseBCD4)
static bool bcd_digits(struct dmr_app_text *t,uint8_t const *p,size_t count){
  static char const digits[] = "0123456789ABCDEF";
  text_clear(t);
  for(size_t i=0; i < count; i++){
    if(!text_byte(t,(uint8_t)digits[(i & 1u) == 0u ? p[i / 2] >> 4 : p[i / 2] & 0x0Fu]))
      return false;
  }
  return true;
}

static bool printable_ascii(uint8_t const *p,size_t n){
  for(size_t i=0; i < n; i++){
    if(p[i] < 0x20u || p[i] > 0x7Eu)
      return false;
  }
  return true;
}

// ---------------- IPv4 and UDP ----------------

// The ones-complement sum of 16-bit words (an odd last octet is the high half of a word), on top of sum
static uint32_t ones_sum(uint8_t const *p,size_t n,uint32_t sum){
  for(size_t i=0; i + 1 < n; i += 2)
    sum += get_be16(p + i);
  if((n & 1u) != 0u)
    sum += (uint32_t)p[n - 1] << 8;
  return sum;
}
static uint16_t fold_ones(uint32_t sum){
  while((sum >> 16) != 0u)
    sum = (sum & 0xFFFFu) + (sum >> 16);
  return (uint16_t)sum;
}

void dmr_ip_udp_split_ipv4(struct dmr_ip_udp *r,uint8_t const *octets,size_t n){
  assert(r != NULL);
  memset(r,0,sizeof *r);
  if(octets == NULL || n < 20 || (octets[0] >> 4) != 4)
    return;
  size_t const header_octets = (size_t)(octets[0] & 0x0Fu) * 4u;
  if(header_octets < 20 || header_octets > n)
    return;
  r->header_octets = (uint8_t)header_octets;
  r->total_length = get_be16(octets + 2);
  r->identification = get_be16(octets + 4);
  uint16_t const flags_offset = get_be16(octets + 6);
  r->more_fragments = (flags_offset & 0x2000u) != 0u;
  r->fragment_offset = (uint16_t)(flags_offset & 0x1FFFu);
  r->ttl = octets[8];
  r->protocol = octets[9];
  r->source_address = get_be32(octets + 12);
  r->destination_address = get_be32(octets + 16);
  r->header_checksum_ok = fold_ones(ones_sum(octets,header_octets,0)) == 0xFFFFu;
  if(!r->header_checksum_ok || r->total_length < header_octets)
    return;
  r->ipv4 = true;

  // The datagram may be shorter than the octets given (trailing octets are not part of it)
  size_t datagram = r->total_length;
  if(datagram > n){
    r->truncated = true;
    datagram = n;
  }
  if(r->protocol != DMR_IP_PROTOCOL_UDP || r->fragment_offset != 0 || datagram < header_octets + 8)
    return;

  uint8_t const *u = octets + header_octets;
  r->source_port = get_be16(u);
  r->destination_port = get_be16(u + 2);
  r->udp_length = get_be16(u + 4);
  uint16_t const checksum = get_be16(u + 6);
  if(r->udp_length < 8)
    return;
  size_t udp_octets = r->udp_length;
  bool const whole = !r->more_fragments && !r->truncated && header_octets + udp_octets <= datagram;
  if(header_octets + udp_octets > datagram)
    udp_octets = datagram - header_octets;
  r->udp = true;
  r->payload_offset = header_octets + 8;
  r->payload_length = udp_octets - 8;
  r->udp_checksum_present = checksum != 0;
  if(r->udp_checksum_present && whole){
    uint32_t sum = ones_sum(octets + 12,8,0); // the pseudo-header: addresses,
    sum += DMR_IP_PROTOCOL_UDP;                 // protocol,
    sum += r->udp_length;                       // UDP length
    sum = ones_sum(u,udp_octets,sum);
    r->udp_checksum_ok = fold_ones(sum) == 0xFFFFu;
  }
}

static bool compressed_port(uint8_t id,uint16_t *out,uint8_t const *octets,size_t n,size_t *at){
  if(id == 0){
    if(*at + 2 > n)
      return false;
    *out = get_be16(octets + *at);
    *at += 2;
  } else if(id == 1){
    *out = 5016;
  } else if(id == 2){
    *out = 5017;
  } else {
    *out = 0;  // reserved or manufacturer specific: the id is all there is
  }
  return true;
}

void dmr_ip_udp_split_compressed(struct dmr_ip_udp *r,uint8_t const *octets,size_t n){
  assert(r != NULL);
  memset(r,0,sizeof *r);
  r->compressed = true;
  if(octets == NULL || n < 5)
    return;
  r->identification = get_be16(octets);
  r->source_address_id = (uint8_t)(octets[2] >> 4);
  r->destination_address_id = (uint8_t)(octets[2] & 0x0Fu);
  r->source_port_id = (uint8_t)(octets[3] & 0x7Fu);
  r->destination_port_id = (uint8_t)(octets[4] & 0x7Fu);
  size_t at = 5;
  if(!compressed_port(r->source_port_id,&r->source_port,octets,n,&at)
     || !compressed_port(r->destination_port_id,&r->destination_port,octets,n,&at))
    return;
  r->udp = true;
  r->protocol = DMR_IP_PROTOCOL_UDP;
  r->payload_offset = at;
  r->payload_length = n - at;
}

void dmr_ip_udp_split_packet(struct dmr_ip_udp *r,struct dmr_data_packet const *p){
  assert(r != NULL && p != NULL);
  memset(r,0,sizeof *r);
  if(p->encrypted || !p->complete || !p->payload_trimmed)
    return;
  if(p->sap == DMR_SAP_IP_PACKET)
    dmr_ip_udp_split_ipv4(r,p->payload,p->payload_length);
  else if(p->sap == DMR_SAP_UDP_IP_COMPRESSION)
    dmr_ip_udp_split_compressed(r,p->payload,p->payload_length);
}

// ---------------- LRRP ----------------

char const *dmr_lrrp_type_name(uint8_t type){
  switch(type){
  case DMR_LRRP_IMMEDIATE_LOCATION_REQUEST: return "immediate-location-request";
  case DMR_LRRP_IMMEDIATE_LOCATION_RESPONSE: return "immediate-location-response";
  case DMR_LRRP_TRIGGERED_LOCATION_START_REQUEST: return "triggered-location-start-request";
  case DMR_LRRP_TRIGGERED_LOCATION_START_RESPONSE: return "triggered-location-start-response";
  case DMR_LRRP_TRIGGERED_LOCATION: return "triggered-location";
  case DMR_LRRP_TRIGGERED_LOCATION_STOP_REQUEST: return "triggered-location-stop-request";
  case DMR_LRRP_TRIGGERED_LOCATION_STOP_RESPONSE: return "triggered-location-stop-response";
  case DMR_LRRP_PROTOCOL_VERSION_REQUEST: return "protocol-version-request";
  case DMR_LRRP_PROTOCOL_VERSION_RESPONSE: return "protocol-version-response";
  default: return NULL;
  }
}

bool dmr_lrrp_type_is_response(uint8_t type){
  return type == DMR_LRRP_IMMEDIATE_LOCATION_RESPONSE || type == DMR_LRRP_TRIGGERED_LOCATION_START_RESPONSE
    || type == DMR_LRRP_TRIGGERED_LOCATION || type == DMR_LRRP_TRIGGERED_LOCATION_STOP_RESPONSE
    || type == DMR_LRRP_PROTOCOL_VERSION_RESPONSE;
}

char const *dmr_lrrp_result_name(uint16_t code){
  // sdrtrunk ResponseCode, from Moto.Net's LRRPResponseCodes
  switch(code){
  case DMR_LRRP_RESULT_SUCCESS: return "success";
  case DMR_LRRP_RESULT_INVALID_COMMAND: return "invalid-command";
  case 0x000F: return "unrecognized-error-0F";
  case DMR_LRRP_RESULT_NO_GPS: return "no-gps";
  case DMR_LRRP_RESULT_DUPLICATE_REQUEST: return "duplicate-request";
  case DMR_LRRP_RESULT_GPS_INITIALIZING: return "gps-initializing";
  default: return "unknown";
  }
}

char const *dmr_lrrp_shape_name(enum dmr_lrrp_shape s){
  switch(s){
  case DMR_LRRP_POINT_2D: return "point-2d";
  case DMR_LRRP_POINT_3D: return "point-3d";
  case DMR_LRRP_CIRCLE_2D: return "circle-2d";
  case DMR_LRRP_CIRCLE_3D: return "circle-3d";
  default: return "none";
  }
}

enum token_result { TOKEN_OK, TOKEN_UNKNOWN, TOKEN_BAD };

// Positions: latitude (sign and 31 bits) and longitude (two's complement), each a fraction of the circle
static void lrrp_position(struct reader *r,struct dmr_lrrp *m,enum dmr_lrrp_shape shape){
  m->latitude_raw = be32(r);
  m->longitude_raw = be32(r);
  double const magnitude = (double)(m->latitude_raw & 0x7FFFFFFFu) * (180.0 / 4294967295.0);
  m->latitude = (m->latitude_raw & 0x80000000u) != 0u ? -magnitude : magnitude;
  m->longitude = (double)(int32_t)m->longitude_raw * (360.0 / 4294967295.0);
  m->shape = shape;
  m->has_radius = false;
  m->has_altitude = false;
  m->has_altitude_accuracy = false;
}

// One token whose id has been read. TOKEN_UNKNOWN: the id has no layout here (nothing consumed)
static enum token_result lrrp_token(uint8_t id,struct reader *r,struct dmr_lrrp *m){
  switch(id){
  case DMR_LRRP_TOKEN_REQUEST_ID: {
    size_t const n = u8(r);
    uint8_t const *p = take(r,n);
    if(p == NULL)
      return TOKEN_BAD;
    m->has_request_id = true;
    m->request_id_length = (uint8_t)n;
    memcpy(m->request_id,p,n);
    break;
  }
  case DMR_LRRP_TOKEN_UNKNOWN_23:
  case DMR_LRRP_TOKEN_REQUEST_61:
  case DMR_LRRP_TOKEN_REQUEST_73:
    u8(r);
    if(m->other_count < sizeof m->other_tokens)
      m->other_tokens[m->other_count++] = id;
    break;
  case DMR_LRRP_TOKEN_TRIGGER_PERIODIC:
    m->trigger_seconds = u8(r);
    m->has_trigger_periodic = true;
    break;
  case DMR_LRRP_TOKEN_TRIGGER_DISTANCE:
    m->trigger_distance = u8(r);
    m->has_trigger_distance = true;
    break;
  case DMR_LRRP_TOKEN_TRIGGER_ON_MOVE:
    m->trigger_on_move = u8(r);
    m->has_trigger_on_move = true;
    break;
  case DMR_LRRP_TOKEN_TRIGGER_GPIO:
    m->trigger_gpio = true;
    break;
  case DMR_LRRP_TOKEN_TIME: {
    // year (14) month (4) day (5) hour (5) minute (6) second (6)
    uint64_t const high = be32(r);
    uint64_t const v = (high << 8) | u8(r);
    m->year = (uint16_t)((v >> 26) & 0x3FFFu);
    m->month = (uint8_t)((v >> 22) & 0xFu);
    m->day = (uint8_t)((v >> 17) & 0x1Fu);
    m->hour = (uint8_t)((v >> 12) & 0x1Fu);
    m->minute = (uint8_t)((v >> 6) & 0x3Fu);
    m->second = (uint8_t)(v & 0x3Fu);
    if(m->month < 1 || m->month > 12 || m->day < 1 || m->day > 31 || m->hour > 23 || m->minute > 59 || m->second > 59)
      return TOKEN_BAD;
    m->has_time = true;
    break;
  }
  case DMR_LRRP_TOKEN_VERSION:
    m->version = u8(r);
    m->has_version = true;
    break;
  case DMR_LRRP_TOKEN_RESULT: {
    // The first bit says whether the code is 7 bits or 15
    uint8_t const first = u8(r);
    m->result_code = first & 0x7Fu;
    if((first & 0x80u) != 0u)
      m->result_code = (uint16_t)((m->result_code << 8) | u8(r));
    m->has_result = true;
    break;
  }
  case DMR_LRRP_TOKEN_SUCCESS:
    m->result_code = DMR_LRRP_RESULT_SUCCESS;
    m->has_result = true;
    break;
  case DMR_LRRP_TOKEN_POINT_2D:
    lrrp_position(r,m,DMR_LRRP_POINT_2D);
    break;
  case DMR_LRRP_TOKEN_POINT_3D:
    lrrp_position(r,m,DMR_LRRP_POINT_3D);
    m->altitude_m = be24(r) * 0.01;
    m->has_altitude = true;
    break;
  case DMR_LRRP_TOKEN_CIRCLE_2D:
    lrrp_position(r,m,DMR_LRRP_CIRCLE_2D);
    m->radius_m = be16(r) * 0.01;
    m->has_radius = true;
    break;
  case DMR_LRRP_TOKEN_CIRCLE_3D:
    lrrp_position(r,m,DMR_LRRP_CIRCLE_3D);
    m->radius_m = be16(r) * 0.01;
    m->altitude_m = be16(r) * 0.01;
    m->altitude_accuracy_m = be16(r) * 0.01;
    u8(r);  // the token is 15 octets; sdrtrunk reads 14 of them
    m->has_radius = true;
    m->has_altitude = true;
    m->has_altitude_accuracy = true;
    break;
  case DMR_LRRP_TOKEN_HEADING:
    m->heading_degrees = u8(r) * 2.0;
    if(m->heading_degrees >= 360.0)
      return TOKEN_BAD;
    m->has_heading = true;
    break;
  case DMR_LRRP_TOKEN_SPEED:
    m->speed_raw = be16(r);
    m->speed = m->speed_raw * 0.01;
    m->has_speed = true;
    break;
  default:
    return TOKEN_UNKNOWN;
  }
  return r->ok ? TOKEN_OK : TOKEN_BAD;
}

// Ids sdrtrunk names with no payload and no parser: one octet each in a response
static bool lrrp_is_bare_token(uint8_t id){
  return id == 0x3A || id == 0x50 || id == 0x52 || id == 0x54 || id == 0x57 || id == 0x62 || id == 0x64;
}
// Every id sdrtrunk's TokenType lists
static bool lrrp_is_known_token(uint8_t id){
  switch(id){
  case 0x22: case 0x23: case 0x31: case 0x34: case 0x36: case 0x37: case 0x38: case 0x3A: case 0x42:
  case 0x4A: case 0x50: case 0x51: case 0x52: case 0x54: case 0x55: case 0x56: case 0x57: case 0x61:
  case 0x62: case 0x64: case 0x66: case 0x69: case 0x6C: case 0x73: case 0x78:
    return true;
  default:
    return false;
  }
}
// In a request these ids carry a parameter; every other octet is the id of something asked for
// (sdrtrunk TokenType.isRequestParameterToken)
static bool lrrp_is_request_parameter(uint8_t id){
  return id == DMR_LRRP_TOKEN_REQUEST_ID || id == DMR_LRRP_TOKEN_TRIGGER_DISTANCE || id == DMR_LRRP_TOKEN_TRIGGER_GPIO
    || id == DMR_LRRP_TOKEN_TRIGGER_ON_MOVE || id == DMR_LRRP_TOKEN_TRIGGER_PERIODIC || id == DMR_LRRP_TOKEN_REQUEST_61
    || id == DMR_LRRP_TOKEN_REQUEST_73;
}

// The fields a failed parse keeps: type and length only
static void lrrp_head(struct dmr_lrrp *m,uint8_t const *octets,size_t n){
  memset(m,0,sizeof *m);
  if(octets == NULL || n < 2)
    return;
  m->type = octets[0];
  m->length_field = octets[1];
  m->type_known = dmr_lrrp_type_name(m->type) != NULL;
  m->response = dmr_lrrp_type_is_response(m->type);
  m->length_ok = (size_t)m->length_field + 2 == n;
}

void dmr_lrrp_parse(struct dmr_lrrp *m,uint8_t const *octets,size_t n){
  assert(m != NULL);
  lrrp_head(m,octets,n);
  if(octets == NULL || n < 2 || !m->type_known || !m->length_ok)
    return;

  struct reader r;
  reader_init(&r,octets + 2,n - 2);
  bool partial = false;
  size_t tokens = 0;
  while(remaining(&r) > 0){
    size_t const token_at = r.at;
    uint8_t const id = u8(&r);
    enum token_result result = TOKEN_UNKNOWN;
    if(!m->response && !lrrp_is_request_parameter(id)){
      // A request names what it asks for, one id each
      if(lrrp_is_known_token(id)){
        if(m->requested_count < sizeof m->requested_tokens)
          m->requested_tokens[m->requested_count++] = id;
        result = TOKEN_OK;
      }
    } else {
      result = lrrp_token(id,&r,m);
      if(result == TOKEN_UNKNOWN && lrrp_is_bare_token(id)){
        if(m->other_count < sizeof m->other_tokens)
          m->other_tokens[m->other_count++] = id;
        result = TOKEN_OK;
      }
    }
    if(result == TOKEN_BAD){
      lrrp_head(m,octets,n);
      return;
    }
    if(result == TOKEN_UNKNOWN){
      if(tokens == 0){
        lrrp_head(m,octets,n);  // nothing of it was understood
        return;
      }
      m->unparsed_offset = 2 + token_at;
      m->unparsed_length = n - 2 - token_at;
      partial = true;
      break;
    }
    tokens++;
  }
  m->status = partial ? DMR_APP_PARTIAL : DMR_APP_PARSED;
}

int dmr_lrrp_describe(char *buf,size_t size,struct dmr_lrrp const *m){
  size_t len = 0;
  append(buf,size,&len,"LRRP");
  if(m->type_known)
    append(buf,size,&len," %s",dmr_lrrp_type_name(m->type));
  else
    append(buf,size,&len," type=%02X",(unsigned)m->type);
  if(m->status == DMR_APP_IDENTIFIED){
    append(buf,size,&len,"%s",m->length_ok ? " (not parsed)" : " (not parsed: length mismatch)");
    return finish(buf,size,len);
  }
  if(m->has_request_id){
    append(buf,size,&len," request=");
    hex_octets(buf,size,&len,m->request_id,m->request_id_length);
  }
  if(m->has_result)
    append(buf,size,&len," result=%s(%u)",dmr_lrrp_result_name(m->result_code),(unsigned)m->result_code);
  if(dmr_lrrp_has_position(m))
    append(buf,size,&len," position=%s",dmr_lrrp_shape_name(m->shape));
  if(m->has_altitude)
    append(buf,size,&len," altitude");
  if(m->has_time)
    append(buf,size,&len," time");
  if(m->has_speed)
    append(buf,size,&len," speed");
  if(m->has_heading)
    append(buf,size,&len," heading");
  if(m->has_version)
    append(buf,size,&len," version=%u",(unsigned)m->version);
  if(m->has_trigger_periodic)
    append(buf,size,&len," every=%us",(unsigned)m->trigger_seconds);
  if(m->has_trigger_distance)
    append(buf,size,&len," distance-trigger=%u",(unsigned)m->trigger_distance);
  if(m->trigger_gpio)
    append(buf,size,&len," gpio-trigger");
  if(m->has_trigger_on_move)
    append(buf,size,&len," on-move-trigger");
  if(m->requested_count > 0){
    append(buf,size,&len," asks=");
    hex_octets(buf,size,&len,m->requested_tokens,m->requested_count);
  }
  if(m->status == DMR_APP_PARTIAL)
    append(buf,size,&len," PARTIAL(%zu octets not parsed)",m->unparsed_length);
  return finish(buf,size,len);
}

// ---------------- ARS ----------------

char const *dmr_ars_type_name(uint8_t type){
  switch(type){
  case DMR_ARS_DEVICE_REGISTRATION: return "device-registration";
  case DMR_ARS_DEVICE_DEREGISTRATION: return "device-deregistration";
  case DMR_ARS_QUERY: return "query";
  case DMR_ARS_USER_REGISTRATION: return "user-registration";
  case DMR_ARS_USER_DEREGISTRATION: return "user-deregistration";
  case DMR_ARS_USER_REGISTRATION_ACK: return "user-registration-ack";
  case DMR_ARS_REGISTRATION_ACK: return "registration-ack";
  default: return NULL;
  }
}

static void ars_head(struct dmr_ars *m,uint8_t const *octets,size_t n){
  memset(m,0,sizeof *m);
  if(octets == NULL || n < 3)
    return;
  m->length_field = get_be16(octets);
  m->length_ok = (size_t)m->length_field + 2 == n;
  m->extension = (octets[2] & 0x80u) != 0u;
  m->acknowledge = (octets[2] & 0x40u) != 0u;
  m->priority = (octets[2] & 0x20u) != 0u;
  m->control = (octets[2] & 0x10u) != 0u;
  m->pdu_type = octets[2] & 0x0Fu;
  m->type_known = dmr_ars_type_name(m->pdu_type) != NULL;
}

void dmr_ars_parse(struct dmr_ars *m,uint8_t const *octets,size_t n){
  assert(m != NULL);
  ars_head(m,octets,n);
  if(octets == NULL || n < 3 || !m->length_ok || !m->type_known)
    return;

  struct reader r;
  reader_init(&r,octets + 3,n - 3);
  if(dmr_ars_is_ack(m)){
    m->success = !m->acknowledge;
    if(m->extension){
      m->value = u8(&r) & 0x7Fu;
      m->has_value = true;
    }
  } else if(dmr_ars_is_registration(m)){
    if(m->extension){
      uint8_t const second = u8(&r);
      m->event = (second >> 5) & 0x3u;
      m->encoding = second & 0x1Fu;
      m->has_event = true;
    }
    for(int i=0; i < 3 && r.ok && remaining(&r) > 0; i++){
      size_t const size = u8(&r);
      uint8_t const *p = take(&r,size);
      if(p == NULL){
        ars_head(m,octets,n);
        return;
      }
      if(size == 0)
        continue;
      if(i == 0){
        if(!printable_ascii(p,size)){
          ars_head(m,octets,n);
          return;
        }
        memcpy(m->device_id,p,size);
        m->device_id[size] = '\0';
        m->device_id_length = (uint8_t)size;
        m->has_device = true;
      } else if(i == 1){
        memcpy(m->user_id,p,size);
        m->user_id_length = (uint8_t)size;
        m->has_user = true;
      } else {
        memcpy(m->password,p,size);
        m->password_length = (uint8_t)size;
        m->has_password = true;
      }
    }
  } else if(m->extension){
    u8(&r);  // de-registrations and the query: an extension octet with nothing read from it
  }
  // Every octet accounted for: a message with more after its last field is not one this code knows
  if(!r.ok || remaining(&r) != 0){
    ars_head(m,octets,n);
    return;
  }
  m->status = DMR_APP_PARSED;
}

int dmr_ars_describe(char *buf,size_t size,struct dmr_ars const *m){
  size_t len = 0;
  append(buf,size,&len,"ARS");
  if(m->type_known)
    append(buf,size,&len," %s",dmr_ars_type_name(m->pdu_type));
  else
    append(buf,size,&len," type=%X",(unsigned)m->pdu_type);
  if(m->status == DMR_APP_IDENTIFIED){
    append(buf,size,&len,"%s",m->length_ok ? " (not parsed)" : " (not parsed: length mismatch)");
    return finish(buf,size,len);
  }
  if(dmr_ars_is_registration(m)){
    if(m->has_event)
      append(buf,size,&len,"%s",m->event == 1 ? " initial" : " refresh");
    if(m->has_device)
      append(buf,size,&len," device=%s",m->device_id);
    if(m->has_user)
      append(buf,size,&len," user=(%zu octets)",(size_t)m->user_id_length);
    if(m->has_password)
      append(buf,size,&len," password=(present)");
  } else if(dmr_ars_is_ack(m)){
    append(buf,size,&len,"%s",m->success ? " success" : " failure");
    if(m->has_value && m->pdu_type == DMR_ARS_REGISTRATION_ACK && m->success)
      append(buf,size,&len," refresh-in=%umin",(unsigned)m->value * 30u);
    else if(m->has_value)
      append(buf,size,&len," value=%u",(unsigned)m->value);
  }
  return finish(buf,size,len);
}

// ---------------- TMS ----------------

static void tms_head(struct dmr_tms *m,uint8_t const *octets,size_t n){
  memset(m,0,offsetof(struct dmr_tms,text));
  text_clear(&m->text);
  if(octets == NULL || n < 4)
    return;
  m->length_field = get_be16(octets);
  m->length_ok = (size_t)m->length_field + 2 == n;
  m->first_header = octets[2];
  m->extension = (octets[2] & 0x80u) != 0u;
  m->ack_required = (octets[2] & 0x40u) != 0u;
  m->control = (octets[2] & 0x10u) != 0u;
  m->pdu_type = octets[2] & 0x0Fu;
}

void dmr_tms_parse(struct dmr_tms *m,uint8_t const *octets,size_t n){
  assert(m != NULL);
  tms_head(m,octets,n);
  if(octets == NULL || n < 4 || !m->length_ok)
    return;

  struct reader r;
  reader_init(&r,octets + 3,n - 3);
  size_t const address_size = u8(&r);
  uint8_t const *address = take(&r,address_size);
  if(address == NULL)
    goto fail;
  memcpy(m->address,address,address_size);
  m->address_length = (uint8_t)address_size;
  if(m->extension){
    uint8_t const seq = u8(&r);
    m->sequence = seq & 0x1Fu;
    m->has_sequence = true;
    if((seq & 0x80u) != 0u){
      uint8_t const enc = u8(&r);
      m->encoding = enc & 0x1Fu;
      m->has_encoding = true;
      if((enc & 0x80u) != 0u)
        goto fail;  // a third extension octet: not a header this code knows
    }
  }
  if(!r.ok)
    goto fail;

  if(m->pdu_type == DMR_TMS_TYPE_ACK){
    if(remaining(&r) != 0)
      goto fail;
    m->is_ack = true;
    m->status = DMR_APP_PARSED;
    return;
  }
  if(m->pdu_type != DMR_TMS_TYPE_MESSAGE)
    goto fail;  // a PDU type with no reading here
  if(m->has_encoding && m->encoding != DMR_TMS_ENCODING_UTF16LE){
    m->status = DMR_APP_PARTIAL;  // a text in an encoding this code has no reading for
    return;
  }

  m->text_offset = 3 + r.at;
  {
    size_t const text_octets = remaining(&r);
    uint8_t const *text = take(&r,text_octets);
    if(text_octets == 0 || !utf16_to_utf8(&m->text,text,text_octets,true))
      goto fail;
  }
  if(m->text.length >= 2 && m->text.utf8[0] == '\r' && m->text.utf8[1] == '\n'){
    m->leading_crlf = true;
    memmove(m->text.utf8,m->text.utf8 + 2,m->text.length - 2 + 1);
    m->text.length -= 2;
  }
  text_trim_nuls(&m->text);
  m->has_text = true;
  m->status = DMR_APP_PARSED;
  return;
 fail:
  tms_head(m,octets,n);
}

int dmr_tms_describe(char *buf,size_t size,struct dmr_tms const *m){
  size_t len = 0;
  append(buf,size,&len,"TMS");
  if(m->status == DMR_APP_IDENTIFIED){
    append(buf,size,&len,"%s",m->length_ok ? " (not parsed)" : " (not parsed: length mismatch)");
    return finish(buf,size,len);
  }
  if(m->is_ack)
    append(buf,size,&len," ack");
  else if(m->has_text)
    append(buf,size,&len," text chars=%zu",dmr_app_text_chars(&m->text));
  else
    append(buf,size,&len," encoding=%u PARTIAL",(unsigned)m->encoding);
  if(m->has_sequence)
    append(buf,size,&len," seq=%u",(unsigned)m->sequence);
  if(m->ack_required && !m->is_ack)
    append(buf,size,&len," ack-required");
  return finish(buf,size,len);
}

// ---------------- Hytera tokens ----------------

char const *dmr_hytera_form_name(enum dmr_hytera_form f){
  switch(f){
  case DMR_HYTERA_SMS: return "sms";
  case DMR_HYTERA_REGISTRATION: return "registration";
  case DMR_HYTERA_LOCATION: return "location";
  default: return "other";
  }
}

static bool bcd_ok(uint8_t octet){
  return (octet >> 4) <= 9 && (octet & 0x0Fu) <= 9;
}
static unsigned bcd_value(uint8_t octet){
  return (unsigned)(octet >> 4) * 10u + (octet & 0x0Fu);
}
// An ID token's content: a number only when it is four octets
static bool hytera_id(uint8_t const *p,size_t n,uint32_t *out){
  if(n != 4)
    return false;
  *out = get_be32(p);
  return true;
}

static void hytera_none(struct dmr_hytera *m){
  memset(m,0,offsetof(struct dmr_hytera,text));
  text_clear(&m->text);
  m->unparsed_offset = 0;
  m->unparsed_length = 0;
}

void dmr_hytera_parse(struct dmr_hytera *m,uint8_t const *octets,size_t n){
  assert(m != NULL);
  hytera_none(m);
  if(octets == NULL || n < 2)
    return;

  struct reader r;
  reader_init(&r,octets,n);
  bool partial = false;
  while(remaining(&r) > 0){
    size_t const token_at = r.at;
    uint16_t const opcode = be16(&r);
    if(!r.ok)
      goto none;
    bool known = true;
    switch(opcode){
    case DMR_HYTERA_TOKEN_RRS_HEADER: {
      uint8_t const length = u8(&r);
      if(!r.ok || !bcd_ok(length))
        goto none;
      m->has_rrs_header = true;
      m->message_length = (uint16_t)bcd_value(length);
      break;
    }
    case DMR_HYTERA_TOKEN_TMS_HEADER: {
      uint8_t const high = u8(&r);
      uint8_t const low = u8(&r);
      uint16_t const flags = be16(&r);
      if(!r.ok || !bcd_ok(high) || !bcd_ok(low))
        goto none;
      m->has_tms_header = true;
      m->message_length = (uint16_t)(bcd_value(high) * 100u + bcd_value(low));
      m->message_flags = flags;
      break;
    }
    case DMR_HYTERA_TOKEN_RRS_UNKNOWN:
      break;
    case DMR_HYTERA_TOKEN_MESSAGE_ID:
    case DMR_HYTERA_TOKEN_SOURCE_ID:
    case DMR_HYTERA_TOKEN_DESTINATION_ID:
    case DMR_HYTERA_TOKEN_ENCODING:
    case DMR_HYTERA_TOKEN_PAYLOAD: {
      size_t const length = be16(&r);
      uint8_t const *p = take(&r,length);
      if(p == NULL)
        goto none;
      if(opcode == DMR_HYTERA_TOKEN_MESSAGE_ID){
        m->has_message_id = hytera_id(p,length,&m->message_id);
        partial = partial || !m->has_message_id;
      } else if(opcode == DMR_HYTERA_TOKEN_SOURCE_ID){
        m->has_source_id = hytera_id(p,length,&m->source_id);
        partial = partial || !m->has_source_id;
      } else if(opcode == DMR_HYTERA_TOKEN_DESTINATION_ID){
        m->has_destination_id = hytera_id(p,length,&m->destination_id);
        partial = partial || !m->has_destination_id;
      } else if(opcode == DMR_HYTERA_TOKEN_ENCODING){
        if(length < 2)
          goto none;
        m->encoding = get_be16(p);
        m->has_encoding = true;
      } else {
        m->payload_offset = (size_t)(p - octets);
        m->payload_length = length;
        m->has_payload = true;
      }
      break;
    }
    default:
      known = false;
      break;
    }
    if(!known){
      if(m->tokens == 0)
        goto none;  // not a token message at all
      m->unparsed_offset = token_at;
      m->unparsed_length = n - token_at;
      partial = true;
      break;
    }
    m->tokens++;
  }

  if(m->has_tms_header && m->has_encoding && m->has_payload)
    m->form = m->encoding == DMR_HYTERA_ENCODING_NMEA_GPS ? DMR_HYTERA_LOCATION : DMR_HYTERA_SMS;
  else if(m->has_rrs_header && m->has_destination_id)
    m->form = DMR_HYTERA_REGISTRATION;

  if(m->form == DMR_HYTERA_SMS){
    uint8_t const *p = octets + m->payload_offset;
    size_t const size = m->payload_length;
    switch(m->encoding){
    case DMR_HYTERA_ENCODING_ISO7:
      if(!iso7_to_utf8(&m->text,p,size * 8 / 7))
        goto none;
      m->text_encoding = DMR_TEXT_ISO7;
      m->has_text = true;
      break;
    case DMR_HYTERA_ENCODING_ISO8:
      if(!latin1_to_utf8(&m->text,p,size))
        goto none;
      m->text_encoding = DMR_TEXT_ISO8859;
      m->has_text = true;
      break;
    case DMR_HYTERA_ENCODING_UNICODE: {
      bool little_endian = false;
      if(!utf16_with_mark_to_utf8(&m->text,p,size,&little_endian))
        goto none;
      m->text_encoding = little_endian ? DMR_TEXT_UTF16LE : DMR_TEXT_UTF16BE;
      m->has_text = true;
      break;
    }
    case DMR_HYTERA_ENCODING_GBK:
      m->text_encoding = DMR_TEXT_GBK;  // named; the octets stay in the payload
      partial = true;
      break;
    default:
      partial = true;  // an encoding with no text reading
      break;
    }
    if(m->has_text)
      text_trim_nuls(&m->text);
  } else if(m->form == DMR_HYTERA_LOCATION){
    partial = true;  // named only: the payload is not parsed
  }

  m->status = partial ? DMR_APP_PARTIAL : DMR_APP_PARSED;
  return;
 none:
  hytera_none(m);
}

int dmr_hytera_describe(char *buf,size_t size,struct dmr_hytera const *m){
  size_t len = 0;
  append(buf,size,&len,"Hytera");
  if(m->status == DMR_APP_IDENTIFIED){
    append(buf,size,&len," data (not parsed)");
    return finish(buf,size,len);
  }
  append(buf,size,&len," %s",dmr_hytera_form_name(m->form));
  if(m->has_message_id)
    append(buf,size,&len," id=%u",(unsigned)m->message_id);
  if(m->has_source_id)
    append(buf,size,&len," from=%u",(unsigned)m->source_id);
  if(m->has_destination_id)
    append(buf,size,&len," to=%u%s",(unsigned)dmr_hytera_destination_radio(m),dmr_hytera_destination_is_ip(m) ? "(ip)" : "");
  if(m->has_text)
    append(buf,size,&len," %s chars=%zu",dmr_text_encoding_name(m->text_encoding),dmr_app_text_chars(&m->text));
  else if(m->has_payload)
    append(buf,size,&len," encoding=%u payload=%zu octets",(unsigned)m->encoding,m->payload_length);
  if(m->status == DMR_APP_PARTIAL)
    append(buf,size,&len," PARTIAL");
  return finish(buf,size,len);
}

// ---------------- Defined short data and UDT text ----------------

uint8_t dmr_dd_iso8859_part(uint8_t format){
  if(format < DMR_DD_ISO8859_FIRST || format > DMR_DD_ISO8859_LAST)
    return 0;
  return (uint8_t)(format <= 13 ? format - 2 : format - 1);
}

char const *dmr_udt_format_name(uint8_t format){
  switch(format){
  case DMR_UDT_FORMAT_BINARY: return "binary";
  case DMR_UDT_FORMAT_ADDRESS: return "address";
  case DMR_UDT_FORMAT_BCD: return "bcd";
  case DMR_UDT_FORMAT_ISO7: return "iso-7";
  case DMR_UDT_FORMAT_ISO8: return "iso-8";
  case DMR_UDT_FORMAT_NMEA: return "nmea-gps";
  case DMR_UDT_FORMAT_IP_ADDRESS: return "ip-address";
  case DMR_UDT_FORMAT_UNICODE16: return "unicode-16";
  case DMR_UDT_FORMAT_VENDOR8: return "vendor-8";
  case DMR_UDT_FORMAT_VENDOR9: return "vendor-9";
  case DMR_UDT_FORMAT_MIXED: return "mixed";
  default: return "unknown";
  }
}

static void short_text_head(struct dmr_short_text *m,bool udt,uint8_t format){
  m->status = DMR_APP_IDENTIFIED;
  m->udt = udt;
  m->format = format;
  m->encoding = DMR_TEXT_UNKNOWN;
  m->iso8859_part = 0;
  m->has_text = false;
  text_clear(&m->text);
}

void dmr_short_text_parse_defined(struct dmr_short_text *m,uint8_t format,uint8_t const *octets,size_t n,size_t bits){
  assert(m != NULL);
  short_text_head(m,false,format);
  if(octets == NULL || bits == 0 || bits > 8 * n || !dmr_dd_format_is_text(format))
    return;

  bool partial = false;
  size_t const whole = bits / 8;
  bool ok = true;
  if(format == DMR_DD_7BIT){
    m->encoding = DMR_TEXT_ISO7;
    ok = iso7_to_utf8(&m->text,octets,bits / 7);
  } else if(bits % 8 != 0){
    ok = false;
  } else if(format <= DMR_DD_ISO8859_LAST){
    m->encoding = DMR_TEXT_ISO8859;
    m->iso8859_part = dmr_dd_iso8859_part(format);
    if(m->iso8859_part == 1){
      ok = latin1_to_utf8(&m->text,octets,whole);
    } else {
      for(size_t i=0; i < whole && ok; i++){
        if(octets[i] < 0x80u){
          ok = text_byte(&m->text,octets[i]);
        } else {
          ok = text_utf8(&m->text,0xFFFDu);
          partial = true;
        }
      }
    }
  } else if(format == DMR_DD_UTF8){
    ok = utf8_valid(octets,whole);
    if(ok){
      m->encoding = DMR_TEXT_UTF8;
      for(size_t i=0; i < whole && ok; i++)
        ok = text_byte(&m->text,octets[i]);
    }
  } else if(format == DMR_DD_UTF16){
    bool little_endian = false;
    ok = utf16_with_mark_to_utf8(&m->text,octets,whole,&little_endian);
    m->encoding = little_endian ? DMR_TEXT_UTF16LE : DMR_TEXT_UTF16BE;
  } else if(format == DMR_DD_UTF16BE || format == DMR_DD_UTF16LE){
    ok = utf16_to_utf8(&m->text,octets,whole,format == DMR_DD_UTF16LE);
    m->encoding = format == DMR_DD_UTF16LE ? DMR_TEXT_UTF16LE : DMR_TEXT_UTF16BE;
  } else {
    bool little_endian = format == DMR_DD_UTF32LE;
    uint8_t const *p = octets;
    size_t size = whole;
    if(format == DMR_DD_UTF32 && size >= 4){
      // A byte order mark, either way round
      if(p[0] == 0xFFu && p[1] == 0xFEu && p[2] == 0 && p[3] == 0){
        little_endian = true;
        p += 4;
        size -= 4;
      } else if(p[0] == 0 && p[1] == 0 && p[2] == 0xFEu && p[3] == 0xFFu){
        p += 4;
        size -= 4;
      }
    }
    ok = utf32_to_utf8(&m->text,p,size,little_endian);
    m->encoding = little_endian ? DMR_TEXT_UTF32LE : DMR_TEXT_UTF32BE;
  }
  if(ok){
    text_trim_nuls(&m->text);
    ok = m->text.length > 0;
  }
  if(!ok){
    short_text_head(m,false,format);
    return;
  }
  m->has_text = true;
  m->status = partial ? DMR_APP_PARTIAL : DMR_APP_PARSED;
}

void dmr_short_text_parse_udt(struct dmr_short_text *m,uint8_t format,uint8_t const *octets,size_t n,size_t bits){
  assert(m != NULL);
  short_text_head(m,true,format);
  if(octets == NULL || bits == 0 || bits > 8 * n || !dmr_udt_format_is_text(format))
    return;

  bool ok;
  if(format == DMR_UDT_FORMAT_ISO7){
    m->encoding = DMR_TEXT_ISO7;
    ok = iso7_to_utf8(&m->text,octets,bits / 7);
  } else if(format == DMR_UDT_FORMAT_ISO8){
    m->encoding = DMR_TEXT_ISO8859;
    m->iso8859_part = 1;
    ok = latin1_to_utf8(&m->text,octets,bits / 8);
  } else if(format == DMR_UDT_FORMAT_BCD){
    m->encoding = DMR_TEXT_BCD;
    ok = bcd_digits(&m->text,octets,bits / 4);
  } else {
    size_t units = bits / 16;
    // sdrtrunk's "dangling 0x0006": dropped when it is there
    if(units > 0 && octets[2 * units - 2] == 0x00u && octets[2 * units - 1] == 0x06u)
      units--;
    bool little_endian = false;
    ok = utf16_with_mark_to_utf8(&m->text,octets,2 * units,&little_endian);
    m->encoding = little_endian ? DMR_TEXT_UTF16LE : DMR_TEXT_UTF16BE;
  }
  if(ok){
    text_trim_nuls(&m->text);
    ok = m->text.length > 0;
  }
  if(!ok){
    short_text_head(m,true,format);
    return;
  }
  m->has_text = true;
  m->status = DMR_APP_PARSED;
}

int dmr_short_text_describe(char *buf,size_t size,struct dmr_short_text const *m){
  size_t len = 0;
  append(buf,size,&len,"%s format=%u",m->udt ? "UDT text" : "short data text",(unsigned)m->format);
  if(!m->has_text){
    append(buf,size,&len," (not parsed)");
    return finish(buf,size,len);
  }
  append(buf,size,&len," %s chars=%zu",dmr_text_encoding_name(m->encoding),dmr_app_text_chars(&m->text));
  if(m->status == DMR_APP_PARTIAL)
    append(buf,size,&len," PARTIAL");
  return finish(buf,size,len);
}

// ---------------- The dispatcher ----------------

enum dmr_app_family dmr_app_family_of(enum dmr_app_kind kind){
  switch((unsigned)kind >> 4){
  case 1: return DMR_APP_FAMILY_LOCATION;
  case 2: return DMR_APP_FAMILY_REGISTRATION;
  case 3: return DMR_APP_FAMILY_TEXT;
  case 4: return DMR_APP_FAMILY_VENDOR;
  case 5: return DMR_APP_FAMILY_IP;
  case 6: return DMR_APP_FAMILY_STANDARD;
  default: return kind == DMR_APP_ENCRYPTED ? DMR_APP_FAMILY_ENCRYPTED : DMR_APP_FAMILY_UNKNOWN;
  }
}

char const *dmr_app_kind_name(enum dmr_app_kind kind){
  switch(kind){
  case DMR_APP_ENCRYPTED: return "encrypted";
  case DMR_APP_MOTOROLA_LRRP: return "motorola-lrrp";
  case DMR_APP_HYTERA_LOCATION: return "hytera-location";
  case DMR_APP_UDT_LOCATION: return "udt-location";
  case DMR_APP_MOTOROLA_ARS: return "motorola-ars";
  case DMR_APP_HYTERA_RRS: return "hytera-rrs";
  case DMR_APP_MOTOROLA_TMS: return "motorola-tms";
  case DMR_APP_HYTERA_SMS: return "hytera-sms";
  case DMR_APP_SHORT_DATA_TEXT: return "short-data-text";
  case DMR_APP_UDT_TEXT: return "udt-text";
  case DMR_APP_MOTOROLA_XCMP: return "motorola-xcmp";
  case DMR_APP_MOTOROLA_TELEMETRY: return "motorola-telemetry";
  case DMR_APP_MOTOROLA_OTAP: return "motorola-otap";
  case DMR_APP_MOTOROLA_BATTERY_MANAGEMENT: return "motorola-battery";
  case DMR_APP_MOTOROLA_JOB_TICKET: return "motorola-job-ticket";
  case DMR_APP_MOTOROLA_MNIS: return "motorola-mnis";
  case DMR_APP_CELLOCATOR: return "cellocator";
  case DMR_APP_HYTERA_DATA: return "hytera-data";
  case DMR_APP_ICMP: return "icmp";
  case DMR_APP_UDP_OTHER: return "udp";
  case DMR_APP_IP_OTHER: return "ip";
  case DMR_APP_IP_COMPRESSED: return "ip-compressed";
  case DMR_APP_ARP: return "arp";
  case DMR_APP_SHORT_DATA: return "short-data";
  case DMR_APP_UDT: return "udt";
  case DMR_APP_RESPONSE: return "response";
  default: return "unknown";
  }
}

char const *dmr_icmp_type_name(uint8_t type){
  switch(type){
  case 0: return "echo-reply";
  case 3: return "destination-unreachable";
  case 5: return "redirect";
  case 8: return "echo-request";
  case 9: return "router-advertisement";
  case 10: return "router-solicitation";
  case 11: return "time-exceeded";
  case 12: return "parameter-problem";
  case 13: return "timestamp";
  case 14: return "timestamp-reply";
  case 42: return "extended-echo-request";
  case 43: return "extended-echo-reply";
  default: return "other";
  }
}

static void run_parser(struct dmr_data_classify_trace *trace){
  if(trace != NULL)
    trace->parsers_run++;
}

static void set_app(struct dmr_data_message *m,uint8_t const *p,size_t n){
  memmove(m->payload,p,n);
  m->payload_length = n;
  m->payload_bits = 8 * n;
}

// An application named by a UDP port or an MNIS application type, with its message. parse: the message's
// octets are known good (a complete packet, or a UDP checksum that passed)
static void classify_motorola(struct dmr_data_message *m,enum dmr_app_kind kind,bool parse,
                              struct dmr_data_classify_trace *trace){
  m->kind = kind;
  m->status = DMR_APP_IDENTIFIED;
  uint8_t const *p = m->payload;
  size_t const n = m->payload_length;
  if(!parse)
    return;
  if(kind == DMR_APP_MOTOROLA_XCMP && n > 0){
    m->body = DMR_APP_BODY_XCMP;
    m->u.xcmp.message_type = p[0];
  }
  if(kind == DMR_APP_MOTOROLA_LRRP){
    run_parser(trace);
    dmr_lrrp_parse(&m->u.lrrp,p,n);
    m->status = m->u.lrrp.status;
    m->body = DMR_APP_BODY_LRRP;
  } else if(kind == DMR_APP_MOTOROLA_ARS){
    run_parser(trace);
    dmr_ars_parse(&m->u.ars,p,n);
    m->status = m->u.ars.status;
    m->body = DMR_APP_BODY_ARS;
  } else if(kind == DMR_APP_MOTOROLA_TMS){
    run_parser(trace);
    dmr_tms_parse(&m->u.tms,p,n);
    m->status = m->u.tms.status;
    m->body = DMR_APP_BODY_TMS;
  }
}

static enum dmr_app_kind kind_of_port(uint16_t port){
  switch(port){
  case DMR_PORT_MOTOROLA_LRRP: return DMR_APP_MOTOROLA_LRRP;
  case DMR_PORT_MOTOROLA_XCMP: return DMR_APP_MOTOROLA_XCMP;
  case DMR_PORT_MOTOROLA_ARS: return DMR_APP_MOTOROLA_ARS;
  case DMR_PORT_MOTOROLA_TMS: return DMR_APP_MOTOROLA_TMS;
  case DMR_PORT_MOTOROLA_TELEMETRY: return DMR_APP_MOTOROLA_TELEMETRY;
  case DMR_PORT_MOTOROLA_OTAP: return DMR_APP_MOTOROLA_OTAP;
  case DMR_PORT_MOTOROLA_BATTERY: return DMR_APP_MOTOROLA_BATTERY_MANAGEMENT;
  case DMR_PORT_MOTOROLA_JOB_TICKET: return DMR_APP_MOTOROLA_JOB_TICKET;
  default: return DMR_APP_UNKNOWN;
  }
}

// SAP 4: an IPv4 datagram
static void classify_ip(struct dmr_data_message *m,struct dmr_data_packet const *p,struct dmr_data_classify_trace *trace){
  if(trace != NULL)
    trace->ip_split = true;
  uint8_t const *octets = p->payload;
  struct dmr_ip_udp ip;
  dmr_ip_udp_split_ipv4(&ip,octets,p->payload_length);
  if(!ip.ipv4)
    return;  // not IPv4, or its header checksum failed: unknown
  m->over_ip = true;
  m->ip = ip;
  m->kind = DMR_APP_IP_OTHER;
  bool const whole = !ip.truncated && !ip.more_fragments && ip.fragment_offset == 0;

  if(ip.protocol == DMR_IP_PROTOCOL_ICMP && whole && ip.total_length >= (size_t)ip.header_octets + 8){
    // ICMP: type, code, and a checksum over the whole message, which is checked
    uint8_t const *icmp = octets + ip.header_octets;
    size_t const icmp_octets = (size_t)ip.total_length - ip.header_octets;
    set_app(m,icmp,icmp_octets);
    m->kind = DMR_APP_ICMP;
    run_parser(trace);
    if(fold_ones(ones_sum(m->payload,icmp_octets,0)) == 0xFFFFu){
      m->body = DMR_APP_BODY_ICMP;
      m->u.icmp.type = m->payload[0];
      m->u.icmp.code = m->payload[1];
      m->status = DMR_APP_PARSED;
    }
    return;
  }
  if(!ip.udp)
    return;

  // The ports: covered by the packet CRC of a complete packet, or by the UDP checksum
  bool const checksum_passed = whole && ip.udp_checksum_present && ip.udp_checksum_ok;
  bool const checksum_failed = whole && ip.udp_checksum_present && !ip.udp_checksum_ok;
  m->ports_checked = p->complete || checksum_passed;
  if(!m->ports_checked)
    return;  // an incomplete packet whose UDP header nothing vouches for: IP, no more
  set_app(m,octets + ip.payload_offset,ip.payload_length);

  enum dmr_app_kind kind = kind_of_port(ip.destination_port);
  if(kind == DMR_APP_UNKNOWN)
    kind = kind_of_port(ip.source_port);
  if(kind == DMR_APP_UNKNOWN && m->payload_length >= 4 && m->payload[0] == 'M' && m->payload[1] == 'C'
     && m->payload[2] == 'G' && m->payload[3] == 'P')
    kind = DMR_APP_CELLOCATOR;
  if(kind == DMR_APP_UNKNOWN){
    m->kind = DMR_APP_UDP_OTHER;
    return;
  }
  // The application is parsed when its octets are known good: all of them present, and no checksum
  // saying otherwise
  classify_motorola(m,kind,whole && !checksum_failed,trace);
}

// SAP 9 with a vendor's second header
static void classify_proprietary(struct dmr_data_message *m,struct dmr_data_packet const *p,
                                 struct dmr_data_classify_trace *trace){
  if(!p->has_second_header)
    return;
  struct dmr_data_header const *second = &p->second_header;
  if(second->kind == DMR_DH_MOTOROLA_MNIS){
    m->over_mnis = true;
    m->mnis_application_type = second->mnis_application_type;
    // The message is the header's three prefix octets, then the packet
    memcpy(m->payload,second->mnis_prefix,3);
    memcpy(m->payload + 3,p->payload,p->payload_length);
    m->payload_length = 3 + p->payload_length;
    m->payload_bits = 8 * m->payload_length;
    enum dmr_app_kind kind = DMR_APP_MOTOROLA_MNIS;
    if(second->mnis_application_type == DMR_MNIS_APP_ARS)
      kind = DMR_APP_MOTOROLA_ARS;
    if(second->mnis_application_type == DMR_MNIS_APP_LRRP || second->mnis_application_type == DMR_MNIS_APP_MNIS_LRRP)
      kind = DMR_APP_MOTOROLA_LRRP;
    if(second->mnis_application_type == DMR_MNIS_APP_XCMP)
      kind = DMR_APP_MOTOROLA_XCMP;
    classify_motorola(m,kind,p->complete,trace);
    return;
  }
  if(second->kind == DMR_DH_HYTERA_ENCRYPTION){
    // A Hytera header with algorithm 0 (with any other the packet is encrypted and never gets here)
    m->kind = DMR_APP_HYTERA_DATA;
    if(second->sap != DMR_SAP_PROPRIETARY || !p->complete)
      return;
    run_parser(trace);
    dmr_hytera_parse(&m->u.hytera,p->payload,p->payload_length);
    m->body = DMR_APP_BODY_HYTERA;
    m->status = m->u.hytera.status;
    if(m->u.hytera.status != DMR_APP_IDENTIFIED){
      if(m->u.hytera.form == DMR_HYTERA_SMS)
        m->kind = DMR_APP_HYTERA_SMS;
      if(m->u.hytera.form == DMR_HYTERA_LOCATION)
        m->kind = DMR_APP_HYTERA_LOCATION;
      if(m->u.hytera.form == DMR_HYTERA_REGISTRATION)
        m->kind = DMR_APP_HYTERA_RRS;
    }
  }
}

// SAP 10, or a short data header on a SAP with no other reading
static void classify_short_data(struct dmr_data_message *m,struct dmr_data_packet const *p,
                                struct dmr_data_classify_trace *trace){
  if(p->sap == DMR_SAP_SHORT_DATA && p->complete){
    // Hytera's registration service rides here (sdrtrunk createDefinedShortData)
    run_parser(trace);
    dmr_hytera_parse(&m->u.hytera,p->payload,p->payload_length);
    if(m->u.hytera.status != DMR_APP_IDENTIFIED && m->u.hytera.form == DMR_HYTERA_REGISTRATION){
      m->kind = DMR_APP_HYTERA_RRS;
      m->status = m->u.hytera.status;
      m->body = DMR_APP_BODY_HYTERA;
      return;
    }
  }
  bool const text = p->header.kind == DMR_DH_DEFINED_SHORT_DATA && dmr_dd_format_is_text(p->header.defined_format);
  m->kind = text ? DMR_APP_SHORT_DATA_TEXT : DMR_APP_SHORT_DATA;
  if(!text || !p->complete)
    return;
  run_parser(trace);
  dmr_short_text_parse_defined(&m->u.short_text,p->header.defined_format,p->payload,p->payload_length,p->payload_bits);
  m->status = m->u.short_text.status;
  m->body = DMR_APP_BODY_SHORT_TEXT;
}

static void classify_udt(struct dmr_data_message *m,struct dmr_data_packet const *p,struct dmr_data_classify_trace *trace){
  uint8_t const format = p->header.udt_format;
  m->kind = DMR_APP_UDT;
  if(p->header.udt_supplementary)
    return;
  if(format == DMR_UDT_FORMAT_NMEA){
    m->kind = DMR_APP_UDT_LOCATION;  // named only: no reference for the coding
    return;
  }
  if(!dmr_udt_format_is_text(format))
    return;
  m->kind = DMR_APP_UDT_TEXT;
  if(!p->complete)
    return;
  run_parser(trace);
  dmr_short_text_parse_udt(&m->u.short_text,format,p->payload,p->payload_length,p->payload_bits);
  m->status = m->u.short_text.status;
  m->body = DMR_APP_BODY_SHORT_TEXT;
}

void dmr_data_classify(struct dmr_data_message *m,struct dmr_data_packet const *p,struct dmr_data_classify_trace *trace){
  assert(m != NULL && p != NULL);
  // Not the union: a parser fills the member it uses
  memset(m,0,offsetof(struct dmr_data_message,payload));
  m->kind = DMR_APP_UNKNOWN;
  m->status = DMR_APP_IDENTIFIED;
  m->body = DMR_APP_BODY_NONE;
  m->incomplete = !p->complete;
  m->retransmission = p->retransmission;
  m->slot = p->slot;
  m->source = p->source;
  m->destination = p->destination;
  m->group = p->group;
  m->sap = p->sap;
  m->header_kind = p->header.kind;
  memcpy(m->payload,p->payload,p->payload_length);
  m->payload_length = p->payload_length;
  m->payload_bits = p->payload_bits;

  // Encrypted: nothing below this sees the packet
  if(p->encrypted){
    m->kind = DMR_APP_ENCRYPTED;
    m->body = DMR_APP_BODY_ENCRYPTED;
    m->u.encrypted.mfid = p->encryption_mfid;
    m->u.encrypted.algorithm = p->algorithm;
    m->u.encrypted.key_id = p->key_id;
    m->u.encrypted.iv = p->iv;
    return;
  }

  if(p->header.kind == DMR_DH_UDT)
    classify_udt(m,p,trace);
  else if(p->header.kind == DMR_DH_RESPONSE)
    m->kind = DMR_APP_RESPONSE;
  else if(p->sap == DMR_SAP_IP_PACKET)
    classify_ip(m,p,trace);
  else if(p->sap == DMR_SAP_TCP_IP_COMPRESSION || p->sap == DMR_SAP_UDP_IP_COMPRESSION)
    m->kind = DMR_APP_IP_COMPRESSED;
  else if(p->sap == DMR_SAP_ARP)
    m->kind = DMR_APP_ARP;
  else if(p->sap == DMR_SAP_PROPRIETARY)
    classify_proprietary(m,p,trace);
  // SAP 10, or a short data header that nothing above made anything of
  bool const short_header = p->header.kind == DMR_DH_DEFINED_SHORT_DATA || p->header.kind == DMR_DH_RAW_SHORT_DATA;
  if(m->kind == DMR_APP_UNKNOWN && (p->sap == DMR_SAP_SHORT_DATA || short_header))
    classify_short_data(m,p,trace);
}

int dmr_data_app_describe(char *buf,size_t size,struct dmr_data_message const *m){
  size_t len = 0;
  append(buf,size,&len,"[DMR data] slot=%u %s src=%u dst=%s%u",(unsigned)m->slot,dmr_app_kind_name(m->kind),
         (unsigned)m->source,m->group ? "TG " : "",(unsigned)m->destination);
  if(m->over_ip && m->ip.udp && m->ports_checked)
    append(buf,size,&len," udp %u->%u",(unsigned)m->ip.source_port,(unsigned)m->ip.destination_port);
  else if(m->over_ip)
    append(buf,size,&len," ip-protocol=%u",(unsigned)m->ip.protocol);
  else if(m->over_mnis)
    append(buf,size,&len," mnis-app=%02X",(unsigned)m->mnis_application_type);
  else
    append(buf,size,&len," sap=%u(%s) %s",(unsigned)m->sap,dmr_sap_name(m->sap),dmr_data_header_kind_name(m->header_kind));

  append(buf,size,&len,": ");
  char body[DMR_DATA_DESCRIBE_MAX];
  switch(m->body){
  case DMR_APP_BODY_ENCRYPTED:
    append(buf,size,&len,"ENCRYPTED mfid=%02X alg=%02X key=%u iv=%08X",(unsigned)m->u.encrypted.mfid,
           (unsigned)m->u.encrypted.algorithm,(unsigned)m->u.encrypted.key_id,(unsigned)m->u.encrypted.iv);
    break;
  case DMR_APP_BODY_LRRP:
    dmr_lrrp_describe(body,sizeof body,&m->u.lrrp);
    append(buf,size,&len,"%s",body);
    break;
  case DMR_APP_BODY_ARS:
    dmr_ars_describe(body,sizeof body,&m->u.ars);
    append(buf,size,&len,"%s",body);
    break;
  case DMR_APP_BODY_TMS:
    dmr_tms_describe(body,sizeof body,&m->u.tms);
    append(buf,size,&len,"%s",body);
    break;
  case DMR_APP_BODY_HYTERA:
    dmr_hytera_describe(body,sizeof body,&m->u.hytera);
    append(buf,size,&len,"%s",body);
    break;
  case DMR_APP_BODY_SHORT_TEXT:
    dmr_short_text_describe(body,sizeof body,&m->u.short_text);
    append(buf,size,&len,"%s",body);
    break;
  case DMR_APP_BODY_ICMP:
    append(buf,size,&len,"ICMP %s type=%u code=%u",dmr_icmp_type_name(m->u.icmp.type),(unsigned)m->u.icmp.type,
           (unsigned)m->u.icmp.code);
    break;
  case DMR_APP_BODY_XCMP:
    append(buf,size,&len,"XCMP type=%02X%s (not parsed)",(unsigned)m->u.xcmp.message_type,
           m->u.xcmp.message_type == DMR_XCMP_NETWORK_FREQUENCY_FILE ? " network-frequency-file" : "");
    break;
  default:
    append(buf,size,&len,"%s (not parsed)",dmr_app_kind_name(m->kind));
    break;
  }
  append(buf,size,&len," len=%zu",m->payload_length);
  if(m->incomplete)
    append(buf,size,&len," INCOMPLETE");
  if(m->retransmission)
    append(buf,size,&len," retransmission");
  return finish(buf,size,len);
}
