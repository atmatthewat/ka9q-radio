// What a reassembled DMR data packet carries (dmrdata.h): the IPv4 / UDP split, Motorola LRRP, ARS and
// TMS, Hytera's tokenised messages (SMS, RRS), the text of defined short data and UDT, and the
// dispatcher that names a packet and runs the right parser. dmrdataapp.c has the theory of operation
// Copyright 2026, Matthew Kaufman, KA6SQG
#ifndef _DMRDATAAPP_H
#define _DMRDATAAPP_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmrdata.h"

// Every parser obeys one rule: a read past the end of what it was given, or a value that cannot be,
// makes the whole parse fail (status DMR_APP_IDENTIFIED, no fields). A parse never hands back fields it
// read from beyond what it was given. Texts are UTF-8 whatever the air used. An offset in a parse result
// is into the octets that parse was given.

// How far a parser got
enum dmr_app_status {
  DMR_APP_IDENTIFIED = 0, // named from the headers / ports only; the octets are kept and nothing is parsed
  DMR_APP_PARSED = 1,     // every octet of the application message was read and every check on it passed
  DMR_APP_PARTIAL = 2,    // parsed up to something this code does not know; the fields it gives are sound
};
char const *dmr_app_status_name(enum dmr_app_status s);

// How a text was encoded on the air
enum dmr_text_encoding {
  DMR_TEXT_UNKNOWN = 0,
  DMR_TEXT_BINARY,
  DMR_TEXT_BCD,           // 4-bit digits
  DMR_TEXT_ISO7,          // 7-bit characters, packed
  DMR_TEXT_ISO8859,       // 8-bit; part 1 is transcoded, the other parts only below 0x80
  DMR_TEXT_UTF8,
  DMR_TEXT_UTF16BE,
  DMR_TEXT_UTF16LE,
  DMR_TEXT_UTF32BE,
  DMR_TEXT_UTF32LE,
  DMR_TEXT_GBK,           // named, not transcoded (no table here)
};
char const *dmr_text_encoding_name(enum dmr_text_encoding e);

// The longest text: every octet of a packet (and an MNIS prefix) as a three-octet U+FFFD
enum { DMR_APP_TEXT_MAX = 3 * (DMR_DATA_MAX_OCTETS + 3) + 4 };
struct dmr_app_text {
  size_t length;               // octets of UTF-8 (a text may hold NULs; utf8[length] is a NUL)
  char utf8[DMR_APP_TEXT_MAX];
};
size_t dmr_app_text_chars(struct dmr_app_text const *t); // code points

// ---------------- IPv4 and UDP (SAP 4; SAP 3 compressed) ----------------

enum { DMR_IP_PROTOCOL_ICMP = 1, DMR_IP_PROTOCOL_UDP = 17 };

struct dmr_ip_udp {
  // An IPv4 header: version 4, a header length that fits, and a good header checksum
  bool ipv4;
  bool header_checksum_ok;
  uint8_t header_octets;
  uint16_t total_length;
  uint16_t identification;
  bool more_fragments;
  uint16_t fragment_offset;    // in 8-octet units
  uint8_t ttl;
  uint8_t protocol;
  uint32_t source_address;
  uint32_t destination_address;
  bool truncated;              // the datagram says it is longer than the octets given

  // A UDP header (in an unfragmented datagram, or its first fragment) whose length fits
  bool udp;
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t udp_length;
  bool udp_checksum_present;   // 0 = the sender did not compute one
  bool udp_checksum_ok;        // meaningful when present and the datagram is whole

  // The compressed form (SAP 3): no addresses
  bool compressed;
  uint8_t source_address_id;      // SAID
  uint8_t destination_address_id; // DAID
  uint8_t source_port_id;         // SPID (0 = the port is carried in full)
  uint8_t destination_port_id;    // DPID

  // The UDP payload within the octets given
  size_t payload_offset;
  size_t payload_length;
};
// An IPv4 datagram. ipv4 false: not one (wrong version, bad length or bad header checksum)
void dmr_ip_udp_split_ipv4(struct dmr_ip_udp *r,uint8_t const *octets,size_t n);
// A UDP/IPv4 datagram with the TS 102 361-3 compressed header (SAP 3). A hint (dmrdataapp.c); udp false = too short
void dmr_ip_udp_split_compressed(struct dmr_ip_udp *r,uint8_t const *octets,size_t n);
// By the packet's SAP; nothing (ipv4 and udp false) for a packet encrypted, not complete, or of another SAP
void dmr_ip_udp_split_packet(struct dmr_ip_udp *r,struct dmr_data_packet const *p);

// ---------------- Motorola LRRP (UDP 4001, MNIS 0x01 / 0x11) ----------------

enum {
  DMR_LRRP_IMMEDIATE_LOCATION_REQUEST = 0x05,
  DMR_LRRP_IMMEDIATE_LOCATION_RESPONSE = 0x07,
  DMR_LRRP_TRIGGERED_LOCATION_START_REQUEST = 0x09,
  DMR_LRRP_TRIGGERED_LOCATION_START_RESPONSE = 0x0B,
  DMR_LRRP_TRIGGERED_LOCATION = 0x0D,
  DMR_LRRP_TRIGGERED_LOCATION_STOP_REQUEST = 0x0F,
  DMR_LRRP_TRIGGERED_LOCATION_STOP_RESPONSE = 0x11,
  DMR_LRRP_PROTOCOL_VERSION_REQUEST = 0x14,
  DMR_LRRP_PROTOCOL_VERSION_RESPONSE = 0x15,
};
// Token ids (sdrtrunk TokenType)
enum {
  DMR_LRRP_TOKEN_REQUEST_ID = 0x22,        // a length octet, then that many
  DMR_LRRP_TOKEN_UNKNOWN_23 = 0x23,        // 1
  DMR_LRRP_TOKEN_TRIGGER_PERIODIC = 0x31,  // 1: seconds
  DMR_LRRP_TOKEN_TIME = 0x34,              // 5
  DMR_LRRP_TOKEN_VERSION = 0x36,           // 1
  DMR_LRRP_TOKEN_RESULT = 0x37,            // 1 or 2
  DMR_LRRP_TOKEN_SUCCESS = 0x38,           // 0
  DMR_LRRP_TOKEN_TRIGGER_GPIO = 0x42,      // 0
  DMR_LRRP_TOKEN_TRIGGER_DISTANCE = 0x4A,  // 1
  DMR_LRRP_TOKEN_CIRCLE_2D = 0x51,         // 10
  DMR_LRRP_TOKEN_CIRCLE_3D = 0x55,         // 15
  DMR_LRRP_TOKEN_HEADING = 0x56,           // 1
  DMR_LRRP_TOKEN_REQUEST_61 = 0x61,        // 1
  DMR_LRRP_TOKEN_POINT_2D = 0x66,          // 8
  DMR_LRRP_TOKEN_POINT_3D = 0x69,          // 11
  DMR_LRRP_TOKEN_SPEED = 0x6C,             // 2
  DMR_LRRP_TOKEN_REQUEST_73 = 0x73,        // 1
  DMR_LRRP_TOKEN_TRIGGER_ON_MOVE = 0x78,   // 1
};
// Result codes (sdrtrunk ResponseCode)
enum {
  DMR_LRRP_RESULT_SUCCESS = 0x0000,
  DMR_LRRP_RESULT_INVALID_COMMAND = 0x000A,
  DMR_LRRP_RESULT_NO_GPS = 0x0010,
  DMR_LRRP_RESULT_DUPLICATE_REQUEST = 0x0016,
  DMR_LRRP_RESULT_GPS_INITIALIZING = 0x0200,
};
char const *dmr_lrrp_type_name(uint8_t type);   // NULL for one sdrtrunk does not list
bool dmr_lrrp_type_is_response(uint8_t type);
char const *dmr_lrrp_result_name(uint16_t code);

enum dmr_lrrp_shape { DMR_LRRP_NONE = 0, DMR_LRRP_POINT_2D, DMR_LRRP_POINT_3D, DMR_LRRP_CIRCLE_2D, DMR_LRRP_CIRCLE_3D };
char const *dmr_lrrp_shape_name(enum dmr_lrrp_shape s);

// Fields with a has_ flag mean something only when it is set
struct dmr_lrrp {
  enum dmr_app_status status;
  uint8_t type;
  bool type_known;
  bool response;
  uint8_t length_field;
  bool length_ok;              // the length octet equals the octets that follow it

  bool has_request_id;
  uint8_t request_id_length;
  uint8_t request_id[255];

  // Responses
  bool has_result;             // a result token (0x37) or the success token (0x38)
  uint16_t result_code;
  bool has_time;               // UTC
  uint16_t year;
  uint8_t month;
  uint8_t day;
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
  enum dmr_lrrp_shape shape;
  double latitude;             // degrees, north positive
  double longitude;            // degrees, east positive
  uint32_t latitude_raw;
  uint32_t longitude_raw;
  bool has_radius;
  double radius_m;
  bool has_altitude;
  double altitude_m;
  bool has_altitude_accuracy;
  double altitude_accuracy_m;
  bool has_speed;
  uint16_t speed_raw;
  double speed;                // speed_raw / 100; the unit is not known
  bool has_heading;
  double heading_degrees;      // from true north, 2 degree steps
  bool has_version;
  uint8_t version;

  // Requests
  bool has_trigger_periodic;
  uint8_t trigger_seconds;
  bool has_trigger_distance;
  uint8_t trigger_distance;
  bool trigger_gpio;
  bool has_trigger_on_move;
  uint8_t trigger_on_move;
  uint8_t requested_count;
  uint8_t requested_tokens[255]; // the ids of what the request asks for

  uint8_t other_count;
  uint8_t other_tokens[255];     // ids with no payload that carry nothing read here
  size_t unparsed_offset;        // PARTIAL: from the first id this code does not know to the end
  size_t unparsed_length;
};
static inline bool dmr_lrrp_has_position(struct dmr_lrrp const *m){ return m->shape != DMR_LRRP_NONE; }
// The octets of an LRRP message (a UDP payload, or an MNIS packet with its prefix)
void dmr_lrrp_parse(struct dmr_lrrp *m,uint8_t const *octets,size_t n);
// "LRRP immediate-location-response request=.. result=success(0) position=point-2d time": never the
// coordinates, the time or the speed, only that they are there
int dmr_lrrp_describe(char *buf,size_t size,struct dmr_lrrp const *m);

// ---------------- Motorola ARS (UDP 4005, MNIS 0x33) ----------------

enum {
  DMR_ARS_DEVICE_REGISTRATION = 0x0,
  DMR_ARS_DEVICE_DEREGISTRATION = 0x1,
  DMR_ARS_QUERY = 0x4,
  DMR_ARS_USER_REGISTRATION = 0x5,
  DMR_ARS_USER_DEREGISTRATION = 0x6,
  DMR_ARS_USER_REGISTRATION_ACK = 0x7,
  DMR_ARS_REGISTRATION_ACK = 0xF,
};
char const *dmr_ars_type_name(uint8_t type);    // NULL for one sdrtrunk does not list

struct dmr_ars {
  enum dmr_app_status status;
  uint16_t length_field;
  bool length_ok;              // the length equals the octets that follow it
  uint8_t pdu_type;
  bool type_known;
  bool extension;
  bool acknowledge;
  bool priority;
  bool control;

  // Registrations (device and user), when the extension octet is there
  bool has_event;
  uint8_t event;               // 1 = initial registration, otherwise a refresh
  uint8_t encoding;
  bool has_device;
  uint8_t device_id_length;
  char device_id[256];         // the radio ID as ASCII digits, NUL terminated
  bool has_user;
  uint8_t user_id_length;
  uint8_t user_id[255];        // octets as sent
  bool has_password;
  uint8_t password_length;
  uint8_t password[255];       // octets as sent; never logged

  // Acknowledgements
  bool success;                // the acknowledge bit is clear
  bool has_value;
  uint8_t value;               // registration ack: 30-minute units until a refresh (success) or the
                               // reason (failure; 0 = unauthorized device). User registration ack:
                               // session time, or reason 1 = validation failed, 2 = validation timeout
};
static inline bool dmr_ars_is_registration(struct dmr_ars const *m){
  return m->pdu_type == DMR_ARS_DEVICE_REGISTRATION || m->pdu_type == DMR_ARS_USER_REGISTRATION;
}
static inline bool dmr_ars_is_ack(struct dmr_ars const *m){
  return m->pdu_type == DMR_ARS_REGISTRATION_ACK || m->pdu_type == DMR_ARS_USER_REGISTRATION_ACK;
}
void dmr_ars_parse(struct dmr_ars *m,uint8_t const *octets,size_t n);
// The device identifier is shown; the user identifier and the password only that they are there
int dmr_ars_describe(char *buf,size_t size,struct dmr_ars const *m);

// ---------------- Motorola TMS (UDP 4007) ----------------

enum { DMR_TMS_TYPE_MESSAGE = 0x0, DMR_TMS_TYPE_ACK = 0xF, DMR_TMS_ENCODING_UTF16LE = 4 };

struct dmr_tms {
  enum dmr_app_status status;
  uint16_t length_field;
  bool length_ok;              // the length equals the octets that follow it
  uint8_t first_header;
  bool extension;
  bool ack_required;
  bool control;
  uint8_t pdu_type;
  uint8_t address_length;
  uint8_t address[255];
  bool has_sequence;
  uint8_t sequence;            // 5 bits
  bool has_encoding;
  uint8_t encoding;            // 5 bits
  bool is_ack;                 // PDU type 0xF: an acknowledgement, no text
  bool has_text;
  bool leading_crlf;           // the text on the air began with CR LF; it is not in text
  size_t text_offset;          // where the text begins in the message's octets
  struct dmr_app_text text;
};
void dmr_tms_parse(struct dmr_tms *m,uint8_t const *octets,size_t n);
// Never the text, only its length
int dmr_tms_describe(char *buf,size_t size,struct dmr_tms const *m);

// ---------------- Hytera tokens (SMS, RRS, location) ----------------

enum {
  DMR_HYTERA_TOKEN_RRS_HEADER = 0x0200,
  DMR_HYTERA_TOKEN_TMS_HEADER = 0x0201,
  DMR_HYTERA_TOKEN_MESSAGE_ID = 0x0001,
  DMR_HYTERA_TOKEN_SOURCE_ID = 0x0002,
  DMR_HYTERA_TOKEN_DESTINATION_ID = 0x0003,
  DMR_HYTERA_TOKEN_ENCODING = 0x0101,
  DMR_HYTERA_TOKEN_PAYLOAD = 0x0102,
  DMR_HYTERA_TOKEN_RRS_UNKNOWN = 0x0703,
};
// sdrtrunk HyteraEncodeFormat
enum {
  DMR_HYTERA_ENCODING_BINARY = 0,
  DMR_HYTERA_ENCODING_SUBSCRIBER_NUMBER = 1,
  DMR_HYTERA_ENCODING_BCD = 2,
  DMR_HYTERA_ENCODING_ISO7 = 3,
  DMR_HYTERA_ENCODING_ISO8 = 4,
  DMR_HYTERA_ENCODING_NMEA_GPS = 5,
  DMR_HYTERA_ENCODING_IP = 6,
  DMR_HYTERA_ENCODING_UNICODE = 7,
  DMR_HYTERA_ENCODING_BYTES = 8,
  DMR_HYTERA_ENCODING_GBK = 10,
};
enum dmr_hytera_form {
  DMR_HYTERA_OTHER = 0,        // tokens, but neither of the forms below
  DMR_HYTERA_SMS,              // TMS header + encoding + payload
  DMR_HYTERA_REGISTRATION,     // RRS header + destination
  DMR_HYTERA_LOCATION,         // as SMS with the NMEA GPS encoding: named, the payload not parsed
};
char const *dmr_hytera_form_name(enum dmr_hytera_form f);

struct dmr_hytera {
  enum dmr_app_status status;
  enum dmr_hytera_form form;
  int tokens;                  // tokens read

  bool has_tms_header;
  uint16_t message_length;     // from the TMS or RRS header's BCD digits; what it counts is not known
  uint16_t message_flags;      // TMS header
  bool has_rrs_header;
  bool has_message_id;
  uint32_t message_id;
  bool has_source_id;
  uint32_t source_id;
  bool has_destination_id;
  uint32_t destination_id;
  bool has_encoding;
  uint16_t encoding;
  bool has_payload;
  size_t payload_offset;       // the payload token's content as sent
  size_t payload_length;

  // The text of an SMS, when its encoding is one read here
  bool has_text;
  enum dmr_text_encoding text_encoding;
  struct dmr_app_text text;

  size_t unparsed_offset;      // PARTIAL: from the first opcode this code does not know to the end
  size_t unparsed_length;
};
// The destination is an IP address whose low 24 bits are the radio (sdrtrunk DestinationId.isIp)
static inline bool dmr_hytera_destination_is_ip(struct dmr_hytera const *m){
  return m->has_destination_id && m->destination_id > 0x00FFFFFFu;
}
static inline uint32_t dmr_hytera_destination_radio(struct dmr_hytera const *m){ return m->destination_id & 0x00FFFFFFu; }
void dmr_hytera_parse(struct dmr_hytera *m,uint8_t const *octets,size_t n);
int dmr_hytera_describe(char *buf,size_t size,struct dmr_hytera const *m);

// ---------------- Defined short data and UDT text ----------------

// DD format of a defined short data header (sdrtrunk DefinedDataFormat)
enum {
  DMR_DD_BINARY = 0, DMR_DD_BCD = 1, DMR_DD_7BIT = 2,
  DMR_DD_ISO8859_FIRST = 3,    // part 1 (3..13 are parts 1..11, 14..17 parts 13..16)
  DMR_DD_ISO8859_LAST = 17,
  DMR_DD_UTF8 = 18, DMR_DD_UTF16 = 19, DMR_DD_UTF16BE = 20, DMR_DD_UTF16LE = 21,
  DMR_DD_UTF32 = 22, DMR_DD_UTF32BE = 23, DMR_DD_UTF32LE = 24,
};
static inline bool dmr_dd_format_is_text(uint8_t format){ return format >= DMR_DD_7BIT && format <= DMR_DD_UTF32LE; }
uint8_t dmr_dd_iso8859_part(uint8_t format);    // 1..16 (no part 12), or 0
// UDT format (sdrtrunk UnifiedDataTransportFormat)
enum {
  DMR_UDT_FORMAT_BINARY = 0, DMR_UDT_FORMAT_ADDRESS = 1, DMR_UDT_FORMAT_BCD = 2, DMR_UDT_FORMAT_ISO7 = 3,
  DMR_UDT_FORMAT_ISO8 = 4, DMR_UDT_FORMAT_NMEA = 5, DMR_UDT_FORMAT_IP_ADDRESS = 6, DMR_UDT_FORMAT_UNICODE16 = 7,
  DMR_UDT_FORMAT_VENDOR8 = 8, DMR_UDT_FORMAT_VENDOR9 = 9, DMR_UDT_FORMAT_MIXED = 10,
};
static inline bool dmr_udt_format_is_text(uint8_t format){
  return format == DMR_UDT_FORMAT_BCD || format == DMR_UDT_FORMAT_ISO7 || format == DMR_UDT_FORMAT_ISO8
    || format == DMR_UDT_FORMAT_UNICODE16;
}
char const *dmr_udt_format_name(uint8_t format);

struct dmr_short_text {
  enum dmr_app_status status;
  bool udt;                    // UDT; otherwise defined short data
  uint8_t format;              // the UDT format or the DD format
  enum dmr_text_encoding encoding;
  uint8_t iso8859_part;        // defined short data, ISO 8859: which part
  bool has_text;
  struct dmr_app_text text;
};
// bits data bits in octets (first bit = 0x80 of octets[0])
void dmr_short_text_parse_defined(struct dmr_short_text *m,uint8_t format,uint8_t const *octets,size_t n,size_t bits);
void dmr_short_text_parse_udt(struct dmr_short_text *m,uint8_t format,uint8_t const *octets,size_t n,size_t bits);
int dmr_short_text_describe(char *buf,size_t size,struct dmr_short_text const *m);

// ---------------- The dispatcher ----------------

// What a packet carries. The high nibble is the family
enum dmr_app_kind {
  DMR_APP_UNKNOWN = 0x00,          // nothing matched; the octets are kept
  DMR_APP_ENCRYPTED = 0x01,        // an encryption header: the octets are ciphertext and were not looked at

  DMR_APP_MOTOROLA_LRRP = 0x10,    // location
  DMR_APP_HYTERA_LOCATION = 0x11,
  DMR_APP_UDT_LOCATION = 0x12,

  DMR_APP_MOTOROLA_ARS = 0x20,     // registration
  DMR_APP_HYTERA_RRS = 0x21,

  DMR_APP_MOTOROLA_TMS = 0x30,     // text
  DMR_APP_HYTERA_SMS = 0x31,
  DMR_APP_SHORT_DATA_TEXT = 0x32,
  DMR_APP_UDT_TEXT = 0x33,

  DMR_APP_MOTOROLA_XCMP = 0x40,    // other vendor traffic, named
  DMR_APP_MOTOROLA_TELEMETRY = 0x41,
  DMR_APP_MOTOROLA_OTAP = 0x42,
  DMR_APP_MOTOROLA_BATTERY_MANAGEMENT = 0x43,
  DMR_APP_MOTOROLA_JOB_TICKET = 0x44,
  DMR_APP_MOTOROLA_MNIS = 0x45,    // an MNIS application type with no parser
  DMR_APP_CELLOCATOR = 0x46,
  DMR_APP_HYTERA_DATA = 0x47,      // Hytera proprietary / short data that is not SMS, registration or location

  DMR_APP_ICMP = 0x50,             // IP
  DMR_APP_UDP_OTHER = 0x51,        // UDP on a port with no name here
  DMR_APP_IP_OTHER = 0x52,         // IPv4, another protocol, a fragment, or ports that could not be checked
  DMR_APP_IP_COMPRESSED = 0x53,    // SAP 2 / 3
  DMR_APP_ARP = 0x54,              // SAP 5

  DMR_APP_SHORT_DATA = 0x60,       // the standard's services
  DMR_APP_UDT = 0x61,
  DMR_APP_RESPONSE = 0x62,         // a response packet's blocks (selective retry flags)
};
enum dmr_app_family {
  DMR_APP_FAMILY_UNKNOWN = 0, DMR_APP_FAMILY_ENCRYPTED, DMR_APP_FAMILY_LOCATION, DMR_APP_FAMILY_REGISTRATION,
  DMR_APP_FAMILY_TEXT, DMR_APP_FAMILY_VENDOR, DMR_APP_FAMILY_IP, DMR_APP_FAMILY_STANDARD,
};
enum dmr_app_family dmr_app_family_of(enum dmr_app_kind kind);
char const *dmr_app_kind_name(enum dmr_app_kind kind);

// UDP ports (sdrtrunk PacketMessageFactory.createUDPPayload) and MNIS application types (ApplicationType)
enum {
  DMR_PORT_CELLOCATOR = 231,
  DMR_PORT_MOTOROLA_LRRP = 4001,
  DMR_PORT_MOTOROLA_XCMP = 4004,
  DMR_PORT_MOTOROLA_ARS = 4005,
  DMR_PORT_MOTOROLA_TMS = 4007,
  DMR_PORT_MOTOROLA_TELEMETRY = 4008,
  DMR_PORT_MOTOROLA_OTAP = 4009,
  DMR_PORT_MOTOROLA_BATTERY = 4012,
  DMR_PORT_MOTOROLA_JOB_TICKET = 4013,
};
enum { DMR_MNIS_APP_MNIS_LRRP = 0x01, DMR_MNIS_APP_LRRP = 0x11, DMR_MNIS_APP_ARS = 0x33, DMR_MNIS_APP_XCMP = 0x88 };
enum { DMR_XCMP_NETWORK_FREQUENCY_FILE = 2 };
char const *dmr_icmp_type_name(uint8_t type);

// The encryption header's fields of an encrypted packet. Sent in the clear; they name a key, they are not one
struct dmr_app_encrypted {
  uint8_t mfid;
  uint8_t algorithm;
  uint8_t key_id;
  uint32_t iv;
};
struct dmr_app_icmp { uint8_t type; uint8_t code; };  // when its checksum passes
struct dmr_app_xcmp { uint8_t message_type; };        // named, with its first octet; not parsed

// Which member of struct dmr_data_message's union is filled
enum dmr_app_body {
  DMR_APP_BODY_NONE = 0, DMR_APP_BODY_ENCRYPTED, DMR_APP_BODY_LRRP, DMR_APP_BODY_ARS, DMR_APP_BODY_TMS,
  DMR_APP_BODY_HYTERA, DMR_APP_BODY_SHORT_TEXT, DMR_APP_BODY_ICMP, DMR_APP_BODY_XCMP,
};

struct dmr_data_message {
  enum dmr_app_kind kind;
  enum dmr_app_status status;
  bool incomplete;             // the packet was not complete (dmrdataapp.c says what is still parsed)
  bool retransmission;

  // From the packet's header
  uint8_t slot;
  uint32_t source;
  uint32_t destination;
  bool group;
  uint8_t sap;
  enum dmr_data_header_kind header_kind;

  // How the application message was carried
  bool over_ip;                // ip holds a checked IPv4 header
  struct dmr_ip_udp ip;
  bool ports_checked;          // over_ip: the UDP ports were covered by a check that passed
  bool over_mnis;
  uint8_t mnis_application_type;

  // The application message's octets: a UDP payload, an MNIS prefix and packet, or the packet's payload.
  // For an encrypted packet: the ciphertext as received
  uint8_t payload[DMR_DATA_MAX_OCTETS + 3];
  size_t payload_length;
  size_t payload_bits;

  enum dmr_app_body body;
  union {
    struct dmr_app_encrypted encrypted;
    struct dmr_lrrp lrrp;
    struct dmr_ars ars;
    struct dmr_tms tms;
    struct dmr_hytera hytera;
    struct dmr_short_text short_text;
    struct dmr_app_icmp icmp;
    struct dmr_app_xcmp xcmp;
  } u;
};

// What dmr_data_classify() did, for tests and diagnostics
struct dmr_data_classify_trace {
  unsigned parsers_run;        // application parsers called
  bool ip_split;               // the payload was read as an IPv4 datagram
};
// Name a reassembled packet and parse what it carries. trace may be NULL. The assembler does this for
// every packet (packet->app)
void dmr_data_classify(struct dmr_data_message *m,struct dmr_data_packet const *p,struct dmr_data_classify_trace *trace);
// "[DMR data] slot=1 motorola-lrrp src=.. dst=.. udp 4001->4001: LRRP ... len=..": the kind, the radio IDs
// and what the application message is. Never the text of a message, coordinates, a password or payload
int dmr_data_app_describe(char *buf,size_t size,struct dmr_data_message const *m);

#endif
