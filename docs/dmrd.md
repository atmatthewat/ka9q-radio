Decoding DMR with ka9q-radio
Matthew Kaufman, KA6SQG, November 2026
=====================================

*dmrd* decodes ETSI DMR (TS 102 361) signals from *radiod*: repeater outputs, both timeslots, on conventional and multi-site systems (Motorola Capacity Plus and IP Site Connect, amateur repeaters and networks). Like *p25d* and *pcmrecord*, it listens to a multicast group and handles every channel (SSRC) on it at once, each in its own receiver thread. It:

- logs every transmission on each timeslot, with its talkgroup or unit, source, colour code, how it began and ended, and its encryption state;
- sends the speech of clear (unencrypted) calls as ka9q-radio RTP audio streams that *monitor* plays and *pcmrecord* records (when built with mbelib);
- when several repeaters carry the same call at once, as the repeaters of a multi-site system do, makes one stream of it and takes each 20 ms of speech from whichever repeater received it best;
- decodes control signalling (CSBKs and multi-block CSBKs, short link control) and logs it with what it says about the site: its identity, the rest channel, neighbours, channel grants and releases;
- follows trunked calls: when a site announces a call on a repeater no channel carries (a Capacity Plus Site Status, a Tier III, Connect Plus, Capacity Max or Hytera grant), it asks *radiod* for that repeater for as long as the call lasts.
- decodes packet data: data headers of every kind, blocks at rate 1/2, 3/4 and 1 (confirmed ones with their retries), short data, UDT and unified single block data, and what the packets carry: IP and UDP, Motorola location (LRRP), registration (ARS) and text (TMS), Hytera messages, short data and UDT text.

## Configuring *radiod*

*dmrd* needs complex baseband (I/Q), not demodulated audio, at 19.2 kHz: four samples per 4800 baud symbol. Give it every repeater output you want decoded. See **config/examples/fragments/dmr.conf**:
```
[DMR]
data = dmr-iq.local
mode = iq
samprate = 19200
low = -6250
high = +6250
encoding = f32le
agc = no
gain = 60
freq = "453m4250 453m9750 460m1375 460m6375"
```
Each frequency becomes a separate channel with its own SSRC (the frequency in kHz), all sent to **dmr-iq.local**. Give the I/Q its own group, one nothing else listens to: *monitor* on a group that carries I/Q plays it as noise.

As for *p25d*, the *iq* preset's AGC is turned off and a fixed gain used: *dmrd* sets its own level, and with 32-bit floats there is no clipping. **s16be**, **s16le**, **f32le** and **f32be** are accepted.

**Front end gain.** A DMR repeater's signal is often strong and the band busy; overload shows up as a channel that has signal and no syncs. On an Airspy R2 the software AGC's top step (linearity 21) was enough to lose every burst of a nearby Capacity Plus system, which decoded cleanly at steps 14 to 17. Fix the gain with **gainstep =** and lower **agc-low-threshold** so the AGC does not climb back:
```
[airspy]
linearity = yes
gainstep = 17
agc-low-threshold = -100
```

## Running *dmrd*

```
dmrd [options] dmr-iq.local [more groups ...]
```
- **-I**, **--input** *group*: add an input group (groups may also be given without -I)
- **-R**, **--pcm-out** *group*: send voice to this multicast group (e.g. **dmr-pcm.local**); without it, no audio
- **-N**, **--name** *name*: name the voice output is advertised under (default: not advertised)
- **-D**, **--data-out** *group*: send each packet data packet, with what it carries, to this multicast group (see **Packet stream** below); without it, packet data is only logged
- **-T**, **--ttl** *ttl*: multicast TTL of the voice and packet output (default 0: this host only)
- **-p**, **--tos** *tos*: IP type of service of the voice and packet output (default 184, expedited forwarding)
- **-c**, **--color-code** *n*|**any**|**track**: the colour code to decode, 0-15; **track** (the default) takes each channel's from its first strong sync and follows it; **any** decodes every one
- **-M**, **--mobile**: also look for mobile station and direct mode syncs (simplex, talkaround), not only repeater outputs (**-s all**)
- **-s**, **--stations** **bs**|**ms**|**direct**|**all**|**auto**: which stations' syncs to look for: **bs** (the default) a repeater output, **ms** a repeater input or simplex, **direct** TDMA direct mode, **all** every family, **auto** every family until one family's synced bursts lead each other's by more than 10, then that one only, until 5 seconds pass without a sync (logged); a synced burst counts only within 400 ms of the one before, so that noise's stray syncs do not add up
- **-L**, **--learn-crc-masks**: accept messages whose check fails with a residual seen twice (see **CRC masks** below); also **learn-crc-masks** in a sites file
- **-f**, **--sites** *file*: which repeaters make up each site, and the system each site belongs to (see **Sites** below)
- **-n**, **--no-follow**: don't ask *radiod* for the repeaters calls are announced on
- **-H**, **--hold** *seconds*: keep a followed repeater this long after the last sign of its call (default 5)
- **-g**, **--talkgroups** *list*: follow group calls on only these talkgroups, e.g. **1,3,9000-9099** (repeatable)
- **-x**, **--exclude** *list*: never follow group calls on these talkgroups (repeatable)
- **-m**, **--max-calls** *n*: follow at most *n* calls at once (default: no limit; rest channels don't count)
- **-y**, **--system-type** *type*: the kind of system the channels belong to, which says how its signalling is read: **conventional** (the default; amateur repeaters, IP Site Connect), **tier3**, **capacity_plus**, **linked_capacity_plus**, **connect_plus**, **capacity_max**, **hytera_xpt** or **hytera_tier3**
- **-v**, **--verbose**: more messages; at -v each channel also logs a status line and each site a summary, and link control, talker aliases, re-anchored clocks and probes of a dark site are logged
- **-u**, **--update** *seconds*: interval between the -v status lines (default 10)
- **-t**, **--timeout** *seconds*: close a channel after this long without data (default 20)
- **-S**, **--ssrc** *ssrc*: decode only this channel
- **-o**, **--source** *name-or-address*: accept only this sender (source-specific multicast)
- **-A**, **--iface** *interface*: default multicast interface
- **-l**, **--locale** *locale*: locale for number formatting (default $LANG)
- **-V**, **--version**: show version and exit

SIGUSR1 and SIGUSR2 raise and lower the verbosity while *dmrd* runs. SIGINT, SIGTERM and SIGQUIT stop it; transmissions in progress are ended first. Input is handled as *p25d* handles it: each channel's format and clock come from the status *radiod* sends, lost packets are replaced with zeroes so the symbol timing holds, late and reordered packets are put back in order, and gaps longer than a second are skipped.

## Voice output

Only voice the call tracker has labelled clear is decoded to speech. Its rule is *p25d*'s: the last word wins, and nothing is held back to be confirmed. A transmission starts clear. Two kinds of word say encrypted, and each is undone only by a word of its own kind: a checked link control word (a voice LC header or an embedded LC) with the privacy bit set says encrypted and one with it clear says clear; a PI header or burst F's encryption parameters say encrypted, and this channel's burst F carrying another message (null, TXI) says clear; a reverse channel burst (EMB PI = 1) is the other slot's and says nothing. Voice is encrypted while either says so, so on a system that signals encryption only in burst F the link control words saying clear in between do not undo it. The EMB's PI bit is not a privacy flag (some systems set it on clear calls) and is not used. Each frame goes out as it arrives, labelled by the rule as it stands after its own burst's words.

What that costs, accepted so that no clear speech is lost: a damaged word that passes its checks with wrong contents mislabels the voice until the next word of its kind decodes: that much clear speech muted, or that much of an encrypted transmission decoded as noise. A word of each kind comes once a superframe (360 ms), but on a fading signal they are lost too: in a simulation with about 15% of bursts damaged and sync lost every 200 bursts, encrypted calls came out clear in runs of up to 2.3 s. An encrypted transmission whose header was missed is decoded as noise until its first embedded LC or burst F decodes. Before a transmission has an identity (a late entry, until its first embedded LC), a burst whose voice needed more than 9 error corrections is taken for noise and not decoded: a false sync on noise starts a late entry of a burst or two.

The speech is 8 kHz mono s16be, one RTP packet per 20 ms frame, with *radiod*-style status (frequency, signal to noise of the channel it came from, a description such as **DMR TG 3 src 1**), so *monitor* and *pcmrecord* take it like any *radiod* stream:
```
monitor dmr-pcm.local
```

**Streams.** A group call's stream has its talkgroup as its SSRC, whichever repeater carries it, so a listener sees one stream per talkgroup. A unit-to-unit call, and voice whose destination is not known yet, has the channel's SSRC times ten plus the slot (e.g. **4534251**).

**Voting.** On a multi-site system a wide-area call goes out at the same moment from every repeater of the sites it is on. *dmrd* lines the repeaters' copies up (they send the same vocoder frames, 30 to 60 ms apart) and plays each frame, 120 ms after it is due, from the copy with the fewest error corrections, keeping the repeater it last used on a tie. A repeater that fades is simply not chosen; with the leading repeater of a Capacity Plus system blanked for 3 to 5 seconds in the middle of three calls, every frame was still played, against nine in ten from one repeater alone. Where the copies do not line up (repeaters that do not send identical frames) the stream follows one repeater and moves to another when it fades. Where the same talkgroup number carries different conversations on different repeaters (amateur repeaters have been observed to reuse talkgroup numbers for local calls), a copy that has not lined up within a second is a different call and gets its own stream, under its channel's SSRC times ten plus the slot.

### The vocoder

DMR's vocoder is the AMBE+2 half rate vocoder of P25 Phase 2, and *dmrd* uses the same one as *p25d*: mbelib, when it is found at build time. See *p25d.md* (**The vocoder**, and **Things to know**) for what mbelib does and does not do, and its README's caution about patents.

## Packet data

Each packet, once its last block has come (or when the carrier has been quiet for half a second, or a sync is lost, with what arrived), gets one line saying what it carries:
```
... ssrc 453425 453.425000 MHz slot 1 DATA [DMR data] slot=1 motorola-lrrp src=7002 dst=5001 udp 4001->4001: LRRP triggered-location request=01 position=point-2d len=14
... ssrc 453425 453.425000 MHz slot 1 DATA [DMR data] slot=1 motorola-tms src=7002 dst=5001 udp 4007->4007: TMS text chars=19 seq=3 len=48
```
The line names the application and its fields; it never shows a message's text, a position's coordinates or a password. A packet that is not complete (a block missing, a CRC failed) says INCOMPLETE. At **-v** each data header gets a line too, and each packet a second one with its assembly and CRC evidence (blocks received and good, retries, the CRC-32 as received and the readings that would make it pass). Encrypted packets are marked and left as they are. The **-v** status lines count the packets. On generated signals, a confirmed rate 1/2 packet came through whole at an Es/N0 of 9 dB, a rate 3/4 one at 12 dB, and a rate 1 one (which has no error correction) only above that.

### Packet stream

With **-D** *group*, every packet data packet that ends (complete or not; a data header with no blocks after it, such as a status or a response, is a packet too) and every unified single block goes to *group* as one RTP datagram: a 48-octet header, the packet's data header as received (and the vendor's second header after it, if one came), and the octets the packet carried, the message text, position or whatever else it holds included. That is the way to hand packet data to a program of your own (a map of LRRP positions, a log of text messages, a gateway): the log lines name a packet's contents but never show them. Give the stream a group of its own: nothing else in ka9q-radio reads it. **-T** and **-p** apply to it as to speech; at TTL 0 (the default) it is sent on the loopback interface only, so a reader on the same host joins the group there.

Datagrams go to port 5004 of the group, payload type **98**, one stream (SSRC) per channel: the channel's SSRC. The RTP timestamp is the packet's time in milliseconds, modulo 2^32; the sequence number goes up by one per datagram of the stream (numbering is kept for the 256 streams that sent most recently; one that has been quiet while 256 others sent starts afresh). There are no status packets: the header says everything. All numbers are big-endian:

| Octet | Field |
|---|---|
| 0 | Version, 1 |
| 1 | Protocol: 1 DMR |
| 2 | Record: 1 a packet (data header(s) and blocks, short data, UDT), 2 a unified single block |
| 3 | Flags: 0x01 complete (every block arrived and every check passed), 0x02 encrypted (the octets are ciphertext), 0x04 the destination is a talkgroup, 0x08 confirmed delivery, 0x10 trimmed (pad and packet CRC removed: the octets are the user data), 0x20 the packet CRC could be checked (every block arrived), 0x40 it passed, 0x80 a retransmission of the previous packet |
| 4 | Slot: 1 or 2, 0 not known |
| 5 | Octets of data headers after this header: 12 (the data header), 24 (and the vendor's second header that came after it: Motorola MNIS or encryption, Hytera); 0 in a single block |
| 6-7 | Colour code |
| 8 | Format. A packet: its data header, 1 unconfirmed, 2 confirmed, 3 response, 4 defined short data, 5 raw short data, 6 status / precoded short data, 7 UDT, 8 another proprietary header, 9 Motorola encryption, 10 Motorola MNIS, 11 Hytera encryption. A single block: its service type |
| 9 | SAP, the data header's service access point: 0 UDT, 1 Motorola MNIS, 2 and 3 compressed TCP/IP and UDP/IP, 4 IP, 5 ARP, 9 proprietary, 10 short data |
| 10 | What the packet carries, as dmrd classified it: 0x00 not known, 0x01 encrypted; 0x10 Motorola LRRP location, 0x11 Hytera location, 0x12 UDT location; 0x20 Motorola ARS registration, 0x21 Hytera RRS; 0x30 Motorola TMS text, 0x31 Hytera SMS, 0x32 short data text, 0x33 UDT text; 0x40-0x47 other vendor traffic (Motorola XCMP, telemetry, OTAP, battery management, job tickets, MNIS, Cellocator, other Hytera); 0x50 ICMP, 0x51 UDP on another port, 0x52 other IP, 0x53 compressed IP, 0x54 ARP; 0x60 short data, 0x61 UDT, 0x62 a response |
| 11-13 | Blocks expected, received, and good (received and, for confirmed delivery, CRC-9 passed); 255 at most |
| 14-17 | Source (24 bits); 0 in a single block |
| 18-21 | Destination (24 bits); a single block's target |
| 22-29 | Time of the first burst, nanoseconds since the GPS epoch (*radiod*'s clock) |
| 30-33 | The channel's frequency, Hz |
| 34 | Encryption: the encryption header's manufacturer ID (0 if none) |
| 35 | Algorithm |
| 36-37 | Key ID |
| 38-46 | Message indicator, 72 bits: DMR's 32-bit IV in octets 43-46, the rest 0 |
| 47 | Trimmed: pad bits at the end of the last data octet (short data and UDT count their pad in bits and nibbles), 0-7; otherwise 0 |
| 48- | The data headers, 12 octets each, as decoded (their CRC included). Whatever the fields above do not carry is there: a short data or UDT format, a response's class, type and status, a status number, the three octets of a Motorola MNIS header that come before the message |
| then | The data. Trimmed: the user data (for SAP 4, an IPv4 datagram), whether or not the packet CRC passed (flags 0x20 and 0x40 say). Otherwise (a block missing, an encrypted packet) every block's data octets in place, pad and CRC included, missing blocks zero-filled. None for a header with no blocks. A single block: its 12 octets. The data's bit length is 8 times its octets, less octet 47 |

A receiver should check the version and ignore datagrams it doesn't understand; a change to this layout gets a new version. The layout leaves room for other modes (the protocol octet, a 16-bit network code, a 72-bit message indicator), though only *dmrd* sends it so far. A packet can be up to 3,120 octets, more than one Ethernet frame, so a large one leaves as fragments if the stream goes beyond this host.

## Output

One line per event on standard output, as *p25d* writes them:
```
Mon 23 Nov 2026 22:34:57.952925 UTC ssrc 453425 453.425000 MHz slot 1 transmission start TG 3 src 1 cc 0 (header)
Mon 23 Nov 2026 22:35:04.132925 UTC ssrc 453425 453.425000 MHz slot 1 transmission end TG 3 src 1: terminator, 288 frames clear
Mon 23 Nov 2026 22:35:04.252000 UTC stream 3 ended: 288 frames played, 0 lost; 460638 slot 1 chose 288 of 288 (0 corrections) 453425 slot 1 chose 0 of 290 (0 corrections) 453975 slot 2 chose 0 of 290 (0 corrections)
```
The time is that of the signal (the sender's clock, from *radiod*'s status), not of the decoding.

Control signalling gets lines of its own, with the slot (none for a line about the carrier or the site), the colour code (**-** if not known), and what was heard. A message repeated many times, as a rest channel's beacons are, is written once and then counted, the count written a minute after its last repeat:
```
Mon 23 Nov 2026 21:25:30.149 UTC ssrc 453425 453.425000 MHz slot 1 cc 0 CSBK CAP+ SITE STATUS rest LSN 2 idle (x185 since 13:24:28, last 13:25:30)
Mon 23 Nov 2026 21:27:22.469 UTC ssrc 453425 453.425000 MHz slot 2 cc 0 CSBK CAP+ SITE STATUS rest LSN 1 LSN2:tg 1
Mon 23 Nov 2026 21:27:22.469 UTC ssrc 453425 453.425000 MHz cc - REST channel moved: LSN 2 (LCN 1 TS2) -> LSN 1 (LCN 1 TS1) (NOT CONFIGURED: the plan lists no such repeater)
```
The times in a count are local. Lines about a site rather than one of its channels (its identity, its rest channel) name it, e.g. **site SCMTD/1**. A channel release (P_CLEAR) heard on a slot ends the transmission there.

## Sites

A trunked or multi-site system's signalling is about the site: which of its repeaters is the rest channel, which carries a call, which sites neighbour it. Without being told which repeaters make up a site, *dmrd* treats each channel as a site of its own, of the type **-y** gives, and notes that the other repeaters a message names are not configured. A sites file (**-f**) says which they are, one section per site (see **config/examples/dmrd-sites.conf**):
```
[SCMTD 1]
system = SCMTD
site = 1
type = capacity_plus
color-code = 0
freq = "453m4250"
lcn = "1"
```
- **system**, **site**: names for the lines and the speech streams' descriptions (default: the section's name)
- **type**: as **-y** (default: **-y**'s)
- **color-code**: as **-c** (default: **-c**'s)
- **freq**: the site's repeater outputs (the frequencies *radiod* sends them on)
- **lcn**: each repeater's logical channel number, in the same order, as the system's signalling numbers them (Capacity Plus and Tier III name repeaters by LCN); none for a conventional site
- **learn-crc-masks**: as **-L**, for this site (default: **-L**'s)
- **compressed-talkgroups**: the system's talkgroups are in the dialable form of TS 102 361-2 annex C (Hytera Tier III systems use it): a group call's talkgroup is converted to the number a user dials before it is used for anything (streams, logs, **-g** and **-x**). Default no

A channel joins the site that lists its frequency (to within 1 kHz), whichever *radiod* it comes from; one no site lists is a site of its own. The site's channels share its state and its control log, and their clocks are the signal's. At **-v** each site's summary is written with the status lines, and every configured site's once more when *dmrd* stops: its type and identity, grants, how the calls it announced turned out, its channel map, its neighbours (with their control channel or rest channel where the air says) and each of its channels.

**A dark site.** When none of the channels *dmrd* decodes for a site of more than one repeater has heard anything for 5 seconds (every one of them is dark, so none is the control or rest channel), *dmrd* probes the site's other repeaters one at a time, asking *radiod* for each for 2 seconds. One that carries bursts is kept while it does; what it sends then names the control or rest channel, which is followed as usual. A repeater a channel already carries is not probed. So a site can be configured with every repeater it has but only one or two in *radiod*, and still be found when those are not the rest channel.

## CRC masks

The standard XORs each message's check with a fixed mask that names the kind of message: 0xA5A5 on a CSBK's CRC-CCITT, 0x969696 and 0x999999 on the Reed-Solomon parity of a voice header and a terminator. Some systems use values of their own instead, Motorola's restricted access to system ("RAS") among them, and alter the embedded link control's 5-bit checksum the same way, so that a receiver with the standard masks rejects every CSBK, voice header, terminator and embedded link control word they send. Such a message passes its error correction and fails its check by the same value (the residual) every time: the system's mask. Without help *dmrd* hears nothing of such a system. With **-L** (or **learn-crc-masks** for a site) a message whose check fails is accepted once its residual has been seen twice for the same message type within two minutes, and every later one with that residual, as sdrtrunk does. The first time a residual is accepted a line says so:
```
... ssrc 453425 453.425000 MHz CRC mask learned: csbk CSBKO 62 FID 0x10 residual 0x1234, accepted from now on (an LC so accepted never says clear)
```
A message accepted this way has passed its error correction and nothing more, so a link control word accepted with a learned residual gives the call its talkgroup and source and may say it is encrypted, but never that it is clear: such a call is heard only when a properly checked word says clear. Off by default, since it lets more noise through as messages.

## Following calls

A trunked site announces where each call is: a Capacity Plus site in the Site Status its rest channel sends, Tier III, Connect Plus, Capacity Max and Hytera sites in a grant on their control channel. When the repeater a call is announced on has no channel, *dmrd* asks *radiod* for one there, in the same form as the I/Q channels it already decodes from that *radiod* (as *p25d* does: see *p25d.md*), and logs it:
```
Tue 24 Nov 2026 01:20:04.212 UTC site SCMTD/1 follow 453.975000 MHz LCN 1 TS2 ssrc 453975: CAP+ Site Status (LSN 2 tg 1)
```
Each repeat of the announcement asks again, and the channel's own decoder keeps it while it carries voice; **--hold** seconds after both stop, *radiod* removes it, and *dmrd* closes the channel a second after its data stops (**closed (followed channel released)**), so that a channel asked for again starts afresh. Its I/Q joins the site like any configured channel's, and its speech is voted with the other repeaters'. The repeater's frequency comes from the sites file (its LCN), or from the channel map the site learns from the air (Tier III and Connect Plus send it): without either, the call is logged and not followed. Where there is more than one *radiod*, each is asked in turn until one covers the frequency. Channels *radiod* carries anyway (its configured ones) are left alone.

**The rest channel.** A Capacity Plus site's control information (where calls are, where the rest channel goes next) is on its rest channel, which moves from repeater to repeater. When the rest channel is on a repeater no channel carries, *dmrd* asks for it as it would for a call, keeps it for as long as the site goes on naming it the rest channel, and lets it go **--hold** seconds after the rest channel has moved on (unless it then carries a call). So a site can be decoded from fewer channels than it has repeaters, as long as one of them is the rest channel when *dmrd* starts.

**Which calls.** **-g** and **-x** choose by talkgroup, for group calls whose announcement gives it; a call whose talkgroup is not known yet (or a unit-to-unit call) is followed. A Capacity Plus Site Status gives only a talkgroup's low 8 bits, so there a call is followed when any talkgroup of **-g** has them. **-m** caps the calls followed at once. A call already followed stays followed when these would refuse it now. Each refusal is logged, once every 30 s per call:
```
Tue 24 Nov 2026 02:29:47.399 UTC site SCMTD/1 not followed 453.975000 MHz LCN 1 TS2: talkgroup 3 not wanted (-g, -x); CAP+ Site Status (LSN 2 tg 3)
```

## Running as a service

```
sudo systemctl enable --now dmrd@dmr-iq.local
tail -f /var/log/dmrd.log
```
The instance name is the multicast group. All instances append to **/var/log/dmrd.log**; standard error goes to the journal. For voice output override **ExecStart** with **systemctl edit dmrd@dmr-iq.local**, e.g. **ExecStart=/usr/local/sbin/dmrd -R dmr-pcm.local %i** (after an empty **ExecStart=** line).

## Notes and credits

### Things to know

- **What has been tested.** On the air, from this tree's *radiod* with an Airspy R2: a Motorola Capacity Plus system of three sites (wide-area calls, beacons, rest channel moves, both slots), with a sites file and without, and 67 amateur repeater outputs at once. From recordings of those repeaters and from generated signals (clear and encrypted calls, late entry, unit-to-unit calls, data, both slots, base station, mobile and direct mode, noise and fading): each layer checked frame for frame and field for field. Not yet on the air: Tier III, Connect Plus, Capacity Max or Hytera signalling, a site with more than one repeater, packet data, and more than one *radiod*.
- **CPU.** *dmrd* takes about a quarter of a core of an Apple M-series machine for 67 channels; *radiod* making 67 I/Q channels takes about three cores.
- **More than one front end.** Multi-site and trunked systems often span more than one tuner's bandwidth (e.g. 450-455 and 460-465 MHz). Give *dmrd* each *radiod*'s I/Q group: a sites file places channels by frequency whichever *radiod* they come from, and a followed call is asked of each *radiod* in turn until one covers it. This has not yet been tried with two.
- **Talkgroup numbers.** A stream's SSRC is the talkgroup, and talkgroup numbers are unique only within one system: run one *dmrd*, with its own output group, per system, or accept that two systems' calls on the same number will be voted as one (they will not line up, and the second gets its own stream).

### Credits

sdrtrunk (Dennis Sheirer, GPL-3) and OP25 (Max H. Parke KA1RBI, Graham J. Norbury and others, GPL-3) were used as references for DMR implementation details, along with ETSI TS 102 361. Taken from them, with a credit beside each in the source: the sync words, the Hamming generator matrices, the CACH bit positions, the block product code layouts and interleaves, the RS(12,9) field and octet order, the CRC masks, the link control, talker alias and burst layouts, the CSBK opcode table, message layouts and channel numbering (sdrtrunk; OP25 for parts of Connect Plus), the rules for learning CRC masks and for choosing the station family automatically (sdrtrunk), and the packet data header, block and application layouts (sdrtrunk; OP25 for the data headers' common fields), each checked against TS 102 361-1 and -3. The decoders are not theirs, and several of sdrtrunk's known errors (its EMB table for colour codes 8-15, its inverted RS(12,9) check, its CRC residual rule) are not repeated. The Hytera XPT channel grant layout and the Motorola MNIS packet data CRC span follow DSD-FME (lwvmobile) and dsd-neo (arancormonk), both ISC. Speech decoding uses mbelib (https://github.com/szechyjs/mbelib) when it is installed.

Much of what is here was first worked out, prototyped and run in production by the author in the receivers behind scanrad.io. That is especially true of the front-end signal processing: the approach to receive filtering, carrier frequency tracking, symbol timing recovery and burst framing was originally written for those receivers and tuned there. Those receivers are not ka9q-radio code: what is here is that work, rewritten by the author in plain C for this tree with the assistance of Anthropic's Claude (the Fable and Opus models).
