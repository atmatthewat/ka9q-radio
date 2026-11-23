Decoding DMR with ka9q-radio
Matthew Kaufman, KA6SQG, November 2026
=====================================

*dmrd* decodes ETSI DMR (TS 102 361) signals from *radiod*: repeater outputs, both timeslots, on conventional and multi-site systems (Motorola Capacity Plus and IP Site Connect, amateur repeaters and networks). Like *p25d* and *pcmrecord*, it listens to a multicast group and handles every channel (SSRC) on it at once, each in its own receiver thread. It:

- logs every transmission on each timeslot, with its talkgroup or unit, source, colour code, how it began and ended, and its encryption state;
- sends the speech of clear (unencrypted) calls as ka9q-radio RTP audio streams that *monitor* plays and *pcmrecord* records (when built with mbelib);
- when several repeaters carry the same call at once, as the repeaters of a multi-site system do, makes one stream of it and takes each 20 ms of speech from whichever repeater received it best;
- decodes control signalling (CSBKs and multi-block CSBKs, short link control) and logs it with what it says about the site: its identity, the rest channel, neighbours, channel grants and releases.

Not yet: grouping the repeaters of a site and the sites of a system from a configuration (each channel is its own site for now), following trunked calls on Capacity Plus, Connect Plus or Tier III systems by asking *radiod* for granted channels, and data packets.

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
- **-T**, **--ttl** *ttl*: multicast TTL of the voice output (default 0: this host only)
- **-p**, **--tos** *tos*: IP type of service of the voice output (default 184, expedited forwarding)
- **-c**, **--color-code** *n*|**any**|**track**: the colour code to decode, 0-15; **track** (the default) takes each channel's from its first strong sync and follows it; **any** decodes every one
- **-M**, **--mobile**: also look for mobile station and direct mode syncs (simplex, talkaround), not only repeater outputs
- **-y**, **--system-type** *type*: the kind of system the channels belong to, which says how its signalling is read: **conventional** (the default; amateur repeaters, IP Site Connect), **tier3**, **capacity_plus**, **linked_capacity_plus**, **connect_plus**, **capacity_max**, **hytera_xpt** or **hytera_tier3**
- **-v**, **--verbose**: more messages; at -v each channel also logs a status line, and link control, talker aliases and re-anchored clocks are logged
- **-u**, **--update** *seconds*: interval between the -v status lines (default 10)
- **-t**, **--timeout** *seconds*: close a channel after this long without data (default 20)
- **-S**, **--ssrc** *ssrc*: decode only this channel
- **-o**, **--source** *name-or-address*: accept only this sender (source-specific multicast)
- **-A**, **--iface** *interface*: default multicast interface
- **-l**, **--locale** *locale*: locale for number formatting (default $LANG)
- **-V**, **--version**: show version and exit

SIGUSR1 and SIGUSR2 raise and lower the verbosity while *dmrd* runs. SIGINT, SIGTERM and SIGQUIT stop it; transmissions in progress are ended first. Input is handled as *p25d* handles it: each channel's format and clock come from the status *radiod* sends, lost packets are replaced with zeroes so the symbol timing holds, late and reordered packets are put back in order, and gaps longer than a second are skipped.

## Voice output

A transmission's voice is sent only once the call tracker has labelled it clear, and nothing labelled encrypted or not yet known is ever decoded to speech. Its rule, in short: voice waits until a checked word of the transmission (a voice LC header, or an embedded LC) says unencrypted; a PI header, an LC's privacy bit, burst F's encryption parameters or the EMB's PI bit say encrypted (the last two only when a second word agrees, since one alone is often a damaged word); clear does not cross a gap in the voice, and a transmission once encrypted stays so. Voice held while it waits is sent, with its own timing, once the transmission turns out clear, and dropped otherwise. Preferring clear audio to silence, the rule takes an embedded LC with up to four corrected bits as saying clear, and a burst that nothing confirmed as voice when its own frames needed few corrections; in testing on generated signals with errors, fades and lost bursts, no frame of an encrypted transmission has been labelled clear.

The speech is 8 kHz mono s16be, one RTP packet per 20 ms frame, with *radiod*-style status (frequency, signal to noise of the channel it came from, a description such as **DMR TG 3 src 1**), so *monitor* and *pcmrecord* take it like any *radiod* stream:
```
monitor dmr-pcm.local
```

**Streams.** A group call's stream has its talkgroup as its SSRC, whichever repeater carries it, so a listener sees one stream per talkgroup. A unit-to-unit call, and voice whose destination is not known yet, has the channel's SSRC times ten plus the slot (e.g. **4534251**).

**Voting.** On a multi-site system a wide-area call goes out at the same moment from every repeater of the sites it is on. *dmrd* lines the repeaters' copies up (they send the same vocoder frames, 30 to 60 ms apart) and plays each frame, 120 ms after it is due, from the copy with the fewest error corrections, keeping the repeater it last used on a tie. A repeater that fades is simply not chosen; with the leading repeater of a Capacity Plus system blanked for 3 to 5 seconds in the middle of three calls, every frame was still played, against nine in ten from one repeater alone. Where the copies do not line up (repeaters that do not send identical frames) the stream follows one repeater and moves to another when it fades. Where the same talkgroup number carries different conversations on different repeaters (amateur repeaters' local talkgroups, say), a copy that has not lined up within a second is a different call and gets its own stream, under its channel's SSRC times ten plus the slot.

### The vocoder

DMR's vocoder is the AMBE+2 half rate vocoder of P25 Phase 2, and *dmrd* uses the same one as *p25d*: mbelib, when it is found at build time. See *p25d.md* (**The vocoder**, and **Things to know**) for what mbelib does and does not do, and its README's caution about patents.

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
The times in a count are local. Since each channel is its own site for now, a line about another repeater of the site says it is not configured. A channel release (P_CLEAR) heard on a slot ends the transmission there.

## Running as a service

```
sudo systemctl enable --now dmrd@dmr-iq.local
tail -f /var/log/dmrd.log
```
The instance name is the multicast group. All instances append to **/var/log/dmrd.log**; standard error goes to the journal. For voice output override **ExecStart** with **systemctl edit dmrd@dmr-iq.local**, e.g. **ExecStart=/usr/local/sbin/dmrd -R dmr-pcm.local %i** (after an empty **ExecStart=** line).

## Notes and credits

### Things to know

- **What has been tested.** On the air, from this tree's *radiod* with an Airspy R2: a Motorola Capacity Plus system of four repeaters on two sites (wide-area calls, beacons, both slots), and 67 amateur repeater outputs at once. From recordings of those repeaters and from generated signals (clear and encrypted calls, late entry, unit-to-unit calls, data, both slots, base station, mobile and direct mode, noise and fading): each layer checked frame for frame and field for field.
- **CPU.** *dmrd* takes about a quarter of a core of an Apple M-series machine for 67 channels; *radiod* making 67 I/Q channels takes about three cores.
- **One front end, for now.** The repeaters decoded must all be within what one *radiod* front end covers. Multi-site and trunked systems often span more than one tuner's bandwidth (e.g. 450-455 and 460-465 MHz); work with more than one *radiod*, choosing for each frequency the one that covers it, is planned.
- **Talkgroup numbers.** A stream's SSRC is the talkgroup, and talkgroup numbers are unique only within one system: run one *dmrd*, with its own output group, per system, or accept that two systems' calls on the same number will be voted as one (they will not line up, and the second gets its own stream).

### Credits

sdrtrunk (Dennis Sheirer, GPL-3) and OP25 (Max H. Parke KA1RBI, Graham J. Norbury and others, GPL-3) were used as references for DMR implementation details, along with ETSI TS 102 361. Taken from them, with a credit beside each in the source: the sync words, the Hamming generator matrices, the CACH bit positions, the block product code layouts and interleaves, the RS(12,9) field and octet order, the CRC masks, the link control, talker alias and burst layouts, and the CSBK opcode table, message layouts and channel numbering (sdrtrunk; OP25 for parts of Connect Plus). The decoders are not theirs, and several of sdrtrunk's known errors (its EMB table for colour codes 8-15, its inverted RS(12,9) check, its CRC residual rule) are not repeated. Speech decoding uses mbelib (https://github.com/szechyjs/mbelib) when it is installed.

Much of what is here was first worked out, prototyped and run in production by the author in the receivers behind scanrad.io. That is especially true of the front-end signal processing: the approach to receive filtering, carrier frequency tracking, symbol timing recovery and burst framing was originally written for those receivers and tuned there. Those receivers are not ka9q-radio code: what is here is that work, rewritten by the author in plain C for this tree with the assistance of Anthropic's Claude (the Fable and Opus models).
