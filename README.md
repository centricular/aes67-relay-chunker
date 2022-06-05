# aes67-relay-chunker

Receive an AES67 audio stream and relay it to a remote server in the cloud
which will encode it to AAC and mux it and chunk it into fragments of multiple
seconds, e.g. for HLS streaming purposes.

The goal is to do this in such a way that multiple relay/fragment-encoder
pairs will create bit-identical fragments for the same AES67 stream, even
if they are started at different times or packets are lost occasionally.

If there is packet loss, no encoded fragments will be created for chunks
that are incomplete of course (and possibly several chunks after).

Fragment encoders must use the exact same hardware and software configuration
in order to create bit-identical output.

**Status:**

 - Proof-of-concept for research and experimentation purposes.

 - Has only been tested on Linux so far.

**Limitations:**

 - AES67 is currently assumed to be 24-bit PCM, 2 channels, 48kHz, packet size 1ms.

**Applications:**

 - **`aes67-relay`**: receives AES67 audio stream, reconstructs absolute
   PTP timestamps for each packet and relays the audio to a fragment encoder
   via SRT or UDP.

 - **`fragment-enc`**: receives audio decorated with absolute PTP timestamps
   from an `aes67-relay` application via SRT or UDP and then chunks and encodes
   it along absolute timestamp boundaries. This application should be able to
   run on any machine without the need to have access to the original AES67
   stream or the advertised PTP media clock.

## aes67-relay

Receives an AES67 audio stream, reconstructs absolute PTP timestamps for each
packet and relays the audio decorated with the absolute PTP timestamps to a
fragment encoder via SRT or UDP for encoding and chunking.

**Inputs:**

 - SDP file (e.g. for Dante streams), e.g. `sdp:///path/to/dante.sdp`
 - RTSP (Ravenna), e.g. `rtsp://127.0.0.1:8554/audio` (untested)

**Outputs:**

 - UDP, e.g. `udp://127.0.0.1:8001`
 - SRT, e.g. `srt://127.0.0.1:7001`
 - None, `null://`

**Options:**

 - `--drop-probability N`: Drop probability in packets per million,
   so e.g. 20 = 1 packet every 50 seconds (on average) @ 1ms/packet

The application prints the reconstructed absolute PTP timestamp and
a checksum for the first audio packet in each second. This can be
used to verify that multiple relays are reconstructing the exact same
data, and also serves as a heartbeat to show data flow.

Any packets received before PTP clock sync has been achieved will
be dropped.

### Implementation Details

 - RTP packets will contain a 32-bit RTP timestamp based on the audio
   sample rate as clock rate, so will wrap around about once a day for
   a 48kHz audio stream.

 - `rtpjitterbuffer` is the element that will reconstruct the original
   absolute PTP timestamps for us. It will pick up the media clock details
   from the SDP attributes (which will be put into the RTP caps) and
   instantiate an appropriate net clock instance if RFC7273 sync is
   enabled, which we do enable. This clock will approximate and track
   the real PTP clock, but it won't be 100% accurate, and it doesn't have
   to be. It just needs to be synced to within 12 hours accuracy (half timestamp
   wraparound period) in order to determine which period since the PTP epoch
   we're in. Once we have that we can easily reconstruct the absolute sender
   clock timestamp. If the new `add-reference-timestamp-meta` property is set
   the `rtpjitterbuffer` will add a `GstReferenceTimestampMeta` with the
   reconstructed original sender PTP timestamp to each buffer it pushes out.
   The actual buffer timestamp will have been adjusted based on the base time
   and also clock drift between sender and receiver clock, so can't be used
   for our purposes, as we need sample accuracy.

 - after depayloading the raw audio we will re-payload it to RTP format
   in order to send it through our chosen transport (SRT, UDP) to the
   fragment encoder. We decorate each outgoing RTP packet with the
   reconstructed absolute PTP timestamp through a custom header extension
   that we wrote (`x-rtphdrextptp`) for our purposes. This allows the receiver
   to extract the absolute PTP timestamp for each packet again. We didn't have
   to use RTP here for sending the data through SRT, and could just have used
   a thin header, but RTP is convenient and means we can also send it through
   plain UDP without any problems (even if we have larger payloads later that
   may need fragmenting, like FLAC frames).

### Todo

 - Support sending FLAC through tunnel to fragment encoder (stretch goal)

 - Support for SRT authentication

 - Print RTP receiver statistics

 - Print SRT sender statistics

### Known Issues

 - Sometimes the packet flow seems to stop for 0.5-2 minutes and then resumes
   with the backlog (rtpjitterbuffer issue?); sometimes a process dies
   complaining about stdin having been closed. These might all be side effects
   of putting the relay into the background with `&` in the shell. Perhaps
   there is also some unexpected interaction with the IPC to the gstreamer
   `ptp-helper` binary in that case, or it's got to do with multiple relays
   running in parallel on the same machine. (This is all speculation so far.)
   Sometimes the stuck flow resumes again when one hits the enter key in the
   terminal. When the flow gets stuck packets are still being received
   according to wireshark. Needs more investigating.

 - Lots of possible performance optimisations that could be done, e.g. the
   `rtpjitterbuffer`s inside `sdpsrc` or `rtspsrc` are not strictly needed
   here, we could probably get away with doing something minimal that just
   does the PTP timestamp reconstruction without all the rest of the
   jitterbuffer machinery/overhead. But for now this should work fine.

## fragment-enc

Receives audio decorated with absolute PTP timestamps from an `aes67-relay`
application via SRT or UDP and then chunks and encodes it along absolute
timestamp boundaries.

This application can run on any machine without the need to have access to
the original AES67 stream or the advertised PTP media clock.

**Inputs:**

 - UDP, e.g. `udp://0.0.0.0:8001`
 - SRT, e.g. `srt://0.0.0.0:7001?mode=listener`

**Outputs:**

 - None yet (so far only timestamps and checksums printed to terminal)

**Options:**

 - `--encoding <encoding>`: encoding of the output chunks. Options:
   - `none`: raw PCM audio (no encoding)
   - `flac`: FLAC encoding
   - `aac-fdk`: raw AAC encoding with `fdkaacenc`
   - `aac-vo`: raw AAC encoding with `voaacenc`
   - `ts-aac-fdk`: AAC encoding with `fdkaacenc` muxed into MPEG-TS container
   - `ts-aac-vo`: AAC encoding with `voaacenc` muxed into MPEG-TS container

 - `--frames-per-chunk <frames-per-chunk>`: How many (encoded) frames
   of 1024 samples (hardcoded at the moment, AAC frame size) there
   should be per output audio chunk. At 48kHz one frame is 21.333ms.
   `frames-per-chunk` should be a multiple of 3.


The application prints timestamps and checksums of each chunk, as well as a
"continuity counter", that is distance from the last discont, for the first
N frames after a discontinuity (start or packet loss).

Currently no data is written to disk yet (but that should be easy enough to add).

### Implementation Details

The Fragment Encoder receives audio from an `aes67-relay` over SRT or UDP in
form of RTP packets. The relay will have decorated these packets with absolute
PTP timestamps in form of a custom RTP header extension (`x-rtphdrextptp`
implemented in [`src/bin/rtp_hdr_ext/rtp_hdr_ext_ptp.rs`](src/bin/rtp_hdr_ext/rtp_hdr_ext_ptp.rs)).

Currently the audio is always assumed to be L24, 2 channels @ 48kHz and 1ms
packet size, but in future this may be extened to encoded audio as well.

When we RTP depayload the audio, our custom RTP header extension reader will
set the output buffer timestamp (pts) of the depayloaded raw audio to the
absolute PTP timestamp from the header extension. This is for convenience,
we could also have put a `GstReferenceTimestampMeta` on the depayloaded buffers.
Since we're not going to sync to the clock anywhere in this pipeline it doesn't
really matter if the buffer timestamps are consistent or not.

The depayloaded raw audio is fed into a custom audio chunker element (`x-audiochunker`
implemented in [`src/bin/audio_chunker/audio_chunker.rs`](src/bin/audio_chunker/audio_chunker.rs)).

The audio chunker has two tasks:

 1. Chunk audio along absolute timestamp boundaries (i.e. irrespective of
    the start timestamp of the stream)

 2. Detect missing data and discard, or mark for discarding, chunks that
    are incomplete. It should also mark discontinuities, as the encoded
    output may need to be stabilised again after a discontinuity before
    it can be used.

Note that the audio chunker can't necessarily rely on the RTP depayloader
to detect missing audio data here, it should only look at buffer timestamps
and durations.

Once the audio chunker has collected a complete chunk of raw audio samples
it will feed that to the encoder. The chunk size will be a multiple of the
encoder frame size (1024 samples).

The chunker will push a custom serialised event before and after it pushes
each complete chunk to the encoder, so that chunk boundaries can be
reconstructed after the encoders. This could be done differently as well,
e.g. via custom metas, but this is what's there now.

The application collects the output from the encoders into an aggregator
(basically just a buffer store), and goes to process the collected encoded
data whenever it sees the custom events signalling a chunk boundary.

We currently just print a timestamp and checksum of the encoded chunk and
not write it to disk, since it's not very useful yet without any muxing,
and it's enough to demonstrate the principle.

#### AAC + MPEG-TS

Neither raw encoded AAC data nor ADTS framed AAC data need any post-processing
for our use case.

The MPEG-TS muxing however needs to be done in a certain way to make sure the
written bitstream stays consistent (bit-identical) even when there are gaps
in the data being muxed.

Timestamps (PCR + PTS) will be written based on the absolute PTP timestamps
of the audio data, which will be consistent across chunk encoders already,
and will be correct automatically even if some data is missing, so no action
required there.

MPEG-TS header packets such as PATs and PMTs and all media payload packets
have a 4-bit "continuity counter" in the MPEG-TS packet headers. If there's
a discontinuity in the counter since the last packet for a stream, a decoder
will assume there's a stream discontinuity and reset and resync which would
cause glitches. This means that the continuity counter needs to be increasing
consistently at all times even across chunk/fragment boundaries.

Now, the problem we have in our fragment encoder/muxer implementation is that
if there's packet loss and we're missing some audio data and we're skipping
that chunk, we don't necessarily know how many MPEG-TS packets that chunk
would have had (unless we can assume a perfect constant bitrate audio
encoder, which we don't). Which means we don't know what the correct value
of the continuity counter is for the next chunk we write.

How do we get around this?

For PAT and PMT we know how many PAT/PMT we're writing per fragment (only one
at the beginning of the fragment currently). Given that information we can
easily calculate the right continuity counter value based on the absolute
fragment number which we can derive in turn from the absolute PTP timestamp
and the number of samples per fragment.

For the AAC media stream what we do is we simply make sure that in each fragment
the number of MPEG-TS AAC media payload packets is a multiple of 16, so that the
continuity counter for the media stream starts at 0 in each fragment.

However, according to the MPEG-TS specification the continuity counter for
a stream only increases for MPEG-TS packets that actually carry some media
payload data, so we can't just write empty packets with stuffing data at the
end of the chunk. What we can do though is we can write packets with 1 byte of
media payload and stuffing bytes for the rest of the packet.

#### FLAC encoding

FLAC audio frames and frame headers contain two things that thwart our goal
of creating reproducible output just based on the input data and timestamps:

 1. a frame number starting from 0 (means the same frames would get different
    numbers if fragment-encoders are started at different times)

 2. various CRC checksums: one for the header and one for the entire frame

In order to achieve our goal we

 - rewrite the frame header with a frame number that's based on the absolute
   PTP timestamp (frame number is only 31 bits though, so wraps every 1.45 years)

 - update the frame header crc8 checksum for the updated frame number

 - update the frame crc16 checksum for the updated frame header + crc8

### Todo

 - Post error in audio chunker instead of panicking when client feeding
   SRT source disconnects (and an EOS gets sent)

 - audio-chunker should explicitly signal dropped/incomplete chunks, so
   application can know about them and print them.

 - Print SRT receiver statistics

 - Support for SRT authentication

 - Discard encoded chunks without timestamp (caused by header packets with FLAC)

### Known Issues

 - fdk-aac encoder doesn't create reproducible output yet contrary to earlier
   testing. Would need more investigation why (perhaps some settings changed,
   or it's input dependent and we just got lucky before; might require encoder
   co-operation in the worst case).

   - UPDATE: seems to work fine with `--frames-per-chunk=75` which produces
     'cleanly-sized' chunks of 1.8s (or multiples thereof). Previous testing
     was with `--frame-size=325` which resulted in chunks of 6.933333333s
     (no, me neither).

   - We now make sure frames per chunk is a multiple of 3 so that chunks
     start and end at 'even' timestamps.

 - sometimes voaacenc also doesn't create consistent output. When this happens,
   the buffer timestamps are off by one nanosecond from the other encoder,
   e.g. `4:59:24.799999999` vs. `4:59:24.800000000`. Working hypothesis is
   that there is some off-by-one / rounding error in the initial state setup
   somewhere, possibly in the encoder or encoder baseclass, and then everything
   is off by one sample. Needs investigating. Might also be possible to detect
   this in the application and just have it restart itself when that happens.

   - Might not happen with e.g. `--frames-per-chunk=75` which produces
     'cleanly-sized' chunks of 1.8s (or multiples thereof)

   - We now make sure frames per chunk is a multiple of 3 so that chunks
     start and end at 'even' timestamps.

 - panics when SRT is used and sender disconnects (can make it error out
   though and then just restart; or use proposed [`keep-listening`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/967/)
   property, which needs testing to see if it has the behaviour we need).

 - The application currently picks up the end of an encoded chunk only when
   the next chunk has been processed in the encoder because of the way
   serialised events are held back in the audio encoder and only pushed out
   before the next buffer gets pushed. Should be possible to fix this though,
   or work around it in other ways. Not a problem in any case, just suboptimal.
   We could continuously feed packets to the audio encoder and then throw away
   chunks with missing samples in the application, but that increases complexity
   and might add hard to debug corner cases (although perhaps it could be done
   with missing samples filled in, that could simplify things again). We also
   don't want to drain the encoder after each chunk because that might lead to
   encoder reset and glitches.

## Requirements

- GStreamer >= 1.21.0.1 (`main` branch as of 22 March 2022 at time of writing), in particular:
  - [sdpdemux: add media attribute to caps to fix ptp clock handling](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1924)
  - [rtpjitterbuffer: Improve accuracy of RFC7273 clock time calculations](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1955)
  - [rtpjitterbuffer: add "add-reference-timestamp-meta" property](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1964)

## Build

If you don't have Rust installed yet, go to [https://rustup.rs](https://rustup.rs/)
and follow the instructions. Latest stable release is fine.

Build with `cargo build` inside a GStreamer `main` branch development environment.

The binaries can then be found in `target/debug/` or `target/release/` (if built with `--release`).

Technically the build requirement is only GStreamer 1.20, so it would probably
be possible to build everything against a GStreamer 1.20 system installation
and then only run it from inside a GStreamer development environment.

## Preparation

### gst-ptp-helper setcap in GStreamer uninstalled development environment

- If using an uninstalled GStreamer development environment, you will need to give the `gst-ptp-helper` in the build directory appropriate permissions to perform its job (usually this is done during installation):
  ```
  sudo /usr/sbin/setcap cap_net_bind_service,cap_net_admin+ep $BUILDDIR/subprojects/gstreamer/libs/gst/helpers/gst-ptp-helper
  ```

### SDP (if not using RTSP)

The SDP is contained in the SAP announcements that are broadcast regularly. They
can be retrieved e.g. via VLC by clicking on the 'information' tab and copying
the link and stripping the 'sdp://' prefix. The arguments are separated by
newlines already, so one just needs to copy'n'paste into a text editor.

The SDP should look something like this (2ch, 24-bit, 48kHz, 1ms packets assumed):
```
v=0
o=- 278034 278037 IN IP4 10.1.1.22
s=AVIOUSBC-522880 : 2
c=IN IP4 239.69.165.50/32
t=0 0
a=keywds:Dante
m=audio 5004 RTP/AVP 97
i=2 channels: Left, Right
a=recvonly
a=rtpmap:97 L24/48000/2
a=ptime:1
a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-52-28-80:0
a=mediaclk:direct=1266592257
```

## Testing

### Multiple independent AES67 receivers reconstruct the exact same audio stream and timestamping

This should be the case even if started at different times or when restarted.

Either:

 - Terminal 1: `./target/debug/aes67-relay sdp:///path/to/dante.sdp null://`

 - Terminal 2: `./target/debug/aes67-relay sdp:///path/to/dante.sdp null://`

 - stop/restart at will

or

 - `./target/debug/aes67-relay sdp:///path/to/dante.sdp null:// & sleep 10 && ./target/debug/aes67-relay sdp:///path/to/dante.sdp null://`
   (but see Known Issues below)

Packet loss should not affect anything:

 - pass e.g. `--drop-probability=50` to one receiver and `--drop-probability=180`
   to the other.

### Consistent encoding with different start positions and across restarts

### UDP

 - Terminal 1: `./target/debug/aes67-relay sdp:///path/to/dante.sdp udp://127.0.0.1:8000`

 - Terminal 2: `./target/debug/aes67-relay sdp:///path/to/dante.sdp udp://127.0.0.1:8002`

 - Terminal 3: `./target/debug/fragment-enc udp://0.0.0.0:8000 --frames-per-chunk=75 --encoding=none`

 - Terminal 4: `./target/debug/fragment-enc udp://0.0.0.0:8002 --frames-per-chunk=75 --encoding=none`

 - then stop/restart senders or receivers at will

 - also try with `--encoding=flac` and `--encoding=aac-vo`

### SRT

 - Terminal 1: `./target/debug/aes67-relay sdp:///path/to/dante.sdp srt://127.0.0.1:7001`

 - Terminal 2: `./target/debug/aes67-relay sdp:///path/to/dante.sdp srt://127.0.0.1:7002`

 - Terminal 3: `./target/debug/fragment-enc srt://0.0.0.0:7001?mode=listener --frames-per-chunk=75 --encoding=none`

 - Terminal 4: `./target/debug/fragment-enc srt://0.0.0.0:7001?mode=listener --frames-per-chunk=75 --encoding=none`

 - then stop/restart senders or receivers at will

 - also try with `--encoding=flac` and `--encoding=aac-vo`

### Consistent encoding if packet loss occurs

- Same as above, but pass an extra `--drop-probability=50` / `--drop-probability=30`
  to the `aes67-relay` (different values for different instances).

## License

Mozilla Public License Version 2.0, see [`LICENSE-MPL`](LICENSE-MPL).
