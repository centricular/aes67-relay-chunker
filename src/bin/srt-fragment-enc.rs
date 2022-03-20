// srt-fragment-enc
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

mod audio_chunker;
mod rtp_hdr_ext;

use clap::{Arg, Command};

use gst::prelude::*;
use gst::{gst_info, gst_trace};
use gst_rtp::prelude::RTPHeaderExtensionExt;

use once_cell::sync::Lazy;

use atomic_refcell::AtomicRefCell;

use std::sync::Arc;

use url::Url;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "srt-fragment-enc",
        gst::DebugColorFlags::empty(),
        Some("SRT fragment encoder"),
    )
});

struct ChunkCollector {
    adapter: gst_base::UniqueAdapter,
}

fn create_srt_input(srt_url: &Url) -> gst::Element {
    let bin = gst::Bin::new(Some("srt-source"));

    let src = gst::Element::make_from_uri(gst::URIType::Src, srt_url.as_str(), None).unwrap();
    //src.set_property("latency", 125);
    //src.set_property("wait-for-connection", false);

    let capsfilter = gst::ElementFactory::make("capsfilter", None).unwrap();

    // maybe we should use rtpgdp payloading?
    capsfilter.set_property(
        "caps",
        gst::Caps::builder("application/x-rtp")
            .field("media", "audio")
            .field("clock-rate", 48_000i32) // FIXME: hardcoded
            .field("channels", 2i32) // FIXME: hardcoded
            .build(),
    );

    let src_pad = capsfilter.static_pad("src").unwrap();

    bin.add_many(&[&src, &capsfilter]).unwrap();

    gst::Element::link_many(&[&src, &capsfilter]).unwrap();

    let ghostpad = gst::GhostPad::with_target(Some("src"), &src_pad)
        .unwrap()
        .upcast::<gst::Pad>();

    bin.add_pad(&ghostpad).unwrap();

    bin.upcast::<gst::Element>()
}

fn create_udp_input(udp_url: &Url) -> gst::Element {
    let bin = gst::Bin::new(Some("udp-source"));

    let src = gst::Element::make_from_uri(gst::URIType::Src, udp_url.as_str(), None).unwrap();

    // maybe we should use rtpgdp payloading?
    src.set_property(
        "caps",
        gst::Caps::builder("application/x-rtp")
            .field("media", "audio")
            .field("clock-rate", 48_000i32) // FIXME: hardcoded
            .field("channels", 2i32) // FIXME: hardcoded
            .build(),
    );

    let src_pad = src.static_pad("src").unwrap();

    bin.add_many(&[&src]).unwrap();

    gst::Element::link_many(&[&src]).unwrap();

    let ghostpad = gst::GhostPad::with_target(Some("src"), &src_pad)
        .unwrap()
        .upcast::<gst::Pad>();

    bin.add_pad(&ghostpad).unwrap();

    bin.upcast::<gst::Element>()
}

// Not sure what the point of this test input is
fn create_test_input() -> gst::Element {
    let bin = gst::Bin::new(Some("test-source"));

    let src = gst::ElementFactory::make("audiotestsrc", None).unwrap();
    src.set_property("is-live", true);
    src.set_property("samplesperbuffer", 48i32);
    src.set_property_from_str("wave", "ticks");

    // FIXME: add ReferenceTimestampMeta

    let capsfilter = gst::ElementFactory::make("capsfilter", None).unwrap();

    capsfilter.set_property(
        "caps",
        gst::Caps::builder("audio/x-raw")
            .field("clock-rate", 48_000i32)
            .field("channels", 2i32)
            .build(),
    );

    let payloader = gst::ElementFactory::make("rtpL24pay", None).unwrap();
    payloader.set_property("min-ptime", 1_000_000i64);
    payloader.set_property("max-ptime", 1_000_000i64);
    payloader.set_property("auto-header-extension", false);

    // Set things up to add our RTP header extension data
    let hdr_ext = gst::ElementFactory::make("x-rtphdrextptp", None)
        .unwrap()
        .downcast::<gst_rtp::RTPHeaderExtension>()
        .unwrap();

    hdr_ext.set_id(1);

    payloader.emit_by_name::<()>("add-extension", &[&hdr_ext]);

    bin.add_many(&[&src, &capsfilter, &payloader]).unwrap();

    gst::Element::link_many(&[&src, &capsfilter, &payloader]).unwrap();

    let src_pad = payloader.static_pad("src").unwrap();

    let ghostpad = gst::GhostPad::with_target(Some("src"), &src_pad)
        .unwrap()
        .upcast::<gst::Pad>();

    bin.add_pad(&ghostpad).unwrap();

    bin.upcast::<gst::Element>()
}

// FLAC encoder will write frame numbers or sample numbers into the header,
// which we'll need to fix up based on something that's based on the absolute
// PTP time in order to get consistent/reproducible output. And once we modify
// that we'll also have to fix up various CRC checksums in the frame.
fn make_flacenc() -> gst::Element {
    let flacenc = gst::ElementFactory::make("flacenc", None).unwrap();

    // To match AAC; make configurable? But note that 'odd' values might have
    // implications about the frame header layout assumed in pad probe below!
    flacenc.set_property("blocksize", 1024u32);

    flacenc.set_property("perfect-timestamp", false);
    flacenc.set_property("tolerance", 0i64);
    flacenc.set_property("streamable-subset", true);

    // Buffer probe to rewrite FLAC headers with frame numbers based on PTP time
    // Frame numbers are only 31-bit, so with frames of 1024 samples a full
    // 31-bit frame number would wrap every 1.45 years or so. I'm sure all
    // decoders will handle it well...
    let src_pad = flacenc.static_pad("src").unwrap();
    src_pad.add_probe(
        gst::PadProbeType::BUFFER,
        move |_pad, ref mut probe_info| {
            if let Some(gst::PadProbeData::Buffer(ref mut buffer)) = probe_info.data {
                // Initial flac headers have no timestamp
                if buffer.pts().is_none() {
                    return gst::PadProbeReturn::Ok;
                }

                let abs_ts = buffer.pts().unwrap();

                let sample_rate = 48000; // FIXME: don't hardcode

                // Convert to an absolute sample offset
                let abs_off = abs_ts
                    .nseconds()
                    .mul_div_floor(sample_rate as u64, *gst::ClockTime::SECOND)
                    .unwrap();

                let frame_num = (abs_off + 1023) / (1024 as u64);

                // println!("flac frame: pts {}, abs_off {}, frame number {}", abs_ts, abs_off, frame_num);

                //assert_eq!(frame_num % 1024, 0);

                let map = buffer.map_readable();
                let in_map = map.unwrap();
                let in_data = in_map.as_slice();

                let frame_num_size = {
                    match in_data[4] {
                        0x00..=0x7f => 1, // 0xxxxxxx (7 bits)
                        0xc0..=0xdf => 2, // 110xxxxx 10xxxxxx (13 bits)
                        0xe0..=0xef => 3, // 1110xxxx 10xxxxxx 10xxxxxx (16 bits)
                        0xf0..=0xf7 => 4, // 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx (21 bits)
                        0xf8..=0xfb => 5, // 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxxx (26 bits)
                        0xfc..=0xfd => 6, // 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx (31 bits)
                        0xfe => 7, // 11111110 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx (36 bits) (for sample number, not frame number)
                        _ => unreachable!("unexpected"),
                    }
                };

                // println!("flac frame before:\n{:02x?}", in_data);

                use crczoo::{crc16_buypass, crc8};

                let mut new_buffer =
                    gst::Buffer::with_size(buffer.size() - frame_num_size + 6).unwrap();
                {
                    let new_buffer_mut = new_buffer.get_mut().unwrap();
                    let mut omap = new_buffer_mut.map_writable().unwrap();
                    let osize = omap.size();
                    let odata = omap.as_mut_slice();
                    odata[0..4].copy_from_slice(&in_data[0..4]);
                    // We're lazy and just always write out the frame number
                    // using the longest available notation (for a 31-bit value)
                    let frame_num = frame_num & 0x7fffffff;
                    odata[4] = (0b11111100 | ((frame_num >> 30) & 0b00000001)) as u8;
                    odata[5] = (0b10000000 | ((frame_num >> 24) & 0b00111111)) as u8;
                    odata[6] = (0b10000000 | ((frame_num >> 18) & 0b00111111)) as u8;
                    odata[7] = (0b10000000 | ((frame_num >> 12) & 0b00111111)) as u8;
                    odata[8] = (0b10000000 | ((frame_num >> 06) & 0b00111111)) as u8;
                    odata[9] = (0b10000000 | ((frame_num >> 00) & 0b00111111)) as u8;
                    odata[10] = crc8(&odata[0..10]); // update header checksum
                    odata[11..].copy_from_slice(&in_data[4 + frame_num_size + 1..]);

                    // update frame checksum
                    let chksum = crc16_buypass(&odata[0..osize - 2]);
                    let chksum_bytes = chksum.to_be_bytes();
                    odata[osize - 2..osize].copy_from_slice(&chksum_bytes[0..2]);

                    //  println!("flac frame after:\n{:02x?}", odata);
                }
                let new_buffer_mut = new_buffer.get_mut().unwrap();

                use gst::BufferCopyFlags;
                buffer
                    .copy_into(
                        new_buffer_mut,
                        BufferCopyFlags::FLAGS
                            | BufferCopyFlags::TIMESTAMPS
                            | BufferCopyFlags::META,
                        0,
                        None,
                    )
                    .unwrap();

                drop(in_map);

                *buffer = new_buffer;
            }

            gst::PadProbeReturn::Ok
        },
    );

    flacenc
}

fn main() {
    // Command line arguments
    let matches = Command::new("srt-fragment-encoder")
        .version("0.1")
        .author("Tim-Philipp Müller <tim centricular com>")
        .about("SRT receiver and fragment encoder")
        .arg(
            Arg::new("input-uri")
                .required(true)
                .help("Input URI, e.g. srt://0.0.0.0:7001?mode=listener or udp://0.0.0.0:8001"),
        )
        .arg(
            Arg::new("encoding")
                .short('e')
                .long("encoding")
                .help("Encoding of assembled audio chunks")
                .possible_values(["aac-fdk", "aac-vo", "flac", "none"])
                .default_value("aac-fdk"),
        )
        .arg(
            Arg::new("frames-per-chunk")
                .short('f')
                .long("frames-per-chunk")
                .help("How many (encoded) frames of 1024 samples there should be per output audio chunk")
                .default_value("325"),
        )
        .after_help(
            "Receives an RTP-packetised audio stream with embedded PTP timestamps through
SRT, encodes it and then fragments it into chunks along absolute timestamp boundaries
for reproducibility",
        )
        .get_matches();

    let input_uri = matches.value_of("input-uri").unwrap();

    let input_url = url::Url::parse(input_uri)
        .or_else(|err| {
            eprintln!(
                "Please provide a valid input URI, e.g. srt://0.0.0.0:7001?mode=listener or udp://0.0.0.0:8001 or test://"
            );
            return Err(err);
        })
        .unwrap();

    // Init + Plugin Registration
    gst::init().unwrap();

    gst::Element::register(
        None,
        "x-rtphdrextptp",
        gst::Rank::None,
        rtp_hdr_ext::RTPHeaderExtPTP::static_type(),
    )
    .unwrap();

    gst::Element::register(
        None,
        "x-audiochunker",
        gst::Rank::None,
        audio_chunker::AudioChunker::static_type(),
    )
    .unwrap();

    // Pipeline
    let main_loop = glib::MainLoop::new(None, false);

    let pipeline = gst::Pipeline::new(None);

    let source = match input_url.scheme() {
        "test" => create_test_input(),
        "srt" => create_srt_input(&input_url),
        "udp" => create_udp_input(&input_url),
        scheme => unimplemented!("Unhandled protocol {}", scheme),
    };

    let depayloader = gst::ElementFactory::make("rtpL24depay", None).unwrap();
    depayloader.set_property("auto-header-extension", false);

    // Set things up to retrieve our RTP header extension data
    let hdr_ext = gst::ElementFactory::make("x-rtphdrextptp", None)
        .unwrap()
        .downcast::<gst_rtp::RTPHeaderExtension>()
        .unwrap();

    hdr_ext.set_id(1);

    depayloader.emit_by_name::<()>("add-extension", &[&hdr_ext]);

    let chunker = gst::ElementFactory::make("x-audiochunker", None).unwrap();
    let frames_per_chunk: u32 = matches.value_of_t("frames-per-chunk").unwrap();
    chunker.set_property("frames-per-chunk", frames_per_chunk);

    let conv = gst::ElementFactory::make("audioconvert", None).unwrap();

    let encoding = matches.value_of("encoding").unwrap();

    // TODO: add mpeg-ts muxing once AAC encoding is consistent
    let enc = match encoding {
        "aac-fdk" => gst::ElementFactory::make("fdkaacenc", None).unwrap(),
        "aac-vo" => gst::ElementFactory::make("voaacenc", None).unwrap(),
        "flac" => make_flacenc(),
        "none" => gst::ElementFactory::make("identity", None).unwrap(),
        _ => unreachable!(),
    };

    let sink = gst::ElementFactory::make("appsink", None).unwrap();
    sink.set_property("sync", false);

    pipeline
        .add_many(&[&source, &depayloader, &chunker, &conv, &enc, &sink])
        .unwrap();

    gst::Element::link_many(&[&source, &depayloader, &chunker, &conv, &enc, &sink]).unwrap();

    if input_url.scheme() == "test" {
        pipeline.set_start_time(gst::ClockTime::NONE);
        pipeline.set_base_time(gst::ClockTime::ZERO);
    }

    // Set up AppSink
    let appsink = sink
        .dynamic_cast::<gst_app::AppSink>()
        .expect("Sink element is expected to be an appsink!");

    let chunk_collector = Arc::new(AtomicRefCell::new(ChunkCollector {
        adapter: gst_base::UniqueAdapter::new(),
    }));

    let cc_clone = chunk_collector.clone();

    appsink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |appsink| {
                let mut collector = chunk_collector.borrow_mut();

                let sample = appsink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buf = sample.buffer().unwrap().copy();
                gst_trace!(
                    CAT,
                    obj: appsink.upcast_ref::<gst::Element>(),
                    "{:?}",
                    buf,
                );
                collector.adapter.push(buf);
                Ok(gst::FlowSuccess::Ok)
            })
            .new_event(move |appsink| {
                let mut collector = cc_clone.borrow_mut();

                let event = appsink.pull_object().unwrap();
                let ev = event.downcast::<gst::Event>().ok().unwrap();

                let adapter = &mut collector.adapter;

                use gst::EventView;

                match ev.view() {
                    EventView::CustomDownstream(ev_custom) => {
                        let s = ev_custom.structure().unwrap();
                        match s.name() {
                            "chunk-start" => {
                                // Should be empty already anyway
                                adapter.clear();
                            }
                            "chunk-end" => {
                                // Note that currently the chunk-end event is
                                // only pushed through the audio encoder on
                                // the next chunk, so we have one chunk delay
                                // on the output side here until we can work
                                // around that. (FIXME: even more if there's
                                // packet loss, although we could probably send
                                // a gap event or drain the encoder if that
                                // happens anyway)
                                let avail = adapter.available();

                                let (pts, _distance) = adapter.prev_pts_at_offset(0);
                                //let pts = pts.unwrap();
                                //assert_eq!(distance, 0);

                                let buf = adapter.take_buffer(avail).unwrap();
                                let map = buf.map_readable();
                                let buf_data = map.unwrap();
                                let digest = md5::compute(buf_data.as_slice());

                                println!("{:?}: {:?}", pts, digest);

                                gst_info!(
                                    CAT,
                                    obj: appsink.upcast_ref::<gst::Element>(),
                                    "chunk @ pts {:?}, digest {:?}, size {} bytes",
                                    pts,
                                    digest,
                                    avail,
                                );
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }

                true
            })
            .build(),
    );

    // Bus main loop

    let bus = pipeline.bus().unwrap();

    // Any errors will be picked up via the bus handler
    if let Err(_) = pipeline.set_state(gst::State::Playing) {};

    let main_loop_clone = main_loop.clone();

    bus.add_watch(move |_, msg| {
        use gst::MessageView;

        let main_loop = &main_loop_clone;

        match msg.view() {
            MessageView::Eos(..) => main_loop.quit(),
            MessageView::Error(err) => {
                println!(
                    "Error from {:?}: {} ({:?})",
                    err.src().map(|s| s.path_string()),
                    err.error(),
                    err.debug()
                );
                main_loop.quit();
            }
            _ => (),
        };

        glib::Continue(true)
    })
    .expect("Failed to add bus watch");

    main_loop.run();

    pipeline
        .set_state(gst::State::Null)
        .expect("Failed to shut down the pipeline");

    bus.remove_watch().unwrap();
}
