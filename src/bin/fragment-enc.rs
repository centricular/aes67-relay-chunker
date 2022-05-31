// fragment-enc
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

mod audio_chunker;
mod fragment_enc;
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
        "fragment-enc",
        gst::DebugColorFlags::empty(),
        Some("Fragment encoder"),
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

fn main() {
    // Command line arguments
    let matches = Command::new("fragment-encoder")
        .version("0.1")
        .author("Tim-Philipp Müller <tim centricular com>")
        .about("Audio receiver and fragment encoder")
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
                .default_value("flac"),
        )
        .arg(
            Arg::new("frames-per-chunk")
                .short('f')
                .long("frames-per-chunk")
                .help("How many (encoded) frames of 1024 samples there should be per output audio chunk")
                .default_value("150"),
        )
        .after_help(
            "Receives an RTP-packetised audio stream with embedded PTP timestamps through
SRT or UDP, encodes it and then fragments it into chunks along absolute timestamp boundaries
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

    // Disable dithering as it would mess with the sample values by adding
    // random values and is also not really needed when feeding into an
    // mp3/aac encoder that will do way worse things to the audio anyway.
    conv.set_property_from_str("dithering", "none");

    let encoding = matches.value_of("encoding").unwrap();

    // TODO: add mpeg-ts muxing once AAC encoding is consistent
    let enc = match encoding {
        "aac-fdk" => {
            let aacenc = gst::ElementFactory::make("fdkaacenc", None).unwrap();
            aacenc.set_property("perfect-timestamp", false);
            aacenc.set_property("tolerance", 0i64);
            aacenc.set_property("hard-resync", true); // use for flacenc too?
            aacenc
        }
        "aac-vo" => {
            let aacenc = gst::ElementFactory::make("voaacenc", None).unwrap();
            aacenc.set_property("perfect-timestamp", false);
            aacenc.set_property("tolerance", 0i64);
            aacenc.set_property("hard-resync", true); // use for flacenc too?
            aacenc
        }
        "flac" => fragment_enc::flac::make_flacenc(),
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
                                let continuity_counter =
                                    s.get::<u64>("continuity-counter").unwrap();

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

                                let msg = if continuity_counter < 10 {
                                    format!("continuity {}, discard", continuity_counter)
                                } else {
                                    "".to_string()
                                };

                                println!("{:?}: {:?} {}", pts, digest, msg);

                                gst_info!(
                                    CAT,
                                    obj: appsink.upcast_ref::<gst::Element>(),
                                    "chunk @ pts {:?}, digest {:?}, size {} bytes, continuity {}",
                                    pts,
                                    digest,
                                    avail,
                                    continuity_counter,
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
