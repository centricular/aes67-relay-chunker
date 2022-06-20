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

use fragment_enc::frame::EncodedFrame;

use clap::{Arg, Command};

use gst::prelude::*;
use gst::{gst_info, gst_trace};
use gst::{Caps, ClockTime, ReferenceTimestampMeta};
use gst_rtp::prelude::RTPHeaderExtensionExt;

use once_cell::sync::Lazy;

use atomic_refcell::AtomicRefCell;

use std::fs::File;
use std::io::prelude::*;

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
    frames: Vec<EncodedFrame>,
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

    // Get the audiotestsrc's source pad
    let src_pad = src.static_pad("src").unwrap();

    // Add a buffer probe to the pad so we can decorate buffers with
    // GstReferenceTimestampMetas which the RTP Header Extension writer
    // will look for (in the SDP/RTSP case rtpjitterbuffer adds these)
    let ts_meta_ref = Caps::builder("timestamp/x-systemclock").build();
    src_pad.add_probe(gst::PadProbeType::BUFFER, move |_, probe_info| {
        if let Some(gst::PadProbeData::Buffer(ref mut buffer)) = probe_info.data {
            let pts = buffer.pts().unwrap();

            ReferenceTimestampMeta::add(buffer.make_mut(), &ts_meta_ref, pts, ClockTime::NONE);
        }

        gst::PadProbeReturn::Ok
    });

    let capsfilter = gst::ElementFactory::make("capsfilter", None).unwrap();

    capsfilter.set_property(
        "caps",
        gst::Caps::builder("audio/x-raw")
            .field("rate", 48_000i32)
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
                .help("Input URI, e.g. srt://0.0.0.0:7001?mode=listener&passphrase=longpassword or udp://0.0.0.0:8001"),
        )
        .arg(
            Arg::new("encoding")
                .short('e')
                .long("encoding")
                .help("Encoding (and muxing) of assembled audio chunks")
                .possible_values(["ts-aac-fdk", "ts-aac-vo", "aac-fdk", "aac-vo", "flac", "none"])
                .default_value("flac"),
        )
        .arg(
            Arg::new("frames-per-chunk")
                .short('f')
                .long("frames-per-chunk")
                .help("How many (encoded) frames of 1024 samples there should be per output audio chunk")
                .default_value("150"),
        )
        .arg(
            Arg::new("output-pattern")
                .short('o')
                .long("output-pattern")
                .takes_value(true)
                .value_name("FILENAME-PATTERN")
                .help("File path pattern for chunks, must contain '{num}' placeholder for chunk number, e.g. '/tmp/p1-audio-aac-{num}.ts'")
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
                "Please provide a valid input URI, e.g. srt://0.0.0.0:7001?mode=listener&passphrase=longpassword or udp://0.0.0.0:8001 or test://"
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

    if frames_per_chunk % 3 != 0 {
        eprintln!(
            "Frames per chunk must be a multiple of 3 so that chunk boundaries \
             are at 'even' positions (AAC frame size is 21.3333ms)!"
        );
        std::process::exit(1);
    }

    let conv = gst::ElementFactory::make("audioconvert", None).unwrap();

    // Disable dithering as it would mess with the sample values by adding
    // random values and is also not really needed when feeding into an
    // mp3/aac encoder that will do way worse things to the audio anyway.
    conv.set_property_from_str("dithering", "none");

    let encoding = matches.value_of("encoding").unwrap();

    let enc = match encoding {
        "aac-fdk" | "ts-aac-fdk" => {
            let aacenc = gst::ElementFactory::make("fdkaacenc", None).unwrap();
            aacenc.set_property("perfect-timestamp", false);
            aacenc.set_property("tolerance", 0i64);
            aacenc.set_property("hard-resync", true); // use for flacenc too?
            aacenc
        }
        "aac-vo" | "ts-aac-vo" => {
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

    // How many frames does the encoder need to "stabilise" the bitstream?
    let encoder_stabilisation_frames = match encoding {
        "none" | "flac" => 0,
        "aac-fdk" | "ts-aac-fdk" => 100,
        "aac-vo" | "ts-aac-vo" => 60,
        _ => unreachable!(),
    };

    let mux_mpegts = encoding.starts_with("ts-aac");

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

    let output_pattern = matches.value_of("output-pattern").map(|s| s.to_string());
    if let Some(opattern) = &output_pattern {
        if opattern.find("{num}").is_none() {
            eprintln!("Provided filename output pattern does not contain '{{num}}'!");
            return;
        }
    }

    // Set up AppSink
    let appsink = sink
        .dynamic_cast::<gst_app::AppSink>()
        .expect("Sink element is expected to be an appsink!");

    let chunk_collector = Arc::new(AtomicRefCell::new(ChunkCollector { frames: vec![] }));

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

                collector.frames.push(EncodedFrame {
                    pts: buf.pts(),
                    buffer: buf,
                });

                Ok(gst::FlowSuccess::Ok)
            })
            .new_event(move |appsink| {
                let mut collector = cc_clone.borrow_mut();

                let event = appsink.pull_object().unwrap();
                let ev = event.downcast::<gst::Event>().ok().unwrap();

                use gst::EventView;

                match ev.view() {
                    EventView::CustomDownstream(ev_custom) => {
                        let s = ev_custom.structure().unwrap();
                        match s.name() {
                            "chunk-start" => collector.frames.clear(),
                            "chunk-end" => {
                                let continuity_counter =
                                    s.get::<u64>("continuity-counter").unwrap();

                                let chunk_num = s.get::<u64>("chunk-num").unwrap();

                                let _abs_offset = s.get::<u64>("offset").unwrap();
                                let pts = s.get::<u64>("pts").unwrap();

                                // Note that currently the chunk-end event is
                                // only pushed through the audio encoder on
                                // the next chunk, so we have one chunk delay
                                // on the output side here until we can work
                                // around that. (FIXME: even more if there's
                                // packet loss, although we could probably send
                                // a gap event or drain the encoder if that
                                // happens anyway)

                                let buf = if mux_mpegts {
                                    let chunk = fragment_enc::mpegts::write_ts_chunk(
                                        &collector.frames,
                                        chunk_num,
                                    );

                                    gst::Buffer::from_slice(chunk)
                                } else {
                                    // N.B. in case of FLAC the first few frames
                                    // are header frames without a timestamp. We
                                    // should probably extract those and prepend
                                    // them to each individual chunk (TODO)
                                    let mut adapter = gst_base::UniqueAdapter::new();
                                    for frame in &collector.frames {
                                        adapter.push(frame.buffer.clone());
                                        //println!("Pushed buffer {:?}", frame.buffer);
                                    }
                                    adapter.take_buffer(adapter.available()).unwrap()
                                };

                                let map = buf.map_readable();
                                let buf_data = map.unwrap();
                                let digest = md5::compute(buf_data.as_slice());

                                // Create output filename for the chunk
                                let chunk_fn = if let Some(fn_pattern) = &output_pattern {
                                    // The chunk numbers will vary depending on the frames per chunk,
                                    // so add that to the filename to avoid confusion when the config
                                    // changes. Also, this makes it possible to calculate an absolute
                                    // sample offset from the chunk number and frames per chunk, which
                                    // in turn allows deducing the absolute timestamp of the chunk.
                                    // Note: We've already checked that the pattern contains '{num}'.
                                    let fname = fn_pattern.replace(
                                        "{num}",
                                        &format!("{chunk_num}@{frames_per_chunk}"),
                                    );

                                    Some(fname)
                                } else {
                                    None
                                };

                                let continuous_encoded_frames =
                                    continuity_counter * frames_per_chunk as u64;

                                let drop_chunk =
                                    continuous_encoded_frames < encoder_stabilisation_frames;

                                let msg = if drop_chunk {
                                    format!("continuity {}, discard", continuity_counter)
                                } else if let Some(fname) = &chunk_fn {
                                    format!("file {fname}")
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
                                    buf_data.size(),
                                    continuity_counter,
                                );

                                if !drop_chunk {
                                    // Write chunk to file
                                    if let Some(filename) = &chunk_fn {
                                        match File::create(&filename) {
                                            Ok(mut file) => {
                                                if let Err(err) = file.write(buf_data.as_slice()) {
                                                    eprintln!(
                                                        "ERROR writing file {filename}: {err}"
                                                    );
                                                }
                                            }
                                            Err(ref err) => {
                                                eprintln!("ERROR creating file {filename}: {err}");
                                            }
                                        }
                                    }
                                }
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

    let main_loop_clone = main_loop.clone();

    bus.add_watch(move |_, msg| {
        use gst::MessageView;

        let main_loop = &main_loop_clone;

        match msg.view() {
            MessageView::Eos(..) => {
                println!("EOS. Probably means srt sender went away.");
                main_loop.quit();
            }
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

    loop {
        // Any errors will be picked up via the bus handler
        if let Err(_) = pipeline.set_state(gst::State::Playing) {};

        main_loop.run();

        println!("Shutting down pipeline.");

        pipeline
            .set_state(gst::State::Null)
            .expect("Failed to shut down the pipeline");

        println!("Restarting pipeline...");
    }

    // bus.remove_watch().unwrap();
}
