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

use fragment_enc::frame::*;

use clap::{Arg, Command};

use gst::prelude::*;
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
    let bin = gst::Bin::builder().name("srt-source").build();

    let src = gst::Element::make_from_uri(gst::URIType::Src, srt_url.as_str(), None).unwrap();
    //src.set_property("latency", 125);
    //src.set_property("wait-for-connection", false);

    let capsfilter = gst::ElementFactory::make("capsfilter").build().unwrap();

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

    bin.add_many([&src, &capsfilter]).unwrap();

    gst::Element::link_many([&src, &capsfilter]).unwrap();

    let ghostpad = gst::GhostPad::with_target(&src_pad)
        .unwrap()
        .upcast::<gst::Pad>();

    bin.add_pad(&ghostpad).unwrap();

    bin.upcast::<gst::Element>()
}

fn create_udp_input(udp_url: &Url) -> gst::Element {
    let bin = gst::Bin::builder().name("udp-source").build();

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

    bin.add_many([&src]).unwrap();

    gst::Element::link_many([&src]).unwrap();

    let ghostpad = gst::GhostPad::with_target(&src_pad)
        .unwrap()
        .upcast::<gst::Pad>();

    bin.add_pad(&ghostpad).unwrap();

    bin.upcast::<gst::Element>()
}

// Not sure what the point of this test input is
fn create_test_input() -> gst::Element {
    let bin = gst::Bin::builder().name("test-source").build();

    let src = gst::ElementFactory::make("audiotestsrc").build().unwrap();
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

    let capsfilter = gst::ElementFactory::make("capsfilter").build().unwrap();

    capsfilter.set_property(
        "caps",
        gst::Caps::builder("audio/x-raw")
            .field("rate", 48_000i32)
            .field("channels", 2i32)
            .build(),
    );

    let payloader = gst::ElementFactory::make("rtpL24pay").build().unwrap();
    payloader.set_property("min-ptime", 1_000_000i64);
    payloader.set_property("max-ptime", 1_000_000i64);
    payloader.set_property("auto-header-extension", false);

    // Set things up to add our RTP header extension data
    let hdr_ext = gst::ElementFactory::make("x-rtphdrextptp")
        .build()
        .unwrap()
        .downcast::<gst_rtp::RTPHeaderExtension>()
        .unwrap();

    hdr_ext.set_id(1);

    payloader.emit_by_name::<()>("add-extension", &[&hdr_ext]);

    bin.add_many([&src, &capsfilter, &payloader]).unwrap();

    gst::Element::link_many([&src, &capsfilter, &payloader]).unwrap();

    let src_pad = payloader.static_pad("src").unwrap();

    let ghostpad = gst::GhostPad::with_target(&src_pad)
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
                .value_parser(["ts-aac-fdk", "ts-heaacv1-fdk", "ts-heaacv2-fdk", "ts-aac-vo", "aac-fdk", "heaacv1-fdk", "heaacv2-fdk", "aac-vo", "flac", "none"])
                .default_value("flac"),
        )
        .arg(
            Arg::new("bitrate")
                .short('b')
                .long("bitrate")
                .help("Bitrate of encoded audio for lossy formats, in bits per second")
                .num_args(1)
                .value_name("BITRATE")
                .value_parser(clap::value_parser!(i32))
        )
        .arg(
            Arg::new("frames-per-chunk")
                .short('f')
                .long("frames-per-chunk")
                .help("How many (encoded) frames of 1024 samples there should be per output audio chunk")
                .value_parser(clap::value_parser!(u32))
                .default_value("150"),
        )
        .arg(
            Arg::new("output-pattern")
                .short('o')
                .long("output-pattern")
                .num_args(1)
                .value_name("FILENAME-PATTERN")
                .help("File path pattern for chunks, must contain '{num}' placeholder for chunk number, e.g. '/tmp/p1-audio-aac-{num}.ts'")
        )
        .after_help(
            "Receives an RTP-packetised audio stream with embedded PTP timestamps through
SRT or UDP, encodes it and then fragments it into chunks along absolute timestamp boundaries
for reproducibility",
        )
        .get_matches();

    let input_uri = matches.get_one::<String>("input-uri").unwrap();

    let input_url = url::Url::parse(input_uri)
        .inspect_err(|_err| {
            eprintln!(
                "Please provide a valid input URI, e.g. srt://0.0.0.0:7001?mode=listener&passphrase=longpassword or udp://0.0.0.0:8001 or test://"
            );
        })
        .unwrap();

    // Init + Plugin Registration
    gst::init().unwrap();

    gst::Element::register(
        None,
        "x-rtphdrextptp",
        gst::Rank::NONE,
        rtp_hdr_ext::RTPHeaderExtPTP::static_type(),
    )
    .unwrap();

    gst::Element::register(
        None,
        "x-audiochunker",
        gst::Rank::NONE,
        audio_chunker::AudioChunker::static_type(),
    )
    .unwrap();

    // Pipeline
    let main_loop = glib::MainLoop::new(None, false);

    let pipeline = gst::Pipeline::new();

    let source = match input_url.scheme() {
        "test" => create_test_input(),
        "srt" => create_srt_input(&input_url),
        "udp" => create_udp_input(&input_url),
        scheme => unimplemented!("Unhandled protocol {}", scheme),
    };

    let depayloader = gst::ElementFactory::make("rtpL24depay").build().unwrap();
    depayloader.set_property("auto-header-extension", false);

    // Set things up to retrieve our RTP header extension data
    let hdr_ext = gst::ElementFactory::make("x-rtphdrextptp")
        .build()
        .unwrap()
        .downcast::<gst_rtp::RTPHeaderExtension>()
        .unwrap();

    hdr_ext.set_id(1);

    depayloader.emit_by_name::<()>("add-extension", &[&hdr_ext]);

    let chunker = gst::ElementFactory::make("x-audiochunker").build().unwrap();
    let frames_per_chunk = *matches.get_one::<u32>("frames-per-chunk").unwrap();
    chunker.set_property("frames-per-chunk", frames_per_chunk);

    if frames_per_chunk % 3 != 0 {
        eprintln!(
            "Frames per chunk must be a multiple of 3 so that chunk boundaries \
             are at 'even' positions (AAC frame size is 21.3333ms)!"
        );
        std::process::exit(1);
    }

    let conv = gst::ElementFactory::make("audioconvert").build().unwrap();

    // Disable dithering as it would mess with the sample values by adding
    // random values and is also not really needed when feeding into an
    // mp3/aac encoder that will do way worse things to the audio anyway.
    conv.set_property_from_str("dithering", "none");

    let encoding = matches.get_one::<String>("encoding").unwrap();

    let (enc, enc_caps) = match encoding.as_str() {
        "aac-fdk" | "ts-aac-fdk" => {
            let aacenc = gst::ElementFactory::make("fdkaacenc").build().unwrap();
            aacenc.set_property("perfect-timestamp", false);
            aacenc.set_property("tolerance", 0i64);
            aacenc.set_property("hard-resync", true); // use for flacenc too?
            (aacenc, None)
        }
        "heaacv1-fdk" | "ts-heaacv1-fdk" => {
            let aacenc = gst::ElementFactory::make("fdkaacenc").build().unwrap();
            aacenc.set_property("perfect-timestamp", false);
            aacenc.set_property("tolerance", 0i64);
            aacenc.set_property("hard-resync", true); // use for flacenc too?

            // TODO: This requires the fdkaacenc HE-AACv1 support from
            // https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1785
            // but the profile name string might still change in future versions
            // before it gets merged into main.
            let encoder_caps = gst::Caps::builder("audio/mpeg")
                .field("profile", "he-aac-v1")
                .field("stream-format", "raw")
                .build();

            (aacenc, Some(encoder_caps))
        }
        "heaacv2-fdk" | "ts-heaacv2-fdk" => {
            let aacenc = gst::ElementFactory::make("fdkaacenc").build().unwrap();
            aacenc.set_property("perfect-timestamp", false);
            aacenc.set_property("tolerance", 0i64);
            aacenc.set_property("hard-resync", true); // use for flacenc too?

            // TODO: This requires the fdkaacenc HE-AACv2 support from
            // https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1785
            // but the profile name string might still change in future versions
            // before it gets merged into main.
            let encoder_caps = gst::Caps::builder("audio/mpeg")
                .field("profile", "he-aac-v2")
                .field("stream-format", "raw")
                .build();

            (aacenc, Some(encoder_caps))
        }
        "aac-vo" | "ts-aac-vo" => {
            let aacenc = gst::ElementFactory::make("voaacenc").build().unwrap();
            aacenc.set_property("perfect-timestamp", false);
            aacenc.set_property("tolerance", 0i64);
            aacenc.set_property("hard-resync", true); // use for flacenc too?
            (aacenc, None)
        }
        "flac" => (fragment_enc::flac::make_flacenc(), None),
        "none" => (gst::ElementFactory::make("identity").build().unwrap(), None),
        _ => unreachable!(),
    };

    // How many frames does the encoder need to "stabilise" the bitstream?
    let encoder_stabilisation_frames = match encoding.as_str() {
        "none" | "flac" => 0,
        "aac-fdk" | "ts-aac-fdk" => 100,
        "heaacv1-fdk" | "ts-heaacv1-fdk" => 100, // FIXME: untested
        "heaacv2-fdk" | "ts-heaacv2-fdk" => 100, // FIXME: untested
        "aac-vo" | "ts-aac-vo" => 60,
        _ => unreachable!(),
    };

    if encoding.contains("aac") {
        if let Some(bitrate) = matches.get_one::<i32>("bitrate") {
            enc.set_property("bitrate", bitrate);
        }
    }

    let mux_mpegts = encoding.starts_with("ts-");

    let sink = gst::ElementFactory::make("appsink").build().unwrap();
    sink.set_property("sync", false);

    // Caps on appsink will force the encoder to output a specific profile
    if let Some(encoder_caps) = enc_caps {
        sink.set_property("caps", encoder_caps);
    }

    pipeline
        .add_many([&source, &depayloader, &chunker, &conv, &enc, &sink])
        .unwrap();

    gst::Element::link_many([&source, &depayloader, &chunker, &conv, &enc, &sink]).unwrap();

    if input_url.scheme() == "test" {
        pipeline.set_start_time(gst::ClockTime::NONE);
        pipeline.set_base_time(gst::ClockTime::ZERO);
    }

    let output_pattern = matches
        .get_one::<String>("output-pattern")
        .map(|s| s.to_string());

    if let Some(opattern) = &output_pattern {
        if !opattern.contains("{num}") {
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

                gst::trace!(
                    CAT,
                    obj = appsink.upcast_ref::<gst::Element>(),
                    "{:?}",
                    buf,
                );

                let s = sample.caps().unwrap().structure(0).unwrap();
                let frame_format = match s.name().as_str() {
                    "audio/mpeg" => {
                        let profile = s.get::<&str>("profile").unwrap();
                        let base_profile = s.get::<&str>("base-profile").unwrap_or(profile);
                        match profile {
                            "lc" => EncodedFrameFormat::AacLc,
                            "he-aac-v1" if base_profile == "lc" => EncodedFrameFormat::AacLcSbrExt,
                            "he-aac-v2" => EncodedFrameFormat::AacLcSbrPs,
                            _ => unimplemented!("Profile {profile} with base profile {base_profile} not yet supported!"),
                        }
                    }
                    "audio/x-flac" => EncodedFrameFormat::Flac,
                    _ => EncodedFrameFormat::Other,
                };

                collector.frames.push(EncodedFrame {
                    pts: buf.pts(),
                    buffer: buf,
                    format: frame_format,
                });

                Ok(gst::FlowSuccess::Ok)
            })
            .new_event(move |appsink| {
                let mut collector = cc_clone.borrow_mut();

                let event = appsink.pull_object().unwrap();
                let ev = event.downcast::<gst::Event>().ok().unwrap();

                use gst::EventView;

                if let EventView::CustomDownstream(ev_custom) = ev.view() {
                    let s = ev_custom.structure().unwrap();
                    match s.name().as_str() {
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

                            gst::info!(
                                CAT,
                                obj = appsink.upcast_ref::<gst::Element>(),
                                "chunk @ pts {:?}, digest {:?}, size {} bytes, continuity {}",
                                pts,
                                digest,
                                buf_data.size(),
                                continuity_counter,
                            );

                            if !drop_chunk {
                                // Write chunk to file
                                if let Some(filename) = &chunk_fn {
                                    match File::create(filename) {
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

                true
            })
            .build(),
    );

    // Bus main loop

    let bus = pipeline.bus().unwrap();

    let main_loop_clone = main_loop.clone();

    let _watch = bus
        .add_watch(move |_, msg| {
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

            glib::ControlFlow::Continue
        })
        .expect("Failed to add bus watch");

    loop {
        // Any errors will be picked up via the bus handler
        if pipeline.set_state(gst::State::Playing).is_err() {};

        main_loop.run();

        println!("Shutting down pipeline.");

        pipeline
            .set_state(gst::State::Null)
            .expect("Failed to shut down the pipeline");

        // Sleep a little. We might also restart in case of panics, so throttle.
        std::thread::sleep(std::time::Duration::from_secs(1));

        println!("Restarting pipeline...");
    }

    // drop(watch);
}
