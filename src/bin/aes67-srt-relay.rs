// aes67-srt-relay
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

mod rtp_hdr_ext;

use clap::{Arg, Command};

use gst::prelude::*;
use gst::{Caps, ClockTime, ReferenceTimestampMeta};
use gst_rtp::prelude::RTPHeaderExtensionExt;

use url::Url;

fn create_test_input() -> gst::Element {
    let test_input = gst::parse_bin_from_description(
        "audiotestsrc is-live=true samplesperbuffer=48 wave=ticks name=testsrc
        ! capsfilter caps=audio/x-raw,rate=48000,channels=2",
        true,
    )
    .expect("Error creating test input branch");

    let testsrc = test_input.by_name("testsrc").unwrap();

    // Get the audiotestsrc's source pad
    let src_pad = testsrc.static_pad("src").unwrap();

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

    test_input.upcast::<gst::Element>()
}

// We only support L24 audio for now, and assume PTP clocking is signalled (KISS)
fn create_sdp_input(sdp_url: Url) -> gst::Element {
    let bin = gst::Bin::new(Some("sdp-source"));

    let sdpsrc = gst::ElementFactory::make("sdpsrc", None).unwrap();
    sdpsrc.set_property("location", sdp_url.as_str());

    // sdpsrc doesn't proxy rtpbin/rtpjitterbuffer properties
    //
    // Requires:
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1924
    //   (sdpdemux: add media attribute to caps to fix ptp clock handling)
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1955
    //   (rtpjitterbuffer: Improve accuracy of RFC7273 clock time calculations)
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1964
    //   (rtpjitterbuffer: add "add-reference-timestamp-meta" property)
    sdpsrc
        .dynamic_cast_ref::<gst::Bin>()
        .unwrap()
        .connect_deep_element_added(move |_sdpsrc, _bin, new_element| {
            if let Some(factory) = new_element.factory() {
                if factory.name() == "rtpbin" {
                    new_element.set_property("rfc7273-sync", true);
                    new_element.set_property("add-reference-timestamp-meta", true);
                }
            }
        });

    let depayload = gst::ElementFactory::make("rtpL24depay", None).unwrap();

    let src_pad = depayload.static_pad("src").unwrap();

    bin.add_many(&[&sdpsrc, &depayload]).unwrap();

    let ghostpad = gst::GhostPad::with_target(Some("src"), &src_pad)
        .unwrap()
        .upcast::<gst::Pad>();

    bin.add_pad(&ghostpad).unwrap();

    sdpsrc.connect_pad_added(move |_src, new_src_pad| {
        let sink_pad = depayload
            .static_pad("sink")
            .expect("Failed to get static sink pad from RTP depayloader");

        // TODO: proper error handling. For now we panic if we don't get L24
        new_src_pad.link(&sink_pad).unwrap();
    });

    bin.upcast::<gst::Element>()
}

// We only support RTSP with L24 audio for now (KISS)
fn create_rtsp_input(rtsp_url: Url) -> gst::Element {
    let bin = gst::Bin::new(Some("rtsp-source"));

    // Requires:
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1955
    //   (rtpjitterbuffer: Improve accuracy of RFC7273 clock time calculations)
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1964
    //   (rtpjitterbuffer: add "add-reference-timestamp-meta" property)
    let rtspsrc = gst::ElementFactory::make("rtspsrc", None).unwrap();
    rtspsrc.set_property("location", rtsp_url.as_str());
    rtspsrc.set_property("rfc7273-sync", true);
    rtspsrc.set_property("add-reference-timestamp-meta", true);
    rtspsrc.set_property("do-rtcp", false);

    let depayload = gst::ElementFactory::make("rtpL24depay", None).unwrap();

    let src_pad = depayload.static_pad("src").unwrap();

    bin.add_many(&[&rtspsrc, &depayload]).unwrap();

    let ghostpad = gst::GhostPad::with_target(Some("src"), &src_pad)
        .unwrap()
        .upcast::<gst::Pad>();

    bin.add_pad(&ghostpad).unwrap();

    rtspsrc.connect_pad_added(move |_src, new_src_pad| {
        let sink_pad = depayload
            .static_pad("sink")
            .expect("Failed to get static sink pad from convert");

        // TODO: proper error handling. For now we panic if we don't get L24
        new_src_pad.link(&sink_pad).unwrap();
    });

    bin.upcast::<gst::Element>()
}

fn create_null_output() -> gst::Element {
    let sink = gst::ElementFactory::make("fakesink", None).unwrap();
    sink
}

fn create_srt_output(srt_url: Url) -> gst::Element {
    let sink = gst::Element::make_from_uri(gst::URIType::Sink, srt_url.as_str(), None).unwrap();
    //let sink = gst::ElementFactory::make("srtsink", None).unwrap();
    //sink.set_property("uri", "srt://127.0.0.1:7001");
    sink.set_property("sync", false);
    //sink.set_property("wait-for-connection", false);
    sink
}

fn main() {
    // Command line arguments
    let matches = Command::new("aes67-srt-relay")
        .version("0.1")
        .author("Tim-Philipp Müller <tim centricular com>")
        .about("AES67 to SRT relay")
        .arg(
            Arg::new("input-uri")
                .required(true)
                .help("Input URI, e.g. rtsp://127.0.0.1:8554/audio or test://"),
        )
        .arg(
            Arg::new("output-uri")
                .required(true)
                .help("Output URI, e.g. srt://127.0.0.1:7001 or null://"),
        )
        .arg(
            Arg::new("silent")
                .short('s')
                .long("silent")
                .help("Don't print out buffer checksums every second"),
        )
        .arg(
            Arg::new("drop-probability")
                .short('d')
                .long("drop-probability")
                .help("Drop probability in packets per million")
                .takes_value(true),
        )
        .after_help(
            "Receive an AES67 audio stream, repacketise it with embedded PTP timestamps
and send it to a cloud server via SRT for chunking + encoding.",
        )
        .get_matches();

    let silent = matches.is_present("silent");

    let input_uri = matches.value_of("input-uri").unwrap();

    let input_url = url::Url::parse(input_uri)
        .or_else(|err| {
            eprintln!(
                "Please provide a valid input URI, e.g. sdp:///path/to/foo.sdp or rtsp://127.0.0.1:8554/audio or test://"
            );
            return Err(err);
        })
        .unwrap();

    let output_uri = matches.value_of("output-uri").unwrap();

    let output_url = url::Url::parse(output_uri)
        .or_else(|err| {
            eprintln!("Please provide a valid output URI, e.g. srt://127.0.0.1:7001 or null://");
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

    // Pipeline
    let main_loop = glib::MainLoop::new(None, false);

    let pipeline = gst::Pipeline::new(None);

    let source = match input_url.scheme() {
        "rtsp" => create_rtsp_input(input_url),
        "sdp" => create_sdp_input(input_url),
        "test" => create_test_input(),
        scheme => unimplemented!("Unhandled protocol {}", scheme),
    };

    // For simulating packet drops (not very sophisticated, maybe netsim would be better?)
    let id = gst::ElementFactory::make("identity", None).unwrap();
    if matches.is_present("drop-probability") {
        let p_drop_ppm: u32 = matches.value_of_t("drop-probability").unwrap();
        let p: f32 = p_drop_ppm as f32 / 1_000_000.0f32;
        println!("Configuring packet drop probability to {}!", p);
        id.set_property("drop-probability", p);
    }

    // For good measure, shouldn't be needed
    let conv = gst::ElementFactory::make("audioconvert", None).unwrap();

    // Add a buffer probe to drop all buffers without GstReferenceTimestampMeta,
    // ie. before we have achieved PTP clock sync.
    let src_pad = conv.static_pad("src").unwrap();
    src_pad.add_probe(gst::PadProbeType::BUFFER, move |_, probe_info| {
        if let Some(gst::PadProbeData::Buffer(ref buffer)) = probe_info.data {
            match buffer.meta::<gst::meta::ReferenceTimestampMeta>() {
                Some(ref meta) => {
                    let abs_ts = meta.timestamp();

                    let sample_rate = 48000; // FIXME: don't hardcode
                    let samples_per_buffer = 48; // 1ms, FIXME: don't hardcode

                    // Convert to an absolute sample offset
                    let abs_off = abs_ts
                        .nseconds()
                        .mul_div_floor(sample_rate as u64, *gst::ClockTime::SECOND)
                        .unwrap();

                    // Filter the first buffer in each second
                    let samples_into_second = abs_off % sample_rate;

                    if !silent && samples_into_second < samples_per_buffer {
                        let map = buffer.map_readable();
                        let buf_data = map.unwrap();
                        let digest = md5::compute(buf_data.as_slice());

                        println!(
                            "Buffer @ {:#?} offset {:?} hash {:?}",
                            abs_ts, abs_off, digest
                        );
                    }
                }
                None => {
                    if !silent {
                        println!("No PTP sync yet, dropping buffer");
                    }
                    return gst::PadProbeReturn::Drop;
                }
            }
        }

        gst::PadProbeReturn::Ok
    });

    // We always re-payload instead of passing through L24 RTP packets as-is
    // because that makes everything easier in case we want to add an encoder
    // with larger frame sizes later. Avoids special-casing: we can just use
    // the same mechanism/code for all scenarios.
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

    let sink = match output_url.scheme() {
        "null" => create_null_output(),
        "srt" => create_srt_output(output_url),
        scheme => unimplemented!("Unhandled output protocol {}", scheme),
    };

    pipeline
        .add_many(&[&source, &id, &conv, &payloader, &sink])
        .unwrap();

    gst::Element::link_many(&[&source, &id, &conv, &payloader, &sink]).unwrap();

    pipeline.set_start_time(gst::ClockTime::NONE);
    pipeline.set_base_time(gst::ClockTime::ZERO);

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
