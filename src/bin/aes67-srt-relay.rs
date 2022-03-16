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

            ReferenceTimestampMeta::add(
                buffer.make_mut(),
                &ts_meta_ref,
                pts,
                ClockTime::NONE,
            );
        }

        gst::PadProbeReturn::Ok
    });

    test_input.upcast::<gst::Element>()
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
                .help("Output URI, e.g. srt://127.0.0.1:7001"),
        )
        .after_help(
            "Receive an AES67 audio stream, repacketise it with embedded PTP timestamps
and send it to a cloud server via SRT for chunking + encoding.",
        )
        .get_matches();

    let input_uri = matches.value_of("input-uri").unwrap();

    let input_url = url::Url::parse(input_uri)
        .or_else(|err| {
            eprintln!(
                "Please provide a valid input URI, e.g. rtsp://127.0.0.1:8554/audio or test://"
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
        "test" => create_test_input(),
        "rtsp" => create_rtsp_input(input_url),
        scheme => unimplemented!("Unhandled protocol {}", scheme),
    };

    // For good measure, shouldn't be needed
    let conv = gst::ElementFactory::make("audioconvert", None).unwrap();

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
        .add_many(&[&source, &conv, &payloader, &sink])
        .unwrap();

    gst::Element::link_many(&[&source, &conv, &payloader, &sink]).unwrap();

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
