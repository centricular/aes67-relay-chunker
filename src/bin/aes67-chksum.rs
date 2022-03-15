// aes67-chksum
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

mod audio_chunker;

use clap::{Arg, Command};

use gst::prelude::*;

use url::Url;

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

    let rtspsrc = gst::ElementFactory::make("rtspsrc", None).unwrap();

    // Requires:
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1924
    //   (sdpdemux: add media attribute to caps to fix ptp clock handling)
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1955
    //   (rtpjitterbuffer: Improve accuracy of RFC7273 clock time calculations)
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1964
    //   (rtpjitterbuffer: add "add-reference-timestamp-meta" property)
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

fn main() {
    // Command line arguments
    let matches = Command::new("aes67-chksum")
        .version("0.1")
        .author("Tim-Philipp Müller <tim centricular com>")
        .about("AES67 chksum")
        .arg(
            Arg::new("input-uri")
                .required(true)
                .help("Input URI, e.g. sdp:///path/to/foo.sdp or rtsp://127.0.0.1:8554/audio"),
        )
        .after_help(
            "Receive an AES67 audio stream, and prints hashes and absolute reconstructed PTP timestamps for senders that support RFC7273 sync.",
        )
        .get_matches();

    let input_uri = matches.value_of("input-uri").unwrap();

    let input_url = url::Url::parse(input_uri)
        .or_else(|err| {
            eprintln!(
                "Please provide a valid input URI, e.g. sdp:///path/to/foo.sdp or rtsp://127.0.0.1:8554/audio"
            );
            return Err(err);
        })
        .unwrap();

    // Init + Plugin Registration
    gst::init().unwrap();

    // Pipeline
    let main_loop = glib::MainLoop::new(None, false);

    let pipeline = gst::Pipeline::new(None);

    let source = match input_url.scheme() {
        "sdp" => create_sdp_input(input_url),
        "rtsp" => create_rtsp_input(input_url),
        scheme => unimplemented!("Unhandled protocol {}", scheme),
    };

    // For good measure, shouldn't be needed
    let conv = gst::ElementFactory::make("audioconvert", None).unwrap();

    let sink = gst::ElementFactory::make("fakesink", None).unwrap();
    sink.set_property("signal-handoffs", true);
    sink.connect("handoff", false, |values| {
        let buf = values[1].get::<gst::Buffer>().expect("No buffer");

        let abs_ts = match buf.meta::<gst::meta::ReferenceTimestampMeta>() {
            Some(meta) => meta.timestamp(),
            None => {
                // No timestamp meta means no PTP clock sync yet
                println!("No PTP sync yet");
                return None;
            }
        };

        let sample_rate = 48000; // FIXME: don't hardcode
        let samples_per_buffer = 48; // 1ms, FIXME: don't hardcode

        // Convert to an absolute sample offset
        let abs_off = abs_ts
            .nseconds()
            .mul_div_floor(sample_rate as u64, *gst::ClockTime::SECOND)
            .unwrap();

        // Filter the first buffer in each second
        let samples_into_second = abs_off % sample_rate;

        if samples_into_second < samples_per_buffer {
            let map = buf.map_readable();
            let buf_data = map.unwrap();
            let digest = md5::compute(buf_data.as_slice());

            println!(
                "Buffer @ {:#?} offset {:?} hash {:?}",
                abs_ts, abs_off, digest
            );
        }

        None
    });

    pipeline.add_many(&[&source, &conv, &sink]).unwrap();

    gst::Element::link_many(&[&source, &conv, &sink]).unwrap();

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
