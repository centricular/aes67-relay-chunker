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

use gst::prelude::*;
use gst_rtp::prelude::RTPHeaderExtensionExt;

// TODO: parse srt uri from command line arguments
fn main() {
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

    let main_loop = glib::MainLoop::new(None, false);

    let pipeline = gst::Pipeline::new(None);

    // =================== pseudo input producer (temporary) =================
    // FIXME: use srtsrc instead
    let source = gst::parse_bin_from_description(
        "audiotestsrc is-live=true samplesperbuffer=48 wave=ticks
        ! audio/x-raw,rate=48000,channels=2
        ! rtpL24pay",
        true,
    )
    .expect("Error creating input branch")
    .upcast::<gst::Element>();

    let depayloader = gst::ElementFactory::make("rtpL24depay", None).unwrap();

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

    pipeline
        .add_many(&[&source, &depayloader, &payloader])
        .unwrap();

    gst::Element::link_many(&[&source, &depayloader, &payloader]).unwrap();

    // ============== end pseudo input producer ===============================

    let depayloader = gst::ElementFactory::make("rtpL24depay", None).unwrap();
    depayloader.set_property("auto-header-extension", false);

    // Set things up to retrieve our RTP header extension data
    let hdr_ext = gst::ElementFactory::make("x-rtphdrextptp", None)
        .unwrap()
        .downcast::<gst_rtp::RTPHeaderExtension>()
        .unwrap();

    hdr_ext.set_id(1);

    depayloader.emit_by_name::<()>("add-extension", &[&hdr_ext]);

    let conv = gst::ElementFactory::make("audioconvert", None).unwrap();

    let chunker = gst::ElementFactory::make("x-audiochunker", None).unwrap();

    let sink = gst::ElementFactory::make("fakesink", None).unwrap();

    pipeline
        .add_many(&[&depayloader, &conv, &chunker, &sink])
        .unwrap();

    gst::Element::link_many(&[&payloader, &depayloader]).unwrap(); // FIXME

    gst::Element::link_many(&[&depayloader, &conv, &chunker, &sink]).unwrap();

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
