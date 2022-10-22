// aes67-relay
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

mod rtp_hdr_ext;

use std::sync::{Arc, Mutex};

use clap::{Arg, Command};

use gst::prelude::*;
use gst::{Caps, ClockTime, ReferenceTimestampMeta};
use gst_rtp::prelude::RTPHeaderExtensionExt;

use std::time::Duration;

use url::Url;

fn create_test_input() -> gst::Element {
    let test_input = gst::parse_bin_from_description(
        "audiotestsrc is-live=false samplesperbuffer=48 wave=pink-noise name=testsrc
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
fn create_sdp_input(sdp_url: &Url) -> gst::Element {
    let bin = gst::Bin::new(Some("sdp-source"));

    let sdpsrc = gst::ElementFactory::make("sdpsrc").build().unwrap();
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
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/2655
    //   (rtpjitterbuffer: Fix calculation of RFC7273 RTP time period start)

    sdpsrc
        .dynamic_cast_ref::<gst::Bin>()
        .unwrap()
        .connect_deep_element_added(move |sdpsrc, _bin, new_element| {
            if let Some(factory) = new_element.factory() {
                match factory.name().as_str() {
                    "rtpbin" => {
                        new_element.set_property("rfc7273-sync", true);
                        new_element.set_property("add-reference-timestamp-meta", true);
                    }
                    "rtpjitterbuffer" => {
                        // post a message with the jitterbuffer to our app thread
                        sdpsrc
                            .post_message(
                                gst::message::Application::builder(
                                    gst::structure::Structure::builder("jitterbuffer")
                                        .field("jitterbuffer", new_element.clone())
                                        .build(),
                                )
                                .src(sdpsrc)
                                .build(),
                            )
                            .expect("Element without bus. Should not happen!");
                    }
                    _ => {}
                }
            }
        });

    let depayload = gst::ElementFactory::make("rtpL24depay").build().unwrap();

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
fn create_rtsp_input(rtsp_url: &Url) -> gst::Element {
    let bin = gst::Bin::new(Some("rtsp-source"));

    // Requires:
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1955
    //   (rtpjitterbuffer: Improve accuracy of RFC7273 clock time calculations)
    // - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/1964
    //   (rtpjitterbuffer: add "add-reference-timestamp-meta" property)
    let rtspsrc = gst::ElementFactory::make("rtspsrc").build().unwrap();
    rtspsrc.set_property("location", rtsp_url.as_str());
    rtspsrc.set_property("rfc7273-sync", true);
    rtspsrc.set_property("add-reference-timestamp-meta", true);
    rtspsrc.set_property("do-rtcp", false);

    let depayload = gst::ElementFactory::make("rtpL24depay").build().unwrap();

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
    gst::ElementFactory::make("fakesink").build().unwrap()
}

// wait-for-connection=false means we will consume buffers and drop them
// if there's no connection established instead of waiting for a connection
// and causing backpressure into the pipeline.
//
// wait-for-connection=true means we will cause buffers to pile up in the
// output queue until there is a connection, but since the output queue is
// leaky that might actually be desirable because it means if the SRT connection
// gets dropped for some reason and reconnects quickly no data will be lost.
// Unclear if it really matters in practice though, because SRT is datagram
// based and we wouldn't expect a connection drop in the first place if the
// problem is only transient.
fn create_srt_output(srt_url: Url) -> gst::Element {
    let sink = gst::Element::make_from_uri(gst::URIType::Sink, srt_url.as_str(), None).unwrap();
    sink.set_property("wait-for-connection", false);
    sink
}

fn create_udp_output(udp_url: Url) -> gst::Element {
    let sink = gst::Element::make_from_uri(gst::URIType::Sink, udp_url.as_str(), None).unwrap();
    sink
}

#[derive(Debug)]
struct JitterbufferStats {
    n_pushed: u64,
    n_lost: u64,
    time: gst::ClockTime, // local system clock timestamp, gst::util_get_timestamp()
}

impl JitterbufferStats {
    fn from_structure(stats: &gst::Structure) -> Self {
        JitterbufferStats {
            time: gst::util_get_timestamp(),
            n_lost: stats.get::<u64>("num-lost").unwrap(),
            n_pushed: stats.get::<u64>("num-pushed").unwrap(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum ClockSync {
    None,
    Pending,
    Synchronised,
}

#[derive(Debug)]
struct RelayCtx {
    jb: Option<gst::Element>,
    stats: JitterbufferStats,
    clock_sync: ClockSync,
}

impl Default for RelayCtx {
    fn default() -> Self {
        RelayCtx {
            jb: None,
            stats: JitterbufferStats {
                n_pushed: 0,
                n_lost: 0,
                time: gst::util_get_timestamp(),
            },
            clock_sync: ClockSync::None,
        }
    }
}

fn main() {
    // Command line arguments
    let matches = Command::new("aes67-relay")
        .version("0.1")
        .author("Tim-Philipp Müller <tim centricular com>")
        .about("AES67 to SRT/UDP relay")
        .arg(
            Arg::new("input-uri")
                .required(true)
                .help("Input URI, e.g. rtsp://127.0.0.1:8554/audio or test://"),
        )
        .arg(
            Arg::new("output-uri")
                .required(true)
                .help("Output URI, e.g. srt://127.0.0.1:7001?passphrase=longpassword or udp://127.0.0.1:8001 or null://"),
        )
        .arg(
            Arg::new("silent")
                .short('s')
                .long("silent")
                .help("Don't print out buffer checksums or stats every second"),
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
and send it to a cloud server via SRT or UDP for chunking + encoding.",
        )
        .get_matches();

    let silent = matches.is_present("silent");

    let input_uri = matches.value_of("input-uri").unwrap();

    let input_url = url::Url::parse(input_uri)
        .map_err(|err| {
            eprintln!(
                "Please provide a valid input URI, e.g. sdp:///path/to/foo.sdp or rtsp://127.0.0.1:8554/audio or test://"
            );
            err
        })
        .unwrap();

    let output_uri = matches.value_of("output-uri").unwrap();

    let output_url = url::Url::parse(output_uri)
        .map_err(|err| {
            eprintln!("Please provide a valid output URI, e.g. srt://127.0.0.1:7001?passphrase=longpassword or null://");
            err
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
        "rtsp" => create_rtsp_input(&input_url),
        "sdp" => create_sdp_input(&input_url),
        "test" => create_test_input(),
        scheme => unimplemented!("Unhandled protocol {}", scheme),
    };

    // For simulating packet drops (not very sophisticated, maybe netsim would be better?)
    let id = gst::ElementFactory::make("identity").build().unwrap();
    if matches.is_present("drop-probability") {
        let p_drop_ppm: u32 = matches.value_of_t("drop-probability").unwrap();
        let p: f32 = p_drop_ppm as f32 / 1_000_000.0f32;
        println!("Configuring packet drop probability to {}!", p);
        id.set_property("drop-probability", p);
    }

    // For good measure, shouldn't be needed
    let conv = gst::ElementFactory::make("audioconvert").build().unwrap();

    // Jitterbuffer, will be set from message handler via application message
    let ctx = Arc::new(Mutex::new(RelayCtx::default()));

    let ctx_padprobe = ctx.clone();

    // Add a buffer probe to drop all buffers without GstReferenceTimestampMeta,
    // ie. before we have achieved PTP clock sync.
    let src_pad = conv.static_pad("src").unwrap();
    src_pad.add_probe(gst::PadProbeType::BUFFER, move |_, probe_info| {
        if let Some(gst::PadProbeData::Buffer(ref buffer)) = probe_info.data {
            match buffer.meta::<gst::meta::ReferenceTimestampMeta>() {
                Some(ref meta) => {
                    let mut ctx = ctx_padprobe.lock().unwrap();
                    if ctx.clock_sync != ClockSync::Synchronised {
                        ctx.clock_sync = ClockSync::Synchronised;
                    }

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

                        let msg = match &ctx.jb {
                            None => None,
                            Some(jb) => {
                                let jb_stats = jb.property::<gst::Structure>("stats");
                                let cur_stats = JitterbufferStats::from_structure(&jb_stats);

                                let n_lost = cur_stats.n_lost - ctx.stats.n_lost;

                                // We know our heartbeats are full seconds apart, so will just
                                // approximate based on the local system clock and not the
                                // actual buffer ptp times which we don't save currently.
                                let secs_since_last_heartbeat = (cur_stats.time.mseconds() - ctx.stats.time.mseconds() + 500) / 1000;

                                ctx.stats = cur_stats;

                                if n_lost > 0 {
                                    let packets_per_second = sample_rate / samples_per_buffer;
                                    let expected_packets = packets_per_second * secs_since_last_heartbeat;
                                    let perc_lost = n_lost as f64 / expected_packets as f64 * 100.0;

                                    if secs_since_last_heartbeat == 1 {
                                        Some(format!("{n_lost} packet(s) lost, ~{perc_lost:.1}%"))
                                    } else {
                                        Some(format!("{n_lost} packet(s) lost over {secs_since_last_heartbeat} secs, ~{perc_lost:.1}%"))
                                    }
                                } else {
                                    None
                                }
                            }
                        };

                        println!(
                            "Buffer @ {:#?} offset {:?} hash {:?} {}",
                            abs_ts,
                            abs_off,
                            digest,
                            msg.unwrap_or_default()
                        );
                    }
                }
                None => {
                    let mut ctx = ctx_padprobe.lock().unwrap();
                    if ctx.clock_sync == ClockSync::None {
                        if !silent {
                            println!("Acquiring PTP clock sync..");
                        }
                        ctx.clock_sync = ClockSync::Pending;
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

    const OUTPUT_BACKLOG_LIMIT: u64 = gst::ClockTime::from_seconds(10).nseconds();

    let sink_queue = gst::ElementFactory::make("queue")
        .name("output-queue")
        .build()
        .unwrap();
    sink_queue.set_property("max-size-buffers", 0u32);
    sink_queue.set_property("max-size-bytes", 0u32);
    sink_queue.set_property("max-size-time", OUTPUT_BACKLOG_LIMIT);
    sink_queue.set_property_from_str("leaky", "downstream");

    let sink = match output_url.scheme() {
        "null" => create_null_output(),
        "srt" => create_srt_output(output_url),
        "udp" => create_udp_output(output_url),
        scheme => unimplemented!("Unhandled output protocol {}", scheme),
    };

    // audiotestsrc operates in is-live=false mode for consistent timestamps,
    // so we must make the sink sync to the clock in that case. In case the
    // source is already live, like with udpsrc (sdp) or srtsrc, we set the
    // sink to sync=false.
    sink.set_property("sync", input_url.scheme() == "test");

    pipeline
        .add_many(&[&source, &id, &conv, &payloader, &sink_queue, &sink])
        .unwrap();

    gst::Element::link_many(&[&source, &id, &conv, &payloader, &sink_queue, &sink]).unwrap();

    pipeline.set_start_time(gst::ClockTime::NONE);
    pipeline.set_base_time(gst::ClockTime::ZERO);

    let bus = pipeline.bus().unwrap();

    // Any errors will be picked up via the bus handler
    let _ = pipeline.set_state(gst::State::Playing);

    let main_loop_clone = main_loop.clone();

    let ctx_buswatch = ctx.clone();

    let pipeline_buswatch = pipeline.clone();

    bus.add_watch(move |_, msg| {
        use gst::MessageView;

        let main_loop = &main_loop_clone;

        match msg.view() {
            MessageView::Eos(..) => main_loop.quit(),
            MessageView::Application(app_msg) => {
                let s = app_msg.structure().unwrap();
                if s.name() == "jitterbuffer" {
                    let jb = s.get::<gst::Element>("jitterbuffer").unwrap();

                    let mut ctx = ctx_buswatch.lock().unwrap();
                    ctx.jb.replace(jb);
                }
            }
            MessageView::AsyncDone(..) => {
                gst::debug_bin_to_dot_file_with_ts(
                    &pipeline_buswatch,
                    gst::DebugGraphDetails::all(),
                    &"aes67-relay.async-done",
                );
            }
            MessageView::Error(err) => {
                println!(
                    "Error from {:?}: {} ({:?})",
                    err.src().map(|s| s.path_string()),
                    err.error(),
                    err.debug()
                );
                gst::debug_bin_to_dot_file_with_ts(
                    &pipeline_buswatch,
                    gst::DebugGraphDetails::all(),
                    &"aes67-relay.error",
                );
                main_loop.quit();
            }
            MessageView::Element(..) => {
                println!("Element message: {}", msg.structure().unwrap());
            }
            _ => (),
        };

        glib::Continue(true)
    })
    .expect("Failed to add bus watch");

    // timeout
    glib::source::timeout_add(Duration::from_millis(1000), move || {
        let ctx = ctx.lock().unwrap();

        if silent || ctx.jb.is_none() {
            return glib::Continue(true);
        }

        if ctx.clock_sync != ClockSync::Synchronised {
            println!("Waiting for PTP clock sync..");
            return glib::Continue(true);
        }

        let now = gst::util_get_timestamp();

        if now.mseconds() - ctx.stats.time.mseconds() > 1000 {
            let jb = ctx.jb.as_ref().unwrap();
            let jb_stats = jb.property::<gst::Structure>("stats");

            let cur_stats = JitterbufferStats::from_structure(&jb_stats);

            let n_pushed = cur_stats.n_pushed - ctx.stats.n_pushed;
            let secs_since_last_heartbeat =
                (cur_stats.time.mseconds() - ctx.stats.time.mseconds()) as f64 / 1000.0;

            let packets_per_second = 1000.0f64;
            let expected_packets = packets_per_second * secs_since_last_heartbeat;
            let perc_lost = (expected_packets - n_pushed as f64) / expected_packets * 100.0;

            eprintln!(
                "Warning: {secs_since_last_heartbeat:4.1} seconds since {}! \
                 {n_pushed:4} packet(s) received since, \
                 ~{perc_lost:.1}% missing",
                if ctx.clock_sync == ClockSync::Synchronised {
                    "last heartbeat"
                } else {
                    "startup"
                }
            );
        }

        // Check sink queue
        let cur_level_time = sink_queue.property::<u64>("current-level-time");

        if cur_level_time > gst::ClockTime::from_seconds(2).nseconds() {
            let backlog = cur_level_time as f64 / 1_000_000_000.0;
            let backlog_limit = OUTPUT_BACKLOG_LIMIT as f64 / 1_000_000_000.0;
            let dropping_msg = if backlog / backlog_limit > 0.99 {
                "- dropping packets!"
            } else {
                ""
            };
            eprintln!("Warning: output not sending data fast enough! Backlog: {backlog:.1}s {dropping_msg}");
        }

        glib::Continue(true)
    });

    main_loop.run();

    pipeline
        .set_state(gst::State::Null)
        .expect("Failed to shut down the pipeline");

    bus.remove_watch().unwrap();
}
