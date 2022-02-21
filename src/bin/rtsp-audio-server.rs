// rtsp-audio-server
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst_rtsp_server::prelude::*;

use anyhow::Error;

fn main_loop() -> Result<(), Error> {
    let main_loop = glib::MainLoop::new(None, false);

    let server = gst_rtsp_server::RTSPServer::new();

    let mounts = server.mount_points().unwrap();

    let factory = gst_rtsp_server::RTSPMediaFactory::new();

    // TODO: use more interesting audio signal than wave=ticks
    factory.set_launch(
        "audiotestsrc wave=ticks samplesperbuffer=48
        ! audio/x-raw,rate=48000,channels=2
        ! rtpL24pay min-ptime=1000000 max-ptime=1000000 name=pay0",
    );

    // Each client should get the exact same live data/stream
    factory.set_shared(true);

    // Disable RTCP (esp. Sender Reports)
    factory.set_enable_rtcp(false);

    mounts.add_factory("/audio", &factory);

    // Attach the server to the default main context
    let id = server.attach(None)?;

    println!(
        "Stream ready at rtsp://127.0.0.1:{}/audio",
        server.bound_port()
    );

    // Start the main loop
    main_loop.run();

    id.remove();

    Ok(())
}

fn main() {
    gst::init().unwrap();

    match main_loop() {
        Ok(r) => r,
        Err(e) => eprintln!("Error! {}", e),
    }
    println!("done.");
}
