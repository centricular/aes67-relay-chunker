// fragment-enc - MPEG-TS/AAC muxing support (Tests)
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

#[cfg(test)]
#[test]
fn write_pes_183bytes_in_last_packet() {
    gst::init().unwrap();

    // already written packets (content doesn't matter)
    let mut chunk = vec![0xffu8; 59032];
    let aac_config = super::AacConfig {
        mpeg_version: 4,
        channels: 2,
        rate: 48000,
        aot: 2,
    };

    use super::EncodedFrame;

    let frames = vec![
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33386666666)),
            buffer: gst::Buffer::from_slice(&[0x00u8; 827]),
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33408000000)),
            buffer: gst::Buffer::from_slice(&[0x11u8; 820]),
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33429333333)),
            buffer: gst::Buffer::from_slice(&[0x22u8; 846]),
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33450666666)),
            buffer: gst::Buffer::from_slice(&[0x33u8; 828]),
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33472000000)),
            buffer: gst::Buffer::from_slice(&[0x44u8; 853]),
        },
    ];

    let mut cc: u8 = 8;
    super::write_pes(
        &mut chunk,
        &aac_config,
        &frames,
        &mut cc,
        super::PesNoCounterPadding,
    );
}
