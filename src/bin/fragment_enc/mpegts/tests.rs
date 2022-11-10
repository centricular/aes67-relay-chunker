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
use crate::EncodedFrameFormat::AacLc;

#[cfg(test)]
#[test]
fn write_pes_183bytes_in_last_packet() {
    gst::init().unwrap();

    // already written packets (content doesn't matter)
    let mut chunk = vec![0xffu8; 59032];

    use super::EncodedFrame;

    let frames = vec![
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33386666666)),
            buffer: gst::Buffer::from_slice(&[0x00u8; 827]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33408000000)),
            buffer: gst::Buffer::from_slice(&[0x11u8; 820]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33429333333)),
            buffer: gst::Buffer::from_slice(&[0x22u8; 846]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33450666666)),
            buffer: gst::Buffer::from_slice(&[0x33u8; 828]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33472000000)),
            buffer: gst::Buffer::from_slice(&[0x44u8; 853]),
            format: AacLc,
        },
    ];

    let mut cc: u8 = 8;
    super::write_pes(&mut chunk, &frames, &mut cc, super::PesNoCounterPadding);
}

#[cfg(test)]
#[test]
fn write_pes_no_stuffing_needed() {
    gst::init().unwrap();

    // already written packets (content doesn't matter)
    let mut chunk = vec![0xffu8; 59032];

    use super::EncodedFrame;

    let frames = vec![
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33386666666)),
            buffer: gst::Buffer::from_slice(&[0x00u8; 790]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33408000000)),
            buffer: gst::Buffer::from_slice(&[0x11u8; 853]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33429333333)),
            buffer: gst::Buffer::from_slice(&[0x22u8; 857]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33450666666)),
            buffer: gst::Buffer::from_slice(&[0x33u8; 888]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33472000000)),
            buffer: gst::Buffer::from_slice(&[0x44u8; 971]),
            format: AacLc,
        },
    ];
    let mut cc: u8 = 8;
    super::write_pes(&mut chunk, &frames, &mut cc, super::PesNoCounterPadding);
}

#[cfg(test)]
#[test]
fn write_pes_184byte_payload_for_last_packet() {
    gst::init().unwrap();

    // already written packets (content doesn't matter)
    let mut chunk = vec![0xffu8; 63544];

    use super::EncodedFrame;

    let frames = vec![
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33386666666)),
            buffer: gst::Buffer::from_slice(&[0x00u8; 856]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33408000000)),
            buffer: gst::Buffer::from_slice(&[0x11u8; 880]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33429333333)),
            buffer: gst::Buffer::from_slice(&[0x22u8; 861]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33450666666)),
            buffer: gst::Buffer::from_slice(&[0x33u8; 835]),
            format: AacLc,
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33472000000)),
            buffer: gst::Buffer::from_slice(&[0x44u8; 934]),
            format: AacLc,
        },
    ];

    let mut cc: u8 = 0;
    super::write_pes(
        &mut chunk,
        &frames,
        &mut cc,
        super::PesWithCounterPadding(336),
    );
}
