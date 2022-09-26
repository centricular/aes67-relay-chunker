// fragment-enc - encoded frame support
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

#[derive(Debug)]
pub enum EncodedFrameFormat {
    AacLc,
    AacLcSbrExt, // HE-AACv1 with implicit/backwards-compatible signalling
    Flac,
    Other,
}

// Encoded audio frame
#[derive(Debug)]
pub struct EncodedFrame {
    pub pts: Option<gst::ClockTime>,
    pub buffer: gst::Buffer,
    pub format: EncodedFrameFormat,
}
