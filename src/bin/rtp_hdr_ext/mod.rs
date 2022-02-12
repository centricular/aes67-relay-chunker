// RTP header extension support for aes67-srt-relay + srt-fragment-encoder
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

mod rtp_hdr_ext_ptp;

use gst::glib;

glib::wrapper! {
    pub struct RTPHeaderExtPTP(ObjectSubclass<rtp_hdr_ext_ptp::RTPHeaderExtPTP>) @extends gst_rtp::RTPHeaderExtension, gst::Element, gst::Object;
}

unsafe impl Send for RTPHeaderExtPTP {}
unsafe impl Sync for RTPHeaderExtPTP {}
