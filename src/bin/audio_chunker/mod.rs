// Raw audio chunker - creates chunks of raw audio aligned based on absolute timestamps
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

mod audio_chunker;

use gst::glib;

glib::wrapper! {
    pub struct AudioChunker(ObjectSubclass<audio_chunker::AudioChunker>) @extends gst::Element, gst::Object;
}

unsafe impl Send for AudioChunker {}
unsafe impl Sync for AudioChunker {}
