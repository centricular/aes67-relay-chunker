// RTP header extension support for aes67-srt-relay + srt-fragment-encoder
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::glib;
use gst::subclass::prelude::*;
use gst_rtp::subclass::prelude::*;
use gst_rtp::RTPHeaderExtensionFlags;

use once_cell::sync::Lazy;

use gst::gst_log;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "xrtphdrextptp",
        gst::DebugColorFlags::empty(),
        Some("Custom RTP Header Extension for PTP timestamps"),
    )
});

#[derive(Default)]
pub struct RTPHeaderExtPTP {}

#[glib::object_subclass]
impl ObjectSubclass for RTPHeaderExtPTP {
    const NAME: &'static str = "RTPHeaderExtPTP";
    type Type = super::RTPHeaderExtPTP;
    type ParentType = gst_rtp::RTPHeaderExtension;
}

impl ObjectImpl for RTPHeaderExtPTP {}

impl GstObjectImpl for RTPHeaderExtPTP {}

impl ElementImpl for RTPHeaderExtPTP {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "Custom RTP Header Extension for PTP timestamps",
                &gst_rtp::RTP_HDREXT_ELEMENT_CLASS,
                "Custom RTP Header Extension for PTP timestamps",
                "Tim-Philipp Müller <tim@centricular.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }
}

impl RTPHeaderExtensionImpl for RTPHeaderExtPTP {
    // Not sure if we can easily use RTP_HDREXT_BASE here
    const URI: &'static str = "urn:ietf:params:rtp-hdrext:x-ptp";

    fn supported_flags(&self, _element: &Self::Type) -> RTPHeaderExtensionFlags {
        RTPHeaderExtensionFlags::ONE_BYTE | RTPHeaderExtensionFlags::TWO_BYTE
    }

    fn max_size(&self, _element: &Self::Type, _input: &gst::BufferRef) -> usize {
        8 // just a 64-bit timestamp for now
    }

    fn write(
        &self,
        element: &Self::Type,
        _input: &gst::BufferRef,
        _write_flags: RTPHeaderExtensionFlags,
        output: &mut gst::BufferRef,
        output_data: &mut [u8],
    ) -> Result<usize, gst::LoggableError> {
        assert!(output_data.len() >= 8);

        let pts = output.pts().unwrap();

        gst_log!(
            CAT,
            obj: element,
            "Writing timestamp {:?} duration {:?}",
            pts,
            output.duration()
        );

        let pts_bytes = pts.to_be_bytes();

        for n in 0..=7 {
            output_data[n] = pts_bytes[n];
        }

        Ok(8)
    }

    fn read(
        &self,
        element: &Self::Type,
        _read_flags: RTPHeaderExtensionFlags,
        input_data: &[u8],
        output: &mut gst::BufferRef,
    ) -> Result<(), gst::LoggableError> {
        assert_eq!(input_data.len(), 8); // TODO: nicer error handling

        // FIXME: convert to gst clocktime
        let pts = u64::from_be_bytes([
            input_data[0],
            input_data[1],
            input_data[2],
            input_data[3],
            input_data[4],
            input_data[5],
            input_data[6],
            input_data[7],
        ]);

        gst_log!(
            CAT,
            obj: element,
            "Read timestamp {:?} duration {:?}",
            pts,
            output.duration()
        );

        // FIXME: actually *do* something with the timestamp we extracted

        Ok(())
    }
}
