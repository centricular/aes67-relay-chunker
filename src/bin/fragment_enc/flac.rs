// fragment-enc - FLAC support
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::prelude::*;

// FLAC encoder will write frame numbers or sample numbers into the header,
// which we'll need to fix up based on something that's based on the absolute
// PTP time in order to get consistent/reproducible output. And once we modify
// that we'll also have to fix up various CRC checksums in the frame.
pub fn make_flacenc() -> gst::Element {
    let flacenc = gst::ElementFactory::make("flacenc").build().unwrap();

    // To match AAC; make configurable? But note that 'odd' values might have
    // implications about the frame header layout assumed in pad probe below!
    flacenc.set_property("blocksize", 1024u32);

    flacenc.set_property("perfect-timestamp", false);
    flacenc.set_property("tolerance", 0i64);
    flacenc.set_property("streamable-subset", true);

    // Buffer probe to rewrite FLAC headers with frame numbers based on PTP time
    // Frame numbers are only 31-bit, so with frames of 1024 samples a full
    // 31-bit frame number would wrap every 1.45 years or so. I'm sure all
    // decoders will handle it well...
    let src_pad = flacenc.static_pad("src").unwrap();
    src_pad.add_probe(
        gst::PadProbeType::BUFFER,
        move |_pad, ref mut probe_info| {
            if let Some(gst::PadProbeData::Buffer(ref mut buffer)) = probe_info.data {
                // Initial flac headers have no timestamp
                if buffer.pts().is_none() {
                    return gst::PadProbeReturn::Ok;
                }

                let abs_ts = buffer.pts().unwrap();

                let sample_rate = 48000; // FIXME: don't hardcode

                // Convert to an absolute sample offset
                let abs_off = abs_ts
                    .nseconds()
                    .mul_div_floor(sample_rate as u64, *gst::ClockTime::SECOND)
                    .unwrap();

                let frame_num = (abs_off + 1023) / 1024_u64;

                // println!("flac frame: pts {}, abs_off {}, frame number {}", abs_ts, abs_off, frame_num);

                //assert_eq!(frame_num % 1024, 0);

                let map = buffer.map_readable();
                let in_map = map.unwrap();
                let in_data = in_map.as_slice();

                let frame_num_size = {
                    match in_data[4] {
                        0x00..=0x7f => 1, // 0xxxxxxx (7 bits)
                        0xc0..=0xdf => 2, // 110xxxxx 10xxxxxx (13 bits)
                        0xe0..=0xef => 3, // 1110xxxx 10xxxxxx 10xxxxxx (16 bits)
                        0xf0..=0xf7 => 4, // 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx (21 bits)
                        0xf8..=0xfb => 5, // 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxxx (26 bits)
                        0xfc..=0xfd => 6, // 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx (31 bits)
                        0xfe => 7, // 11111110 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx (36 bits) (for sample number, not frame number)
                        _ => unreachable!("unexpected"),
                    }
                };

                // println!("flac frame before:\n{:02x?}", in_data);

                use crczoo::{crc16_buypass, crc8};

                let mut new_buffer =
                    gst::Buffer::with_size(buffer.size() - frame_num_size + 6).unwrap();
                {
                    let new_buffer_mut = new_buffer.get_mut().unwrap();
                    let mut omap = new_buffer_mut.map_writable().unwrap();
                    let osize = omap.size();
                    let odata = omap.as_mut_slice();
                    odata[0..4].copy_from_slice(&in_data[0..4]);
                    // We're lazy and just always write out the frame number
                    // using the longest available notation (for a 31-bit value)
                    let frame_num = frame_num & 0x7fffffff;
                    odata[4] = (0b11111100 | ((frame_num >> 30) & 0b00000001)) as u8;
                    odata[5] = (0b10000000 | ((frame_num >> 24) & 0b00111111)) as u8;
                    odata[6] = (0b10000000 | ((frame_num >> 18) & 0b00111111)) as u8;
                    odata[7] = (0b10000000 | ((frame_num >> 12) & 0b00111111)) as u8;
                    odata[8] = (0b10000000 | ((frame_num >> 6) & 0b00111111)) as u8;
                    odata[9] = (0b10000000 | (frame_num & 0b00111111)) as u8;
                    odata[10] = crc8(&odata[0..10]); // update header checksum
                    odata[11..].copy_from_slice(&in_data[4 + frame_num_size + 1..]);

                    // update frame checksum
                    let chksum = crc16_buypass(&odata[0..osize - 2]);
                    let chksum_bytes = chksum.to_be_bytes();
                    odata[osize - 2..osize].copy_from_slice(&chksum_bytes[0..2]);

                    //  println!("flac frame after:\n{:02x?}", odata);
                }
                let new_buffer_mut = new_buffer.get_mut().unwrap();

                use gst::BufferCopyFlags;
                buffer
                    .copy_into(
                        new_buffer_mut,
                        BufferCopyFlags::FLAGS
                            | BufferCopyFlags::TIMESTAMPS
                            | BufferCopyFlags::META,
                        0..,
                    )
                    .unwrap();

                drop(in_map);

                *buffer = new_buffer;
            }

            gst::PadProbeReturn::Ok
        },
    );

    flacenc
}
