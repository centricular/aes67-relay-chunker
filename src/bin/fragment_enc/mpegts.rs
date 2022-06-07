// fragment-enc - MPEG-TS/AAC muxing support
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

mod tests;

use crate::EncodedFrame;

use gst::prelude::*;

const PES_HEADER_LEN: usize = 22;

// Frequency for PCR representation
const TS_SYS_CLOCK_FREQ: u64 = 27_000_000;

// Frequency for PTS values
const TS_CLOCK_FREQ: u64 = TS_SYS_CLOCK_FREQ / 300; // 90_000

// Use a fixed buffering offset for the PCR for now: 1/8 second = 125ms
const TS_PCR_OFFSET: u64 = TS_CLOCK_FREQ / 8;

// PCR 0x1444EBF0FE8 <=> PTS 0x114BE3FA0 (PCR+125 ms)
// assert_eq!(pts_to_pcr(0x114BE3FA0), 0x1444EBF0FE8);

// TODO: allow wraparound (even though not really needed if pts are absolute timestamps)
fn pts_to_pcr(pts: u64) -> u64 {
    (pts - TS_PCR_OFFSET) * (TS_SYS_CLOCK_FREQ / TS_CLOCK_FREQ)
}

fn pts_to_pcr_base_ext(pts: u64) -> (u64, u64) {
    let pcr = pts_to_pcr(pts);

    let pcr_base = (pcr / 300) & 0x1ffffffff; // 33 bits
    let pcr_ext = (pcr % 300) & 0x1ff; // 9 bits

    (pcr_base, pcr_ext)
}

fn pts_to_packed_pcr(pts: u64) -> u64 {
    let (pcr_base, pcr_ext) = pts_to_pcr_base_ext(pts);

    assert!(pcr_base < 0x200000000); // 33 bits
    assert!(pcr_ext < 0x200); // 9 bits
    let packed_pcr = (pcr_base << (6 + 9)) | 0b111111_000000000 | pcr_ext;

    packed_pcr
}

/* Packet 0
  ---- TS Header ----
  PID: 0 (0x0000), header size: 171, sync: 0x47
  Error: 0, unit start: 1, priority: 0
  Scrambling: 0, continuity counter: 1
  Adaptation field: yes (167 bytes), payload: yes (17 bytes)
  Discontinuity: 0, random access: 0, ES priority: 0
  ---- Full TS Packet Content ----
  47 40 00 31 A6 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF 00 00 B0 0D 00 01 C1 00 00 00 01 E0 20 A2 C3 29 41

*/
pub fn write_pat(buf: &mut Vec<u8>, continuity_counter: u8) {
    let mut pat = Vec::<u8>::with_capacity(188);

    // Header - Transport stream packet layer (2.4.3.2)
    //
    // 0x47 - sync marker
    pat.push(0x47);

    // 0x40 00 - transport_error_indicator=0, payload_unit_start_indicator=1, transport_priority=0, PID=0x0000
    pat.extend((0b010_0000000000000u16 | 0x0000u16).to_be_bytes());

    // 0x3x - scrambling='00', adaptation_field_control='11' [adaptation_field + payload], continuity_counter=x
    pat.push(0b0011_0000 | continuity_counter);

    // 0xA6 - adaptation_field_length=166 [excl. length byte itself]
    pat.push(166);

    // 0x00 - adaptation field flags
    pat.push(0);

    // 0xFF *165 (stuffing bytes)
    pat.extend_from_slice(&[0xff; 165]);

    // Section (PAT) - Program association table (2.4.4.4)
    //
    // 0x00 - pointer_field, section starts at next byte
    pat.push(0);

    let section_start = pat.len();

    // 0x00 - table_id, 0=program_association_section
    pat.push(0);

    // 0xB0 0D - 0xB. = flags/indicators (section_syntax_indicator=1, 0b011 0/reserved); section_length=13
    pat.extend((0b1_011_000000000000u16 | 13u16).to_be_bytes());

    // 0x00 01 - transport_stream_id = 0x0001 (user defined)
    pat.extend((0x0001u16).to_be_bytes());

    // 0xC1 - reserved='11' + version='00000' + current_next_indicator='1' [1=applicable now]
    pat.push(0b11_00000_1);

    // 0x00 - section_number
    pat.push(0);

    // 0x00 - last_section_number
    pat.push(0);

    // Programs [
    //   0x00 01 - program number
    pat.extend((0x0001u16).to_be_bytes());
    //   0xE0 20 - 0b111 reserved + program_map_PID = 0x20 [PID of PMT]
    pat.extend((0b111_0000000000000u16 | 0x0020u16).to_be_bytes());
    // ]

    // crc
    let crc32 = crczoo::crc32_mpeg2(&pat[section_start..]);
    pat.extend(crc32.to_be_bytes());

    assert_eq!(pat.len(), 188);

    //println!("{:02x?}", pat);

    buf.extend(pat); // KISS
}

/* Packet 1
  ---- TS Header ----
  PID: 32 (0x0020), header size: 166, sync: 0x47
  Error: 0, unit start: 1, priority: 0
  Scrambling: 0, continuity counter: 1
  Adaptation field: yes (162 bytes), payload: yes (22 bytes)
  Discontinuity: 0, random access: 0, ES priority: 0
  ---- Full TS Packet Content ----
  47 40 20 31 A1 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 02
  B0 12 00 01 C1 00 00 E0 41 F0 00 0F E0 41 F0 00 0A 44 05 C7
*/
pub fn write_pmt(buf: &mut Vec<u8>, continuity_counter: u8) {
    let mut pmt = Vec::with_capacity(188);

    // header
    // 0x47 - sync marker
    pmt.push(0x47);

    // 0x40 20 - transport_error_indicator=0, payload_unit_start_indicator=1, transport_priority=0, PID=0x0020
    pmt.extend((0b010_0000000000000u16 | 0x0020u16).to_be_bytes());

    // 0x3x - scrambling='00', adaptation_field_control='11' [adaptation_field + payload], continuity_counter=x
    pmt.push(0b0011_0000 | continuity_counter);

    // 0xA1 - adaptation_field_length=161 [excl. length byte itself]
    pmt.push(161);

    // 0x00 - adaptation field flags
    pmt.push(0);

    // 0xFF *160 (stuffing bytes)
    pmt.extend_from_slice(&[0xff; 160]);

    // Section (PMT) - Program map table (2.4.4.9)
    //
    // 0x00 - pointer_field, section starts at next byte
    pmt.push(0);

    let section_start = pmt.len();

    // 0x02 - table_id, 2=TS_program_map_section
    pmt.push(2);

    // 0xB0 12 - 0xB. = flags/indicators (section_syntax_indicator=1, 0b011 0/reserved); section_length=18
    pmt.extend((0b1_011_000000000000u16 | 18u16).to_be_bytes());

    // 0x00 01 - transport_stream_id = 0x0001 (user defined)
    pmt.extend((0x0001u16).to_be_bytes());

    // 0xC1 - reserved='11' + version='00000' + current_next_indicator='1' [1=applicable now]
    pmt.push(0b11_00000_1);

    // 0x00 - section_number
    pmt.push(0);

    // 0x00 - last_section_number
    pmt.push(0);

    // 0xE0 41 - 0b111 reserved bits + PCR_PID=65/0x41
    pmt.extend((0b111_0000000000000u16 | 0x41u16).to_be_bytes());

    // 0xF0 00 - 0b1111 reserved bits + program_info_length=0
    pmt.extend((0b1111_000000000000u16 | 0u16).to_be_bytes());

    // Streams [
    //   0x0F - stream_type="ISO/IEC 13818-7 Audio with ADTS transport syntax"
    pmt.push(0x0f);

    //   0xE0 41 - 0b111 reserved + elementary_PID=65/0x41
    pmt.extend((0b111_0000000000000u16 | 0x41u16).to_be_bytes());

    //   0xF0 00 - 0b1111 reserved bits + ES_info_length=0
    pmt.extend((0b1111_000000000000u16 | 0u16).to_be_bytes());
    // ]

    // crc
    let crc32 = crczoo::crc32_mpeg2(&pmt[section_start..]);
    pmt.extend(crc32.to_be_bytes());

    assert_eq!(pmt.len(), 188);

    //println!("{:02x?}", pmt);

    buf.extend(&pmt); // KISS
}

const ADTS_HEADER_LEN: usize = 7; // Header without CRC

const AAC_AOT_LC: u8 = 2;

struct AacConfig {
    mpeg_version: u8,
    channels: u8,
    rate: u32,
    aot: u8,
}

// https://wiki.multimedia.cx/index.php/ADTS
fn make_adts_header(aac_config: &AacConfig, frame_size: usize) -> Vec<u8> {
    let mpeg_version = aac_config.mpeg_version;
    let channels = aac_config.channels;
    let rate = aac_config.rate;
    let aot = aac_config.aot;

    assert_eq!(mpeg_version, 4);
    assert_eq!(channels, 2);
    assert_eq!(rate, 48000);
    assert_eq!(aot, AAC_AOT_LC);
    assert!(aot <= 4);

    let mut hdr = Vec::with_capacity(ADTS_HEADER_LEN);

    // Syncword, MPEG-4, Layer, No CRC
    hdr.extend((0b11111111_11110000u16 | 0b0001u16).to_be_bytes());

    let rate_idx: u8 = match rate {
        48000 => 3,
        _ => unimplemented!("Sample rate {}", rate),
    };

    let channel_cfg: u8 = match channels {
        2 => 2,
        _ => unimplemented!("{} channels", channels),
    };

    // Audio Object Type, Sample Rate, Channels (upper)
    hdr.push(((aot - 1) << 6) | (rate_idx << 2) | ((channel_cfg & 0b100) >> 2));

    // Channels (lower), misc bits, Frame Size, Buffer Fullness, Number of RDBs
    let buffer_fullness = 0x7FFu32; // VBR
    let n_blocks = 1u32;
    let frame_len = (ADTS_HEADER_LEN + frame_size) as u32;

    hdr.extend(
        ((((channel_cfg & 0b011) as u32) << 30)
            | (frame_len << 13)
            | (buffer_fullness << 2)
            | (n_blocks - 1))
            .to_be_bytes(),
    );

    assert_eq!(hdr.len(), ADTS_HEADER_LEN);
    //println!("{:02x?}", hdr);

    hdr
}

#[derive(Debug)]
enum PesCounterPadding {
    PesWithCounterPadding(usize),
    PesNoCounterPadding,
}
use PesCounterPadding::*;

// If n_packets_written is passed, the number of AAC TS packets written will be
// padded out to a multiple of 16 (taking into account the number of packets
// written so far), so this would typically set for the last PES in a chunk.
fn write_pes(
    buf: &mut Vec<u8>,
    aac_config: &AacConfig,
    frames: &[EncodedFrame],
    continuity_counter: &mut u8,
    counter_padding: PesCounterPadding,
) -> usize {
    let gst_pts = frames[0].pts.unwrap();

    // Keep it simple and readable for now, can optimise it later if needed
    let payload_bytes = frames
        .iter()
        .fold(0, |sum, frame| sum + ADTS_HEADER_LEN + frame.buffer.size());

    let mut adts = Vec::<u8>::with_capacity(payload_bytes);

    /*
    // Dump frame sizes so we can easily make unit tests from the output
    println!(
        "write_pes: buf_len={}, cc={}, n_frames={} {:?}, cpadding: {:?}",
        buf.len(),
        *continuity_counter,
        frames.len(),
        frames.iter().map(|f| f.buffer.size()).collect::<Vec<usize>>(),
        &counter_padding
    );
    */

    for frame in frames {
        let map = frame.buffer.map_readable();
        let frame_data = map.unwrap();

        let adts_header = make_adts_header(aac_config, frame_data.size());

        adts.extend(&adts_header);

        adts.extend(frame_data.as_slice());
    }

    assert_eq!(payload_bytes, adts.len());

    //println!("ADTS: {:02x?}", adts);

    let n_packets = (PES_HEADER_LEN + payload_bytes + 183) / 184;

    let n_extra_packets =
        if let PesCounterPadding::PesWithCounterPadding(n_written) = counter_padding {
            (16 - ((n_packets + n_written) % 16)) % 16
        } else {
            0
        };
    let n_total_packets = n_packets + n_extra_packets;

    // println!(" -> {n_packets} + {n_extra_packets} = {n_total_packets}");

    // Ensure we always have enough data for 16 packets (1 full + 15); simplifies
    // the code if we don't need to support padding for the first packet with the
    // PES header.
    assert!(adts.len() > 184 + (CONTINUITY_COUNTER_ROUNDS - 1) - PES_HEADER_LEN);

    let mut pes = Vec::<u8>::with_capacity((n_packets + n_extra_packets) * 188);

    // PES header packet

    // header
    // 0x47 - sync marker
    pes.push(0x47);

    // 0x40 41 - transport_error_indicator=0, payload_unit_start_indicator=1, transport_priority=0, PID=0x0041/65
    pes.extend((0b010_0000000000000u16 | 0x0041u16).to_be_bytes());

    // 0x30 - scrambling='00', adaptation_field_control='11' [adaptation_field + payload], continuity_counter=0
    pes.push(0b0011_0000 | *continuity_counter);

    *continuity_counter = (*continuity_counter + 1) % 16;

    assert_eq!(pes.len(), 4);

    // 0x07 - adaptation_field_length=7 [excl. length byte itself]
    pes.push(7);

    // 0x10 - adaptation field flags (0x10 = PCR flag)
    pes.push(0x10);

    let ts = gst_pts
        .mul_div_floor(TS_CLOCK_FREQ, *gst::ClockTime::SECOND)
        .unwrap()
        .nseconds();

    let packed_pcr = pts_to_packed_pcr(ts);
    pes.extend_from_slice(&packed_pcr.to_be_bytes()[2..8]); // lowest 40 bits

    // We checked above that we have enough payload data for a full packet
    // plus however many stuffing packets are needed, but in case we ever want
    // to support the case where we only have a short payload, we'd need to
    // add additional stuffing here.
    //pes.extend_from_slice(&[0xff; 999]);

    assert_eq!(pes.len(), 12);

    // PES header

    // start code
    pes.extend_from_slice(&[0x00, 0x00, 0x01]);

    // stream ID
    pes.push(0xC0);

    // PES payload length
    assert!(adts.len() < 65536);
    pes.extend((adts.len() as u16 + (2 + 1 + 5)).to_be_bytes());

    // PES flags - marker + original=1 + PTS_DTS_flags=10=pts-only
    pes.extend((0b10_000001_10_000000u16).to_be_bytes());

    // 05 - PES header data length
    pes.push(5);

    // Write PTS: 33 bits plus 7 marker bits
    let pts_upper = ((ts & 0b111_000000000000000_000000000000000) >> 30) as u8;
    let pts_middle = ((ts & 0b000_111111111111111_000000000000000) >> 15) as u16;
    let pts_lower = (ts & 0b000_000000000000000_111111111111111) as u16;

    pes.push((pts_upper << 1) | 0b0010_000_1);
    pes.extend(((pts_middle << 1) | 0b1).to_be_bytes());
    pes.extend(((pts_lower << 1) | 0b1).to_be_bytes());

    assert_eq!(pes.len(), 26);

    // First payload part
    pes.extend(&adts[0..162]);

    assert_eq!(pes.len(), 188);

    let mut payload = &adts[162..];

    // PES payload packets without any stuffing
    while payload.len() >= (184 + n_extra_packets + 1) {
        let (packet_payload, remaining_payload) = payload.split_at(184);
        payload = remaining_payload;

        // 0x47 - sync marker
        pes.push(0x47);

        // 0x00 41 - transport_error_indicator=0, payload_unit_start_indicator=0, transport_priority=0, PID=0x0041/65
        pes.extend((0b000_0000000000000u16 | 0x0041u16).to_be_bytes());

        // scrambling='00', adaptation_field_control='01' [payload only], continuity_counter=0
        pes.push(0b00_01_0000 | *continuity_counter);

        *continuity_counter = (*continuity_counter + 1) % 16;

        pes.extend(packet_payload);

        assert_eq!(pes.len() % 188, 0);
    }

    // Last few PES payload packets with stuffing. Stuffing might be required
    // for multiple reasons: perhaps the last piece of the payload doesn't fill
    // an entire MPEG-TS packet; or we need to pad out out the number of packets
    // in a chunk to a multiple of 16 to make the next chunk start with
    // continuity_counter=0; we might even end up here if no padding is needed
    // at all (ie. remaining payload is 184 bytes) because we make extra sure
    // in the previous loop that we have enough bytes left to distribute over
    // the number of packets we have to write out (the +1 in n_extra_packets+1).
    while payload.len() > 0 {
        let packets_written = pes.len() / 188;
        let packets_left_to_write = n_total_packets - packets_written;

        let packet_payload_len = payload.len() / packets_left_to_write;
        assert!(packet_payload_len > 0);
        assert!(packet_payload_len <= 184);

        let (packet_payload, remaining_payload) = payload.split_at(packet_payload_len);
        payload = remaining_payload;

        // 0x47 - sync marker
        pes.push(0x47);

        // 0x00 41 - transport_error_indicator=0, payload_unit_start_indicator=0, transport_priority=0, PID=0x0041/65
        pes.extend((0b000_0000000000000u16 | 0x0041u16).to_be_bytes());

        match packet_payload_len {
            184 => {
                // scrambling='00', adaptation_field_control='01' [payload only], continuity_counter=0
                pes.push(0b00_01_0000 | *continuity_counter);
            }
            183 => {
                // scrambling='00', adaptation_field_control='11' [adaptation_field + payload], continuity_counter=0
                pes.push(0b00_11_0000 | *continuity_counter);

                // adaptation_field_length 0 = single stuffing byte (for 183 byte payload)
                pes.push(0);
            }
            _ => {
                // scrambling='00', adaptation_field_control='11' [adaptation_field + payload], continuity_counter=0
                pes.push(0b00_11_0000 | *continuity_counter);

                let stuffing_len = 184 - 2 - packet_payload_len;

                // adaptation_field_length [excl. length byte itself]
                pes.push(1 + stuffing_len as u8);

                // adaptation field flags
                pes.push(0x00);

                // stuffing bytes
                pes.extend_from_slice(&vec![0xff; stuffing_len]);
            }
        }

        *continuity_counter = (*continuity_counter + 1) % 16;

        // packet payload
        pes.extend(packet_payload);

        assert_eq!(pes.len() % 188, 0);
    }

    assert_eq!(pes.len() / 188, n_total_packets);

    buf.extend(&pes); // KISS

    n_total_packets
}

// TOCONSIDER: or perhaps target max bytes per PES rather than fixed number of frames?
// This is easier for now though, and in real life there'd be a target bitrate
// anyway which means there'd be an easy equivalent that could be configured.
// In MPEG-TS we aim for a PES header about every 15 TS packets, leaving space
// for a (max) 22-byte PES header
// const TS_PACKET_LENGTH = 188;
// const TS_HEADER_LENGTH = 4;
// const TS_PAYLOAD_LENGTH = TS_PACKET_LENGTH - TS_HEADER_LENGTH;
// const DEFAULT_AUDIO_PES_TARGET_BYTES (16 * TS_PAYLOAD_LENGTH - PES_HEADER_LEN)

// FRAMES_PER_PES must not exceed the TS_PCR_OFFSET: 125ms / 21.333ms/frame = 5.86 frames
const FRAMES_PER_PES: usize = 5;

const CONTINUITY_COUNTER_ROUNDS: usize = 16;

pub fn write_ts_chunk(frames: &Vec<EncodedFrame>, chunk_num: u64) -> Vec<u8> {
    let payload_capacity = (2 * 188)
        + (15 * 188)
        + frames
            .iter()
            .fold(0, |sum, frame| sum + ADTS_HEADER_LEN + frame.buffer.size());

    let mut chunk = Vec::<u8>::with_capacity(payload_capacity);

    // We write one PAT + PMT per chunk, so counter increases by one per chunk
    let pat_pmt_continuity_counter = (chunk_num % 16) as u8;
    write_pat(&mut chunk, pat_pmt_continuity_counter);
    write_pmt(&mut chunk, pat_pmt_continuity_counter);

    let n_frames = frames.len();
    //println!("{}", n_frames);

    let aac_config = AacConfig {
        mpeg_version: 4,
        rate: 48000,
        channels: 2,
        aot: AAC_AOT_LC,
    };

    let mut aac_continuity_counter: u8 = 0;
    let mut aac_packets_written = 0; // TODO: could calculate from (chunk.len()/188)-2

    let n_pes = (n_frames + FRAMES_PER_PES - 1) / FRAMES_PER_PES;

    // TODO: write that nicer by using iterators directly
    for (i, frame) in frames.chunks(FRAMES_PER_PES).enumerate() {
        let is_last = (i + 1) == n_pes;

        if !is_last {
            aac_packets_written += write_pes(
                &mut chunk,
                &aac_config,
                frame,
                &mut aac_continuity_counter,
                PesNoCounterPadding,
            );
        } else {
            aac_packets_written += write_pes(
                &mut chunk,
                &aac_config,
                frame,
                &mut aac_continuity_counter,
                PesWithCounterPadding(aac_packets_written),
            );
        }
    }

    /*
        let mut frames_iter = frames.chunks(FRAMES_PER_PES);

        while let Some(pes_frames) = frames_iter.next() {
            if frames_iter.peekable().next().is_some() {
                // Not the last PES
                ...
            } else {
                // Last PES
                ...
            }
        }
    */
    assert_eq!(aac_packets_written % 16, 0);
    assert_eq!(aac_continuity_counter % 16, 0);

    chunk
}
