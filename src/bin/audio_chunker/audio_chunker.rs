// Raw audio chunker - creates chunks of raw audio aligned based on absolute timestamps
////
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::glib;
use gst::prelude::*;
use gst::subclass::prelude::*;

use once_cell::sync::Lazy;

use std::sync::Mutex;

use gst::{gst_debug, gst_error, gst_info, gst_log, gst_trace};

// TODO: make configurable
// FIXME: need to make sure that CHUNK_SAMPLES is a multiple of the encoder
// output frame size (which is 1024 by default in AAC, unless we add a property
// to configure it to 960, which is also possible)
const CHUNK_SAMPLES: u64 = 5 * 48128; // FIXME 5 * 48000u64;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "audiochunker",
        gst::DebugColorFlags::empty(),
        Some("Raw audio chunker"),
    )
});

struct State {
    info: gst_audio::AudioInfo,

    // Number of contiguous segments output, reset on each discont/resync
    continuity_counter: u64,

    // Current chunk (start, stop, pos) as sample offset
    cur_chunk: Option<(u64, u64, u64)>,

    // Adapter to collect samples
    adapter: gst_base::UniqueAdapter,
}

impl State {
    fn new(info: gst_audio::AudioInfo) -> Self {
        State {
            info,
            continuity_counter: 0,
            cur_chunk: None,
            adapter: gst_base::UniqueAdapter::new(),
        }
    }
}

pub struct AudioChunker {
    srcpad: gst::Pad,
    sinkpad: gst::Pad,
    state: Mutex<Option<State>>,
}

#[glib::object_subclass]
impl ObjectSubclass for AudioChunker {
    const NAME: &'static str = "AudioChunker";
    type Type = super::AudioChunker;
    type ParentType = gst::Element;

    fn with_class(klass: &Self::Class) -> Self {
        let templ = klass.pad_template("sink").unwrap();
        let sinkpad = gst::Pad::builder_with_template(&templ, Some("sink"))
            .chain_function(|pad, parent, buffer| {
                Self::catch_panic_pad_function(
                    parent,
                    || Err(gst::FlowError::Error),
                    |this, element| this.sink_chain(pad, element, buffer),
                )
            })
            .event_function(|pad, parent, event| {
                Self::catch_panic_pad_function(
                    parent,
                    || false,
                    |this, element| this.sink_event(pad, element, event),
                )
            })
            .flags(gst::PadFlags::PROXY_CAPS)
            .build();

        let templ = klass.pad_template("src").unwrap();
        let srcpad = gst::Pad::builder_with_template(&templ, Some("src"))
            .query_function(|pad, parent, query| {
                Self::catch_panic_pad_function(
                    parent,
                    || false,
                    |this, element| this.src_query(pad, element, query),
                )
            })
            .flags(gst::PadFlags::PROXY_CAPS)
            .build();

        Self {
            sinkpad,
            srcpad,
            state: Mutex::new(None),
        }
    }
}

impl ObjectImpl for AudioChunker {
    fn constructed(&self, obj: &Self::Type) {
        self.parent_constructed(obj);

        obj.add_pad(&self.sinkpad).unwrap();
        obj.add_pad(&self.srcpad).unwrap();
    }
}

impl GstObjectImpl for AudioChunker {}

impl ElementImpl for AudioChunker {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "Audio Chunker",
                &gst_rtp::RTP_HDREXT_ELEMENT_CLASS,
                "Chunks raw audio based on absolute timestamps",
                "Tim-Philipp Müller <tim@centricular.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: Lazy<Vec<gst::PadTemplate>> = Lazy::new(|| {
            let caps = gst::Caps::builder("audio/x-raw")
                .field(
                    "format",
                    gst::List::new([
                        "S16LE", "S16BE", "U16LE", "U16BE", "S24LE", "S24BE", "U24LE", "U24BE",
                        "S32LE", "S32BE", "U32LE", "U32BE", "F32LE", "F32BE", "F64LE", "F64BE",
                    ]),
                )
                .field("rate", 48_000i32) // TODO: allow range
                .field("channels", gst::IntRange::new(1, std::i32::MAX))
                .field("layout", "interleaved")
                .build();

            let src_pad_template = gst::PadTemplate::new(
                "src",
                gst::PadDirection::Src,
                gst::PadPresence::Always,
                &caps,
            )
            .unwrap();

            let sink_pad_template = gst::PadTemplate::new(
                "sink",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &caps,
            )
            .unwrap();

            vec![src_pad_template, sink_pad_template]
        });

        PAD_TEMPLATES.as_ref()
    }

    #[allow(clippy::single_match)]
    fn change_state(
        &self,
        element: &Self::Type,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        let res = self.parent_change_state(element, transition);

        match transition {
            gst::StateChange::PausedToReady => {
                // Drop state
                let _ = self.state.lock().unwrap().take();
            }
            _ => (),
        }

        res
    }
}

impl AudioChunker {
    fn advance_chunk(&self, element: &super::AudioChunker, state: &mut State, pos: u64) {
        let (new_start, new_stop) = match state.cur_chunk {
            Some((start, stop, _)) => (start + CHUNK_SAMPLES, stop + CHUNK_SAMPLES),
            None => unreachable!(),
        };

        state.cur_chunk = Some((new_start, new_stop, new_start + pos));

        gst_debug!(
            CAT,
            obj: element,
            "Starting new chunk: {}-{}, pos {}",
            new_start,
            new_stop,
            pos,
        );
    }

    fn sink_chain(
        &self,
        _pad: &gst::Pad,
        element: &super::AudioChunker,
        mut buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        gst_log!(CAT, obj: element, "Handling buffer {:?}", buffer);

        let mut state_guard = self.state.lock().unwrap();

        let mut state = match *state_guard {
            None => {
                gst_error!(CAT, obj: element, "Not negotiated yet");
                return Err(gst::FlowError::NotNegotiated);
            }
            Some(ref mut state) => state,
        };

        // Determine absolute timestamp for this buffer (use pts for starters) (FIXME)
        let abs_ts = buffer.pts().unwrap();

        // Convert to an absolute sample offset
        let mut abs_off = abs_ts
            .nseconds()
            .mul_div_floor(state.info.rate() as u64, *gst::ClockTime::SECOND)
            .unwrap();

        let mut n_samples = buffer.size() as u64 / state.info.bpf() as u64;

        let abs_end_off = abs_off.checked_add(n_samples).unwrap();

        gst_log!(
            CAT,
            obj: element,
            "absolute ts: {:?}, sample offset: {}-{}, n_samples: {}",
            abs_ts,
            abs_off,
            abs_end_off,
            n_samples,
        );

        if n_samples > CHUNK_SAMPLES {
            return Err(gst::FlowError::NotSupported);
        }

        loop {
            // Get current chunk. If there is no current chunk,
            // determine next chunk [start; stop[ in sample offsets
            let (chunk_start_off, chunk_end_off, chunk_pos_off) = match state.cur_chunk {
                Some((start, stop, pos)) => (start, stop, pos),
                None => {
                    let start = (abs_off / CHUNK_SAMPLES) * CHUNK_SAMPLES;
                    let stop = start + CHUNK_SAMPLES;
                    state.cur_chunk = Some((start, stop, start));
                    (start, stop, start)
                }
            };

            gst_log!(
                CAT,
                obj: element,
                "Current chunk: {} @ {}-{} continuity={}",
                chunk_pos_off,
                chunk_start_off,
                chunk_end_off,
                state.continuity_counter,
            );

            // If buffer is entirely before the current chunk position, drop it
            if abs_end_off <= chunk_pos_off {
                gst_debug!(
                    CAT,
                    obj: element,
                    "Buffer entirely before chunk position: {}-{} < {} @ {}-{}, dropping",
                    abs_off,
                    abs_end_off,
                    chunk_pos_off,
                    chunk_start_off,
                    chunk_end_off,
                );

                return Ok(gst::FlowSuccess::Ok);
            }

            // If current buffer overlaps with current chunk start boundary, clip it
            if abs_off < chunk_pos_off {
                let clip_samples = chunk_pos_off - abs_off;

                gst_debug!(
                    CAT,
                    obj: element,
                    "Buffer partially before chunk position: {}-{} < {} @ {}-{}, clipping {} samples",
                    abs_off,
                    abs_end_off,
                    chunk_pos_off,
                    chunk_start_off,
                    chunk_end_off,
                    clip_samples,
                );

                let clip_bytes = clip_samples as usize * state.info.bpf() as usize;

                buffer = buffer
                    .copy_region(gst::BufferCopyFlags::MEMORY, clip_bytes, None)
                    .unwrap();

                assert!(clip_samples < n_samples);

                abs_off += clip_samples;
                n_samples -= clip_samples;

                assert_eq!(
                    buffer.size(),
                    n_samples as usize * state.info.bpf() as usize
                );
            }

            // If buffer does not align with next expected sample offset
            // (i.e. current chunk position), we have missing samples and
            // need to reset/resync. Note that depayloaders may not be able
            // to flag all such discontinuities, so we don't rely on buffer
            // flags for this (and also, the first buffer will be flagged).
            //
            // In case of such a discontinuity (missing samples), we throw
            // away the current chunk, reset continuity counters and move
            // on to the next chunk, then re-check the buffer again.
            if abs_off > chunk_pos_off {
                let missing_samples = abs_off - chunk_pos_off;

                gst_debug!(
                    CAT,
                    obj: element,
                    "Discontinuity: {} missing samples! Buffer {}-{} after chunk position {} @ {}-{}",
                    missing_samples,
                    abs_off,
                    abs_end_off,
                    chunk_pos_off,
                    chunk_start_off,
                    chunk_end_off,
                );

                // TODO: maybe seng GAP event downstream and/or
                // post informational message for application

                state.adapter.clear();
                state.continuity_counter = 0;

                self.advance_chunk(element, state, 0);
                continue;
            }

            // Buffer aligns with expected next sample in chunk
            assert_eq!(abs_off, chunk_pos_off);

            state.adapter.push(buffer);

            // Advance expected position. It's okay if the position ends up
            // going beyond the chunk end position, we'll fix that up below.
            state.cur_chunk = Some((chunk_start_off, chunk_end_off, chunk_pos_off + n_samples));

            break;
        }

        let chunk_size = CHUNK_SAMPLES as usize * state.info.bpf() as usize;

        // Push out complete chunks, if any
        while state.adapter.available() >= chunk_size {
            let (chunk_start_off, chunk_end_off, _) = state.cur_chunk.unwrap();

            gst_info!(
                CAT,
                obj: element,
                "Completed chunk: {}-{} continuity={}",
                chunk_start_off,
                chunk_end_off,
                state.continuity_counter,
            );

            gst_trace!(
                CAT,
                obj: element,
                "Bytes in adapter: {}",
                state.adapter.available()
            );

            let mut outbuf = state.adapter.take_buffer(chunk_size).unwrap();

            let outbuf_ref = outbuf.get_mut().unwrap();

            if state.continuity_counter == 0 {
                outbuf_ref.set_flags(gst::BufferFlags::DISCONT);
            } else {
                outbuf_ref.unset_flags(gst::BufferFlags::DISCONT);
            }

            outbuf_ref.set_offset(chunk_start_off);
            outbuf_ref.set_offset_end(chunk_end_off);

            let chunk_pts = chunk_start_off
                .mul_div_round(*gst::ClockTime::SECOND, state.info.rate() as u64)
                .map(gst::ClockTime::from_nseconds)
                .unwrap();

            let chunk_end_pts = chunk_end_off
                .mul_div_round(*gst::ClockTime::SECOND, state.info.rate() as u64)
                .map(gst::ClockTime::from_nseconds)
                .unwrap();

            let chunk_duration = chunk_end_pts - chunk_pts;

            outbuf_ref.set_duration(chunk_duration);
            outbuf_ref.set_pts(chunk_pts);
            outbuf_ref.set_dts(None);

            // Drop state lock before we push out events/buffers
            drop(state);
            drop(state_guard);

            // Push some serialised custom events before/after each chunk,
            // so we can still determine chunk boundaries after the audio
            // encoder (which will output smaller frames) and muxer, and
            // collect all coded packets belonging to the same input chunk.
            let s = gst::Structure::builder("chunk-start")
                .field("offset", abs_off)
                .field("pts", chunk_pts)
                .build();

            self.srcpad.push_event(gst::event::CustomDownstream::new(s));

            // TODO: put continuity counter on outgoing chunks, or flag all
            // buffers with a continuity counter value < 5 as DROPPABLE or
            // something, so that we can later drop the first few encoded
            // chunks to make sure the encoder has stabilised its output.

            gst_log!(CAT, obj: element, "Pushing buffer {:?}", outbuf);

            self.srcpad.push(outbuf)?;

            let s = gst::Structure::builder("chunk-end")
                .field("offset", abs_off)
                .field("pts", chunk_pts)
                .build();

            self.srcpad.push_event(gst::event::CustomDownstream::new(s));

            // Re-acquire state
            state_guard = self.state.lock().unwrap();
            state = state_guard.as_mut().unwrap();

            let samples_left = state.adapter.available() as u64 / state.info.bpf() as u64;

            gst_log!(
                CAT,
                obj: element,
                "Samples left in adapter: {}",
                samples_left
            );

            self.advance_chunk(element, state, samples_left);
            state.continuity_counter += 1;
        }

        Ok(gst::FlowSuccess::Ok)
    }

    fn sink_event(&self, pad: &gst::Pad, element: &super::AudioChunker, event: gst::Event) -> bool {
        use gst::EventView;

        gst_log!(CAT, obj: pad, "Handling event {:?}", event);

        match event.view() {
            EventView::Caps(c) => {
                let caps = c.caps();
                gst_info!(CAT, obj: pad, "Got caps {:?}", caps);

                let info = match gst_audio::AudioInfo::from_caps(caps) {
                    Ok(info) => info,
                    Err(_) => {
                        gst_error!(CAT, obj: pad, "Failed to parse caps");
                        return false;
                    }
                };

                let state_guard = self.state.lock();
                let mut state = state_guard.unwrap();

                if state.is_some() {
                    unimplemented!("Caps changes are not supported!");
                }

                *state = Some(State::new(info));
            }
            EventView::Eos(_) => {
                unimplemented!("EOS");
            }
            EventView::FlushStop(_) => {
                unimplemented!("Flushing");
            }
            _ => (),
        }

        pad.event_default(Some(element), event)
    }

    #[allow(clippy::single_match)]
    fn src_query(
        &self,
        pad: &gst::Pad,
        element: &super::AudioChunker,
        query: &mut gst::QueryRef,
    ) -> bool {
        use gst::QueryViewMut;

        gst_log!(CAT, obj: pad, "Handling query {:?}", query);

        match query.view_mut() {
            QueryViewMut::Latency(q) => {
                let mut peer_query = gst::query::Latency::new();
                if self.sinkpad.peer_query(&mut peer_query) {
                    let (live, min_latency, max_latency) = peer_query.result();

                    let state_guard = self.state.lock().unwrap();

                    let sample_rate = if let Some(state) = state_guard.as_ref() {
                        state.info.rate()
                    } else {
                        48000u32
                    };

                    let chunk_duration = CHUNK_SAMPLES
                        .mul_div_round(*gst::ClockTime::SECOND, sample_rate as u64)
                        .map(gst::ClockTime::from_nseconds)
                        .unwrap();

                    q.set(
                        live,
                        min_latency + chunk_duration,
                        max_latency.opt_add(chunk_duration),
                    );
                    true
                } else {
                    false
                }
            }
            _ => pad.query_default(Some(element), query),
        }
    }
}
