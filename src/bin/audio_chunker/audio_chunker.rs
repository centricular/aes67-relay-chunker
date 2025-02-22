// Raw audio chunker - creates chunks of raw audio aligned based on absolute timestamps
//
// Copyright (C) 2022-2025 Tim-Philipp Müller <tim centricular com>
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

use smallvec::SmallVec;

use std::sync::Mutex;

// 1024 samples is the default frame size in AAC (960 is theoretically
// also possible, but none of our encoders support that unfortunately)
const DEFAULT_SAMPLES_PER_FRAME: u32 = 1024;
const DEFAULT_FRAMES_PER_CHUNK: u32 = 235;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "audiochunker",
        gst::DebugColorFlags::empty(),
        Some("Raw audio chunker"),
    )
});

struct Settings {
    samples_per_frame: u32,
    frames_per_chunk: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            samples_per_frame: DEFAULT_SAMPLES_PER_FRAME,
            frames_per_chunk: DEFAULT_FRAMES_PER_CHUNK,
        }
    }
}

struct State {
    info: gst_audio::AudioInfo,

    // Number of contiguous segments output, reset on each discont/resync
    continuity_counter: u64,

    // Current chunk (start, stop, pos) as sample offset
    cur_chunk: Option<(u64, u64, u64)>,

    // Adapter to collect samples
    adapter: gst_base::UniqueAdapter,

    // Calculated from samples_per_frame * frames_per_chunk (properties)
    chunk_samples: u64,
}

impl State {
    fn new(info: gst_audio::AudioInfo, spf: u32, fpc: u32) -> Self {
        State {
            info,
            continuity_counter: 0,
            cur_chunk: None,
            adapter: gst_base::UniqueAdapter::new(),
            chunk_samples: spf as u64 * fpc as u64,
        }
    }
}

#[derive(Debug)]
struct TsOffset {
    size: usize,
    pts: gst::ClockTime,
    dur: gst::ClockTime,
    offset: u64,
    offset_end: u64,
}

impl TsOffset {
    fn from_samples(offset: u64, n_samples: u64, rate: u32, bpf: u32) -> Self {
        let rate = rate as u64;
        let bpf = bpf as u64;

        let size = n_samples * bpf;

        let pts = offset
            .mul_div_round(*gst::ClockTime::SECOND, rate)
            .map(gst::ClockTime::from_nseconds)
            .unwrap();

        let dur = n_samples
            .mul_div_round(*gst::ClockTime::SECOND, rate)
            .map(gst::ClockTime::from_nseconds)
            .unwrap();

        let offset_end = offset + n_samples;

        Self {
            size: size as usize,
            pts,
            dur,
            offset,
            offset_end,
        }
    }
}

struct TsOffsetIter<'a> {
    offset: u64,
    samples: &'a [u64],
    rate: u32,
    bpf: u32,
}

impl<'a> TsOffsetIter<'a> {
    fn new(offset: u64, samples: &'a [u64], rate: u32, bpf: u32) -> Self {
        Self {
            offset,
            samples,
            rate,
            bpf,
        }
    }
}

impl Iterator for TsOffsetIter<'_> {
    type Item = TsOffset;

    fn next(&mut self) -> Option<Self::Item> {
        let n_samples = *self.samples.first()?;

        let offset = self.offset;
        self.samples = &self.samples[1..];
        self.offset += n_samples;

        Some(TsOffset::from_samples(
            offset, n_samples, self.rate, self.bpf,
        ))
    }
}

pub struct AudioChunker {
    srcpad: gst::Pad,
    sinkpad: gst::Pad,
    state: Mutex<Option<State>>,
    settings: Mutex<Settings>,
}

#[glib::object_subclass]
impl ObjectSubclass for AudioChunker {
    const NAME: &'static str = "AudioChunker";
    type Type = super::AudioChunker;
    type ParentType = gst::Element;

    fn with_class(klass: &Self::Class) -> Self {
        let templ = klass.pad_template("sink").unwrap();
        let sinkpad = gst::Pad::builder_from_template(&templ)
            .chain_function(|pad, parent, buffer| {
                Self::catch_panic_pad_function(
                    parent,
                    || Err(gst::FlowError::Error),
                    |this| this.sink_chain(pad, buffer),
                )
            })
            .event_function(|pad, parent, event| {
                Self::catch_panic_pad_function(parent, || false, |this| this.sink_event(pad, event))
            })
            .flags(gst::PadFlags::PROXY_CAPS)
            .build();

        let templ = klass.pad_template("src").unwrap();
        let srcpad = gst::Pad::builder_from_template(&templ)
            .query_function(|pad, parent, query| {
                Self::catch_panic_pad_function(parent, || false, |this| this.src_query(pad, query))
            })
            .flags(gst::PadFlags::PROXY_CAPS)
            .build();

        assert!(!gst::meta::CustomMeta::is_registered("X-ChunkStartMeta"));
        gst::meta::CustomMeta::register("X-ChunkStartMeta", &["audio"]);

        assert!(!gst::meta::CustomMeta::is_registered("X-ChunkEndMeta"));
        gst::meta::CustomMeta::register("X-ChunkEndMeta", &["audio"]);

        Self {
            sinkpad,
            srcpad,
            state: Mutex::new(None),
            settings: Mutex::new(Settings::default()),
        }
    }
}

impl ObjectImpl for AudioChunker {
    fn constructed(&self) {
        self.parent_constructed();

        self.obj().add_pad(&self.sinkpad).unwrap();
        self.obj().add_pad(&self.srcpad).unwrap();
    }

    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecUInt::builder("frames-per-chunk")
                    .nick("Frames per chunk")
                    .blurb("How many audio frames should be grouped into a single chunk")
                    .minimum(1)
                    .maximum(u32::MAX)
                    .default_value(DEFAULT_FRAMES_PER_CHUNK)
                    .build(),
                glib::ParamSpecUInt::builder("samples-per-frame")
                    .nick("Samples per Frame")
                    .blurb("Audio samples in a codec frame")
                    .minimum(1)
                    .maximum(u32::MAX)
                    .default_value(DEFAULT_SAMPLES_PER_FRAME)
                    .build(),
            ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        let mut settings = self.settings.lock().unwrap();
        match pspec.name() {
            "frames-per-chunk" => {
                settings.frames_per_chunk = value.get().expect("type checked upstream");
            }
            "samples-per-frame" => {
                settings.samples_per_frame = value.get().expect("type checked upstream");
            }
            _ => unimplemented!(),
        };
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        let settings = self.settings.lock().unwrap();
        match pspec.name() {
            "frames-per-chunk" => settings.frames_per_chunk.to_value(),
            "samples-per-frame" => settings.samples_per_frame.to_value(),
            _ => unimplemented!(),
        }
    }
}

impl GstObjectImpl for AudioChunker {}

impl ElementImpl for AudioChunker {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "Audio Chunker",
                gst_rtp::RTP_HDREXT_ELEMENT_CLASS,
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
                .field("channels", gst::IntRange::new(1, i32::MAX))
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
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        let res = self.parent_change_state(transition);

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
    fn advance_chunk(&self, state: &mut State, pos: u64) {
        let samples_per_chunk = state.chunk_samples;

        let (new_start, new_stop) = match state.cur_chunk {
            Some((start, stop, _)) => (start + samples_per_chunk, stop + samples_per_chunk),
            None => unreachable!(),
        };

        state.cur_chunk = Some((new_start, new_stop, new_start + pos));

        gst::debug!(
            CAT,
            imp = self,
            "Starting new chunk: {}-{}, pos {}",
            new_start,
            new_stop,
            pos,
        );
    }

    fn sink_chain(
        &self,
        _pad: &gst::Pad,
        mut buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        gst::log!(CAT, imp = self, "Handling buffer {:?}", buffer);

        let mut state_guard = self.state.lock().unwrap();

        let mut state = match *state_guard {
            None => {
                gst::error!(CAT, imp = self, "Not negotiated yet");
                return Err(gst::FlowError::NotNegotiated);
            }
            Some(ref mut state) => state,
        };

        let samples_per_chunk = state.chunk_samples;

        // Determine absolute timestamp for this buffer (RTP header extension
        // parser will have set the pts to the absolute PTP timestamp) in our
        // case (maybe we should instead use ReferenceTimestampMeta here too?)
        let abs_ts = buffer.pts().unwrap();

        // Convert to an absolute sample offset
        let mut abs_off = abs_ts
            .nseconds()
            .mul_div_floor(state.info.rate() as u64, *gst::ClockTime::SECOND)
            .unwrap();

        let mut n_samples = buffer.size() as u64 / state.info.bpf() as u64;

        let abs_end_off = abs_off.checked_add(n_samples).unwrap();

        gst::log!(
            CAT,
            imp = self,
            "absolute ts: {:?}, sample offset: {}-{}, n_samples: {}",
            abs_ts,
            abs_off,
            abs_end_off,
            n_samples,
        );

        if n_samples > samples_per_chunk {
            return Err(gst::FlowError::NotSupported);
        }

        loop {
            // Get current chunk. If there is no current chunk,
            // determine next chunk [start; stop[ in sample offsets
            let (chunk_start_off, chunk_end_off, chunk_pos_off) = match state.cur_chunk {
                Some((start, stop, pos)) => (start, stop, pos),
                None => {
                    let start = (abs_off / samples_per_chunk) * samples_per_chunk;
                    let stop = start + samples_per_chunk;
                    state.cur_chunk = Some((start, stop, start));
                    (start, stop, start)
                }
            };

            gst::log!(
                CAT,
                imp = self,
                "Current chunk: {} @ {}-{} continuity={}",
                chunk_pos_off,
                chunk_start_off,
                chunk_end_off,
                state.continuity_counter,
            );

            // If buffer is entirely before the current chunk position, drop it
            if abs_end_off <= chunk_pos_off {
                gst::debug!(
                    CAT,
                    imp = self,
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

                gst::debug!(
                    CAT,
                    imp = self,
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
                    .copy_region(gst::BufferCopyFlags::MEMORY, clip_bytes..)
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

                gst::debug!(
                    CAT,
                    imp = self,
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

                self.advance_chunk(state, 0);
                continue;
            }

            // Remove GstReferenceTimestampMetas from buffers, otherwise our output buffer will
            // have thousands of those on it, and we don't need those any more here anyway.
            {
                use gst::buffer::BufferMetaForeachAction;
                use std::ops::ControlFlow::*;

                buffer.get_mut().unwrap().foreach_meta_mut(|mut meta| {
                    if meta.downcast_ref::<gst::ReferenceTimestampMeta>().is_some() {
                        Continue(BufferMetaForeachAction::Remove)
                    } else {
                        Continue(BufferMetaForeachAction::Keep)
                    }
                });
            }

            // Buffer aligns with expected next sample in chunk
            assert_eq!(abs_off, chunk_pos_off);

            state.adapter.push(buffer);

            // Advance expected position. It's okay if the position ends up
            // going beyond the chunk end position, we'll fix that up below.
            state.cur_chunk = Some((chunk_start_off, chunk_end_off, chunk_pos_off + n_samples));

            break;
        }

        let chunk_size = samples_per_chunk as usize * state.info.bpf() as usize;

        // Push out complete chunks, if any
        while state.adapter.available() >= chunk_size {
            let (chunk_start_off, chunk_end_off, _) = state.cur_chunk.unwrap();

            gst::info!(
                CAT,
                imp = self,
                "Completed chunk: {}-{} continuity={}",
                chunk_start_off,
                chunk_end_off,
                state.continuity_counter,
            );

            gst::trace!(
                CAT,
                imp = self,
                "Bytes in adapter: {}",
                state.adapter.available()
            );

            let continuity_counter = state.continuity_counter;

            let discont = continuity_counter == 0;

            let chunk_pts = chunk_start_off
                .mul_div_round(*gst::ClockTime::SECOND, state.info.rate() as u64)
                .map(gst::ClockTime::from_nseconds)
                .unwrap();

            let chunk_end_pts = chunk_end_off
                .mul_div_round(*gst::ClockTime::SECOND, state.info.rate() as u64)
                .map(gst::ClockTime::from_nseconds)
                .unwrap();

            let _chunk_duration = chunk_end_pts - chunk_pts;

            let chunk_number = abs_off / samples_per_chunk;

            // Split chunk into three output buffers (480 samples each for the first and last one,
            // with the middle buffer carrying the rest), so we can set custom metas on the
            // first and last buffers. The audio encoder will then pass through those metas on the
            // output side, which will be much smaller encoded frames (of 1024 samples). The
            // fragment encoder can then tell which output chunk the encoded audio frames belong
            // to via the start/end custom metas. 480 samples is a somewhat arbitrary value, it's
            // been chosen to create clean durations/offsets with 48kHz, but could have been
            // anything else as long as it's <= 1024.
            let buffer_samples = [480, chunk_end_off - chunk_start_off - 2 * 480, 480];

            let ts_iter = TsOffsetIter::new(
                chunk_start_off,
                &buffer_samples,
                state.info.rate(),
                state.info.bpf(),
            );

            let mut bufs: SmallVec<[gst::Buffer; 3]> = SmallVec::new();

            for (i, details) in ts_iter.enumerate() {
                gst::info!(CAT, imp = self, "{i}: {details:?}");

                let mut outbuf = state.adapter.take_buffer(details.size).unwrap();
                {
                    let outbuf_ref = outbuf.get_mut().unwrap();

                    outbuf_ref.set_pts(details.pts);
                    outbuf_ref.set_duration(details.dur);
                    outbuf_ref.set_offset(details.offset);
                    outbuf_ref.set_offset_end(details.offset_end);

                    if i == 0 && discont {
                        outbuf_ref.set_flags(gst::BufferFlags::DISCONT);
                    } else {
                        outbuf_ref.unset_flags(gst::BufferFlags::DISCONT);
                    }

                    let meta_name = match i {
                        0 => Some("X-ChunkStartMeta"),
                        2 => Some("X-ChunkEndMeta"),
                        _ => None,
                    };

                    if let Some(meta_name) = meta_name {
                        let mut meta = gst::meta::CustomMeta::add(outbuf_ref, meta_name).unwrap();

                        let s = meta.mut_structure();
                        s.set("chunk-num", chunk_number);
                        s.set("offset", abs_off);
                        s.set("pts", chunk_pts);
                        s.set("continuity-counter", continuity_counter);
                        gst::info!(CAT, imp = self, "{i}: {s:?}");
                    };
                }

                bufs.push(outbuf);
            }

            // Drop state lock before we push out events/buffers
            drop(state_guard);

            for outbuf in bufs.drain(..) {
                gst::log!(CAT, imp = self, "Pushing buffer {:?}", outbuf);

                self.srcpad.push(outbuf)?;
            }

            // Re-acquire state
            state_guard = self.state.lock().unwrap();
            state = state_guard.as_mut().unwrap();

            let samples_left = state.adapter.available() as u64 / state.info.bpf() as u64;

            gst::log!(CAT, imp = self, "Samples left in adapter: {}", samples_left);

            self.advance_chunk(state, samples_left);
            state.continuity_counter += 1;
        }

        Ok(gst::FlowSuccess::Ok)
    }

    fn sink_event(&self, pad: &gst::Pad, event: gst::Event) -> bool {
        use gst::EventView;

        gst::log!(CAT, obj = pad, "Handling event {:?}", event);

        match event.view() {
            EventView::Caps(c) => {
                let caps = c.caps();
                gst::info!(CAT, obj = pad, "Got caps {:?}", caps);

                let info = match gst_audio::AudioInfo::from_caps(caps) {
                    Ok(info) => info,
                    Err(_) => {
                        gst::error!(CAT, obj = pad, "Failed to parse caps");
                        return false;
                    }
                };

                let state_guard = self.state.lock();
                let mut state = state_guard.unwrap();

                if state.is_some() {
                    unimplemented!("Caps changes are not supported!");
                }

                let (spf, fpc) = {
                    let settings = self.settings.lock().unwrap();
                    (settings.samples_per_frame, settings.frames_per_chunk)
                };

                *state = Some(State::new(info, spf, fpc));

                gst::info!(
                    CAT,
                    obj = pad,
                    "Samples per frame: {}, frames per chunk: {}, samples per chunk: {}",
                    spf,
                    fpc,
                    spf * fpc
                );
            }
            EventView::FlushStop(_) => {
                unimplemented!("Flushing");
            }
            // just forward the event
            EventView::Eos(_) => (),
            _ => (),
        }

        gst::Pad::event_default(pad, Some(&*self.obj()), event)
    }

    #[allow(clippy::single_match)]
    fn src_query(&self, pad: &gst::Pad, query: &mut gst::QueryRef) -> bool {
        use gst::QueryViewMut;

        gst::log!(CAT, obj = pad, "Handling query {:?}", query);

        match query.view_mut() {
            QueryViewMut::Latency(q) => {
                let mut peer_query = gst::query::Latency::new();
                if self.sinkpad.peer_query(&mut peer_query) {
                    let (live, min_latency, max_latency) = peer_query.result();

                    let state_guard = self.state.lock().unwrap();

                    let (sample_rate, samples_per_chunk) = if let Some(state) = state_guard.as_ref()
                    {
                        (state.info.rate(), state.chunk_samples)
                    } else {
                        let settings = self.settings.lock().unwrap();
                        let samples_per_chunk =
                            settings.samples_per_frame as u64 * settings.frames_per_chunk as u64;

                        (48000u32, samples_per_chunk)
                    };

                    let chunk_duration = samples_per_chunk
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
            _ => gst::Pad::query_default(pad, Some(&*self.obj()), query),
        }
    }
}
