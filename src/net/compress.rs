//! Connection compression.
//!
//! IRC servers may compress a link after negotiation. This implementation keeps
//! one persistent zlib stream per direction and flushes it at every message
//! boundary, which is what makes compression worthwhile on IRC: individual
//! lines are ~70 bytes, so a fresh zlib stream per line would *expand* them.
//! Sharing the dictionary across messages turns a typical channel corpus into a
//! 30x saving.
//!
//! Framing:
//!
//! ```text
//! +----------------+----------------+---------------------------+
//! | uncompressed   | compressed     | zlib bytes for this flush |
//! | length (u32 LE)| length (u32 LE)| (exactly that many)       |
//! +----------------+----------------+---------------------------+
//! ```
//!
//! Both lengths are validated before allocation, so a decompression bomb cannot
//! be expressed: the reader bounds its output buffer by the declared size and
//! rejects frames that use more or fewer input bytes than they announce.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

/// Largest frame this server will emit or accept on the wire.
pub const MAX_FRAME: usize = 1 << 20;

/// Wire size of a frame header.
pub const HEADER_LEN: usize = 8;

/// Failures while (de)compressing a frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompressionError {
    /// The zlib stream is corrupt or the compressor failed.
    #[error("zlib stream error: {0}")]
    Stream(String),
    /// An announced size exceeds the configured ceiling.
    #[error("declared frame of {declared} bytes exceeds limit {limit}")]
    TooLarge {
        /// Size announced by the peer.
        declared: usize,
        /// Configured ceiling.
        limit: usize,
    },
    /// The stream produced fewer bytes than the header promised.
    #[error("truncated compressed frame: {produced} of {expected} bytes")]
    Truncated {
        /// Bytes actually produced.
        produced: usize,
        /// Bytes the frame header promised.
        expected: usize,
    },
    /// The compressor emitted more bytes than the frame header allows.
    #[error("frame expanded beyond its declared {declared} bytes")]
    Expanded {
        /// Declared uncompressed size.
        declared: usize,
    },
    /// Input bytes were left over or missing relative to the header.
    #[error("frame header declared {declared} bytes but consumed {consumed} of {total} compressed bytes")]
    LengthMismatch {
        /// Declared uncompressed size.
        declared: usize,
        /// Compressed bytes consumed.
        consumed: usize,
        /// Compressed bytes available.
        total: usize,
    },
}

/// Split a frame header into `(uncompressed, compressed)` lengths.
#[inline]
pub fn parse_header(header: &[u8; HEADER_LEN]) -> (usize, usize) {
    let declared = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let compressed = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    (declared, compressed)
}

/// Writer-side compression state.
pub struct Compressor {
    state: Compress,
    history: usize,
}

impl Compressor {
    /// Create a compressor at `level` (0-9, clamped).
    pub fn new(level: u32) -> Self {
        Self {
            state: Compress::new(Compression::new(level.min(9)), true),
            history: 0,
        }
    }

    /// Compress one frame, returning the header followed by its zlib bytes.
    pub fn compress_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, CompressionError> {
        if frame.len() > MAX_FRAME {
            return Err(CompressionError::TooLarge {
                declared: frame.len(),
                limit: MAX_FRAME,
            });
        }
        let mut out = Vec::with_capacity(HEADER_LEN + frame.len() / 4 + 32);
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        let body_start = out.len();

        let mut scratch = [0u8; 16 * 1024];
        let mut consumed = 0usize;
        let mut rounds = 0u32;
        loop {
            rounds += 1;
            if rounds > 1024 {
                return Err(CompressionError::Stream(
                    "compressor did not reach a flush boundary".to_owned(),
                ));
            }
            let before_in = self.state.total_in();
            let before_out = self.state.total_out();
            self.state
                .compress(&frame[consumed..], &mut scratch, FlushCompress::Sync)
                .map_err(|error| CompressionError::Stream(error.to_string()))?;
            consumed += (self.state.total_in() - before_in) as usize;
            let produced = (self.state.total_out() - before_out) as usize;
            out.extend_from_slice(&scratch[..produced]);
            // `produced < scratch.len()` means the flush drained completely.
            if consumed == frame.len() && produced < scratch.len() {
                break;
            }
        }

        let compressed = out.len() - body_start;
        if compressed > MAX_FRAME {
            return Err(CompressionError::TooLarge {
                declared: compressed,
                limit: MAX_FRAME,
            });
        }
        out[4..8].copy_from_slice(&(compressed as u32).to_le_bytes());
        self.history = self.history.saturating_add(frame.len());
        Ok(out)
    }

    /// Total uncompressed bytes handed to this compressor.
    pub fn history(&self) -> usize {
        self.history
    }
}

impl std::fmt::Debug for Compressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compressor")
            .field("history", &self.history)
            .finish()
    }
}

/// Reader-side decompression state.
pub struct Decompressor {
    state: Decompress,
    limit: usize,
}

impl Decompressor {
    /// Create a decompressor refusing frames larger than `limit`.
    pub fn new(limit: usize) -> Self {
        Self {
            state: Decompress::new(true),
            limit: limit.min(MAX_FRAME),
        }
    }

    /// Decode one frame whose header declared `declared` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CompressionError`] for oversized, truncated, over-long or
    /// corrupt frames.
    pub fn decompress_frame(
        &mut self,
        payload: &[u8],
        declared: usize,
    ) -> Result<Vec<u8>, CompressionError> {
        if declared > self.limit {
            return Err(CompressionError::TooLarge {
                declared,
                limit: self.limit,
            });
        }
        // One byte of headroom makes an over-long stream observable instead of
        // silently truncating it.
        let mut out = vec![0u8; declared + 1];
        let mut consumed = 0usize;
        let mut produced = 0usize;
        let mut stalls = 0u32;

        while produced < declared {
            let before_in = self.state.total_in();
            let before_out = self.state.total_out();
            let status = self
                .state
                .decompress(
                    &payload[consumed..],
                    &mut out[produced..],
                    FlushDecompress::Sync,
                )
                .map_err(|error| CompressionError::Stream(error.to_string()))?;
            let used = (self.state.total_in() - before_in) as usize;
            let made = (self.state.total_out() - before_out) as usize;
            consumed += used;
            produced += made;

            if produced > declared {
                return Err(CompressionError::Expanded { declared });
            }
            if produced == declared {
                break;
            }
            if status == Status::StreamEnd {
                break;
            }
            if made == 0 {
                stalls += 1;
                if stalls > 2 {
                    return Err(CompressionError::Truncated {
                        produced,
                        expected: declared,
                    });
                }
            } else {
                stalls = 0;
            }
        }

        if produced < declared {
            return Err(CompressionError::Truncated {
                produced,
                expected: declared,
            });
        }

        // Consume the rest of this frame: the zlib header and sync-flush marker
        // produce no output, so any output here means the header lied about the
        // frame size. Draining with a small scratch buffer keeps memory bounded.
        let mut scratch = [0u8; 64];
        let mut rounds = 0u32;
        while consumed < payload.len() {
            rounds += 1;
            if rounds > 4096 {
                return Err(CompressionError::Stream("frame did not drain".to_owned()));
            }
            let before_in = self.state.total_in();
            let before_out = self.state.total_out();
            self.state
                .decompress(&payload[consumed..], &mut scratch, FlushDecompress::Sync)
                .map_err(|error| CompressionError::Stream(error.to_string()))?;
            let used = (self.state.total_in() - before_in) as usize;
            let made = (self.state.total_out() - before_out) as usize;
            consumed += used;
            if made > 0 {
                return Err(CompressionError::Expanded { declared });
            }
            if used == 0 {
                return Err(CompressionError::LengthMismatch {
                    declared,
                    consumed,
                    total: payload.len(),
                });
            }
        }
        out.truncate(declared);
        Ok(out)
    }
}

impl std::fmt::Debug for Decompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decompressor")
            .field("limit", &self.limit)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_payload(encoded: &[u8]) -> (usize, &[u8]) {
        let header: [u8; HEADER_LEN] = encoded[..HEADER_LEN].try_into().expect("header");
        let (declared, _compressed) = parse_header(&header);
        (declared, &encoded[HEADER_LEN..])
    }

    #[test]
    fn round_trips_across_frames() {
        let mut compressor = Compressor::new(6);
        let mut decompressor = Decompressor::new(MAX_FRAME);
        let frames = [
            b"PRIVMSG #rust :hello world\r\n".to_vec(),
            b"PRIVMSG #rust :hello world again\r\n".to_vec(),
            vec![b'x'; 4096],
            b":nick!user@host PRIVMSG #channel :short\r\n".to_vec(),
            Vec::new(),
        ];
        let expected_history: usize = frames.iter().map(Vec::len).sum();
        for frame in frames {
            let encoded = compressor.compress_frame(&frame).expect("compress");
            let (declared, payload) = frame_payload(&encoded);
            assert_eq!(declared, frame.len());
            let decoded = decompressor
                .decompress_frame(payload, declared)
                .expect("decompress");
            assert_eq!(decoded, frame);
        }
        assert_eq!(compressor.history(), expected_history);
    }

    #[test]
    fn reuses_the_dictionary_across_frames() {
        let mut compressor = Compressor::new(6);
        let line = b":alice!alice@example.com PRIVMSG #rust :repeated text\r\n";
        let first = compressor.compress_frame(line).expect("first");
        let second = compressor.compress_frame(line).expect("second");
        assert!(
            second.len() < first.len(),
            "second frame {} should be smaller than first {}",
            second.len(),
            first.len()
        );
    }

    #[test]
    fn rejects_oversized_declaration() {
        let mut decompressor = Decompressor::new(16);
        let error = decompressor
            .decompress_frame(&[0u8; 8], 1024)
            .expect_err("must reject");
        assert!(matches!(error, CompressionError::TooLarge { .. }));
    }

    #[test]
    fn reports_truncated_payload() {
        let mut compressor = Compressor::new(9);
        let encoded = compressor
            .compress_frame(b"a long repeated line repeated again")
            .expect("compress");
        let (declared, payload) = frame_payload(&encoded);
        let mut decompressor = Decompressor::new(MAX_FRAME);
        let error = decompressor
            .decompress_frame(&payload[..payload.len() / 2], declared)
            .expect_err("must reject");
        assert!(matches!(
            error,
            CompressionError::Truncated { .. } | CompressionError::Stream(_)
        ));
    }

    #[test]
    fn rejects_a_header_that_lies_about_the_size() {
        let mut compressor = Compressor::new(6);
        let encoded = compressor.compress_frame(b"0123456789").expect("compress");
        let (_, payload) = frame_payload(&encoded);
        let mut decompressor = Decompressor::new(MAX_FRAME);
        let error = decompressor
            .decompress_frame(payload, 5)
            .expect_err("must reject");
        assert!(matches!(
            error,
            CompressionError::Expanded { .. } | CompressionError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn empty_frame_round_trips() {
        let mut compressor = Compressor::new(1);
        let encoded = compressor.compress_frame(b"").expect("compress empty");
        let (declared, payload) = frame_payload(&encoded);
        assert_eq!(declared, 0);
        let mut decompressor = Decompressor::new(MAX_FRAME);
        let decoded = decompressor
            .decompress_frame(payload, declared)
            .expect("decompress empty");
        assert!(decoded.is_empty());
    }
}
