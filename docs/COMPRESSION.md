# Compression: algorithm choice

Measured on the development machine (2 vCPU, `x86_64`, no `target-cpu=native`),
single-threaded, one benchmark at a time. Reproduce with:

```bash
cargo bench --bench compression
```

Corpus: 400 lines (28,845 bytes) of mixed IRC traffic — chat with repeated
nicks and channel names, joins, numerics and mode changes.

## What "compression" means for IRC

An IRC line averages 70 bytes. Compressing each line as an independent stream
is *worse than sending it plain*, because every algorithm pays a header and
trailer per stream. The first table shows exactly that; the second shows what
happens once the dictionary is shared across messages, which is how the wire
protocol here works (persistent deflate stream, `Z_SYNC_FLUSH` per frame).

### Per-message framing (one stream per line)

| Algorithm | Bytes | Ratio |
|---|---:|---:|
| zlib level 6, persistent stream (this server) | 11,139 | **2.59x** |
| brotli q3, independent frames | 28,161 | 1.02x |
| LZ4, independent frames | 30,422 | 0.95x |
| zstd level 1, independent frames | 31,845 | 0.91x |
| zstd level 3, independent frames | 31,872 | 0.91x |
| zlib level 6, independent frames | 32,434 | 0.89x |

Independent frames expand short lines. Only dictionary reuse makes compression
worth enabling.

### Single stream over the whole corpus

| Algorithm | Bytes | Ratio | Throughput |
|---|---:|---:|---:|
| brotli q6 | 543 | 53.12x | 126 MiB/s |
| brotli q3 | 548 | 52.64x | 125 MiB/s |
| zstd level 1 | 623 | 46.30x | 1.71 GiB/s |
| zstd level 3 | 664 | 43.44x | 1.20 GiB/s |
| zlib level 6 | 829 | 34.79x | 258 MiB/s |
| zlib level 9 | 829 | 34.79x | 250 MiB/s |
| zlib level 1 | 879 | 32.82x | 1.26 GiB/s |
| LZ4 | 1,244 | 23.19x | 5.42 GiB/s |

Per-frame cost with a persistent stream: 27 MiB/s for zlib level 6, versus
~6 MiB/s for independent zlib frames and ~13 MiB/s for independent zstd frames.

## Decision

**zlib (flate2) at a configurable level, persistent stream, sync flush per
frame.**

* It is the only candidate that preserves the historically negotiated
  `COMPRESS zlib` token, so existing IRC compression implementations can talk
  to it.
* `flate2`'s default backend is pure Rust (`miniz_oxide`): no C toolchain, no
  FFI, and it cross-compiles to Windows without a build environment.
* Level 6 is the default; level 1 is 5x faster for a 6% ratio loss and remains
  available through `compression.level`.

## Honest caveat

zstd level 3 beats zlib on the same persistent-stream workload (43x versus 35x
at roughly 5x the throughput). Brotli wins on ratio but is 10x slower than zstd.
If interoperability with the old `COMPRESS` convention were not a requirement,
zstd would be the better default, and it is the natural upgrade path: the frame
header already carries both lengths, so a second method token only needs a
codec switch. It was not adopted here because it adds a C library to a server
that is otherwise free of C dependencies.

## Bomb resistance

The frame header carries both the uncompressed and compressed length. The
reader rejects either value above `compression.max_decompressed` (default
1 MiB) before allocating, inflates into a buffer of exactly the declared size
plus one byte, and rejects frames that consume more or fewer compressed bytes
than announced. A stream that expands beyond its header is rejected rather
than truncated. Covered by unit tests in `src/net/compress.rs`.
