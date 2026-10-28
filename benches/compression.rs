//! Compression algorithm comparison for IRC traffic.
//!
//! Compares the candidates for link/connection compression on a realistic IRC
//! corpus: zlib/deflate at several levels, zstd, brotli and LZ4. Compression
//! ratio is what matters on the wire; throughput matters because compression
//! runs on every outbound frame.
//!
//! Run alone with `cargo bench --bench compression`.

use std::hint::black_box;
use std::io::Write;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

/// A realistic mix of IRC traffic: chat, joins, mode changes and numerics.
fn corpus() -> Vec<u8> {
    let mut corpus = Vec::with_capacity(32 * 1024);
    for index in 0..400 {
        let line = match index % 4 {
            0 => format!(
                ":alice!alice@client.example.com PRIVMSG #rust :message number {index} with some repeated words\r\n"
            ),
            1 => ":bob!bob@other.example.net JOIN #rust\r\n".to_owned(),
            2 => ":irc.example.org 353 alice = #rust :@alice +bob charlie dave\r\n".to_owned(),
            _ => format!(
                ":charlie!charlie@third.example.org PRIVMSG #rust :another line {index}, talking about Rust and IRC\r\n"
            ),
        };
        corpus.extend_from_slice(line.as_bytes());
    }
    corpus
}

fn zlib_compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(level));
    encoder.write_all(data).expect("compress");
    encoder.finish().expect("finish")
}

fn zstd_compress(data: &[u8], level: i32) -> Vec<u8> {
    zstd::bulk::compress(data, level).expect("zstd")
}

fn brotli_compress(data: &[u8], quality: u32) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut output, 4096, quality, 22);
        writer.write_all(data).expect("brotli");
    }
    output
}

fn lz4_compress(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

fn report(corpus: &[u8]) {
    let mut rows: Vec<(&str, usize)> = vec![
        ("zlib level 1", zlib_compress(corpus, 1).len()),
        ("zlib level 6", zlib_compress(corpus, 6).len()),
        ("zlib level 9", zlib_compress(corpus, 9).len()),
        ("zstd level 1", zstd_compress(corpus, 1).len()),
        ("zstd level 3", zstd_compress(corpus, 3).len()),
        ("brotli q3", brotli_compress(corpus, 3).len()),
        ("brotli q6", brotli_compress(corpus, 6).len()),
        ("lz4", lz4_compress(corpus).len()),
    ];
    rows.sort_by_key(|(_, size)| *size);
    println!("\nIRC corpus: {} bytes\n", corpus.len());
    println!("{:<16} {:>10} {:>8}", "algorithm", "bytes", "ratio");
    for (name, size) in &rows {
        println!(
            "{name:<16} {size:>10} {:>7.2}x",
            corpus.len() as f64 / *size as f64
        );
    }
    println!();
}

/// Compress every line as its own frame, which is how the wire protocol works.
fn per_message_sizes(corpus: &[u8]) -> Vec<(&'static str, usize)> {
    let lines: Vec<&[u8]> = corpus.split_inclusive(|byte| *byte == b'\n').collect();
    let sum = |mut sizes: Vec<usize>| sizes.drain(..).sum::<usize>();
    let mut persistent = ircd::net::compress::Compressor::new(6);
    let persistent_bytes = lines
        .iter()
        .map(|line| persistent.compress_frame(line).expect("compress").len())
        .sum::<usize>();
    vec![
        ("zlib persistent (server)", persistent_bytes),
        (
            "zlib level 6",
            sum(lines
                .iter()
                .map(|line| zlib_compress(line, 6).len())
                .collect()),
        ),
        (
            "zstd level 1",
            sum(lines
                .iter()
                .map(|line| zstd_compress(line, 1).len())
                .collect()),
        ),
        (
            "zstd level 3",
            sum(lines
                .iter()
                .map(|line| zstd_compress(line, 3).len())
                .collect()),
        ),
        (
            "brotli q3",
            sum(lines
                .iter()
                .map(|line| brotli_compress(line, 3).len())
                .collect()),
        ),
        (
            "lz4",
            sum(lines.iter().map(|line| lz4_compress(line).len()).collect()),
        ),
    ]
}

fn compile_per_message_benchmarks(criterion: &mut Criterion) {
    let corpus = corpus();
    let mut rows = per_message_sizes(&corpus);
    rows.sort_by_key(|(_, size)| *size);
    println!(
        "\nPer-message framing ({} lines):\n",
        corpus.split_inclusive(|b| *b == b'\n').count()
    );
    println!("{:<16} {:>10} {:>8}", "algorithm", "bytes", "ratio");
    for (name, size) in &rows {
        println!(
            "{name:<16} {size:>10} {:>7.2}x",
            corpus.len() as f64 / *size as f64
        );
    }
    println!();

    let max_line = 128usize;
    let mut group = criterion.benchmark_group("compress_per_message");
    group.throughput(Throughput::Bytes(corpus.len() as u64));
    group.bench_function("zlib_6", |bencher| {
        bencher.iter(|| {
            let mut total = 0usize;
            for line in corpus.split_inclusive(|byte| *byte == b'\n') {
                total += zlib_compress(black_box(line), 6).len();
            }
            total.max(max_line)
        });
    });
    group.bench_function("zstd_3", |bencher| {
        bencher.iter(|| {
            let mut total = 0usize;
            for line in corpus.split_inclusive(|byte| *byte == b'\n') {
                total += zstd_compress(black_box(line), 3).len();
            }
            total.max(max_line)
        });
    });
    group.bench_function("zlib_persistent", |bencher| {
        bencher.iter(|| {
            let mut compressor = ircd::net::compress::Compressor::new(6);
            let mut total = 0usize;
            for line in corpus.split_inclusive(|byte| *byte == b'\n') {
                total += compressor
                    .compress_frame(black_box(line))
                    .expect("compress")
                    .len();
            }
            total.max(max_line)
        });
    });
    group.finish();
}

fn compression_benchmarks(criterion: &mut Criterion) {
    let corpus = corpus();
    report(&corpus);
    let mut group = criterion.benchmark_group("compress");
    group.throughput(Throughput::Bytes(corpus.len() as u64));

    group.bench_function("zlib_1", |bencher| {
        bencher.iter(|| zlib_compress(black_box(&corpus), 1));
    });
    group.bench_function("zlib_6", |bencher| {
        bencher.iter(|| zlib_compress(black_box(&corpus), 6));
    });
    group.bench_function("zlib_9", |bencher| {
        bencher.iter(|| zlib_compress(black_box(&corpus), 9));
    });
    group.bench_function("zstd_1", |bencher| {
        bencher.iter(|| zstd_compress(black_box(&corpus), 1));
    });
    group.bench_function("zstd_3", |bencher| {
        bencher.iter(|| zstd_compress(black_box(&corpus), 3));
    });
    group.bench_function("brotli_3", |bencher| {
        bencher.iter(|| brotli_compress(black_box(&corpus), 3));
    });
    group.bench_function("brotli_6", |bencher| {
        bencher.iter(|| brotli_compress(black_box(&corpus), 6));
    });
    group.bench_function("lz4", |bencher| {
        bencher.iter(|| lz4_compress(black_box(&corpus)));
    });
    group.finish();
}

criterion_group!(
    benches,
    compile_per_message_benchmarks,
    compression_benchmarks
);
criterion_main!(benches);
