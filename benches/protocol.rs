//! Protocol hot-path benchmarks.
//!
//! Run with `cargo bench --bench protocol`. These are deliberately single
//! threaded: concurrent benchmarks contend for the same core and produce
//! meaningless numbers on small machines.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ircd::casemap::CaseMapping;
use ircd::protocol::{Message, Numeric};
use ircd::util::wildcard_match;

fn parse_benchmarks(criterion: &mut Criterion) {
    let plain = ":nick!user@host PRIVMSG #channel :hello world, this is a message\r\n";
    let tagged = "@time=2024-01-01T00:00:00.000Z;msgid=abc123;account=alice \
                  :nick!user@host PRIVMSG #channel :hello world";
    let mut group = criterion.benchmark_group("message_parse");
    group.throughput(Throughput::Bytes(plain.len() as u64));
    group.bench_function("plain", |bencher| {
        bencher.iter(|| Message::parse(black_box(plain), 512).expect("parse"));
    });
    group.throughput(Throughput::Bytes(tagged.len() as u64));
    group.bench_function("tagged", |bencher| {
        bencher.iter(|| Message::parse(black_box(tagged), 512).expect("parse"));
    });
    group.finish();
}

fn serialise_benchmarks(criterion: &mut Criterion) {
    let mut message =
        Message::with_params("PRIVMSG", ["#channel", "hello world, this is a message"]);
    message.prefix = Some("nick!user@host".to_owned());
    let mut group = criterion.benchmark_group("message_serialise");
    group.bench_function("untagged", |bencher| {
        bencher.iter(|| message.to_bytes_limited(black_box(512)));
    });
    message.push_tag("time", "2024-01-01T00:00:00.000Z");
    group.bench_function("tagged", |bencher| {
        bencher.iter(|| message.to_bytes_limited(black_box(512)));
    });
    group.finish();
}

fn casemap_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("casemapping");
    for mapping in [
        CaseMapping::Ascii,
        CaseMapping::Rfc1459,
        CaseMapping::StrictRfc1459,
    ] {
        group.bench_function(mapping.token(), |bencher| {
            bencher.iter(|| mapping.fold(black_box("SomeNickname[1]")));
        });
    }
    group.bench_function("equality", |bencher| {
        bencher.iter(|| CaseMapping::Rfc1459.eq(black_box("Nick[1]"), black_box("nick{1}")));
    });
    group.finish();
}

fn mask_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("wildcard");
    group.bench_function("hostmask", |bencher| {
        bencher.iter(|| {
            wildcard_match(
                black_box("*!*@*.example.com"),
                black_box("nick!user@host.example.com"),
            )
        });
    });
    group.bench_function("no_match", |bencher| {
        bencher.iter(|| {
            wildcard_match(
                black_box("*!*@*.example.org"),
                black_box("nick!user@host.example.com"),
            )
        });
    });
    group.finish();
}

fn numeric_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("numeric_format");
    group.bench_function("display", |bencher| {
        bencher.iter(|| black_box(Numeric::ERR_NEEDMOREPARAMS).to_string());
    });
    group.finish();
}

criterion_group!(
    benches,
    parse_benchmarks,
    serialise_benchmarks,
    casemap_benchmarks,
    mask_benchmarks,
    numeric_benchmarks
);
criterion_main!(benches);
