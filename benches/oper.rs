//! Operator-path benchmarks: ban matching, the empty-ban fast path and snomask
//! filtering.
//!
//! The ban list is empty on almost every server, so the interesting numbers are
//! the cheap "nothing to check" path and the worst case where the list is long
//! and the match is at the end. Single-threaded like the other targets.

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use ircd::config::Config;
use ircd::server::{BanKind, Server, ServerBan, Snomask};

fn server() -> Arc<Server> {
    Server::new(Arc::new(Config::default()), None).expect("server state")
}

fn bans(count: usize) -> Vec<ServerBan> {
    (0..count)
        .map(|index| {
            ServerBan::new(
                BanKind::Gline,
                &format!("*!*@host{index}.example"),
                "bench",
                None,
                "benchmark entry",
            )
        })
        .collect()
}

fn ban_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("oper_ban");
    group.throughput(Throughput::Elements(1));

    group.bench_function("empty_fast_path", |bencher| {
        let server = server();
        bencher.iter(|| server.has_bans());
    });

    group.bench_function("miss_32", |bencher| {
        let server = server();
        for ban in bans(32) {
            server.add_ban(ban);
        }
        bencher.iter_batched(
            || (),
            |()| {
                server.matching_ban(
                    &[BanKind::Gline],
                    "nick",
                    "user",
                    "good.example",
                    "192.0.2.1",
                    None,
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("hit_last_32", |bencher| {
        let server = server();
        for ban in bans(32) {
            server.add_ban(ban);
        }
        bencher.iter_batched(
            || (),
            |()| {
                server.matching_ban(
                    &[BanKind::Gline],
                    "nick",
                    "user",
                    "host31.example",
                    "192.0.2.1",
                    None,
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn snomask_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("snomask");
    let mask = Snomask::ALL;
    group.bench_function("contains", |bencher| {
        bencher.iter(|| mask.contains(Snomask::BAN));
    });
    group.bench_function("from_letters", |bencher| {
        bencher.iter(|| Snomask::from_letters("cqkorlbg"));
    });
    group.bench_function("letters", |bencher| bencher.iter(|| mask.letters()));
    group.finish();
}

criterion_group!(oper, ban_benchmarks, snomask_benchmarks);
criterion_main!(oper);
