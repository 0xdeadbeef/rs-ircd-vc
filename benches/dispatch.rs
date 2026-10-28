//! Command dispatch benchmarks.
//!
//! The hash-map arm reproduces the previous lookup (a `HashMap<&str, _>`
//! populated with the same key set) so the comparison is apples to apples: same
//! keys, same miss rate, same single-threaded harness.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::LazyLock;

use criterion::{criterion_group, criterion_main, Criterion};

static BASELINE: LazyLock<HashMap<&'static str, usize>> = LazyLock::new(|| {
    ircd::commands::names()
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name, index))
        .collect()
});

fn lookups(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("command_lookup");
    group.bench_function("hash_map_hit", |bencher| {
        bencher.iter(|| BASELINE.get(black_box("PRIVMSG")).copied().unwrap_or(0));
    });
    group.bench_function("match_table_hit", |bencher| {
        bencher.iter(|| ircd::commands::lookup(black_box("PRIVMSG")).map(|spec| spec.name));
    });
    group.bench_function("match_table_miss", |bencher| {
        bencher.iter(|| ircd::commands::lookup(black_box("NOSUCHCMD")).map(|spec| spec.name));
    });
    group.finish();
}

criterion_group!(dispatch, lookups);
criterion_main!(dispatch);
