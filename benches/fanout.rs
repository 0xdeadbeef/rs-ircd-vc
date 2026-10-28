//! Channel fan-out benchmarks: what the per-recipient tag variants cost.
//!
//! [`Server::broadcast_text`] builds at most eight serialisations, one per
//! combination of the `server-time`, `account-tag` and `message-tags` bits, and
//! shares them across the audience. These benchmarks measure both ends of that
//! design: an audience where one variant serves everybody, and an audience
//! spread across all eight variants.
//!
//! Run with `cargo bench --bench fanout`. Single-threaded on purpose, like the
//! other benchmark targets.

use std::net::SocketAddr;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use ircd::config::Config;
use ircd::protocol::Message;
use ircd::server::{CapSet, ClientHandle, Outbound, Server};
use tokio::sync::mpsc;

/// Recipients in every benchmark, so the numbers are directly comparable.
const RECIPIENTS: usize = 64;

fn server() -> Arc<Server> {
    Server::new(Arc::new(Config::default()), None).expect("server state")
}

/// Build an audience whose capability set is chosen per index.
fn audience(
    caps_for: impl Fn(usize) -> CapSet,
) -> (Vec<Arc<ClientHandle>>, Vec<mpsc::Receiver<Outbound>>) {
    let peer: SocketAddr = "127.0.0.1:5000".parse().expect("socket address");
    let mut recipients = Vec::with_capacity(RECIPIENTS);
    let mut receivers = Vec::with_capacity(RECIPIENTS);
    for index in 0..RECIPIENTS {
        let (sender, receiver) = mpsc::channel(4096);
        let client = ClientHandle::new(index as u64, peer, "host".to_owned(), false, false, sender);
        client.set_caps(caps_for(index));
        recipients.push(Arc::new(client));
        receivers.push(receiver);
    }
    (recipients, receivers)
}

fn message() -> Message {
    let mut message =
        Message::with_params("PRIVMSG", ["#channel", "hello world, this is a message"]);
    message.prefix = Some("alice!alice@127.0.0.1".to_owned());
    message
}

fn tags() -> Vec<(String, String)> {
    vec![
        ("+example".to_owned(), "one".to_owned()),
        ("+draft/reply".to_owned(), "abc".to_owned()),
    ]
}

/// Empty the queue between iterations so a full outbound buffer never changes
/// the measured path. Setup runs outside the timed routine.
fn drain(receivers: &mut [mpsc::Receiver<Outbound>]) {
    for receiver in receivers {
        while receiver.try_recv().is_ok() {}
    }
}

fn fanout_benchmarks(criterion: &mut Criterion) {
    let server = server();
    let message = message();
    let tags = tags();
    let all = CapSet::SERVER_TIME | CapSet::ACCOUNT_TAG | CapSet::MESSAGE_TAGS;

    let mut group = criterion.benchmark_group("fanout");
    group.throughput(Throughput::Elements(RECIPIENTS as u64));
    group.sample_size(20);

    // No tags at all: one serialisation, shared by every recipient.
    let (plain, mut plain_receivers) = audience(|_| CapSet::default());
    group.bench_function("untagged_homogeneous", |bencher| {
        bencher.iter_batched(
            || {
                drain(&mut plain_receivers);
                plain.clone()
            },
            |recipients| server.broadcast_text(recipients, &message, None, None, &[]),
            BatchSize::SmallInput,
        );
    });

    // Account and client tags for an audience that wants both, plus `@time`:
    // still one serialisation.
    let (tagged, mut tagged_receivers) = audience(|_| all);
    group.bench_function("tagged_homogeneous", |bencher| {
        bencher.iter_batched(
            || {
                drain(&mut tagged_receivers);
                tagged.clone()
            },
            |recipients| server.broadcast_text(recipients, &message, None, Some("alice"), &tags),
            BatchSize::SmallInput,
        );
    });

    // Half the audience plain, half fully capable: two serialisations.
    let (split, mut split_receivers) = audience(|index| {
        if index % 2 == 0 {
            CapSet::default()
        } else {
            all
        }
    });
    group.bench_function("tagged_mixed_2", |bencher| {
        bencher.iter_batched(
            || {
                drain(&mut split_receivers);
                split.clone()
            },
            |recipients| server.broadcast_text(recipients, &message, None, Some("alice"), &tags),
            BatchSize::SmallInput,
        );
    });

    // Every combination of the three tag bits, eight recipients each: the
    // cache's worst case.
    let (mixed, mut mixed_receivers) = audience(|index| match index % 8 {
        0 => CapSet::default(),
        1 => CapSet::SERVER_TIME,
        2 => CapSet::ACCOUNT_TAG,
        3 => CapSet::SERVER_TIME | CapSet::ACCOUNT_TAG,
        4 => CapSet::MESSAGE_TAGS,
        5 => CapSet::SERVER_TIME | CapSet::MESSAGE_TAGS,
        6 => CapSet::ACCOUNT_TAG | CapSet::MESSAGE_TAGS,
        _ => all,
    });
    group.bench_function("tagged_mixed_8", |bencher| {
        bencher.iter_batched(
            || {
                drain(&mut mixed_receivers);
                mixed.clone()
            },
            |recipients| server.broadcast_text(recipients, &message, None, Some("alice"), &tags),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, fanout_benchmarks);
criterion_main!(benches);
