use age::{x25519, Decryptor, Encryptor, Recipient};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

#[cfg(unix)]
use pprof::criterion::{Output, PProfProfiler};

use std::io::Write;

fn bench(c: &mut Criterion) {
    let recipients: Vec<_> = (0..10)
        .map(|_| Box::new(x25519::Identity::generate().to_public()))
        .collect();
    let mut group = c.benchmark_group("header");

    for count in 1..10 {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_function(BenchmarkId::new("parse", count), |b| {
            let mut encrypted = vec![];
            let mut output = Encryptor::with_recipients(
                recipients
                    .iter()
                    .take(count)
                    .cloned()
                    .map(|r| r as Box<dyn Recipient + Send>)
                    .collect(),
            )
            .unwrap()
            .wrap_output(&mut encrypted)
            .unwrap();
            output.write_all(&[]).unwrap();
            output.finish().unwrap();

            b.iter(|| Decryptor::new(&encrypted[..]))
        });
    }

    group.finish();
}

#[cfg(unix)]
criterion_group!(
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench
);
#[cfg(not(unix))]
criterion_group!(benches, bench);
criterion_main!(benches);
