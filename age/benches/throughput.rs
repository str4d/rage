use age::{x25519, Encryptor};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use std::io::{self, Write};

const KB: usize = 1024;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let recipient = x25519::Identity::generate().to_public();
    let mut group = c.benchmark_group("stream");
    let buf = vec![0u8; 1024 * KB];

    for &size in &[KB, 16 * KB, 64 * KB, 128 * KB, 256 * KB, 500 * KB, 1024 * KB] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            let mut output = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
                .wrap_output(io::sink())
                .unwrap();

            b.iter(|| output.write_all(&buf[..size]))
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);
criterion_main!(benches);
