use age::{Encryptor, SecretKey};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use std::io::{self, Write};

const KB: usize = 1024;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let recipients = vec![SecretKey::generate().to_public()];
    let mut group = c.benchmark_group("stream");

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 128 * KB] {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            let mut output = Encryptor::with_recipients(recipients.clone())
                .wrap_output(io::sink())
                .unwrap();

            b.iter(|| output.write_all(&buf))
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
