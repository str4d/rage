use age::{x25519, Decryptor, Encryptor};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use std::io::{self, Read, Write};
use std::iter;

const KB: usize = 1024;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    let mut group = c.benchmark_group("stream");
    let mut buf = vec![0u8; 1024 * KB];

    for &size in &[
        KB,
        4 * KB,
        16 * KB,
        64 * KB,
        128 * KB,
        256 * KB,
        500 * KB,
        1024 * KB,
    ] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            b.iter(|| {
                let mut output = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
                    .wrap_output(io::sink())
                    .unwrap();
                output.write_all(&buf[..size]).unwrap();
                output.finish().unwrap();
            })
        });

        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            let mut encrypted = vec![];
            let mut output = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
                .wrap_output(&mut encrypted)
                .unwrap();
            output.write_all(&buf[..size]).unwrap();
            output.finish().unwrap();

            b.iter(|| {
                let decryptor = match Decryptor::new(&encrypted[..]).unwrap() {
                    Decryptor::Recipients(decryptor) => decryptor,
                    _ => panic!(),
                };
                let mut input = decryptor
                    .decrypt(iter::once(&identity as &dyn age::Identity))
                    .unwrap();
                input.read_exact(&mut buf[..size]).unwrap();
            })
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
