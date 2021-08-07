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

    // Prepare buffers to use in the benchmarks.
    let pt_buf = vec![7u8; 1024 * KB];
    let mut ct_buf = vec![];
    let mut out_buf = vec![0u8; 1024 * KB];

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
                output.write_all(&pt_buf[..size]).unwrap();
                output.finish().unwrap();
            })
        });

        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            let mut output = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
                .wrap_output(&mut ct_buf)
                .unwrap();
            output.write_all(&pt_buf[..size]).unwrap();
            output.finish().unwrap();

            b.iter(|| {
                let decryptor = match Decryptor::new(&ct_buf[..]).unwrap() {
                    Decryptor::Recipients(decryptor) => decryptor,
                    _ => panic!(),
                };
                let mut input = decryptor
                    .decrypt(iter::once(&identity as &dyn age::Identity))
                    .unwrap();
                input.read_exact(&mut out_buf[..size]).unwrap();
            });

            ct_buf.clear();
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
