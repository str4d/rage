use age::{x25519, Decryptor, Encryptor};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use criterion_cycles_per_byte::CyclesPerByte;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
type Criterion_ = Criterion<CyclesPerByte>;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
type Criterion_ = Criterion;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn setup_criterion() -> Criterion_ {
    Criterion::default().with_measurement(CyclesPerByte)
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn setup_criterion() -> Criterion_ {
    Criterion::default()
}

#[cfg(unix)]
use pprof::criterion::{Output, PProfProfiler};

use std::io::{self, Read, Write};
use std::iter;

const KB: usize = 1024;

fn bench(c: &mut Criterion_) {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    let mut group = c.benchmark_group("age");

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
                    .unwrap()
                    .wrap_output(io::sink())
                    .unwrap();
                output.write_all(&pt_buf[..size]).unwrap();
                output.finish().unwrap();
            })
        });

        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            let mut output = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
                .unwrap()
                .wrap_output(&mut ct_buf)
                .unwrap();
            output.write_all(&pt_buf[..size]).unwrap();
            output.finish().unwrap();

            b.iter(|| {
                let decryptor = match Decryptor::new_buffered(&ct_buf[..]).unwrap() {
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

#[cfg(unix)]
criterion_group!(
    name = benches;
    config = setup_criterion()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench
);
#[cfg(not(unix))]
criterion_group!(
    name = benches;
    config = setup_criterion();
    targets = bench
);
criterion_main!(benches);
