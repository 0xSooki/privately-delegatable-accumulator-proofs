use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use num_bigint::BigUint;
use privacy_preserving_accumulators::RsaAccumulator;

fn benchmark_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_add");

    group.sample_size(100);

    let new_element = BigUint::from(42u32);

    group.bench_function("add_one_element", |b| {
        b.iter_batched(|| RsaAccumulator::setup(), |mut acc| {acc.add(&new_element);}, BatchSize::SmallInput);
    });

    group.finish();

}

criterion_group!(benches, benchmark_addition);
criterion_main!(benches);
