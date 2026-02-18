use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use num_bigint::BigUint;
use privacy_preserving_accumulators::{RsaAccumulator};

fn benchmark_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_add_scaling");
    group.sample_size(10);

    let sizes = [10, 100, 1000];


    // setup
    for size in sizes.iter() {
        let mut elements: Vec<BigUint> = Vec::new();
        for i in 0..*size {
            elements.push(BigUint::from(i as u64));
        }
    
        let base_acc = RsaAccumulator::setup();
    
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &_s| {
            b.iter_batched(|| {
                (base_acc.clone(), elements.clone())
            }, |(mut acc, elems)| {
                for x in elems {
                    acc.add(&x);
                }
            }, BatchSize::SmallInput,
        );
        });
    }
    group.finish();
    
}
criterion_group!(benches, benchmark_addition);
criterion_main!(benches);