use ark_std::time::Duration;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use num_bigint::BigUint;
use privacy_preserving_accumulators::RsaAccumulator;

fn benchmark_blind_mem_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(100);

    let element = BigUint::from(7 as usize);

    group.bench_function("blind_proof", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::setup();

                let ep: BigUint = acc.add(&element);

                for i in 2..5 {
                    acc.add(&BigUint::from(i as usize));
                }

                let proof = acc.mem_proof_create(&ep);

                (acc, proof)
            },
            |(acc, proof)| {
                acc.blind_mem_proof(&proof);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_unblind_mem_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(100);

    group.bench_function("unblind_proof", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::setup();

                let element = BigUint::from(7 as usize);
                let ep: BigUint = acc.add(&element);

                for i in 2..5 {
                    acc.add(&BigUint::from(i as usize));
                }

                let proof = acc.mem_proof_create(&ep);

                let blinded_proof = acc.blind_mem_proof(&proof);

                (acc, blinded_proof)
            },
            |(acc, blindedproof)| {
                acc.unblind_mem_proof(&blindedproof.0, &blindedproof.1);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_ver_blind_mem_proof_upd(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(100);

    group.measurement_time(Duration::from_secs(10));

    group.bench_function("ver_blind_proof_upd", |b| {
        b.iter_batched(
            || {
                let mut acc = RsaAccumulator::setup();

                let ep = acc.add(&BigUint::from(200003u32));

                let acct = acc.acc.clone();

                let proof = acc.mem_proof_create(&ep);

                let blinded_proof = acc.blind_mem_proof(&proof);

                let elements_in = vec![
                    BigUint::from(65537u32),
                    BigUint::from(100003u32),
                    BigUint::from(104729u32),
                    BigUint::from(1299709u32),
                    BigUint::from(15485863u32),
                ];

                let elements_out = vec![];
                for elem in &elements_in {
                    acc.add(&elem);
                }

                let updated_blind_proof =
                    acc.blind_mem_proof_upd(elements_in, elements_out, &acct, &blinded_proof.0);

                (acc, acct, blinded_proof, updated_blind_proof)
            },
            |(acc, acct, blindedproof, updated_blind_proof)| {
                acc.ver_blind_mem_proof_upd(
                    &acct,
                    &blindedproof.0,
                    &updated_blind_proof.0,
                    &updated_blind_proof.1,
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_blind_mem_proof_upd(c: &mut Criterion) {
    let mut group = c.benchmark_group("membership_proofs");

    group.sample_size(10);

    group.measurement_time(Duration::from_secs(10));

    let sizes = [10, 200, 400, 600, 800, 1000];

    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("blind_mem_proof_upd", size), size, |b, &n| {
            b.iter_batched(
                || {
                    let mut acc = RsaAccumulator::setup();

                    let ep = acc.add(&BigUint::from(200003u32));

                    let acct = acc.acc.clone();

                    let proof = acc.mem_proof_create(&ep);

                    let blinded_proof = acc.blind_mem_proof(&proof);

                    let mut elements_in = Vec::new();

                    for i in 0..n {
                        let elem = BigUint::from(i as u64);
                        elements_in.push(elem);
                    }

                    let elements_out = vec![];
                    for elem in &elements_in {
                        acc.add(&elem);
                    }

                    (acc, elements_in, elements_out, acct, blinded_proof)
                },
                |(acc, elements_in, elements_out, acct, blinded_proof)| {
                    acc.blind_mem_proof_upd(elements_in, elements_out, &acct, &blinded_proof.0);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}




fn benchmark_blind_non_mem_proof_upd(c: &mut Criterion) {
    let mut group = c.benchmark_group("non_membership_proofs");

    group.sample_size(10);

    group.measurement_time(Duration::from_secs(10));

    let sizes = [10, 200, 400, 600, 800, 1000];

    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("blind_non_mem_proof_upd", size), size, |b, &n| {
            b.iter_batched(
                || {
                    let mut acc = RsaAccumulator::setup();

                    let non_member = BigUint::from(200003u32);

                    let blinded_non_mem_proof = acc.blind_non_mem_proof(&non_member);

                    let mut elements_in = Vec::new();

                    for i in 0..n {
                        let elem = BigUint::from(i as u64);
                        elements_in.push(elem);
                    }

                    //let elements_out: Vec<BigUint> = vec![];
                    for elem in &elements_in {
                        acc.add(&elem);
                    }

                    (acc, blinded_non_mem_proof)
                },
                |(acc, blinded_non_mem_proof)| {
                    acc.blind_non_mem_proof_upd(&blinded_non_mem_proof.0);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_blind_mem_proof,
    benchmark_unblind_mem_proof,
    benchmark_ver_blind_mem_proof_upd,
    benchmark_blind_mem_proof_upd,
    benchmark_blind_non_mem_proof_upd
);
criterion_main!(benches);
