use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_poly_commit::kzg10::{Powers, KZG10};
use ark_std::test_rng;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
#[cfg(feature = "class-group")]
use curv::BigInt as CurvBigInt;
use num_bigint::{BigInt as NumBigInt, BigUint};
use num_integer::Integer;
#[cfg(feature = "class-group")]
use private_accumulator_proof_delegation::groups::{
    class_group::{ClassGroupElement, ClassGroupExponent},
    ClassGroup,
};
use private_accumulator_proof_delegation::{
    groups::RsaGroup,
    nizk::{BilinearNIZK, NIZK},
    BilinearAccumulator, Group, RsaAccumulator,
};
use std::borrow::Cow;

type G1 = <Bls12_381 as Pairing>::G1Affine;

const MEMBER: u64 = 200_003;
const NON_MEMBER: u64 = 741_569;
const UPDATE: u64 = 900_001;

fn syn_div_by_x_minus_c(poly: &DensePolynomial<Fr>, c: &Fr) -> (DensePolynomial<Fr>, Fr) {
    let coeffs = poly.coeffs();
    if coeffs.len() <= 1 {
        let r = coeffs.first().copied().unwrap_or_else(Fr::zero);
        return (DensePolynomial::zero(), r);
    }

    let n = coeffs.len();
    let mut q = vec![Fr::zero(); n - 1];
    q[n - 2] = coeffs[n - 1];
    for i in (0..n - 2).rev() {
        q[i] = coeffs[i + 1] + *c * q[i + 1];
    }

    let r = coeffs[0] + *c * q[0];
    (DensePolynomial::from_coefficients_vec(q), r)
}

fn syn_div_by_x_plus_alpha(poly: &DensePolynomial<Fr>, alpha: &Fr) -> (DensePolynomial<Fr>, Fr) {
    let c = -*alpha;
    syn_div_by_x_minus_c(poly, &c)
}

fn build_poly_from_roots(roots: &[Fr]) -> DensePolynomial<Fr> {
    roots.iter().fold(
        DensePolynomial::from_coefficients_vec(vec![Fr::one()]),
        |acc, root| {
            let factor = DensePolynomial::from_coefficients_vec(vec![-*root, Fr::one()]);
            &acc * &factor
        },
    )
}

fn setup_aux_powers(len: usize) -> Vec<G1> {
    let mut rng = test_rng();
    let pp = KZG10::<Bls12_381, DensePolynomial<Fr>>::setup(len + 2, false, &mut rng)
        .expect("KZG setup failed");
    pp.powers_of_g.iter().take(len).copied().collect()
}

struct BilinearMemContext {
    acc_after_update: BilinearAccumulator<Bls12_381>,
    pi_blinded: G1,
    acc_t: G1,
    acc_t_prime: G1,
    crs_prime: Vec<G1>,
    q_star: DensePolynomial<Fr>,
    powers_acc_t_vec: Vec<G1>,
    powers_g1_vec: Vec<G1>,
    pi_prime: G1,
}

fn prepare_bilinear_mem_context(batch_size: usize) -> BilinearMemContext {
    assert!(batch_size > 0, "batch_size must be positive");

    let mut rng = test_rng();
    let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut rng, (batch_size * 4) + 64);

    let member = Fr::from(MEMBER);
    acc.add(&member);

    let base_roots = [2u64, 3, 5, 7, 11].map(Fr::from);
    for root in &base_roots {
        acc.add(root);
    }

    let mut current_roots = vec![member];
    current_roots.extend_from_slice(&base_roots);
    let s_poly = build_poly_from_roots(&current_roots);
    let (q, _) = syn_div_by_x_minus_c(&s_poly, &member);

    let (crs_prime, _r) = acc
        .blind_mem_proof(&mut rng, &q, batch_size)
        .expect("blind membership proof creation failed");
    let pi_blinded = crs_prime
        .first()
        .copied()
        .expect("blinded CRS must include base term");
    let acc_t = acc.value();

    let update_elements: Vec<Fr> = (10_000u64..).take(batch_size).map(Fr::from).collect();
    let q_star = build_poly_from_roots(&update_elements);
    let powers_acc_t_vec = acc.shift_com(&s_poly, q_star.coeffs().len());

    for root in &update_elements {
        acc.add(root);
    }
    let acc_t_prime = acc.value();

    let required_len = q_star.coeffs().len();
    let powers_for_pi = Powers::<Bls12_381> {
        powers_of_g: Cow::Borrowed(&crs_prime[..required_len]),
        powers_of_gamma_g: Cow::Owned(vec![]),
    };
    let pi_prime =
        BilinearNIZK::com::<Bls12_381>(&powers_for_pi, &q_star).expect("commitment failed");

    let alpha = BilinearNIZK::poe_eq_challenge::<Bls12_381>(
        &acc_t,
        &acc_t_prime,
        &pi_blinded,
        &pi_prime,
        &q_star,
    );
    let (h_poly, _) = syn_div_by_x_plus_alpha(&q_star, &alpha);

    let powers_g1_vec = setup_aux_powers(required_len);

    BilinearMemContext {
        acc_after_update: acc,
        pi_blinded,
        acc_t,
        acc_t_prime,
        crs_prime,
        q_star,
        powers_acc_t_vec,
        powers_g1_vec,
        pi_prime,
    }
}

struct BilinearNonMemContext {
    acc_after_update: BilinearAccumulator<Bls12_381>,
    acc_t: G1,
    acc_t_prime: G1,
    sn_plus_one: Fr,
    blinded_non_mem_proof: ((G1, G1), Fr),
    q_prime: G1,
    delta: DensePolynomial<Fr>,
    h_poly: DensePolynomial<Fr>,
    powers_g1_vec: Vec<G1>,
}

fn prepare_bilinear_non_mem_context() -> BilinearNonMemContext {
    let mut rng = test_rng();
    let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut rng, 64);

    for root in [2u64, 3, 5, 7, 11].map(Fr::from) {
        acc.add(&root);
    }

    let non_member = Fr::from(NON_MEMBER);
    let non_mem_proof = acc
        .non_mem_proof_create(non_member)
        .expect("non-membership proof creation failed");
    let (blinded_non_mem_proof, _r) = acc.blind_non_mem_proof(&non_mem_proof, non_member);

    let acc_t = acc.value();
    let sn_plus_one = Fr::from(UPDATE);
    acc.add(&sn_plus_one);
    let acc_t_prime = acc.value();

    let q_prime = (blinded_non_mem_proof.0 .1.into_group()
        - blinded_non_mem_proof.0 .0.into_group() * sn_plus_one)
        .into_affine();
    let delta = DensePolynomial::from_coefficients_vec(vec![-sn_plus_one, Fr::one()]);

    let alpha = BilinearNIZK::poe_eq_challenge::<Bls12_381>(
        &acc_t,
        &acc_t_prime,
        &blinded_non_mem_proof.0 .0,
        &q_prime,
        &delta,
    );
    let (h_poly, _) = syn_div_by_x_plus_alpha(&delta, &alpha);
    let powers_g1_vec = setup_aux_powers(delta.coeffs().len());

    BilinearNonMemContext {
        acc_after_update: acc,
        acc_t,
        acc_t_prime,
        sn_plus_one,
        blinded_non_mem_proof,
        q_prime,
        delta,
        h_poly,
        powers_g1_vec,
    }
}

struct RsaMemContext {
    acc_after_update: RsaAccumulator<RsaGroup>,
    acc_t: BigUint,
    acc_t_prime: BigUint,
    blinded_proof: BigUint,
    elements_in: Vec<BigUint>,
    delta: BigUint,
    a: BigUint,
    b: BigUint,
}

fn prepare_rsa_mem_context() -> RsaMemContext {
    let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

    let ep = acc.add(&MEMBER);
    for v in [2u64, 3, 5, 7, 11] {
        acc.add(&v);
    }

    let proof = acc.mem_proof_create(&ep).unwrap();
    let (blinded_proof, _st) = acc.blind_mem_proof(&proof);
    let acc_t = acc.acc.clone();

    let elements_in = [65537u64, 100003, 104729, 1299709, 15485863]
        .iter()
        .map(|v| acc.add(v))
        .collect::<Vec<_>>();

    let delta = elements_in
        .iter()
        .fold(BigUint::from(1u32), |prod, e| prod * e);

    let acc_t_prime = acc.acc.clone();
    let g = acc.group.g();
    let a = acc.group.exp(&blinded_proof, &delta);
    let b = acc.group.exp(&g, &delta);

    RsaMemContext {
        acc_after_update: acc,
        acc_t,
        acc_t_prime,
        blinded_proof,
        elements_in,
        delta,
        a,
        b,
    }
}

struct RsaNonMemContext {
    acc_after_update: RsaAccumulator<RsaGroup>,
    blinded_non_mem_proof: (BigUint, BigUint),
    delta: NumBigInt,
    gcd_exp_b: NumBigInt,
    hash_input: Vec<u8>,
}

fn prepare_rsa_non_mem_context() -> RsaNonMemContext {
    let mut acc = RsaAccumulator::<RsaGroup>::setup_trapdoorless();

    for v in [2u64, 3, 5, 7, 11] {
        acc.add(&v);
    }

    let non_member = BigUint::from(NON_MEMBER);
    let blinded_non_mem_proof = acc.blind_non_mem_proof(&non_member);

    for v in [13u64, 17, 19, 23, 29] {
        acc.add(&v);
    }

    let delta = NumBigInt::from(acc.calculate_product_unreduced());
    let blinded_int = NumBigInt::from(blinded_non_mem_proof.0.clone());
    let egcd = Integer::extended_gcd(&delta, &blinded_int);
    assert_eq!(egcd.gcd, NumBigInt::from(1u32));

    RsaNonMemContext {
        acc_after_update: acc,
        blinded_non_mem_proof,
        delta,
        gcd_exp_b: egcd.y,
        hash_input: non_member.to_bytes_be(),
    }
}

#[cfg(feature = "class-group")]
struct ClassMemContext {
    acc_after_update: RsaAccumulator<ClassGroup>,
    acc_t: ClassGroupElement,
    acc_t_prime: ClassGroupElement,
    blinded_proof: ClassGroupElement,
    elements_in: Vec<ClassGroupExponent>,
    delta: ClassGroupExponent,
    a: ClassGroupElement,
    b: ClassGroupElement,
}

#[cfg(feature = "class-group")]
fn prepare_class_mem_context() -> ClassMemContext {
    let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

    let ep = acc.add(&MEMBER);
    for v in [2u64, 3, 5, 7, 11] {
        acc.add(&v);
    }

    let proof = acc.mem_proof_create(&ep).unwrap();
    let (blinded_proof, _st) = acc.blind_mem_proof(&proof);
    let acc_t = acc.acc.clone();

    let elements_in = [65537u64, 100003, 104729, 1299709, 15485863]
        .iter()
        .map(|v| acc.add(v))
        .collect::<Vec<_>>();

    let delta = elements_in.iter().fold(ClassGroup::exp_id(), |prod, e| {
        ClassGroup::exp_mul(&prod, e)
    });

    let acc_t_prime = acc.acc.clone();
    let g = acc.group.g();
    let a = acc.group.exp(&blinded_proof, &delta);
    let b = acc.group.exp(&g, &delta);

    ClassMemContext {
        acc_after_update: acc,
        acc_t,
        acc_t_prime,
        blinded_proof,
        elements_in,
        delta,
        a,
        b,
    }
}

#[cfg(feature = "class-group")]
struct ClassNonMemContext {
    acc_after_update: RsaAccumulator<ClassGroup>,
    blinded_non_mem_proof: (ClassGroupExponent, ClassGroupExponent),
    delta: CurvBigInt,
    gcd_exp_b: CurvBigInt,
    hash_input: Vec<u8>,
}

#[cfg(feature = "class-group")]
fn prepare_class_non_mem_context() -> ClassNonMemContext {
    let mut acc = RsaAccumulator::<ClassGroup>::setup_trapdoorless();

    for v in [2u64, 3, 5, 7, 11] {
        acc.add(&v);
    }

    let non_member = acc.group.hash_to_prime(&NON_MEMBER.to_be_bytes());
    let blinded_non_mem_proof = acc.blind_non_mem_proof(&non_member);

    for v in [13u64, 17, 19, 23, 29] {
        acc.add(&v);
    }

    let delta = acc.calculate_product_unreduced();
    let egcd = Integer::extended_gcd(&delta, &blinded_non_mem_proof.0 .0);
    assert_eq!(egcd.gcd, CurvBigInt::from(1u32));

    ClassNonMemContext {
        acc_after_update: acc,
        blinded_non_mem_proof,
        delta,
        gcd_exp_b: egcd.y,
        hash_input: non_member.to_string().into_bytes(),
    }
}

#[cfg(feature = "class-group")]
fn class_signed_exp(
    group: &ClassGroup,
    base: &ClassGroupElement,
    exponent: &CurvBigInt,
) -> ClassGroupElement {
    if exponent < &CurvBigInt::from(0u32) {
        let positive = ClassGroupExponent((-exponent).clone());
        let pos = group.exp(base, &positive);
        group.inv(&pos)
    } else {
        group.exp(base, &ClassGroupExponent(exponent.clone()))
    }
}

fn benchmark_mem_update_breakdown(c: &mut Criterion) {
    let mut bilinear_group = c.benchmark_group("mem_update_breakdown_bilinear");
    bilinear_group.sample_size(10);

    for size in [64] {
        let ctx = prepare_bilinear_mem_context(size);

        let required_len = ctx.q_star.coeffs().len();

        let powers_for_pi = Powers::<Bls12_381> {
            powers_of_g: Cow::Borrowed(&ctx.crs_prime[..required_len]),
            powers_of_gamma_g: Cow::Owned(vec![]),
        };

        bilinear_group.bench_with_input(BenchmarkId::new("full_update", size), &size, |b, &_| {
            b.iter_batched(
                || {
                    (
                        ctx.acc_after_update.clone(),
                        ctx.crs_prime.clone(),
                        ctx.q_star.clone(),
                        ctx.powers_acc_t_vec.clone(),
                    )
                },
                |(acc, crs_prime, q_star, powers_acc_t)| {
                    let _ = black_box(acc.blind_mem_proof_upd(
                        &ctx.pi_blinded,
                        &ctx.acc_t,
                        crs_prime,
                        q_star,
                        powers_acc_t,
                    ));
                },
                BatchSize::SmallInput,
            );
        });

        bilinear_group.bench_with_input(BenchmarkId::new("nizk_proving", size), &size, |b, &_| {
            b.iter(|| {
                let powers_for_acc_t = Powers::<Bls12_381> {
                    powers_of_g: Cow::Borrowed(&ctx.powers_acc_t_vec[..required_len]),
                    powers_of_gamma_g: Cow::Owned(vec![]),
                };
                let powers_for_g1 = Powers::<Bls12_381> {
                    powers_of_g: Cow::Borrowed(&ctx.powers_g1_vec[..required_len]),
                    powers_of_gamma_g: Cow::Owned(vec![]),
                };

                let _ = black_box(
                    BilinearNIZK::prove_poe_eq::<Bls12_381>(
                        &powers_for_acc_t,
                        &powers_for_pi,
                        &powers_for_g1,
                        &ctx.acc_t,
                        &ctx.acc_t_prime,
                        &ctx.pi_blinded,
                        &ctx.pi_prime,
                        &ctx.q_star,
                    )
                    .expect("PoEEq proof creation failed"),
                );
            });
        });

        bilinear_group.bench_with_input(BenchmarkId::new("hashing_fs", size), &size, |b, &_| {
            b.iter(|| {
                black_box(BilinearNIZK::poe_eq_challenge::<Bls12_381>(
                    &ctx.acc_t,
                    &ctx.acc_t_prime,
                    &ctx.pi_blinded,
                    &ctx.pi_prime,
                    &ctx.q_star,
                ));
            });
        });

        bilinear_group.bench_with_input(
            BenchmarkId::new("exponentiations", size),
            &size,
            |b, &_| {
                b.iter(|| {
                    let pi_prime = BilinearNIZK::com::<Bls12_381>(&powers_for_pi, &ctx.q_star)
                        .expect("commitment failed");
                    let _ = black_box(pi_prime);
                });
            },
        );
    }

    bilinear_group.finish();

    let mut rsa_group = c.benchmark_group("mem_update_breakdown_rsa");
    rsa_group.sample_size(10);

    let ctx = prepare_rsa_mem_context();
    let nizk = NIZK::setup(&ctx.acc_after_update.group);
    let g = ctx.acc_after_update.group.g();

    rsa_group.bench_function("full_update", |b| {
        b.iter_batched(
            || (ctx.acc_after_update.clone(), ctx.delta.clone()),
            |(acc, delta)| {
                let delta_int = NumBigInt::from(delta);
                let _ =
                    black_box(acc.blind_mem_proof_upd(&ctx.acc_t, &ctx.blinded_proof, &delta_int));
            },
            BatchSize::SmallInput,
        );
    });

    rsa_group.bench_function("nizk_proving", |b| {
        b.iter(|| {
            let pi1 = nizk.prove_dleq(
                &ctx.blinded_proof,
                &ctx.a,
                &ctx.acc_t,
                &ctx.acc_t_prime,
                &ctx.delta,
            );
            let pi2 = nizk.prove_dleq(&g, &ctx.b, &ctx.blinded_proof, &ctx.a, &ctx.delta);
            let _ = black_box((pi1, pi2));
        });
    });

    rsa_group.bench_function("hashing_fs", |b| {
        b.iter(|| {
            let c1 = nizk.dleq_challenge(
                &ctx.blinded_proof,
                &ctx.a,
                &ctx.acc_t,
                &ctx.acc_t_prime,
                &ctx.a,
                &ctx.acc_t_prime,
            );
            let c2 = nizk.dleq_challenge(&g, &ctx.b, &ctx.blinded_proof, &ctx.a, &ctx.b, &ctx.a);
            let _ = black_box((c1, c2));
        });
    });

    rsa_group.bench_function("exponentiations", |b| {
        b.iter(|| {
            let a = ctx
                .acc_after_update
                .group
                .exp(&ctx.blinded_proof, &ctx.delta);
            let _ = black_box(a);
        });
    });

    rsa_group.finish();

    #[cfg(feature = "class-group")]
    {
        let mut class_group = c.benchmark_group("mem_update_breakdown_class_group");
        class_group.sample_size(10);

        let ctx = prepare_class_mem_context();
        let nizk = NIZK::setup(&ctx.acc_after_update.group);
        let g = ctx.acc_after_update.group.g();

        class_group.bench_function("full_update", |b| {
            b.iter_batched(
                || (ctx.acc_after_update.clone(), ctx.delta.0.clone()),
                |(acc, delta)| {
                    let _ =
                        black_box(acc.blind_mem_proof_upd(&ctx.acc_t, &ctx.blinded_proof, &delta));
                },
                BatchSize::SmallInput,
            );
        });

        class_group.bench_function("nizk_proving", |b| {
            b.iter(|| {
                let pi1 = nizk.prove_dleq(
                    &ctx.blinded_proof,
                    &ctx.a,
                    &ctx.acc_t,
                    &ctx.acc_t_prime,
                    &ctx.delta,
                );
                let pi2 = nizk.prove_dleq(&g, &ctx.b, &ctx.blinded_proof, &ctx.a, &ctx.delta);
                let _ = black_box((pi1, pi2));
            });
        });

        class_group.bench_function("hashing_fs", |b| {
            b.iter(|| {
                let c1 = nizk.dleq_challenge(
                    &ctx.blinded_proof,
                    &ctx.a,
                    &ctx.acc_t,
                    &ctx.acc_t_prime,
                    &ctx.a,
                    &ctx.acc_t_prime,
                );
                let c2 =
                    nizk.dleq_challenge(&g, &ctx.b, &ctx.blinded_proof, &ctx.a, &ctx.b, &ctx.a);
                let _ = black_box((c1, c2));
            });
        });

        class_group.bench_function("exponentiations", |b| {
            b.iter(|| {
                let a = ctx
                    .acc_after_update
                    .group
                    .exp(&ctx.blinded_proof, &ctx.delta);
                let _ = black_box(a);
            });
        });

        class_group.finish();
    }
}

fn benchmark_non_mem_update_breakdown(c: &mut Criterion) {
    let mut bilinear_group = c.benchmark_group("non_mem_update_breakdown_bilinear");
    bilinear_group.sample_size(10);

    let ctx = prepare_bilinear_non_mem_context();
    let required_len = ctx.delta.coeffs().len();

    let q_base_powers_vec = vec![
        ctx.blinded_non_mem_proof.0 .0,
        ctx.blinded_non_mem_proof.0 .1,
    ];
    let powers_for_q_base = Powers::<Bls12_381> {
        powers_of_g: Cow::Borrowed(q_base_powers_vec.as_slice()),
        powers_of_gamma_g: Cow::Owned(vec![]),
    };
    let powers_for_g1 = Powers::<Bls12_381> {
        powers_of_g: Cow::Borrowed(&ctx.powers_g1_vec[..required_len]),
        powers_of_gamma_g: Cow::Owned(vec![]),
    };

    let acc_t_tau =
        (ctx.acc_t_prime.into_group() + ctx.acc_t.into_group() * ctx.sn_plus_one).into_affine();
    let acc_t_powers_vec = vec![ctx.acc_t, acc_t_tau];
    let powers_for_acc_t = Powers::<Bls12_381> {
        powers_of_g: Cow::Borrowed(acc_t_powers_vec.as_slice()),
        powers_of_gamma_g: Cow::Owned(vec![]),
    };

    bilinear_group.bench_function("full_update", |b| {
        b.iter(|| {
            let _ = black_box(ctx.acc_after_update.blind_non_mem_proof_upd(
                &ctx.blinded_non_mem_proof,
                &ctx.acc_t,
                &ctx.sn_plus_one,
            ));
        });
    });

    bilinear_group.bench_function("nizk_proving", |b| {
        b.iter(|| {
            let _ = black_box(
                BilinearNIZK::prove_poe_eq::<Bls12_381>(
                    &powers_for_acc_t,
                    &powers_for_q_base,
                    &powers_for_g1,
                    &ctx.acc_t,
                    &ctx.acc_t_prime,
                    &ctx.blinded_non_mem_proof.0 .0,
                    &ctx.q_prime,
                    &ctx.delta,
                )
                .expect("PoEEq proof creation failed"),
            );
        });
    });

    bilinear_group.bench_function("exponentiations", |b| {
        b.iter(|| {
            let q_prime = (ctx.blinded_non_mem_proof.0 .1.into_group()
                - ctx.blinded_non_mem_proof.0 .0.into_group() * ctx.sn_plus_one)
                .into_affine();
            let _ = black_box(q_prime);
        });
    });

    bilinear_group.finish();

    let mut rsa_group = c.benchmark_group("non_mem_update_breakdown_rsa");
    rsa_group.sample_size(10);

    let ctx = prepare_rsa_non_mem_context();

    rsa_group.bench_function("full_update", |b| {
        b.iter(|| {
            let _ = black_box(
                ctx.acc_after_update
                    .blind_non_mem_proof_upd(&ctx.blinded_non_mem_proof.0, &ctx.delta),
            );
        });
    });

    rsa_group.bench_function("exponentiations", |b| {
        b.iter(|| {
            let _ = black_box(
                ctx.acc_after_update
                    .group
                    .signed_exp(&ctx.acc_after_update.group.g(), &ctx.gcd_exp_b),
            );
        });
    });

    rsa_group.finish();

    #[cfg(feature = "class-group")]
    {
        let mut class_group = c.benchmark_group("non_mem_update_breakdown_class_group");
        class_group.sample_size(10);

        let ctx = prepare_class_non_mem_context();

        class_group.bench_function("full_update", |b| {
            b.iter(|| {
                let _ = black_box(
                    ctx.acc_after_update
                        .blind_non_mem_proof_upd(&ctx.blinded_non_mem_proof.0, &ctx.delta),
                );
            });
        });

        class_group.bench_function("exponentiations", |b| {
            b.iter(|| {
                black_box(class_signed_exp(
                    &ctx.acc_after_update.group,
                    &ctx.acc_after_update.group.g(),
                    &ctx.gcd_exp_b,
                ));
            });
        });

        class_group.finish();
    }
}

criterion_group!(
    benches,
    benchmark_mem_update_breakdown,
    benchmark_non_mem_update_breakdown
);
criterion_main!(benches);
