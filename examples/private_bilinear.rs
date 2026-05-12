use ark_bls12_381::{Bls12_381, Fr};
use ark_std::test_rng;
use private_accumulator_proof_delegation::bilinear_accumulator::{
    BilinearAccumulator, BlindedMembershipBundle,
};
use private_accumulator_proof_delegation::traits::{Accumulator, PrivatelyDelegatableAccumulator};

fn main() {
    let mut acc = BilinearAccumulator::<Bls12_381>::setup(&mut test_rng(), 64);

    let initial: Vec<Fr> = (1u64..=4).map(Fr::from).collect();
    for e in &initial {
        acc.add(e);
    }

    let target = initial[2];
    let proof = acc.mem_proof_create(&target).expect("target is a member");
    println!("membership verifies:     {}", acc.mem_ver(&proof, &target));

    let non_member = Fr::from(999u64);
    let non_proof = acc
        .non_mem_proof_create(&non_member)
        .expect("non-member is not in the set");
    println!(
        "non-membership verifies: {}",
        acc.non_mem_ver(&non_proof, &non_member)
    );

    let acc_t = *acc.value();
    let (blinded, st) = acc.blind_mem_proof(&proof);

    let added: Vec<Fr> = (5u64..=7).map(Fr::from).collect();
    for e in &added {
        acc.add(e);
    }

    let (upd, aux, _new_acc) = acc
        .blind_mem_proof_upd(&acc_t, &blinded, &added)
        .expect("update succeeds");
    assert!(acc.ver_blind_mem_proof_upd(&acc_t, &blinded, &upd, &aux));

    let unblinded = acc.unblind_mem_proof(
        &BlindedMembershipBundle {
            pi_blinded: upd.pi_prime,
            crs_prime: blinded.crs_prime.clone(),
            poly_s: blinded.poly_s.clone(),
        },
        &st,
    );
    println!(
        "updated-proof verifies:  {}",
        acc.mem_ver(&unblinded, &target)
    );
}
