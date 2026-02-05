use num_bigint::BigUint;
use privacy_preserving_accumulators::RsaAccumulator;
use rand::thread_rng;

fn main() {
    let mut acc = RsaAccumulator::setup();
    println!("Initial accumulator: {:?}", acc.acc);
    
    acc.add(BigUint::from_bytes_be(b"sdf"));
    println!("After adding element: {:?}", acc.acc);
    
    acc.del(BigUint::from_bytes_be(b"sdf"));
    println!("After deleting element: {:?}", acc.acc);

    let val1 = BigUint::from(100u32);
    let val2 = BigUint::from(200u32);

    acc.add(val1);
    acc.add(val2);

    let target_elemet = acc.set.iter().next().unwrap().clone();
    println!("Proof for this number (hashed prime): {}", target_elemet);

    let proof = RsaAccumulator::mem_proof_create(&acc, &target_elemet);

    let is_valid = RsaAccumulator::mem_ver(&acc, &proof, &target_elemet);

    if(is_valid) {
        println!("Success! The proof is valid:)");
    } else {
        println!("Error.. The proof is not valid:(");
    }

}