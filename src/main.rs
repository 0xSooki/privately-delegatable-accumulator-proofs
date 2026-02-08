use num_bigint::BigUint;
use privacy_preserving_accumulators::RsaAccumulator;
use rand::thread_rng;

fn main() {
        let mut acc = RsaAccumulator::setup();
        let element = BigUint::from(7 as usize);
        let ep = acc.add(&element);
    
        for i in 2..5 {
            acc.add(&BigUint::from(i as u32));
        }

        for i in &acc.set {
            print!("{:?}, ", i)
        }
        println!("");
        let proof = acc.mem_proof_create(&ep);

        println!("{:?}",acc.mem_ver(&proof, &ep));

        let nonelement = BigUint::from(383 as usize);
        let nonproof = acc.non_mem_proof_create(&nonelement);

        println!("nonmemver: {:?}",acc.non_mem_ver(&nonproof, &nonelement));
}