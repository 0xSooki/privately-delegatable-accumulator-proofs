use num_bigint::BigUint;
use privacy_preserving_accumulators::RsaAccumulator;

fn main() {
    let mut acc = RsaAccumulator::setup();
    println!("Initial accumulator: {:?}", acc.acc);
    
    acc.add(BigUint::from_bytes_be(b"sdf"));
    println!("After adding element: {:?}", acc.acc);
    
    acc.del(BigUint::from_bytes_be(b"sdf"));
    println!("After deleting element: {:?}", acc.acc);
}