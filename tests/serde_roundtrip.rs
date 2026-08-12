//! Integration tests verifying JSON round-trips for RSA proof types
//! and binary round-trips for bilinear proof types.
//!
//! Run with:
//! ```bash
//! cargo test --features serde --test serde_roundtrip
//! ```

#[cfg(feature = "serde")]
mod rsa_serde {
    use num_bigint::{BigInt, BigUint, ToBigInt};
    use private_accumulator_proof_delegation::{
        rsa_group::RsaGroup, RsaAccumulator, RsaBlindedMembershipProof,
        RsaBlindedNonMembershipProof, RsaDleqProof, RsaMembershipProof, RsaNizkAux,
        RsaNonMembershipProof, RsaUpdatedBlindedMembershipProof,
        RsaUpdatedBlindedNonMembershipProof,
    };

    fn small_acc() -> RsaAccumulator<RsaGroup> {
        RsaAccumulator::<RsaGroup>::setup_from_params(
            BigUint::from(61u32),
            BigUint::from(53u32),
            BigUint::from(2u32),
            Some(BigUint::from(3120u32)),
        )
    }

    #[test]
    fn mem_proof_json_roundtrip() {
        let mut acc = small_acc();
        let ep = acc.add_raw(&BigUint::from(7u32));
        let proof_raw = acc.mem_proof_create_raw(&ep).unwrap();
        let proof = RsaMembershipProof::from_raw(proof_raw.clone());

        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: RsaMembershipProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof2.0, proof_raw, "round-trip value mismatch");
    }

    #[test]
    fn non_mem_proof_json_roundtrip() {
        let mut acc = small_acc();
        acc.add_raw(&BigUint::from(2u32));
        acc.add_raw(&BigUint::from(3u32));

        let non_member = BigUint::from(5u32);
        let product = acc.calculate_product_unreduced().to_bigint().unwrap();
        let (a, b) = acc.non_mem_proof_create_raw(&non_member, &product).unwrap();
        let proof = RsaNonMembershipProof::from_raw(a.clone(), b.clone());

        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: RsaNonMembershipProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof2.a, a);
        assert_eq!(proof2.b, b);
    }

    #[test]
    fn non_mem_proof_negative_a_roundtrip() {
        // Craft a proof with a negative `a` directly to exercise the '-' prefix path
        let proof = RsaNonMembershipProof {
            a: BigInt::from(-42i64),
            b: BigUint::from(123u32),
        };
        let json = serde_json::to_string(&proof).expect("serialize");
        assert!(
            json.contains('-'),
            "expected '-' in JSON for negative BigInt"
        );
        let proof2: RsaNonMembershipProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof2.a, BigInt::from(-42i64));
        assert_eq!(proof2.b, BigUint::from(123u32));
    }

    #[test]
    fn blinded_mem_proof_json_roundtrip() {
        let mut acc = small_acc();
        let ep = acc.add_raw(&BigUint::from(7u32));
        let proof_raw = acc.mem_proof_create_raw(&ep).unwrap();
        let (blinded_raw, _st) = acc.blind_mem_proof_raw(&proof_raw);
        let blinded = RsaBlindedMembershipProof::from_raw(blinded_raw.clone());

        let json = serde_json::to_string(&blinded).expect("serialize");
        let blinded2: RsaBlindedMembershipProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(blinded2.0, blinded_raw);
    }

    #[test]
    fn blinded_non_mem_proof_json_roundtrip() {
        let acc = small_acc();
        let (value, q) = acc.blind_non_mem_proof_raw(&BigUint::from(17u32));
        let proof = RsaBlindedNonMembershipProof::from_raw(value.clone(), q.clone());

        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: RsaBlindedNonMembershipProof =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof2.value, value);
        assert_eq!(proof2.q, q);
    }

    #[test]
    fn updated_blinded_mem_proof_json_roundtrip() {
        let mut acc = small_acc();
        let ep = acc.add_raw(&BigUint::from(7u32));
        let acc_t = acc.acc.clone();
        let proof_raw = acc.mem_proof_create_raw(&ep).unwrap();
        let (blinded_raw, _st) = acc.blind_mem_proof_raw(&proof_raw);
        let new_ep = acc.add_raw(&BigUint::from(11u32));
        let delta = new_ep.clone();
        let delta_int = delta.to_bigint().unwrap();
        let upd = acc
            .blind_mem_proof_upd_raw(&acc_t, &blinded_raw, &delta_int)
            .unwrap();
        let (a, b) = upd.0;
        let named = RsaUpdatedBlindedMembershipProof::from_raw(a.clone(), b.clone());

        let json = serde_json::to_string(&named).expect("serialize");
        let named2: RsaUpdatedBlindedMembershipProof =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(named2.a, a);
        assert_eq!(named2.b, b);
    }

    #[test]
    fn updated_blinded_non_mem_proof_json_roundtrip() {
        let mut acc = small_acc();
        let non_member = BigUint::from(17u32);
        let (blinded, _q) = acc.blind_non_mem_proof_raw(&non_member);
        acc.add_raw(&BigUint::from(5u32));
        let product = acc.calculate_product_unreduced().to_bigint().unwrap();
        let (a, b) = acc.blind_non_mem_proof_upd_raw(&blinded, &product).unwrap();
        let named = RsaUpdatedBlindedNonMembershipProof::from_raw(a.clone(), b.clone());

        let json = serde_json::to_string(&named).expect("serialize");
        let named2: RsaUpdatedBlindedNonMembershipProof =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(named2.a, a);
        assert_eq!(named2.b, b);
    }

    #[test]
    fn dleq_proof_json_roundtrip() {
        let proof = RsaDleqProof {
            q1: BigUint::from(1234u32),
            q2: BigUint::from(5678u32),
            q3: BigUint::from(9999u32),
            a: BigUint::from(1111u32),
            r: BigUint::from(2222u32),
        };
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: RsaDleqProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof2.q1, proof.q1);
        assert_eq!(proof2.q2, proof.q2);
        assert_eq!(proof2.q3, proof.q3);
        assert_eq!(proof2.a, proof.a);
        assert_eq!(proof2.r, proof.r);
    }

    #[test]
    fn nizk_aux_json_roundtrip() {
        let aux = RsaNizkAux {
            pi1: RsaDleqProof {
                q1: BigUint::from(1u32),
                q2: BigUint::from(2u32),
                q3: BigUint::from(3u32),
                a: BigUint::from(4u32),
                r: BigUint::from(5u32),
            },
            pi2: RsaDleqProof {
                q1: BigUint::from(6u32),
                q2: BigUint::from(7u32),
                q3: BigUint::from(8u32),
                a: BigUint::from(9u32),
                r: BigUint::from(10u32),
            },
        };
        let json = serde_json::to_string(&aux).expect("serialize");
        let aux2: RsaNizkAux = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(aux2.pi1.q1, aux.pi1.q1);
        assert_eq!(aux2.pi2.r, aux.pi2.r);
    }

    #[test]
    fn accumulator_error_json_roundtrip() {
        use private_accumulator_proof_delegation::AccumulatorError;
        for err in [
            AccumulatorError::ElementNotInSet,
            AccumulatorError::NotCoprime,
            AccumulatorError::NegativeDelta,
        ] {
            let json = serde_json::to_string(&err).expect("serialize");
            let err2: AccumulatorError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(err2, err);
        }
    }
}

#[cfg(feature = "bilinear")]
mod bilinear_serde {
    use ark_bls12_381::Bls12_381;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::test_rng;
    use private_accumulator_proof_delegation::{
        BilinearAccumulator, BilinearMembershipProof, BilinearNonMembershipProof,
    };

    fn small_acc() -> BilinearAccumulator<Bls12_381> {
        BilinearAccumulator::<Bls12_381>::setup(&mut test_rng(), 16)
    }

    #[test]
    fn membership_proof_binary_roundtrip() {
        let mut acc = small_acc();
        let element = ark_bls12_381::Fr::from(42u64);
        acc.add_raw(&element);
        let proof: BilinearMembershipProof<Bls12_381> =
            acc.mem_proof_create_raw(element).expect("element in set");

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).expect("serialize");

        let proof2: BilinearMembershipProof<Bls12_381> =
            BilinearMembershipProof::deserialize_compressed(&bytes[..]).expect("deserialize");
        assert_eq!(proof, proof2);
    }

    #[test]
    fn non_membership_proof_binary_roundtrip() {
        let mut acc = small_acc();
        for e in [1u64, 2, 3, 4].map(ark_bls12_381::Fr::from) {
            acc.add_raw(&e);
        }
        let non_member = ark_bls12_381::Fr::from(999u64);
        let proof: BilinearNonMembershipProof<Bls12_381> = acc
            .non_mem_proof_create_raw(non_member)
            .expect("not in set");

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).expect("serialize");

        let proof2: BilinearNonMembershipProof<Bls12_381> =
            BilinearNonMembershipProof::deserialize_compressed(&bytes[..]).expect("deserialize");
        assert_eq!(proof, proof2);
    }
}
