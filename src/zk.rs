use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::{CRHSchemeGadget, pedersen};
use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective as JubJub};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, uint8::UInt8};
use ark_relations::r1cs::ConstraintSynthesizer;
pub type ConstraintF = ark_bls12_381::Fr;

pub struct PedersenCircuit<'a> {
    message: Vec<Fr>,
    crh_params: &'a pedersen::Parameters<JubJub>,
    hash_result: &'a EdwardsAffine,
}

impl<'a> PedersenCircuit<'a> {
    pub fn new(
        message: Vec<Fr>,
        crh_params: &'a pedersen::Parameters<JubJub>,
        hash_result: &'a EdwardsAffine,
    ) -> Self {
        Self {
            message,
            crh_params,
            hash_result,
        }
    }
}

impl<'a> ConstraintSynthesizer<Fr> for PedersenCircuit<'a> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        type CRHGadget = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window>;

        let input_message: Vec<u8> = self
            .message
            .iter()
            .flat_map(|x| x.into_bigint().to_bytes_le())
            .collect();

        let parameters_var = pedersen::constraints::CRHParametersVar::new_constant(
            ark_relations::ns!(cs, "CRH Parameters"),
            self.crh_params,
        )
        .unwrap();

        let mut input_bytes = vec![];
        for byte in input_message.iter() {
            input_bytes.push(UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap());
        }

        let result = CRHGadget::evaluate(&parameters_var, &input_bytes).unwrap();

        let expected_hash = EdwardsVar::new_input(ark_relations::ns!(cs, "expected_hash"), || {
            Ok(*self.hash_result)
        })?;

        // Enforce equality directly
        result.enforce_equal(&expected_hash)?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct Window;

impl pedersen::Window for Window {
    const WINDOW_SIZE: usize = 127;
    const NUM_WINDOWS: usize = 9;
}
