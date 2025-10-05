use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::bowe_hopwood::constraints::CRHGadget;
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget, pedersen};
use ark_ec::AffineRepr;
use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::prelude::ToBytesGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
pub type ConstraintF = ark_bls12_381::Fr;

use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, EdwardsProjective as Ed};
use ark_std::rand::{RngCore, SeedableRng};

#[derive(Clone)]
pub struct PedersonParams<A: AffineRepr> {
    pub generators: Vec<A>,
}

pub struct PedersenCircuit<C: AffineRepr> {
    generators: PedersonParams<C>,
    message: Vec<C::ScalarField>,
    randomness: Vec<C::ScalarField>,
}

impl<C: AffineRepr> PedersenCircuit<C> {
    pub fn new(
        generators: PedersonParams<C>,
        message: Vec<C::ScalarField>,
        randomness: Vec<C::ScalarField>,
    ) -> Self {
        Self {
            generators,
            message,
            randomness,
        }
    }
}

impl ConstraintSynthesizer<Fr> for PedersenCircuit<ark_bls12_381::G1Affine> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        type CRH = pedersen::CRH<JubJub, Window>;

        type CRHGadget = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window>;

        let mut rng = ark_std::rand::rngs::StdRng::from_seed([1; 32]);
        let parameters = CRH::setup(&mut rng).unwrap();

        let input_message: Vec<u8> = self
            .message
            .iter()
            .flat_map(|x| x.into_bigint().to_bytes_le())
            .collect();

        let parameters_var = pedersen::constraints::CRHParametersVar::new_constant(
            ark_relations::ns!(cs, "CRH Parameters"),
            &parameters,
        )
        .unwrap();

        let mut input_bytes = vec![];
        for byte in input_message.iter() {
            input_bytes.push(UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap());
        }

        CRHGadget::evaluate(&parameters_var, &input_bytes).unwrap();
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct Window;

impl pedersen::Window for Window {
    const WINDOW_SIZE: usize = 127;
    const NUM_WINDOWS: usize = 9;
}
