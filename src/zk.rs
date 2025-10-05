use ark_bls12_381::Fr;
use ark_ec::AffineRepr;
use ark_relations::r1cs::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

pub type ConstraintF = ark_bls12_381::Fr;

#[derive(Clone)]
pub struct PedersonParams<A: AffineRepr> {
    pub generators: Vec<A>,
}

pub struct PedersenCircuit<C: AffineRepr> {
    generators: PedersonParams<C>,
    message: Vec<C::ScalarField>,
    randomness: Vec<C::ScalarField>,
}

impl<C: AffineRepr> PedersonParams<C> {
    pub fn new(generators: Vec<C>) -> Self {
        Self { generators }
    }

    pub fn commit(
        &self,
        cs: ConstraintSystemRef<C::ScalarField>,
        message: &[C::ScalarField],
        randomness: &[C::ScalarField],
    ) -> Result<(), SynthesisError> {
        let one = cs.new_witness_variable(|| Ok(C::ScalarField::ONE))?;
        let mut commitment = cs.new_witness_variable(|| Ok(C::ScalarField::ONE))?;
        for (i, m) in message.iter().enumerate() {
            let w1 = cs.new_witness_variable(|| Ok(*m))?;
            // Represent the generator's action through a witness
            let generator_effect = cs.new_witness_variable(|| Ok(C::ScalarField::ONE))?;
            let w3 = cs.new_witness_variable(|| Ok(randomness[i]))?;

            // This is a simplified approach - in a real implementation,
            // you would need to properly represent the scalar multiplication of the curve point
            let temp_witness = cs.new_witness_variable(|| Ok(C::ScalarField::ONE))?;
            cs.enforce_constraint(lc!() + w1, lc!() + generator_effect, lc!() + temp_witness)?;

            let temp_sum_witness = cs.new_witness_variable(|| Ok(C::ScalarField::ONE))?;
            cs.enforce_constraint(
                lc!() + temp_witness + w3,
                lc!() + one,
                lc!() + temp_sum_witness,
            )?;

            if i > 0 {
                let final_commitment = cs.new_witness_variable(|| Ok(C::ScalarField::ONE))?;
                cs.enforce_constraint(
                    lc!() + commitment + temp_sum_witness,
                    lc!() + one,
                    lc!() + final_commitment,
                )?;
                commitment = final_commitment;
            } else {
                commitment = temp_sum_witness;
            }
        }

        Ok(())
    }
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

impl<C: AffineRepr> ConstraintSynthesizer<C::ScalarField> for PedersenCircuit<C> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::ScalarField>,
    ) -> ark_relations::r1cs::Result<()> {
        // Allocate the commitment as a public input - represents the commitment somehow using scalar AffineReprs
        let commitment_var = cs.new_input_variable(|| Ok(C::ScalarField::ONE))?;

        // Compute the commitment in the circuit
        let calculated_commitment =
            self.generators
                .commit(cs.clone(), &self.message, &self.randomness)?;

        Ok(())
    }
}
