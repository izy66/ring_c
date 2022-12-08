#include "ring.h"

// prove a ^ r = b
// (a, r) <- (GT, Zr)

void schnorr_proof(ZKP *proof, element_t r, element_t a) {
  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  // commitment
  element_random(tmp_r);
  element_pow_zn(proof->t, a, tmp_r); 
  // challenge
  element_hash_GT(tmp_r2, proof->t); 
  // response
  element_mul_zn(tmp_r2, r, tmp_r2); 
  element_add(proof->z, tmp_r, tmp_r2);
  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
}

// verify knowledge of x s.t. a ^ {x} = b

int schnorr_verify(ZKP *proof, element_t a, element_t b) {
  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  // a ** z
  element_pow_zn(tmp_t, a, proof->z);
  // b ** c * t
  element_hash_GT(tmp_r, proof->t);
  element_pow_zn(tmp_t2, b, tmp_r);
  element_mul(tmp_t2, tmp_t2, proof->t);
  int ret = !element_cmp(tmp_t, tmp_t2);
  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
  return ret;
}

// generate fake proofs with prover-chosen challenge
//  used in OR-relation proofs, where the prover combine simulated and 
//  faithful proofs to hide his identity.

void schnorr_sim_proof(ZKP* proof, element_t g, element_t u, mpz_t c) {
  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  element_set_mpz(tmp_r, c);
  element_random(proof->z);
  element_pow_zn(tmp_t, g, proof->z);
  element_pow_zn(tmp_t2, u, tmp_r);
  element_div(proof->t, tmp_t, tmp_t2);
  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
}

int schnorr_sim_verify(ZKP *proof, element_t g, element_t u, mpz_t c) {
  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  element_set_mpz(tmp_r, c);
  element_pow_zn(tmp_t, g, proof->z);
  element_pow_zn(tmp_t2, u, tmp_r);
  element_mul(tmp_t2, tmp_t2, proof->t);
  int ret = !element_cmp(tmp_t, tmp_t2);
  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
  return ret;
}

void okamoto_sim_proof(ZKP *proof, element_t g, element_t h, element_t u, mpz_t c) {
  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  element_set_mpz(tmp_r, c);
  element_random(proof->z);
  element_random(proof->z2);
  element_pow_zn(tmp_t, g, proof->z);
  element_pow_zn(tmp_t2, h, proof->z2);
  element_mul(tmp_t, tmp_t, tmp_t2);
  element_pow_zn(tmp_t2, u, tmp_r);
  element_div(proof->t, tmp_t, tmp_t2);
  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
}

int okamoto_sim_verify(ZKP *proof, element_t g, element_t h, element_t u, mpz_t c) {
  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  element_set_mpz(tmp_r, c);
  element_pow_zn(tmp_t, g, proof->z);
  element_pow_zn(tmp_t2, h, proof->z2);
  element_mul(tmp_t, tmp_t, tmp_t2);
  element_pow_zn(tmp_t2, u, tmp_r);
  element_mul(tmp_t2, tmp_t2, proof->t);
  int ret = !element_cmp(tmp_t, tmp_t2);
  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
  return ret;
}
