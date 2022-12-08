#include "ring.h"

void signature_gen(Signature *signature, element_t tracer_public_key, element_t signer_public_id, element_t user_secret_key, int self_index, unsigned char *message) {
  
  sign_key_gen(signature->sign_key);

  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  
  // encrypt signing key to each ring member and generate a proof of correct encryption

  for (int i = 0; i < RING_SIZE; ++i) {
    // encrypt secret signing key under ring's public keys 
    // with ElGamal on G1
    // (c1, c2) <- (g1 ^ r, ring_pk ^ r * sign_sk)
    element_random(tmp_r);
    element_pow_zn(signature->key_enc[i]->cipher->c1, pp->g1, tmp_r);
    element_pow_zn(signature->key_enc[i]->cipher->c2, ring[i].public_key, tmp_r);
    element_mul(signature->key_enc[i]->cipher->c2, signature->key_enc[i]->cipher->c2, signature->sign_key->secret_key);
    // prove correct encryption
    schnorr_proof(signature->key_enc[i]->pf1, tmp_r, pp->g3);
    pairing_apply(tmp_t, signature->key_enc[i]->cipher->c1, pp->g2, pairing);
    element_pow_zn(tmp_t2, pp->g3, tmp_r);
    assert(schnorr_verify(signature->key_enc[i]->pf1, pp->g3, tmp_t));

    schnorr_proof(signature->key_enc[i]->pf2, tmp_r, ring[i].public_id);
    pairing_apply(tmp_t, signature->key_enc[i]->cipher->c2, pp->g2, pairing);
    element_div(tmp_t, tmp_t, signature->sign_key->public_key);
    assert(schnorr_verify(signature->key_enc[i]->pf2, ring[i].public_id, tmp_t));
  }

  // encrypt signer's id to tracer and generate a proof of correct encryption
  // without revealing whose identity is encrypted
  // Triple ElGamal: (c1, c2, c3) <- (g3 ^ r1, g2 ^ r2, tracer_pk ^ r2 * sign_pk ^ r3 * PID)
  
  element_random(tmp_r);
  element_random(tmp_r2);
  element_pow_zn(signature->pid_enc->cipher->c1, pp->g3, tmp_r);
  element_pow_zn(signature->pid_enc->cipher->c2, pp->g2, tmp_r2);
  element_pow_zn(tmp_t, tracer_public_key, tmp_r);
  element_pow_zn(tmp_t2, signature->sign_key->public_key, tmp_r2);
  element_mul(tmp_t, tmp_t, tmp_t2);
  element_mul(signature->pid_enc->cipher->c3, tmp_t, signer_public_id);

  // prove encryption of one's own PID without revealing one's identity
  // so that signature can be verified by any third parties not in the ring

  signature_of_knowledge_proof(signature->pid_enc->sok, self_index, user_secret_key, tmp_r, tmp_r2, tracer_public_key, signature->sign_key->public_key, signature->pid_enc->cipher, message);

  // erase secret sign key, although any ring member can decrypt it from the signature

  element_random(signature->sign_key->secret_key);

  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
}

// # verify the correctness of signature by checking:
// # 1. correct encryption of signature key to each ring members;
// # 2. correct encryption of public id under verification key and tracer's key

// # !!! any third parties (not nessesary a Ring member) should be able to verify the signature
// # without revealing which member generated such signature,
// # thus anonymity is ensured among the Ring.

int signature_verify(Signature *signature, element_t tracer_public_key, unsigned char* message) {

  element_t tmp_t;
  element_init_GT(tmp_t, pairing);

  for (int i = 0; i < RING_SIZE; ++i) {

    pairing_apply(tmp_t, signature->key_enc[i]->cipher->c1, pp->g2, pairing);

    if (!schnorr_verify(signature->key_enc[i]->pf1, pp->g3, tmp_t)) {
      puts("key encryption proof 1 failed.");
      return 0;
    }

    pairing_apply(tmp_t, signature->key_enc[i]->cipher->c2, pp->g2, pairing);
    element_div(tmp_t, tmp_t, signature->sign_key->public_key);

    if (!schnorr_verify(signature->key_enc[i]->pf2, ring[i].public_id, tmp_t)) {
			puts("key encryption proof 2 failed.");
      return 0;
    }
  }


  element_clear(tmp_t);

  return signature_of_knowledge_verify(signature->pid_enc->sok, signature->pid_enc->cipher, tracer_public_key, signature->sign_key->public_key, message);
}

// 1. prove the signer is a member of the Ring
// 2. prove the correct encryption of signer's public id
// OR-relation NIZK {(sk, r2, r3, index) : g3 ^ sk = PID[index] and PKtr ^ r2 * PKsign ^ r3 * PID[index] = c3}

void signature_of_knowledge_proof(SoK *sok, int signer_index, element_t user_secret_key, element_t r2, element_t r3, element_t tracer_public_key, element_t signature_public_key, PID_Cipher *pid_cipher, unsigned char *message) {

  mpz_t c_sum, c_tmp;
  mpz_init(c_sum);
  mpz_init(c_tmp);

  element_t challenge;
  element_init_Zr(challenge, pairing);
  element_hash_Str(challenge, message);

  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  
  for (int i = 0; i < RING_SIZE; ++i) {
    if (i != signer_index) {
      element_random(tmp_r);
      element_to_mpz(sok->challenge[i], tmp_r);
      schnorr_sim_proof(sok->schnorr[i], pp->g3, ring[i].public_id, sok->challenge[i]);
      assert(schnorr_sim_verify(sok->schnorr[i], pp->g3, ring[i].public_id, sok->challenge[i]));
      element_div(tmp_t, pid_cipher->c3, ring[i].public_id);
      okamoto_sim_proof(sok->okamoto[i], tracer_public_key, signature_public_key, tmp_t, sok->challenge[i]);
      assert(okamoto_sim_verify(sok->okamoto[i], tracer_public_key, signature_public_key, tmp_t, sok->challenge[i]));

      mpz_xor(c_sum, c_sum, sok->challenge[i]);
      element_hash_GT(tmp_r, sok->schnorr[i]->t);
      element_mul(challenge, challenge, tmp_r);
      element_hash_GT(tmp_r, sok->okamoto[i]->t);
      element_mul(challenge, challenge, tmp_r);
    }
  }

  // generates the honest proof

  element_t u0, u1;
  element_init_Zr(u0, pairing);
  element_init_Zr(u1, pairing);
  element_random(u0);
  element_random(u1);

  // commitments

  element_pow_zn(sok->schnorr[signer_index]->t, pp->g3, u0);
  element_pow_zn(tmp_t, tracer_public_key, u0);
  element_pow_zn(tmp_t2, signature_public_key, u1);
  element_mul(sok->okamoto[signer_index]->t, tmp_t, tmp_t2);

  // challenge
  // hash from commitment set then xor against fake challenges;
  // last challenge is erased, so signer's identity won't leak;
  // can forge all but one proof, which proves membership while 
  // hiding exact identity.

  element_hash_GT(tmp_r, sok->schnorr[signer_index]->t);
  element_mul(challenge, challenge, tmp_r);
  element_hash_GT(tmp_r, sok->okamoto[signer_index]->t);
  element_mul(challenge, challenge, tmp_r);
  element_to_mpz(c_tmp, challenge);
  mpz_xor(sok->challenge[signer_index], c_tmp, c_sum);

  // response

  element_set_mpz(tmp_r2, sok->challenge[signer_index]);  
  element_mul(tmp_r, user_secret_key, tmp_r2);
  element_add(sok->schnorr[signer_index]->z, tmp_r, u0);
  element_mul(tmp_r, tmp_r2, r2);
  element_add(sok->okamoto[signer_index]->z, tmp_r, u0);
  element_mul(tmp_r, tmp_r2, r3);
  element_add(sok->okamoto[signer_index]->z2, tmp_r, u1);

  mpz_xor(sok->challenge[RING_SIZE-1], sok->challenge[RING_SIZE-1], sok->challenge[RING_SIZE-1]);

  mpz_clear(c_sum);
  mpz_clear(c_tmp);
  element_clear(challenge);
  element_clear(u0);
  element_clear(u1);

  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
}

int signature_of_knowledge_verify(SoK *sok, PID_Cipher *pid_cipher, element_t tracer_public_key, element_t signature_public_key, unsigned char *message) {

  mpz_t c_sum, c_tmp;
  mpz_init(c_sum);
  mpz_init(c_tmp);

  element_t challenge;
  element_init_Zr(challenge, pairing);
  element_hash_Str(challenge, message);

  element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  
  for (int i = 0; i < RING_SIZE; ++i) {
    element_hash_GT(tmp_r, sok->schnorr[i]->t);
    element_mul(challenge, challenge, tmp_r);
    element_hash_GT(tmp_r, sok->okamoto[i]->t);
    element_mul(challenge, challenge, tmp_r);
  }

  element_to_mpz(c_sum, challenge);

  for (int i = 0; i < RING_SIZE-1; ++i) {
    mpz_xor(c_sum, c_sum, sok->challenge[i]);
  }

  mpz_set(sok->challenge[RING_SIZE-1], c_sum);

  int ret = 1;

  for (int i = 0; i < RING_SIZE && ret; ++i) {
    if (!schnorr_sim_verify(sok->schnorr[i], pp->g3, ring[i].public_id, sok->challenge[i])) {
      printf("schnorr sim verification failed at index %d.\n", i);
      ret = 0;
    }
    element_div(tmp_t, pid_cipher->c3, ring[i].public_id);
    if (!okamoto_sim_verify(sok->okamoto[i], tracer_public_key, signature_public_key, tmp_t, sok->challenge[i])) {
      printf("okamoto sim verification failed at index %d.\n", i);
      ret = 0;
    }
  }

  mpz_clear(c_sum);
  mpz_clear(c_tmp);
  element_clear(tmp_r);
  element_clear(tmp_r2);
  element_clear(tmp_t);
  element_clear(tmp_t2);
  element_clear(challenge);

  return ret;
}
