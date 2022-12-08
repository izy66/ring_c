#include "ring.h"

// a reporter (ring member) decrypt the secret signing key
// anyone can verify correct decryption by pairing on the key pair

void report_signature(Signature *signature, int reporter_index, element_t reporter_sk) {

  element_t tmp_g1;
  element_init_G1(tmp_g1, pairing);

  element_pow_zn(tmp_g1, signature->key_enc[reporter_index]->cipher->c1, reporter_sk);
  element_div(signature->sign_key->secret_key, signature->key_enc[reporter_index]->cipher->c2, tmp_g1);

  element_clear(tmp_g1);
}

// after decrypting the secret signing key, the tracer decrypt the signer's ID 
// with his secret key and signing key, and generate a proof of correct decryption

void trace_signature(Signature *signature, element_t tracer_sk) {

  // verify that signing key is a valid key pair
  // which only happens when one of the ring members have decrypted the secret key

  element_t tmp_t;
  element_init_GT(tmp_t, pairing);
  pairing_apply(tmp_t, signature->sign_key->secret_key, pp->g2, pairing);

  if (element_cmp(tmp_t, signature->sign_key->public_key)) {
    puts("signing key pair doesn't match!");
    exit(0);
  }

  // decrypte signer's ID using secret signing key and tracer's secret key

  pairing_apply(tmp_t, signature->sign_key->secret_key, signature->pid_enc->cipher->c2, pairing);
  element_div(signature->trace, signature->pid_enc->cipher->c3, tmp_t);
  element_pow_zn(tmp_t, signature->pid_enc->cipher->c1, tracer_sk);
  element_div(signature->signer_PID, signature->trace, tmp_t);

  // prove correct decryption

  schnorr_proof(signature->trace_pf1, tracer_sk, signature->pid_enc->cipher->c1);

  element_clear(tmp_t);
}

int trace_verify(Signature *signature) {

  // if signing key pair is valid, then the tracing must involve one ring member
  // who decrypted and reported the secret signing key

  element_t tmp_t;
  element_init_GT(tmp_t, pairing);

  pairing_apply(tmp_t, signature->sign_key->secret_key, pp->g2, pairing);

  if (element_cmp(tmp_t, signature->sign_key->public_key)) {
    puts("signing key pair doesn't match!");
    return 0;
  }

  // check correct decryption with secret signing key

  pairing_apply(tmp_t, signature->sign_key->secret_key, signature->pid_enc->cipher->c2, pairing);
  element_div(tmp_t, signature->pid_enc->cipher->c3, tmp_t);

  if (element_cmp(signature->trace, tmp_t)) {
    puts("incorrect tracing detected!");
    return 0;
  }

  // if PID is correctly decrypted from the cipher text, one can conclude a successful report & tracing.

  element_div(tmp_t, signature->trace, signature->signer_PID);

  if (!schnorr_verify(signature->trace_pf1, signature->pid_enc->cipher->c1, tmp_t)) {
    puts("decryption proof failed!");
    return 0;
  }
  
  element_clear(tmp_t);
  
  return 1;
}
