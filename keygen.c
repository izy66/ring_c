#include "ring.h"

void pairing_init() {
  pp = malloc(sizeof(Pairing_param));
  element_init_Zr(tmp_r, pairing);
  element_init_Zr(tmp_r2, pairing);
  element_init_GT(tmp_t, pairing);
  element_init_GT(tmp_t2, pairing);
  element_init_G1(pp->g1, pairing);
  element_init_G2(pp->g2, pairing);
  element_init_GT(pp->g3, pairing);
  element_random(pp->g1);
  element_random(pp->g2);
  pairing_apply(pp->g3, pp->g1, pp->g2, pairing);
  for (int i = 0; i < RING_SIZE; ++i) {
    element_init_G1(ring[i].public_key, pairing);
    element_init_GT(ring[i].public_id, pairing);
    element_random(tmp_r);
    element_pow_zn(ring[i].public_key, pp->g1, tmp_r);
    element_pow_zn(ring[i].public_id, pp->g3, tmp_r);
  }
}

void Sign_Cipher_init(Sign_Cipher *cipher) {
  element_init_G1(cipher->c1, pairing);
  element_init_G1(cipher->c2, pairing);
}

void Sign_Cipher_clear(Sign_Cipher *cipher) {
  element_clear(cipher->c1);
  element_clear(cipher->c2);
}

void PID_Cipher_init(PID_Cipher *cipher) {
  element_init_GT(cipher->c1, pairing);
  element_init_G2(cipher->c2, pairing);
  element_init_GT(cipher->c3, pairing);
}

void PID_Cipher_clear(PID_Cipher *cipher) {
  element_clear(cipher->c1);
  element_clear(cipher->c2);
  element_clear(cipher->c3);
}

void ZKP_init(ZKP *p) {
  element_init_GT(p->t, pairing);
  element_init_Zr(p->z, pairing);
  element_init_Zr(p->z2, pairing);
}

void ZKP_clear(ZKP *p) {
  element_clear(p->t);
  element_clear(p->z);
  element_clear(p->z2);
}

void Key_Enc_init(Key_Enc_Prf *key_enc) {
  key_enc->cipher = malloc(sizeof(Sign_Cipher));
  Sign_Cipher_init(key_enc->cipher);
  key_enc->pf1 = malloc(sizeof(ZKP));
  key_enc->pf2 = malloc(sizeof(ZKP));
  ZKP_init(key_enc->pf1);
  ZKP_init(key_enc->pf2);
}

void Key_Enc_clear(Key_Enc_Prf *key_enc) {
  element_clear(key_enc->cipher->c1);
  element_clear(key_enc->cipher->c2);
  ZKP_clear(key_enc->pf1);
  ZKP_clear(key_enc->pf2);
  free(key_enc->cipher);
  free(key_enc->pf1);
  free(key_enc->pf2);
}

void SoK_init(SoK *sok) {
  for (int i = 0; i < RING_SIZE; ++i) {
    sok->schnorr[i] = malloc(sizeof(ZKP));
    sok->okamoto[i] = malloc(sizeof(ZKP));
    ZKP_init(sok->schnorr[i]);
    ZKP_init(sok->okamoto[i]);
    mpz_init(sok->challenge[i]);
  }
}

void SoK_clear(SoK *sok) {
  for (int i = 0; i < RING_SIZE; ++i) {
    ZKP_clear(sok->schnorr[i]);
    ZKP_clear(sok->okamoto[i]);
    free(sok->schnorr[i]);
    free(sok->okamoto[i]);
    mpz_clear(sok->challenge[i]);
  }
}

void PID_Enc_init(PID_Enc_SoK *pid_enc) {
  pid_enc->cipher = malloc(sizeof(PID_Cipher));
  PID_Cipher_init(pid_enc->cipher);
  pid_enc->sok = malloc(sizeof(SoK));
  SoK_init(pid_enc->sok);
}

void PID_Enc_clear(PID_Enc_SoK *pid_enc) {
  PID_Cipher_clear(pid_enc->cipher);
  SoK_clear(pid_enc->sok);
  free(pid_enc->cipher);
  free(pid_enc->sok);
}

void Signature_init(Signature *signature) {
  signature->sign_key = malloc(sizeof(PKE_key_pair));
  sign_key_init(signature->sign_key);
  for (int i = 0; i < RING_SIZE; ++i) {
    signature->key_enc[i] = malloc(sizeof(Key_Enc_Prf));
    Key_Enc_init(signature->key_enc[i]);
  }
  signature->pid_enc = malloc(sizeof(PID_Enc_SoK));
  PID_Enc_init(signature->pid_enc);
  element_init_GT(signature->signer_PID, pairing);
  element_init_GT(signature->trace, pairing);
  signature->trace_pf1 = malloc(sizeof(ZKP));
  ZKP_init(signature->trace_pf1);
}

void Signature_clear(Signature *signature) {
  PKE_key_clear(signature->sign_key);
  free(signature->sign_key);
  for (int i = 0; i < RING_SIZE; ++i) {
    Key_Enc_clear(signature->key_enc[i]);
    free(signature->key_enc[i]);
  }
  PID_Enc_clear(signature->pid_enc);
  free(signature->pid_enc);
  element_clear(signature->signer_PID);
  element_clear(signature->trace);
  ZKP_clear(signature->trace_pf1);
  free(signature->trace_pf1);
}

void element_hash_GT(element_t h, element_t e) {
  int n = pairing_length_in_bytes_GT(pairing);

  unsigned char* data = malloc(n);
  element_to_bytes(data, e);

  unsigned char* hash = malloc(HASH_SIZE);
  crypto_generichash(hash, sizeof hash, data, n, NULL, 0);
  element_from_hash(h, hash, HASH_SIZE);

  free(data);
  free(hash);
}

void element_hash_Str(element_t h, unsigned char *data) {
  unsigned char* hash = malloc(HASH_SIZE);
  crypto_generichash(hash, sizeof hash, data, sizeof data, NULL, 0);
  element_from_hash(h, hash, HASH_SIZE);

  free(hash);
}

void user_key_init(PKE_key_pair *key) {
  element_init_Zr(key->secret_key, pairing);
  element_init_G1(key->public_key, pairing);
}

void user_key_gen(PKE_key_pair *key) {
  element_random(key->secret_key);
  element_pow_zn(key->public_key, pp->g1, key->secret_key);
}

void tracer_key_init(PKE_key_pair *key) {
  element_init_Zr(key->secret_key, pairing);
  element_init_GT(key->public_key, pairing);
}

void tracer_key_gen(PKE_key_pair *key) {
  element_random(key->secret_key);
  element_pow_zn(key->public_key, pp->g3, key->secret_key);
}

void sign_key_init(PKE_key_pair *key) {
  element_init_G1(key->secret_key, pairing);
  element_init_GT(key->public_key, pairing);
}

void sign_key_gen(PKE_key_pair *key) {
  element_random(tmp_r);
  element_pow_zn(key->secret_key, pp->g1, tmp_r);
  element_pow_zn(key->public_key, pp->g3, tmp_r);
}

void PKE_key_clear(PKE_key_pair *key) {
  element_clear(key->public_key);
  element_clear(key->secret_key);
}

void Pairing_param_clear(Pairing_param *pp) {
  element_clear(pp->g1);
  element_clear(pp->g2);
  element_clear(pp->g3);
}
