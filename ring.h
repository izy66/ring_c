#ifndef ring_H
#define ring_H

#include <pbc/pbc.h>
#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define RING_SIZE 2
#define HASH_SIZE 224

typedef struct {
  element_t public_key, public_id;
} Ring;

typedef struct {
  element_t secret_key, public_key;
} PKE_key_pair;

typedef struct {
  element_t g1, g2, g3;
} Pairing_param;

extern pairing_t pairing;
extern Ring ring[RING_SIZE];
extern Pairing_param *pp;

void pairing_var_init();
void pairing_var_clear();

typedef struct {
  element_t c1, c2;
} Sign_Cipher;

void Sign_Cipher_init(Sign_Cipher *cipher);
void Sign_Cipher_clear(Sign_Cipher *cipher);

typedef struct {
  element_t c1, c2, c3;
} PID_Cipher;

void PID_Cipher_init(PID_Cipher *cipher);
void PID_Cipher_clear(PID_Cipher *cipher);

typedef struct {
  element_t t, z, z2;
} ZKP;

void ZKP_init(ZKP *p);
void ZKP_clear(ZKP *p);

typedef struct {
  Sign_Cipher *cipher;
  ZKP *pf1, *pf2;
} Key_Enc_Prf;

void Key_Enc_init(Key_Enc_Prf *key_enc);
void Key_Enc_clear(Key_Enc_Prf *key_enc);

typedef struct {
  ZKP *schnorr[RING_SIZE], *okamoto[RING_SIZE];
  mpz_t challenge[RING_SIZE];
} SoK;

void SoK_init(SoK *sok);
void SoK_clear(SoK *sok);

typedef struct {
  PID_Cipher *cipher;
  SoK *sok;
} PID_Enc_SoK;

void PID_Enc_init(PID_Enc_SoK *pid_enc);
void PID_Enc_clear(PID_Enc_SoK *pid_enc);

typedef struct {
  PKE_key_pair *sign_key;
  Key_Enc_Prf *key_enc[RING_SIZE];
  PID_Enc_SoK *pid_enc;
  element_t signer_PID, trace;
  ZKP *trace_pf1;
} Signature;

void Signature_init(Signature *signature);
void Signature_clear(Signature *signature);

// hashing from GT to Zr

void element_hash_GT(element_t h, element_t e);

// hashing from char* to Zr

void element_hash_Str(element_t h, unsigned char *data);

// user key pair: Sk \in Zr, Pk \in G1

void user_key_init(PKE_key_pair *key);
void user_key_gen(PKE_key_pair *key);

// tracer key pair: Sk \in Zr, Pk \in Gt

void tracer_key_init(PKE_key_pair *key);
void tracer_key_gen(PKE_key_pair *key);

// signing key pair: Sk \in G1, Pk \in Gt

void sign_key_init(PKE_key_pair *key);
void sign_key_gen(PKE_key_pair *key);

void PKE_key_clear(PKE_key_pair *key);

void schnorr_proof(ZKP *proof, element_t r, element_t a);

int schnorr_verify(ZKP *proof, element_t a, element_t b);

void schnorr_sim_proof(ZKP* proof, element_t g, element_t u, mpz_t c);

int schnorr_sim_verify(ZKP *proof, element_t g, element_t u, mpz_t c);

void okamoto_sim_proof(ZKP *proof, element_t g, element_t h, element_t u, mpz_t c);

int okamoto_sim_verify(ZKP *proof, element_t g, element_t h, element_t u, mpz_t c);

void signature_gen(Signature *signature, element_t tracer_public_key, element_t public_id, element_t user_secret_key, int self_index, unsigned char *message);

int signature_verify(Signature *signature, element_t tracer_public_key, unsigned char* message);

void signature_of_knowledge_proof(SoK *sok, int signer_index, element_t user_secret_key, element_t r2, element_t r3, element_t tracer_public_key, element_t signature_public_key, PID_Cipher *pid_cipher, unsigned char *message);

int signature_of_knowledge_verify(SoK *sok, PID_Cipher *pid_cipher, element_t tracer_public_key, element_t signature_public_key, unsigned char *message);

void report_signature(Signature *signature, int reporter_index, element_t reporter_sk);

void trace_signature(Signature *signature, element_t tracer_sk);

int trace_verify(Signature *signature);

#endif
