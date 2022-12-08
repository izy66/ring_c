#include "ring.h"
#include "time.h"

pairing_t pairing;
element_t tmp_r, tmp_r2, tmp_t, tmp_t2;
Ring ring[RING_SIZE];
Pairing_param *pp;

int main() {
  // FILE *f = freopen("out", "w", stdout);

  clock_t timer;

  char param[2048];

  FILE* stream = fopen("param/d224.param", "r");
  size_t count = fread(param, 1, 2048, stream);

  if (!count) pbc_die("input error");

  pairing_init_set_buf(pairing, param, count);
  pairing_var_init();

  PKE_key_pair *my_key = malloc(sizeof(PKE_key_pair));
  user_key_init(my_key);
  user_key_gen(my_key);

  //srand(time(NULL));
  int my_index = rand() % RING_SIZE;

  element_set(ring[my_index].public_key, my_key->public_key);
  element_pow_zn(ring[my_index].public_id, pp->g3, my_key->secret_key);

  unsigned char message[] = "YELLOW SUBMARINE";
  element_t h;
  element_init_Zr(h, pairing); 
  element_hash_Str(h, message); 
  element_clear(h);

  PKE_key_pair *tracer_key = malloc(sizeof(PKE_key_pair));
  tracer_key_init(tracer_key);
  tracer_key_gen(tracer_key);

  Signature *signature = malloc(sizeof(Signature));
  Signature_init(signature);

  timer = (float)clock()/CLOCKS_PER_SEC;
  signature_gen(signature, tracer_key->public_key, ring[my_index].public_id, my_key->secret_key, my_index, message);
  printf("signing time: %.3f s\n", (float)clock()/CLOCKS_PER_SEC - timer);

  if (signature_verify(signature, tracer_key->public_key, message)) {

    printf("signature verification time: %.3f s\n", (float)clock()/CLOCKS_PER_SEC - timer);
    
    timer = (float)clock()/CLOCKS_PER_SEC;
    report_signature(signature, my_index, my_key->secret_key);
    trace_signature(signature, tracer_key->secret_key);
    printf("report & trace time: %.3f s\n", (float)clock()/CLOCKS_PER_SEC - timer);

    assert(!element_cmp(signature->signer_PID, ring[my_index].public_id));
    assert(trace_verify(signature));
    
  } else {
    puts("signature verification failed.");
  }

  Signature_clear(signature);
  free(signature);
  PKE_key_clear(tracer_key);
  free(tracer_key);
  PKE_key_clear(my_key);
  free(my_key);
  pairing_var_clear();
  fclose(stream);

  return 0;
}

