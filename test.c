#include "ring.h"
#include "time.h"

int main() {
  // FILE *f = freopen("out", "w", stdout);

  clock_t timer;

  char param[2048];

  FILE* stream = fopen("param/d224.param", "r");
  size_t count = fread(param, 1, 2048, stream);

  if (!count) pbc_die("input error");

  pairing_init_set_buf(pairing, param, count);
  pairing_init();

  PKE_key_pair *my_key = malloc(sizeof(PKE_key_pair));
  user_key_init(my_key);
  user_key_gen(my_key);

  srand(time(NULL));
  int my_index = rand() % RING_SIZE;

  element_set(ring[my_index].public_key, my_key->public_key);
  element_pow_zn(ring[my_index].public_id, pp->g3, my_key->secret_key);

  unsigned char message[] = "YELLOW SUBMARINE";

  PKE_key_pair *tracer_key = malloc(sizeof(PKE_key_pair));
  tracer_key_init(tracer_key);
  tracer_key_gen(tracer_key);

  Signature *signature = malloc(sizeof(Signature));
  Signature_init(signature);

  timer = (float)clock()/CLOCKS_PER_SEC;
  signature_gen(signature, tracer_key->public_key, ring[my_index].public_id, my_key->secret_key, my_index, message);
  printf("signing time: %.3f s\n", (float)clock()/CLOCKS_PER_SEC - timer);

  timer = (float)clock()/CLOCKS_PER_SEC;
  if (signature_verify(signature, tracer_key->public_key, message)) {
    puts("signature verified.");
  } else {
    puts("signature verification failed.");
  }
  printf("signature verification time: %.3f s\n", (float)clock()/CLOCKS_PER_SEC - timer);

  timer = (float)clock()/CLOCKS_PER_SEC;
  report_signature(signature, my_index, my_key->secret_key);
  trace_signature(signature, tracer_key->secret_key);
  printf("report & trace time: %.3f s\n", (float)clock()/CLOCKS_PER_SEC - timer);

  assert(!element_cmp(signature->signer_PID, ring[my_index].public_id));
  assert(trace_verify(signature));
  
  for (int i = 0; i < RING_SIZE; ++i) {
    element_clear(ring[i].public_id);
    element_clear(ring[i].public_key);
  }
  PKE_key_clear(tracer_key);
  PKE_key_clear(my_key);
  Pairing_param_clear(pp);
  pairing_clear(pairing);
  fclose(stream);
}

