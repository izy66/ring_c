# ring_c

A re-implementation of [ring](https://github.com/izy66/ring) in C.

## Dependencies

[PBC](https://github.com/blynn/pbc)

[libsodium](https://github.com/jedisct1/libsodium)

[gmp](https://gmplib.org/)

## Test Run

Compile with the following command:

```
gcc -L. -lgmp -lpbc -lsodium test.c signature.c zkp.c keygen.c report_trace.c -o test & ./test
```

## Other Stuff

See https://github.com/izy66/ring.