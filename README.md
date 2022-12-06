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

## Benchmark

The following result is tested on Apple Silicon M1, with RING_SIZE = 100, on curve of 224-bit prime characteristic and embedding degree 6.

signing time: 1.401 s

signature verification time: 2.433 s

report & trace time: 0.444 s

## Other Stuff

See https://github.com/izy66/ring.
