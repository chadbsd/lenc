#ifndef SIGMA_API_H
#define SIGMA_API_H

#include <stddef.h>
#include <stdint.h>

#define SIGMA3_PUBLICKEYBYTES 1952
#define SIGMA3_SECRETKEYBYTES 4032
#define SIGMA3_BYTES 3309

int sigma3_keypair(uint8_t *pk, uint8_t *sk);

int sigma3_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);

int sigma3(uint8_t *sm, size_t *smlen,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);

int sigma3_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int sigma3_open(uint8_t *m, size_t *mlen,
                                   const uint8_t *sm, size_t smlen,
                                   const uint8_t *ctx, size_t ctxlen,
                                   const uint8_t *pk);

#endif
