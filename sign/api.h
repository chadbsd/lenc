#ifndef SIGMA_API_H
#define SIGMA_API_H

#include <stddef.h>
#include <stdint.h>

#define TUAH3_PUBLICKEYBYTES 1952
#define TUAH3_SECRETKEYBYTES 4032
#define TUAH3_BYTES 3309

int tuah3_keypair(uint8_t *pk, uint8_t *sk);

int tuah3_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);

int tuah3(uint8_t *sm, size_t *smlen,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);

int tuah3_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int tuah3_open(uint8_t *m, size_t *mlen,
                                   const uint8_t *sm, size_t smlen,
                                   const uint8_t *ctx, size_t ctxlen,
                                   const uint8_t *pk);

#endif
