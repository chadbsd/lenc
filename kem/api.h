#ifndef SKIBIDI_API_H
#define SKIBIDI_API_H

#include <stdint.h>

#define SKIBIDI768_SECRETKEYBYTES 2400
#define SKIBIDI768_PUBLICKEYBYTES 1184
#define SKIBIDI768_CIPHERTEXTBYTES 1088
#define SKIBIDI768_KEYPAIRCOINBYTES 64
#define SKIBIDI768_ENCCOINBYTES 32
#define SKIBIDI768_BYTES 32

int skibidi768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int skibidi768_keypair(uint8_t *pk, uint8_t *sk);
int skibidi768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int skibidi768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int skibidi768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif
