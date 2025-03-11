#ifndef SKIBIDI_API_H
#define SKIBIDI_API_H

#include <stdint.h>

#define HAWK768_SECRETKEYBYTES 2400
#define HAWK768_PUBLICKEYBYTES 1184
#define HAWK768_CIPHERTEXTBYTES 1088
#define HAWK768_KEYPAIRCOINBYTES 64
#define HAWK768_ENCCOINBYTES 32
#define HAWK768_BYTES 32

int hawk768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int hawk768_keypair(uint8_t *pk, uint8_t *sk);
int hawk768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int hawk768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int hawk768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif
