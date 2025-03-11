#ifndef CONFIG_H
#define CONFIG_H

//#define DILITHIUM_MODE 2
#define DILITHIUM_RANDOMIZED_SIGNING
//#define USE_RDPMC
//#define DBENCH

#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 3
#endif

#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define DILITHIUM_NAMESPACETOP tuah2
#define DILITHIUM_NAMESPACE(s) tuah2_##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACETOP tuah3
#define DILITHIUM_NAMESPACE(s) tuah3_##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define DILITHIUM_NAMESPACETOP tuah5
#define DILITHIUM_NAMESPACE(s) tuah5_##s
#endif

#endif
