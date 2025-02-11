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
#define DILITHIUM_NAMESPACETOP sigma2
#define DILITHIUM_NAMESPACE(s) sigma2_##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACETOP sigma3
#define DILITHIUM_NAMESPACE(s) sigma3_##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define DILITHIUM_NAMESPACETOP sigma5
#define DILITHIUM_NAMESPACE(s) sigma5_##s
#endif

#endif
