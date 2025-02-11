/* current version of lenc */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <err.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "monocypher.h"
#include "kem/api.h"
#include "sign/api.h"

struct file {
    struct file *next;
    struct stat st;
    const char *path;
    int fd, set;
} file_init = {
    .next = NULL,
    .st = {0},
    .path = NULL,
    .fd = -1, 
    .set = 0,
};

#define PUBKEYFILESIZE (SKIBIDI768_PUBLICKEYBYTES + SIGMA3_PUBLICKEYBYTES)
#define SECKEYFILESIZE (SKIBIDI768_SECRETKEYBYTES + SIGMA3_SECRETKEYBYTES)

struct pubkey {
    union {
        unsigned char buf[PUBKEYFILESIZE];
        struct {
            unsigned char kem[SKIBIDI768_PUBLICKEYBYTES];
            unsigned char sign[SIGMA3_PUBLICKEYBYTES];
        };
    };
};

struct seckey {
    union {
        unsigned char buf[SECKEYFILESIZE];
        struct {
            unsigned char kem[SKIBIDI768_SECRETKEYBYTES];
            unsigned char sign[SIGMA3_SECRETKEYBYTES];
        };
    };
};

#define FILE_INIT(ptr) memcpy(ptr, &file_init, sizeof(*ptr))

enum {
    NONE,
    GENERATE,
    ENCRYPT,
    DECRYPT,
    SIGN,
    VERIFY,
};

void *xcalloc(size_t nmemb, size_t size);
void process_args(struct file *keypath, struct file *recpath,
                  struct file *inpath, struct file *outpath,
                  struct file *sigpath);
void readpubkeyfile(int fd, struct pubkey *out);
void readseckeyfile(int fd, struct seckey *out);

/* commands */
int lenc_generate(void);
int lenc_encrypt(struct file *key, struct file *recs,
                 struct file *in, struct file *out);
int lenc_decrypt(struct file *key, struct file *recs,
                 struct file *in, struct file *out);

/* globals */
int force, verbose, quiet;
unsigned char read_buf[65536];
unsigned char enc_buf[65536];

static struct option longopts[] = {
    /* commands */
    { "generate",   no_argument,        NULL,   'G' },
    { "encrypt",    no_argument,        NULL,   'E' },
    { "decrypt",    no_argument,        NULL,   'D' },
    { "sign",       no_argument,        NULL,   'S' },
    { "verify",     no_argument,        NULL,   'V' },
    /* flags */
    { "verbose",    no_argument,        NULL,   'v' },
    { "quiet",      no_argument,        NULL,   'q' },
    { "force",      no_argument,        NULL,   'f' },
    /* args */
    { "key",        required_argument,  NULL,   'k' },
    { "recipient",  required_argument,  NULL,   'r' },
    { "output",     required_argument,  NULL,   'o' },
    { "signature",  required_argument,  NULL,   's' },
    { NULL,         0,                  NULL,    0  },
};

/* file format v1
 *
 * |----------------------------------------------------|
 * | recipient_count:   uint16_t                        |
 * |----------------------------------------------------|
 * | recipients:        SKIBIDI768_CIPHERTEXTBYTES * nr |
 * |----------------------------------------------------|
 * | cipher_text:       <file size>                     |
 * |----------------------------------------------------|
 * | signature:         SIGMA3_BYTES + 64               |
 * |----------------------------------------------------|
 */

int
main(int argc, char *argv[])
{
    int ch, op;
    const char *optstring;
    struct file keypath, inpath, outpath, sigpath;
    struct file recpath, *reccur = &recpath;

    
    FILE_INIT(&keypath);
    FILE_INIT(&recpath);
    FILE_INIT(&inpath);
    FILE_INIT(&outpath);
    FILE_INIT(&sigpath);

    op = NONE;
    optstring = "GEDSVvqfk:r:o:s:";
    while ((ch = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
        switch (ch) {
        /* commands */
        case 'G': op = GENERATE; break;
        case 'E': op = ENCRYPT; break;
        case 'D': op = DECRYPT; break;
        case 'S': op = SIGN; break;
        case 'V': op = VERIFY; break;
        /* flags */
        case 'v': verbose = 1; break;
        case 'q': quiet = 1; break;
        case 'f': force = 1; break;
        /* args */
        case 'k':
            keypath.path = optarg;
            keypath.set = 1;
            break;
        case 'r':
            reccur->path = optarg;
            reccur->set = 1;
            reccur->next = xcalloc(1, sizeof(*reccur));
            reccur = reccur->next;
            break;
        case 'o':
            outpath.path = optarg;
            outpath.set = 1;
            break;
        case 's':
            sigpath.path = optarg;
            sigpath.set = 1;
            break;
        default:
            fprintf(stderr, "usage: go fuck yourself\n");
            return 1;
        }
    }

    if (argv[optind] != NULL) {
        inpath.path = argv[optind];
        inpath.set = 1;
    }

    process_args(&keypath, &recpath, &inpath, &outpath, &sigpath);

    switch (op) {
    case GENERATE: return lenc_generate();
    case ENCRYPT: return lenc_encrypt(&keypath, &recpath, &inpath, &outpath);
    case DECRYPT: return lenc_decrypt(&keypath, &recpath, &inpath, &outpath);
    case SIGN: break;
    case VERIFY: break;
    default:
        fprintf(stderr, "usage: go fuck yourself\n");
        return 1;
    }
}

int
lenc_encrypt(struct file *key, struct file *recs,
             struct file *in,  struct file *out)
{
    static unsigned char sm[64 + SIGMA3_BYTES];
    static unsigned char ct[SKIBIDI768_CIPHERTEXTBYTES];
    static struct pubkey pub;
    static struct seckey sec;
    static struct blake2b_ctx ctx;

    unsigned char nonce[24], mac[16];
    unsigned char hash[64];
    unsigned char ss[32], shared[32], coins[64];
    uint16_t nrecs;
    uint64_t counter, enc_len, len2;
    ssize_t len;
    size_t smlen;

    if (!out->set) errx(1, "need output file");
    if (!key->set) errx(1, "need key file");
    if (!recs->set) errx(1, "need recipients");
    if (!in->set) errx(1, "need file to encrypt");

    arc4random_buf(coins, 64);

    readpubkeyfile(recs->fd, &pub);
    readseckeyfile(key->fd, &sec);

    /* TODO: replace with actual nrecs */
    nrecs = 1;
    
    if (write(out->fd, &nrecs, sizeof(nrecs)) != sizeof(nrecs)) {
        err(1, "write(nrecs)");
    }
    
    /* only runs once until i add actual nrecs */
    for (uint16_t i = 0; i < nrecs; i++) {
        skibidi768_enc_derand(ct, ss, pub.kem, coins);
        crypto_blake2b(shared, 32, ss, 32);
        crypto_wipe(ss, 32);
        len = write(out->fd, ct, SKIBIDI768_CIPHERTEXTBYTES);
        if (len != SKIBIDI768_CIPHERTEXTBYTES) err(1, "write(ct)");
    }

    arc4random_buf(nonce, 24);
    if (write(out->fd, nonce, 24) != 24) err(1, "write(nonce)");

    crypto_blake2b_init(&ctx, 64);
    counter = 0;

again:
    /* TODO: guarantee 65536 is read until the very end */
    while ((len = read(in->fd, read_buf, 65536)) > 0) {
        crypto_blake2b_update(&ctx, read_buf, len);
        crypto_poly1305(mac, read_buf, len, shared);
        if (write(out->fd, mac, 16) != 16) err(1, "write(mac)");
        len2 = len;
        counter = crypto_chacha20_x((uint8_t*)&enc_len, (uint8_t*)&len2, 
                                    sizeof(uint64_t), shared, nonce, counter);
        if (write(out->fd, &enc_len, sizeof(uint64_t)) != sizeof(uint64_t)) {
            err(1, "write(enc_len)");
        }
        counter = crypto_chacha20_x(enc_buf, read_buf, len,
                                    shared, nonce, counter);
        if (write(out->fd, enc_buf, len) != len) err(1, "write(enc)");
    }
    if (len == -1) {
        if (errno == EINTR) goto again;
        err(1, "wtf??");
    }
    crypto_blake2b_final(&ctx, hash);
    sigma3(sm, &smlen, hash, 64, NULL, 0, sec.sign);
    if (smlen != 64 + SIGMA3_BYTES) {
        errx(1, "erm what the sigma");
    }
    if (write(out->fd, sm, smlen) != (ssize_t)smlen) {
        err(1, "write(sm)");
    }

    if (out->fd != STDOUT_FILENO && !quiet) {
        fprintf(stderr, "wrote encrypted file to %s.\n", out->path);
    }

    close(out->fd);
    close(in->fd);
    close(key->fd);
    close(recs->fd);
    crypto_wipe(shared, 32);
    crypto_wipe(&sec, sizeof(sec));
    return 0;
}

int
lenc_decrypt(struct file *key, struct file *rec,
             struct file *in, struct file *out)
{
    static unsigned char ct[SKIBIDI768_CIPHERTEXTBYTES];
    static unsigned char sm[64 + SIGMA3_BYTES];
    static struct pubkey pub;
    static struct seckey sec;
    static struct blake2b_ctx ctx;
    
    unsigned char hash1[64], hash2[64];
    unsigned char ss[32], shared[32];
    unsigned char nonce[24], mac1[16], mac2[16];
    uint64_t counter, enc_len, len2;
    uint16_t nrecs;
    ssize_t len;
    size_t mlen;
    int ret;
    
    if (!out->set) errx(1, "need output file");
    if (!key->set) errx(1, "need key file");
    if (!rec->set) errx(1, "need recipients");
    if (!in->set) errx(1, "need file to decrypt");

    readseckeyfile(rec->fd, &sec);
    readpubkeyfile(key->fd, &pub);

    /* TODO: handle multiple recipients */
    len = read(in->fd, &nrecs, sizeof(nrecs));
    if (len != sizeof(nrecs)) err(1, "read(nrecs)");
    len = read(in->fd, ct, SKIBIDI768_CIPHERTEXTBYTES);
    if (len != SKIBIDI768_CIPHERTEXTBYTES) err(1, "read(ct)");
    skibidi768_dec(ss, ct, sec.kem);
    crypto_blake2b(shared, 32, ss, 32);
    crypto_wipe(ss, 32);

    if (read(in->fd, nonce, 24) != 24) err(1, "read(nonce)");

    crypto_blake2b_init(&ctx, 64);
    counter = 0;

    for (;;) {
        len = read(in->fd, mac1, 16);
        if (len == -1) {
            err(1, "read(mac)");
        }
        if (len != 16) err(1, "read(mac)");
        len = read(in->fd, &enc_len, sizeof(uint64_t));
        if (len != sizeof(uint64_t)) err(1, "read(enc_len)");
        counter = crypto_chacha20_x((uint8_t*)&len2, (uint8_t*)&enc_len, 
                                    sizeof(uint64_t), shared, nonce, counter);
        if (len2 == 0 || len2 > 65536) errx(1, "invalid state");
        len = read(in->fd, read_buf, len2);
        if (len == 0) errx(1, "invalid state (no encrypted text)");
        if (len == -1) {
            err(1, "read(enc)");
        }
        if (len != (ssize_t)len2) err(1, "read(enc)");
        counter = crypto_chacha20_x(enc_buf, read_buf, len,
                                    shared, nonce, counter);
        if (write(out->fd, enc_buf, len) != len) err(1, "write(enc)");
        crypto_blake2b_update(&ctx, enc_buf, len);
        crypto_poly1305(mac2, enc_buf, len, shared);
        if (memcmp(mac1, mac2, 16) != 0) err(1, "invalid state (mac)");
        if (len < 65536) break;
    }
    crypto_blake2b_final(&ctx, hash1);

    if (read(in->fd, sm, 64 + SIGMA3_BYTES) != 64 + SIGMA3_BYTES) {
        err(1, "read(sm)");
    }

    ret = sigma3_open(hash2, &mlen, sm, 64 + SIGMA3_BYTES, 
                        NULL, 0, pub.sign);
    if (ret == -1) errx(1, "signature failed: 0x01");
    if (mlen != 64) errx(1, "signature failed: 0x02");
    if (memcmp(hash1, hash2, 64)) errx(1, "signature failed: 0x03");

    if (!quiet) {
        fprintf(stderr, "signature passed\n");
        if (out->fd != STDOUT_FILENO) {
            fprintf(stderr, "wrote to %s.\n", out->path);
        }
    }

    close(out->fd);
    close(in->fd);
    close(key->fd);
    close(rec->fd);
    crypto_wipe(shared, 32);
    crypto_wipe(&sec, sizeof(sec));
    return 0;
}

int
lenc_generate(void)
{
    static unsigned char skisec[SKIBIDI768_SECRETKEYBYTES];
    static unsigned char skipub[SKIBIDI768_PUBLICKEYBYTES];
    static unsigned char sigsec[SIGMA3_SECRETKEYBYTES];
    static unsigned char sigpub[SIGMA3_PUBLICKEYBYTES];

    int pubfd, secfd;
    ssize_t len;

    skibidi768_keypair(skipub, skisec);
    sigma3_keypair(sigpub, sigsec);

    pubfd = open("public.key", O_RDWR | O_CREAT, 0644);
    if (pubfd == -1) err(1, "open(public.key)");
    secfd = open("secret.key", O_RDWR | O_CREAT, 0600);
    if (secfd == -1) err(1, "open(secret.key)");

    len = write(pubfd, skipub, SKIBIDI768_PUBLICKEYBYTES);
    if (len != SKIBIDI768_PUBLICKEYBYTES) err(1, "write(public.key)");
    len = write(pubfd, sigpub, SIGMA3_PUBLICKEYBYTES);
    if (len != SIGMA3_PUBLICKEYBYTES) err(1, "write(public.key)");
    if (!quiet) fprintf(stderr, "wrote public key to public.key\n");

    len = write(secfd, skisec, SKIBIDI768_SECRETKEYBYTES);
    if (len != SKIBIDI768_SECRETKEYBYTES) err(1, "write(secret.key)");
    len = write(secfd, sigsec, SIGMA3_SECRETKEYBYTES);
    if (len != SIGMA3_SECRETKEYBYTES) err(1, "write(secret.key)");
    if (!quiet) fprintf(stderr, "wrote secret key to secret.key\n");

    close(secfd);
    close(pubfd);
    crypto_wipe(skisec, SKIBIDI768_SECRETKEYBYTES);
    crypto_wipe(sigsec, SIGMA3_SECRETKEYBYTES);
    return 0;
}

void
readpubkeyfile(int fd,
               struct pubkey *out)
{
    ssize_t ret;
    if (out == NULL) errx(1, "pubkey out == NULL");

again:
    if ((ret = read(fd, out->buf, PUBKEYFILESIZE)) == -1) {
        if (errno == EINTR) goto again;
        else err(1, "read(pubkey)");
    }
    if (ret != PUBKEYFILESIZE) errx(1, "error reading pubkey");
}

void
readseckeyfile(int fd,
               struct seckey *out)
{
    ssize_t ret;
    if (out == NULL) errx(1, "seckey out == NULL");

again:
    if ((ret = read(fd, out->buf, SECKEYFILESIZE)) == -1) {
        if (errno == EINTR) goto again;
        else err(1, "read(seckey)");
    }
    if (ret != SECKEYFILESIZE) err(1, "error reading seckey: %zd", ret);
}

int
process_inarg(const char *name, struct file *f)
{
    if (f->path != NULL) {
        if (strcmp(f->path, "-") == 0) {
            f->fd = STDIN_FILENO;
            return 1;
        } else {
            f->fd = open(f->path, O_RDONLY);
            if (f->fd == -1) { 
                err(1, "%s: open(%s)", name, f->path);
            }
            fstat(f->fd, &f->st);
        }
    } else if (!f->set) {
        return 0;
    } else {
        /* btw i have no idea if this is reachable */
        errx(1, "must pass arg for %s", name);
    }
    return 0;
}

void
process_args(struct file *keypath, struct file *recpath,
             struct file *inpath,  struct file *outpath,
             struct file *sigpath)
{
    int nstdin;
    
    nstdin = 0;

    nstdin += process_inarg("key path", keypath);
    nstdin += process_inarg("input file", inpath);
    nstdin += process_inarg("signal file", sigpath);

    for (;recpath != NULL; recpath = recpath->next) {
        nstdin += process_inarg("recipient path", recpath);
    }

    if (outpath->set) {
        if (strcmp(outpath->path, "-") == 0) {
            outpath->fd = STDOUT_FILENO;
        } else {
            outpath->fd = open(outpath->path, O_RDWR | O_CREAT, 0644);
            if (outpath->fd == -1) err(1, "open(%s)", outpath->path);
        }
    } else {
        if (!isatty(STDOUT_FILENO)) {
            outpath->fd = STDOUT_FILENO;
        }
    }
    
    if (nstdin > 1) {
        errx(1, "only 1 input may be accepted from stdin");
    }
}

void *
xcalloc(size_t nmemb, size_t size)
{
    void *ret = calloc(nmemb, size);
    if (ret == NULL) {
        err(1, "xcalloc(%zu, %zu)", nmemb, size);
    }
    return ret;
}
