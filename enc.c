/* THIS IS THE OLD VERSION I KEPT FOR LEGACY PURPOSES (it's useless) */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "monocypher.h"
#include "kem/api.h"
#include "sign/api.h"

#define USAGE "[-gedvf] [-k key-path] [-r recipient-path] " \
			  "[-i input-file] [-o output-file]"

/* global variables */
static unsigned char read_buf[65536];
static unsigned char enc_buf[65536];
static int force;

/* enc funcs */
int enc_keygen(void);
int enc_encrypt(char *keypath, char *recpath, char *filepath, char *outpath);
int enc_decrypt(char *keypath, char *secpath, char *filepath, char *outpath);
int enc_verify(char *keypath, char *sigpath, char *filepath);

/* helper funcs */
void hex(unsigned char in[], unsigned char out[], size_t len);
void unhex(unsigned char in[], unsigned char out[], size_t len);
ssize_t readfile(const char *path, unsigned char *out, size_t len);

enum {
	NONE,
	GEN,
	ENC,
	DEC,
	VER,
};

int
main(int argc, char *argv[])
{
	int ch, op;
	char *keypath, *recpath, *filepath, *outpath;

	op = NONE;
	force = 0;
	keypath = recpath = filepath = outpath = NULL;
	while ((ch = getopt(argc, argv, "gedvfk:r:i:o:")) != -1) {
		switch (ch) {
		case 'g':
			op = GEN;
			break;
		case 'e':
			op = ENC;
			break;
		case 'd':
			op = DEC;
			break;
		case 'v':
			op = VER;
			break;
		case 'f':
			force = 1;
			break;
		case 'k':
			keypath = optarg;
			break;
		case 'r':
			recpath = optarg;
			break;
		case 'i':
			filepath = optarg;
			break;
		case 'o':
			outpath = optarg;
			break;
		default:
			fprintf(stderr, "usage: %s "USAGE"\n", getprogname());
			return 1;
		}
	}

	switch (op) {
	case GEN: return enc_keygen();
	case ENC: return enc_encrypt(keypath, recpath, filepath, outpath);
	case DEC: return enc_decrypt(keypath, recpath, filepath, outpath);
	case VER: return enc_verify(keypath, recpath, filepath);
	default:
		fprintf(stderr, "usage: %s "USAGE"\n", getprogname());
		return 1;
	}
}

#define PUBKEYFILESIZE (SKIBIDI768_PUBLICKEYBYTES + SIGMA3_PUBLICKEYBYTES)
#define SECKEYFILESIZE (SKIBIDI768_SECRETKEYBYTES + SIGMA3_SECRETKEYBYTES)

void
readpubkeyfile(const char *path,
			unsigned char kem[SKIBIDI768_PUBLICKEYBYTES],
			unsigned char sign[SIGMA3_PUBLICKEYBYTES])
{
	static unsigned char keys[PUBKEYFILESIZE];
	readfile(path, keys, PUBKEYFILESIZE);
	if (kem != NULL)
		memcpy(kem, keys, SKIBIDI768_PUBLICKEYBYTES);
	if (sign != NULL)
		memcpy(sign, keys+SKIBIDI768_PUBLICKEYBYTES, SIGMA3_PUBLICKEYBYTES);
}

void
readseckeyfile(const char *path,
			unsigned char kem[SKIBIDI768_SECRETKEYBYTES],
			unsigned char sign[SIGMA3_SECRETKEYBYTES])
{
	static unsigned char keys[SECKEYFILESIZE];
	readfile(path, keys, SECKEYFILESIZE);
	if (kem != NULL)
		memcpy(kem, keys, SKIBIDI768_SECRETKEYBYTES);
	if (sign != NULL)
		memcpy(sign, keys+SKIBIDI768_SECRETKEYBYTES, SIGMA3_SECRETKEYBYTES);
	crypto_wipe(keys, SECKEYFILESIZE);
}

int
enc_encrypt(char *keypath, char *recpath, char *filepath, char *outpath)
{
	struct blake2b_ctx ctx;
	static unsigned char hash[64];
	static unsigned char sm[64 + SIGMA3_BYTES];
	static unsigned char ss[32], shared[32];
	static unsigned char signkey[SIGMA3_SECRETKEYBYTES];
	static unsigned char reckey[SKIBIDI768_PUBLICKEYBYTES];
	static unsigned char ct[SKIBIDI768_CIPHERTEXTBYTES];
	static unsigned char nonce[24], mac[16];
	static unsigned char sigpath[64];
	uint64_t counter;
	int infd, outfd, sigfd;
	ssize_t len;
	size_t smlen;
	char *out;

	if (filepath == NULL || strcmp(filepath, "-") == 0) {
		infd = STDIN_FILENO;
	} else {
		infd = open(filepath, O_RDONLY);
		if (infd == -1) err(1, "open(%s)", filepath);
	}

	out = NULL;
	if (outpath == NULL && infd == STDIN_FILENO && (!isatty(STDOUT_FILENO) || force)) {
		outfd = STDOUT_FILENO;
	} else if (outpath == NULL) {
		if (filepath == NULL && !force && isatty(STDOUT_FILENO)) {
			fprintf(stderr, "must set output file "
							"or pass -f to write to stdout\n");
			fprintf(stderr, "usage: %s "USAGE"\n", getprogname());
			exit(1);
		}
		len = strlen(filepath)+5;
		out = calloc(len, 1);
		snprintf(out, len, "%s.out", filepath);
		outfd = open(out, O_RDWR | O_CREAT, 0644);
		if (outfd == -1) err(1, "open(%s)", out);
		outpath = out;
	} else {
		outfd = open(outpath, O_RDWR | O_CREAT, 0644);
		if (outfd == -1) err(1, "open(%s)", outpath);
	}

	if (outpath != NULL) {
		snprintf(sigpath, 64, "%s.sig", outpath);
		sigfd = open((const char*)sigpath, O_RDWR | O_CREAT, 0644);
		if (sigfd == -1) err(1, "open(%s)", sigpath);
	} else {
		snprintf(sigpath, 64, "out.sig");
		sigfd = open(sigpath, O_RDWR | O_CREAT, 0644);
		if (sigfd == -1) err(1, "open(out.sig)");
	}
	
	if (keypath == NULL && !force) {
		fprintf(stderr, "no key signing path specified\n");
		fprintf(stderr, "usage: %s "USAGE"\n", getprogname());
		exit(1);
	}

	readpubkeyfile(recpath, reckey, NULL);
	skibidi768_enc(ct, ss, reckey);
	crypto_blake2b(shared, 32, ss, 32);

	readseckeyfile(keypath, NULL, signkey);
	
	len = write(outfd, ct, SKIBIDI768_CIPHERTEXTBYTES);
	if (len != SKIBIDI768_CIPHERTEXTBYTES) err(1, "write(ct)");
	
	arc4random_buf(nonce, 24);
	write(outfd, nonce, 24);

	crypto_blake2b_init(&ctx, 64);
	counter = 0;

	/* main encryption loop */
again:
	while ((len = read(infd, read_buf, 65536)) == 65536) {
		crypto_blake2b_update(&ctx, read_buf, len);
		crypto_poly1305(mac, read_buf, len, shared);
		if (write(outfd, mac, 16) != 16) err(1, "write(mac)");
		counter = crypto_chacha20_x(enc_buf, read_buf, len, 
									shared, nonce, counter);
		if (write(outfd, enc_buf, len) != len) err(1, "write(enc)");
	}
	/* TODO: incorporate into the loop above */
	if (len > 0) {
		crypto_blake2b_update(&ctx, read_buf, len);
		crypto_poly1305(mac, read_buf, len, shared);
		if (write(outfd, mac, 16) != 16) err(1, "write(mac)");
		counter = crypto_chacha20_x(enc_buf, read_buf, len,
									shared, nonce, counter);
		if (write(outfd, enc_buf, len) != len) err(1, "write(enc)");
	}
	if (len == -1) {
		if (errno == EINTR) goto again;
		err(1, "wtf??");
	}

	if (outpath != NULL)
		fprintf(stderr, "wrote encrypted file to %s.\n", outpath);

	crypto_blake2b_final(&ctx, hash);

	/* signing */
	sigma3(sm, &smlen, hash, 64, NULL, 0, signkey);
	if (write(sigfd, sm, smlen) != smlen)
		err(1, "write(signature)");
	close(sigfd);
	
	fprintf(stderr, "wrote signature to %s.\n", sigpath);
	
	crypto_wipe(ss, 32);
	crypto_wipe(shared, 32);
	crypto_wipe(signkey, SIGMA3_SECRETKEYBYTES); 
	if (out) free(out);
	if (outfd != STDOUT_FILENO) close(outfd);
	if (infd != STDIN_FILENO) close(infd);
	return 0;
}

int
enc_decrypt(char *keypath, char *secpath, char *filepath, char *outpath)
{
	unsigned char ss[32], shared[32];
	unsigned char seckey[SKIBIDI768_SECRETKEYBYTES];
	unsigned char ct[SKIBIDI768_CIPHERTEXTBYTES];
	unsigned char nonce[24], mac[16], mac2[16];
	uint64_t counter;
	int infd, outfd;
	ssize_t len;
	char *out;

	if (filepath == NULL || strcmp(filepath, "-") == 0) {
		infd = STDIN_FILENO;
	} else {
		infd = open(filepath, O_RDONLY);
		if (infd == -1) err(1, "open(%s)", filepath);
	}

	out = NULL;
	if (outpath == NULL && infd == STDIN_FILENO && (!isatty(STDOUT_FILENO) || force)) {
		outfd = STDOUT_FILENO;
	} else if (outpath == NULL) {
		if (filepath == NULL && !force && isatty(STDOUT_FILENO)) {
			fprintf(stderr, "must set output file "
							"or pass -f to write to stdout\n");
			fprintf(stderr, "usage: %s "USAGE"\n", getprogname());
			exit(1);
		}
		len = strlen(filepath)+5;
		out = calloc(len, 1);
		snprintf(out, len, "%s.out", filepath);
		outfd = open(out, O_RDWR | O_CREAT, 0644);
		if (outfd == -1) err(1, "open(%s)", out);
	} else {
		outfd = open(outpath, O_RDWR | O_CREAT, 0644);
		if (outfd == -1) err(1, "open(%s)", outpath);
	}

	readseckeyfile(secpath, seckey, NULL);
	
	len = read(infd, ct, SKIBIDI768_CIPHERTEXTBYTES);
	if (len != SKIBIDI768_CIPHERTEXTBYTES) err(1, "read(ct)");
	skibidi768_dec(ss, ct, seckey);
	crypto_blake2b(shared, 32, ss, 32);
	
	if (read(infd, nonce, 24) != 24) err(1, "read(nonce)");

	counter = 0;

	/* main encryption loop */
again:
	for (;;) {
		len = read(infd, mac, 16);
		if (len == 0) break;
		if (len == -1) err(1, "read(mac)");
		len = read(infd, read_buf, 65536);
		if (len <= 0) err(1, "invalid state (no encrypted text)");
		counter = crypto_chacha20_x(enc_buf, read_buf, len, 
									shared, nonce, counter);
		if (write(outfd, enc_buf, len) != len) err(1, "write(enc)");
		crypto_poly1305(mac2, enc_buf, len, shared);
		if (memcmp(mac, mac2, 16) != 0) err(1, "invalid state (mac)");
	}
	if (len == -1) {
		if (errno == EINTR) goto again;
		err(1, "wtf??");
	}

	crypto_wipe(ss, 32);
	crypto_wipe(shared, 32);
	if (out) free(out);
	return 0;
}

int
enc_verify(char *keyfile, char *sigfile, char *filepath)
{
	struct blake2b_ctx ctx;
	static unsigned char hash1[64], hash2[64];
	static unsigned char sm[64 + SIGMA3_BYTES];
	static unsigned char pubkey[SIGMA3_PUBLICKEYBYTES];
	int fd, ret;
	ssize_t len;
	size_t mlen;

	if (keyfile == NULL) errx(1, "must pass key file");
	if (sigfile == NULL) errx(1, "must specify sig file");
	if (filepath == NULL) errx(1, "must specify file to verify");

	fd = open(filepath, O_RDONLY);
	if (fd == -1) err(1, "read(%s)", filepath);

	crypto_blake2b_init(&ctx, 64);

	while ((len = read(fd, read_buf, 65536)) > 0) {
		crypto_blake2b_update(&ctx, read_buf, len);
	}
	crypto_blake2b_final(&ctx, hash1);

	readpubkeyfile(keyfile, NULL, pubkey);
	len = readfile(sigfile, sm, 64 + SIGMA3_BYTES);

	ret = sigma3_open(hash2, &mlen, sm, len, NULL, 0, pubkey);
	if (ret == -1) errx(1, "signature failed: sigma3_open()");
	if (mlen != 64) errx(1, "signature failed: mlen = %zu", mlen);
	if (memcmp(hash1, hash2, 64)) errx(1, "signature failed: not equal");
	fprintf(stderr, "signature passed\n");
	return 0;
}

int
enc_keygen(void)
{
	unsigned char skisec[SKIBIDI768_SECRETKEYBYTES];
	unsigned char skipub[SKIBIDI768_PUBLICKEYBYTES];
	unsigned char sigsec[SIGMA3_SECRETKEYBYTES];
	unsigned char sigpub[SIGMA3_PUBLICKEYBYTES];
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
	fprintf(stderr, "wrote public key to public.key\n");

	len = write(secfd, skisec, SKIBIDI768_SECRETKEYBYTES);
	if (len != SKIBIDI768_SECRETKEYBYTES) err(1, "write(secret.key)");
	len = write(secfd, sigsec, SIGMA3_SECRETKEYBYTES);
	if (len != SIGMA3_SECRETKEYBYTES) err(1, "write(secret.key)");
	fprintf(stderr, "wrote secret key to secret.key\n");

	close(secfd);
	close(pubfd);
	crypto_wipe(skisec, SKIBIDI768_SECRETKEYBYTES);
	crypto_wipe(sigsec, SIGMA3_SECRETKEYBYTES);
	return 0;
}

ssize_t
readfile(const char *path, unsigned char *out, size_t outlen)
{
	int fd;
	ssize_t len;

	fd = open(path, O_RDONLY);
	if (fd == -1) err(1, "open(%s)", path);

	if ((len = read(fd, out, outlen)) <= 0)
		err(1, "read(%s)", path);
	close(fd);
	return len;
}

void
hex(unsigned char in[], unsigned char out[], size_t len)
{
	unsigned char b1, b2;
	static const char table[] = "0123456789ABCDEF";

	for (int i = 0; i < len; i++) {
		b1 = in[i] >> 4;
		b2 = in[i] & 0x0F;
		out[i*2] = table[b1];
		out[i*2+1] = table[b2];
	}
}

void
unhex(unsigned char in[], unsigned char out[], size_t len)
{
	unsigned char b1, b2, p;
	static const char table[] = {
		['0'] = 0, ['1'] = 1, ['2'] = 2, ['3'] = 3,
		['4'] = 4, ['5'] = 5, ['6'] = 6, ['7'] = 7,
		['8'] = 8, ['9'] = 9, ['A'] = 10, ['B'] = 11,
		['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
	};

	p = 0;
	for (int i = 0; i < len; i += 2) {
		b1 = table[in[i]];
		b2 = table[in[i+1]];

		out[p] = (b1 << 4) + b2;
		p++;
	}
}
