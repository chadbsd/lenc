CFLAGS = -O0 -g3 -Wall -Wextra
LDFLAGS = 

.PREFIXES = .c .o

SIGN = 	sign/fips202.o \
		sign/ntt.o \
		sign/packing.o \
		sign/poly.o \
		sign/polyvec.o \
		sign/reduce.o \
		sign/rounding.o \
		sign/sign.o \
		sign/symmetric-shake.o

KEM =	kem/cbd.o \
		kem/fips202.o \
		kem/indcpa.o \
		kem/kem.o \
		kem/ntt.o \
		kem/poly.o \
		kem/polyvec.o \
		kem/reduce.o \
		kem/symmetric-shake.o \
		kem/verify.o

CRYPTO = monocypher.o randombytes.o ${KEM} ${SIGN}

all: enc lenc lenc.old

enc: enc.o ${CRYPTO}
	${CC} -o $@ enc.o ${CRYPTO} ${LDFLAGS}

lenc: lenc.o ${CRYPTO}
	${CC} -o $@ lenc.o ${CRYPTO} ${LDFLAGS}

lenc.old: lenc.old.o ${CRYPTO}
	${CC} -o $@ lenc.old.o ${CRYPTO} ${LDFLAGS}

test: test.o ${CRYPTO}
	${CC} -o $@ test.o ${CRYPTO} ${LDFLAGS}

.c.o:
	${CC} -c -o $@ ${CFLAGS} $<

clean:
	rm -f lenc lenc.old enc test *.o ${SIGN} ${KEM}
