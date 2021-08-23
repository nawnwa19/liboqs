#include <stdio.h>
#include "falcon.h"
#include <oqs/sig_falcon.h>


static void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "memory allocation error\n");
		exit(EXIT_FAILURE);
	}
	return buf;
}

static void
xfree(void *buf)
{
	if (buf != NULL) {
		free(buf);
	}
}

int CUSTOM_PADDED_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *sk, unsigned logn) {
    int result;
    shake256_context rng;
    shake256_init_prng_from_seed(&rng, "external", 8);

    *siglen = FALCON_SIG_PADDED_SIZE(logn);

    size_t privkey_len = FALCON_PRIVKEY_SIZE(logn);

    size_t tmp_len = FALCON_TMPSIZE_SIGNDYN(logn);
    uint8_t *tmp = xmalloc(tmp_len);

    result = falcon_sign_dyn(&rng, sig, siglen, FALCON_SIG_PADDED, sk,
                             privkey_len, m, mlen, tmp, tmp_len);
    xfree(tmp);
    return result;
}

int CUSTOM_PADDED_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *pk, unsigned logn) {
    int result;
    siglen = FALCON_SIG_PADDED_SIZE(logn);
    size_t pubkey_len = FALCON_PUBKEY_SIZE(logn);
    size_t tmp_len = FALCON_TMPSIZE_VERIFY(logn);
    uint8_t *tmp = xmalloc(tmp_len);

    result = falcon_verify(sig, siglen, FALCON_SIG_PADDED, pk, pubkey_len, m,
                           mlen, tmp, tmp_len);
    xfree(tmp);
    return result;
}