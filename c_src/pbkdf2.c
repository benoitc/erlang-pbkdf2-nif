/* Copyright (c) 2016 Benoit Chesneau <bchesneau@gmail.com> */

/* hmac_sha1, pkcs5_pbkdf2 by Damien Bergamini
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>

 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "erl_nif.h"
#include <sys/types.h>

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <util.h>

#include "sha1.h"
#include "explicit_bzero.h"

#define	MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

/*
 * HMAC-SHA-1 (from RFC 2202).
 */
static void
hmac_sha1(const u_int8_t *text, size_t text_len, const u_int8_t *key,
    size_t key_len, u_int8_t digest[SHA1_DIGEST_LENGTH])
{
	SHA1_CTX ctx;
	u_int8_t k_pad[SHA1_BLOCK_LENGTH];
	u_int8_t tk[SHA1_DIGEST_LENGTH];
	int i;

	if (key_len > SHA1_BLOCK_LENGTH) {
		SHA1Init(&ctx);
		SHA1Update(&ctx, key, key_len);
		SHA1Final(tk, &ctx);

		key = tk;
		key_len = SHA1_DIGEST_LENGTH;
	}

	bzero(k_pad, sizeof k_pad);
	bcopy(key, k_pad, key_len);
	for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
		k_pad[i] ^= 0x36;

	SHA1Init(&ctx);
	SHA1Update(&ctx, k_pad, SHA1_BLOCK_LENGTH);
	SHA1Update(&ctx, text, text_len);
	SHA1Final(digest, &ctx);

	bzero(k_pad, sizeof k_pad);
	bcopy(key, k_pad, key_len);
	for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
		k_pad[i] ^= 0x5c;

	SHA1Init(&ctx);
	SHA1Update(&ctx, k_pad, SHA1_BLOCK_LENGTH);
	SHA1Update(&ctx, digest, SHA1_DIGEST_LENGTH);
	SHA1Final(digest, &ctx);
}

/*
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
 * Code based on IEEE Std 802.11-2007, Annex H.4.2.
 */
int
pkcs5_pbkdf2(const unsigned char *pass, size_t pass_len, const uint8_t *salt,
    size_t salt_len, uint8_t *key, size_t key_len, unsigned int rounds)
{
	uint8_t *asalt, obuf[SHA1_DIGEST_LENGTH];
	uint8_t d1[SHA1_DIGEST_LENGTH], d2[SHA1_DIGEST_LENGTH];
	unsigned int i, j;
	unsigned int count;
	size_t r;

	if (rounds < 1 || key_len == 0)
		return -1;
	if (salt_len == 0 || salt_len > SIZE_MAX - 4)
		return -1;
	if ((asalt = malloc(salt_len + 4)) == NULL)
		return -1;

	memcpy(asalt, salt, salt_len);

	for (count = 1; key_len > 0; count++) {
		asalt[salt_len + 0] = (count >> 24) & 0xff;
		asalt[salt_len + 1] = (count >> 16) & 0xff;
		asalt[salt_len + 2] = (count >> 8) & 0xff;
		asalt[salt_len + 3] = count & 0xff;
		hmac_sha1(asalt, salt_len + 4, pass, pass_len, d1);
		memcpy(obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			hmac_sha1(d1, sizeof(d1), pass, pass_len, d2);
			memcpy(d1, d2, sizeof(d1));
			for (j = 0; j < sizeof(obuf); j++)
				obuf[j] ^= d1[j];
		}

		r = MINIMUM(key_len, SHA1_DIGEST_LENGTH);
		memcpy(key, obuf, r);
		key += r;
		key_len -= r;
	};
	explicit_bzero(asalt, salt_len + 4);
	free(asalt);
	explicit_bzero(d1, sizeof(d1));
	explicit_bzero(d2, sizeof(d2));
	explicit_bzero(obuf, sizeof(obuf));

	return 0;
}

static
int enif_pbkdf2_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

/* Errors */
static
ERL_NIF_TERM pbkdf2_error_tuple(ErlNifEnv *env, char *error_atom)
{
	return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error_atom));
}

static
ERL_NIF_TERM pbkdf2(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
    unsigned int rounds;
    int length;
    ErlNifBinary pass, salt;


    if ((argc != 4) || (!enif_inspect_binary(env, argv[0], &pass)) ||
        (!enif_inspect_binary(env, argv[1], &salt)) ||
        (!enif_get_uint(env, argv[2], &rounds)) ||
        (!enif_get_int(env, argv[3], &length)))
    {
        return enif_make_badarg(env);
    }


    ERL_NIF_TERM key_term;
    uint8_t *key;

    if ((key = enif_make_new_binary(env, length, &key_term)) == NULL)
    {
       return enif_make_badarg(env);
   }

    if ((pkcs5_pbkdf2((const unsigned char*)pass.data, pass.size,
        (const uint8_t* const)salt.data, salt.size,
        key, length, rounds)) != 0)
    {
        return pbkdf2_error_tuple(env, "pbkdf2_failed");
    }

    return enif_make_tuple2(env, enif_make_atom(env, "ok"), key_term);

}

static ErlNifFunc
nif_funcs[] =
{
    {"pbkdf2", 4, pbkdf2}
};

ERL_NIF_INIT(pbkdf2, nif_funcs, enif_pbkdf2_load, NULL, NULL, NULL);
