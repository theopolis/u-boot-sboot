/*
 * libsboot - U-Boot Trusted/Secured Boot implementation.
 * Author: Teddy Reed <teddy@prosauce.org>
 *
 * Sboot depends on libtlcl, a lite TSS based on tlcl from the Chromium Project's vboot.
 * The functions defined in libsboot are implemented in U-boot and optionally in SPL.
 *
 * Sboot_keys includes functions for storing verified public keys used by SPL
 * and U-Boot to verify and seal an updated secured boot.
 *
 * To create your public key using the TPM (for SPL to use):
 *   $ ./createkey -kt s -pwdk password1 -ok /tmp/sboot_key -hp 40000000
 * or without the TPM:
 *   $ openssl genrsa -out /tmp/sboot_key.pem 2048
 *   $ openssl rsa -pubout -in /tmp/sboot_key.pem -out /tmp/sboot_key.pub
 * then extract the public key:
 *   $ ./rsa_pubkey -pub /tmp/sboot_key.pub > /tmp/pubkey.raw
 *
 * To sign using the TPM:
 *   $ ./loadkey -hp 40000000 -ik /tmp/sboot_key.pem -pwdz
 *   $ ./signfile -hk <key handle of loaded key> -if <file> -of <file>.sig -pwdk password1
 * or to sign without the TPM:
 *   $ echo -n "<sha1sum of file>" | openssl rsautl -encrypt -inkey /tmp/sboot_key.pem > <file>.sig
 *
 * If CONFIG_SBOOT_AUTO_UPDATES is enabled:
 *   CONFIG_SBOOT_KEYSTORE_INDEX must be defined as PPREAD/PPWRITE.
 *   CONFIG_SBOOT_KEYSTORE_LENGTH optionally allows > 1 keys in NVRAM.
 *
 *   Then SPL/Sboot will look for the optional files u-boot.update and
 *   u-boot.update.sig, where u-boot.update.sig is a signed SHA1 hash of
 *   u-boot.update (signed by a keypair loaded in Sboot/Keystore).
 *   If they exist, SPL/Sboot will attempt the verify the PKCS#1.5 RSA
 *   signature in u-boot.update.sig. On success, SPL/Sboot will measure
 *   and load u-boot.update.
 *
 *   The same is true for U-boot/Sboot and the files:
 *     uImage.update, uImage.update.sig
 *     etc...
 *
 * To implement this signature checking, the application needs to choose to read
 * <file>.sig then call:
 *   sboot_verify_digest(signature, digest)
 *   sboot_verify_data(signature, start, size)
 * Where for digest, the SHA1 sum is pre-computed and passed as an argument, and for data
 * a start memory address and size are given, and the SHA1 sum is computed.
 *
 */

#include <common.h>
#include <crypto.h>
#include <sha1.h>
#include <malloc.h>

#include <sboot.h>

#define SBOOT_MAX_PASS 256
#define SBOOT_SIG_ALGORITHM 3

__attribute__((unused))
uint8_t sboot_verify_digest(const uint8_t *signature, const uint8_t *digest)
{
	RSAPublicKey key;
	uint32_t sig_size;
	uint16_t nv_index;

	uint8_t result = SBOOT_DATA_ERROR;

#ifndef CONFIG_SBOOT_KEYSTORE_INDEX
	return result;
#else
	nv_index = CONFIG_SBOOT_KEYSTORE_INDEX;
	result = sboot_signature_key(nv_index, &key);
#endif
	if (result != SBOOT_SUCCESS)
		return SBOOT_DATA_ERROR;

	/* Only support algorithm 3, 2048-bit key and SHA1 */
	sig_size = siglen_map[SBOOT_SIG_ALGORITHM];

	result = RSAVerify(&key, signature, sig_size, SBOOT_SIG_ALGORITHM, digest);

	/* RSAVerify returns 1 on success */
	return (result == 1) ? SBOOT_SUCCESS : SBOOT_DATA_ERROR;
}

__attribute__((unused))
uint8_t sboot_verify_data(const uint8_t *signature, const uint8_t *start, uint32_t size)
{
	uint8_t digest[20];
	SHA1_CTX ctx;

	sha1_starts(&ctx); /* could be 1 function, sha1_csum */
	sha1_update(&ctx, (const unsigned char*) start, size);
	sha1_finish(&ctx, digest);

	return sboot_verify_digest(signature, digest);
}

__attribute__((unused))
uint8_t sboot_signature_key(uint16_t nv_index, RSAPublicKey *key)
{
	uint32_t key_size;
	uint32_t result;
	uint8_t *buf;

	key->n = NULL;
	key->rr = NULL;
	key->len = 0;
	key->algorithm = 0;

	/* Read stored data size, respect endianess */
	result = TlclRead(nv_index, &key_size, sizeof(key->len));
	if (result != TPM_SUCCESS) {
		printf("sboot: failed to read public key length from %d\n", nv_index);
		return SBOOT_TPM_ERROR;
	}
	key_size /= 64;

	buf = (uint8_t*) malloc(sizeof(uint32_t) * 2 + key_size * 2);
	result = TlclRead(nv_index, buf, sizeof(uint32_t) * 2 + key_size * 2);
	if (result != TPM_SUCCESS) {
		printf("sboot: failed to read public key from %d (size=%d)\n", nv_index, key_size);
		return SBOOT_TPM_ERROR;
	}

	/* Sanity check the key size, can only support 1024, 2048 */
	if (RSA1024NUMBYTES != key_size && RSA2048NUMBYTES != key_size) {
		printf("sboot: incorrect key size for public key\n");
		key->len = 0;
		return SBOOT_DATA_ERROR;
	}

	memcpy(&key->n0inv, buf + sizeof(uint32_t), sizeof(key->n0inv));
	key->n = (uint32_t*) malloc(key_size);
	memcpy(&key->n, buf + sizeof(uint32_t) * 2, key_size);
	key->rr = (uint32_t*) malloc(key_size);
	memcpy(&key->rr, buf + sizeof(uint32_t) * 2 + key_size, key_size);

	return SBOOT_SUCCESS;
}

/* not used, just an FYI */
void sboot_getpass(uint8_t *pass, uint32_t *pass_size)
{
	uint8_t *pass_p = pass;
	uint32_t size = 0;
	uint8_t c;

	if (pass == NULL) {
		return;
	}

	for (;;) {
		c = getc();

		switch (c) {
		/* Enter, finished typing password */
		case '\r':
		case '\n':
		case '\0':
			*pass_p = '\0';
			puts("\r\n");
			*pass_size = size;
			return;
		/* Break, discard input */
		case 0x03:
			while (size > 0) {
				*(--pass_p) = '\0';
				--size;
			}
			*pass_size = 0;
			return;
		/* ^U, erase line or ^W, erase word */
		case 0x15:
			while (size > 0) {
				*(--pass_p) = '\0';
				--size;
			}
			continue;
		case 0x08:
		case 0x7F:
			if (size > 0) {
				*(--pass_p) = '\0';
				--size;
			}
			continue;
		default:
			*pass_p++ = c;
			++size;
			break;
		}

		if (size >= SBOOT_MAX_PASS)
			*pass_size = size;
			puts("\r\n");
			return;
	}
}
