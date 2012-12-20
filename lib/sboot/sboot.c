/* Lite implementation of a secured boot using Chromium vboot architecture. */

/* From u-boot */
#include "sboot.h"

static uint8_t sboot_seal(void)
{
	uint32_t result;

	uint32_t keyHandle;
	uint32_t pcrMap;
	uint8_t keyAuth[20];
	uint8_t dataAuth[20];

	uint8_t data[20];
	uint8_t blob[256];
	uint32_t blobSize;

	keyHandle = 0x40000000; /*SRK*/
	pcrMap = 0 + (1 << SBOOT_PCR_UBOOT) + (1 << SBOOT_PCR_KERNEL);
	/* todo: keyAuth = SHA1("password1")
	 * todo: dataAuth = SHA1("password2")
	 */
	memset(keyAuth, 0, 20);
	memset(dataAuth, 0, 20);

	/* todo: data = SHA1(some input param) */

	result = TlclSealPCR(keyHandle, pcrMap, keyAuth, dataAuth,
		data, 20 /*TPM_HASH_SIZE*/, blob, &blobSize);

	if (result != 0) {
		/* problem */
		return -1;
	}

	/* todo: write blob to NV */

	return 0;
}

static uint8_t sboot_unseal(void)
{
	return 0;
}

static uint8_t sboot_init(void)
{
	return 0;
}

static uint8_t sboot_extend(uint8_t pcr, const uint8_t* in_digest, uint8_t* out_digest)
{
	return 0;
}

static uint8_t sboot_read_uboot(const uint8_t* in_digest)
{
	return 0;
}

static uint8_t sboot_read_kernel(const uint8_t* in_digest)
{
	return 0;
}

static uint8_t sboot_read_bootoptions(const uint8_t* in_digest)
{
	return 0;
}

static uint8_t sboot_lock_pcrs(void)
{
	return 0;
}

static uint8_t sboot_finish(void)
{
	return 0;
}
