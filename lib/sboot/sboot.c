/* Lite implementation of a secured boot using Chromium vboot architecture. */

/* From u-boot */
#include "sboot.h"

static uint8_t sboot_seal(void)
{
	/* Architecture question, should this be implemented in vboot's TPM lib? */
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
