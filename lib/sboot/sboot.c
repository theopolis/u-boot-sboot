/*
 * libsboot - U-Boot Trusted/Secured Boot implementation.
 * Author: Teddy Reed <teddy@prosauce.org>
 *
 * Sboot depends on libtlcl, a lite TSS based on tlcl from the Chromium Project's vboot.
 * The functions defined in libsboot are implemented in U-boot and optionally in SPL.
 */

#include <common.h>
#include <sha1.h>

#include <sboot.h>

#define	TPM_BASE						0
#define	TPM_INVALID_POSTINIT			(TPM_BASE+38)

/* TPM must be started, enabled, activated, and owned.
 *   If not owned, OSAP will return a key use error.
 */
__attribute__((unused))
uint8_t sboot_seal(const uint8_t *key, uint32_t keySize,
	uint32_t pcrMap, uint16_t nv_index)
{
	uint32_t result;

	uint32_t keyHandle;
	uint8_t keyAuth[20];
	uint8_t dataAuth[20];

	uint8_t blob[312];
	uint32_t blobSize;

	/* Max size of key */
	if (keySize > 96) {
		return SBOOT_DATA_ERROR;
	}

	/* Use SRK for encrypting */
	keyHandle = 0x40000000;

	/* default TPM passwords */
	memset(keyAuth, 0, 20);
	memset(dataAuth, 0, 20);

	result = TlclSealPCR(keyHandle, pcrMap, keyAuth, dataAuth,
		key, keySize, blob, &blobSize);

	if (result != TPM_SUCCESS) {
		/* problem */
		debug("sboot: failed to seal.");
		return SBOOT_TPM_ERROR;
	}

	debug("sboot: writing blob to nvram: %d\n", nv_index);

	result = TlclWrite(nv_index, blob, blobSize);
	if (result != TPM_SUCCESS) {
		debug("sboot: failed to write nvram\n");
		return SBOOT_TPM_ERROR;
	}

	return 0;
}

__attribute__((unused))
uint8_t sboot_seal_toggle(void)
{
	int result;

	result = setenv("sbootseal", "bootm");
	if (result != 0)
		return SBOOT_DATA_ERROR;
	return SBOOT_SUCCESS;
}

__attribute__((unused))
uint8_t sboot_seal_uboot(void)
{
	uint8_t result;

	uint32_t pcrMap;
	uint8_t key[20];

	/* Create bitmap of PCR registers to seal on */
	pcrMap = 0 + (1 << SBOOT_PCR_UBOOT) + (1 << SBOOT_PCR_CHIPSET_CONFIG);

	memset(key, SBOOT_SEAL_WELL_KNOWN_KEY, 20);
	result = sboot_seal(key, 20, pcrMap, SBOOT_NV_INDEX_SEAL_UBOOT);

	return result;
}

__attribute__((unused))
uint8_t sboot_seal_default(void)
{
	uint8_t result;

	uint32_t pcrMap;
	uint8_t key[20];

	/* Create bitmap of PCR registers to seal on */
	pcrMap = 0 + (1 << SBOOT_PCR_UBOOT) + (1 << SBOOT_PCR_CHIPSET_CONFIG) +
		(1 << SBOOT_PCR_KERNEL);
	/* Only add PCRs if measuring environment and console. */
#ifndef CONFIG_SBOOT_UBOOT_DISABLE_ENV_EXTEND
	pcrMap += (1 << SBOOT_PCR_UBOOT_ENVIRONMENT);
#endif
#ifndef CONFIG_SBOOT_UBOOT_DISABLE_CONSOLE_EXTEND
	pcrMap += (1 << SBOOT_PCR_UBOOT_CONSOLE);
#endif

	memset(key, SBOOT_SEAL_WELL_KNOWN_KEY, 20);
	result = sboot_seal(key, 20, pcrMap, SBOOT_NV_INDEX_SEAL_OS);

	return result;
}

uint8_t sboot_unseal(const uint8_t *sealData, uint32_t sealDataSize,
	uint8_t *unsealData, uint32_t *unsealDataSize)
{
	uint32_t result;

	uint8_t keyAuth[20];
	uint8_t dataAuth[20];

	/* Use WK-password for SRK and data */
	memset(keyAuth, 0, 20);
	memset(dataAuth, 0, 20);
	result = TlclUnseal(0x40000000, keyAuth, dataAuth,
		sealData, sealDataSize, unsealData, unsealDataSize);
	if (result != TPM_SUCCESS) {
		debug("sboot: failed to unseal data\n");
		return SBOOT_DATA_ERROR;
	}

	return SBOOT_SUCCESS;
}

uint8_t sboot_init(void)
{
	uint32_t tpm_result;

	TSS_BOOL disabled, deactivated, nvlocked;
	uint32_t permissions;

	tpm_result = TlclLibInit();
	if (tpm_result != TPM_SUCCESS) {
		goto error;
	}

	tpm_result = TlclStartup();
	if (tpm_result != TPM_SUCCESS && tpm_result != TPM_INVALID_POSTINIT) {
		/* Invalid Postinit is returned if TPM is already started */
		goto error;
	}

	TlclSelfTestFull(); /* Required by some TPMs */
	TlclSetNvLocked(); /* Enforce security controls on NVRAM. */
	TlclGetFlags(&disabled, &deactivated, &nvlocked);

	if (disabled == 1 || deactivated == 1) {
		/* TPM is deactivated or disabled, possibly try to enable/activate */
		/* Todo: SBOOT should return an error notifying the implementor to
		 * configure (enable/activate) their TPM
		 */
		/* Todo: Set enabled and activated, then try again. */
		debug("sboot: the TPM is disabled or deactived.\n");
		goto error;
	}

	if (nvlocked != 1) {
		/* TPM's NVRAM is not locked, meaning there is no read/write control
		 * enforcement. SBOOT can set GlobalLock, but the Owner should also
		 * be set (which should happen external to SBOOT). If the Owner is set
		 * then the defined NVRAM indexes need to be defined with PPREAD|PPWRITE.
		 */
		debug("sboot: the TPM's NVRAM is not locked.\n");
		goto error;
	}

	/* Check NVRAM indexes and permissions, the permissions must be PPREAD|PPWRITE */
	tpm_result = TlclGetPermissions(SBOOT_NV_INDEX_SEAL_UBOOT, &permissions);
	if (tpm_result != TPM_SUCCESS) {
		debug("sboot: failed to get permissions for NVRAM UBOOT_SEAL index\n");
		goto error;
	}
	if (permissions != (TPM_NV_PER_PPWRITE|TPM_NV_PER_PPREAD)) {
		debug("sboot: NVRAM permissions for UBOOT_SEAL are incorrect (perm=%d)\n", permissions);
		goto error;
	}

	TlclGetPermissions(SBOOT_NV_INDEX_SEAL_OS, &permissions);
	if (tpm_result != TPM_SUCCESS) {
		debug("sboot: failed to get permissions for NVRAM OS_SEAL index\n");
		goto error;
	}
	if (permissions != (TPM_NV_PER_PPWRITE|TPM_NV_PER_PPREAD)) {
		debug("sboot: NVRAM permissions for OS_SEAL are incorrect (perm=%d)\n", permissions);
		goto error;
	}

	/* Physical presence must match the security controls on NVRAM. */
	TlclAssertPhysicalPresence();

error:
	if (tpm_result != TPM_SUCCESS) {
		puts("sboot: Failed to initialize TPM (please read the SBOOT documentation).\n");
		return SBOOT_TPM_ERROR;
	}

	return SBOOT_SUCCESS;
}

/* Read seal data containing 268 bytes (20byte encrypted hash) from TPM NV ram.
 * Try to unseal (verifying correct PCR values).
 */
uint8_t sboot_check(uint16_t nv_index)
{
	uint32_t result;

	uint32_t unsealDataSize;
	uint8_t sealData[312];
	uint8_t unsealData[20];

	result = TlclRead(nv_index, sealData, 312);
	if (result != TPM_SUCCESS) {
		debug("sboot: failed to read seal data from %d\n", nv_index);

		sboot_finish();
		return SBOOT_TPM_ERROR;
	}

	result = sboot_unseal(sealData, 312, unsealData, &unsealDataSize);
	if (result != SBOOT_SUCCESS) {
		sboot_finish();
		return result;
	}

	/* no need to check unsealed data */

	return TPM_SUCCESS;
}

__attribute__((unused))
uint8_t sboot_check_default(void)
{
	return sboot_check(SBOOT_NV_INDEX_SEAL_OS);
}

__attribute__((unused))
uint8_t sboot_extend(uint16_t pcr, const uint8_t* in_digest, uint8_t* out_digest)
{
	uint32_t result;

	result = TlclExtend(pcr, in_digest, out_digest);
	if (result != TPM_SUCCESS)
		return SBOOT_TPM_ERROR;

	return 0;
}

__attribute__((unused))
uint8_t sboot_extend_console(const char *buffer, uint32_t size)
{
	uint32_t result;

	uint8_t digest[20], out_digest[20];
	SHA1_CTX ctx;

	debug("SBOOT: extending console with %s (size=%d)\n", buffer, size);

	sha1_starts(&ctx); /* could be 1 function, sha1_csum */
	sha1_update(&ctx, (const unsigned char*) buffer, size);
	sha1_finish(&ctx, digest);

	result = sboot_extend(SBOOT_PCR_UBOOT_CONSOLE, digest, out_digest);
	return result;
}

__attribute__((unused))
uint8_t sboot_extend_environment(const char *buffer, uint32_t size)
{
	uint32_t result;

	uint8_t digest[20], out_digest[20];
	SHA1_CTX ctx;

	debug("SBOOT: extending env with %s (size=%d)\n", buffer, size);

	sha1_starts(&ctx); /* could be 1 function, sha1_csum */
	sha1_update(&ctx, (const unsigned char*) buffer, size);
	sha1_finish(&ctx, digest);

	result = sboot_extend(SBOOT_PCR_UBOOT_ENVIRONMENT, digest, out_digest);
	return result;
}

__attribute__((unused))
uint8_t sboot_read_kernel(const uint8_t* in_digest)
{
	return 0;
}

__attribute__((unused))
uint8_t sboot_lock_pcrs(void)
{
	uint8_t lockNonce[20]; /* should be TPM_NONCE_SIZE */
	uint32_t size;
	uint8_t output[20];

	TlclGetRandom(lockNonce, 20, &size);

	sboot_extend(SBOOT_PCR_UBOOT, lockNonce, output);
	sboot_extend(SBOOT_PCR_CHIPSET_CONFIG, lockNonce, output);
	sboot_extend(SBOOT_PCR_UBOOT_ENVIRONMENT, lockNonce, output);
	sboot_extend(SBOOT_PCR_UBOOT_CONSOLE, lockNonce, output);
	sboot_extend(SBOOT_PCR_UBOOT_MEMORY, lockNonce, output);
	sboot_extend(SBOOT_PCR_KERNEL, lockNonce, output);
	return 0;
}

__attribute__((unused))
uint8_t sboot_finish(void)
{
	/* Remove PP, thus locking READ/WRITE to NVRAM. */
	sboot_lock_pcrs();
	TlclLockPhysicalPresence();

	return 0;
}
