/*
 * spl_sboot.c
 */

#include <common.h>
#include <spl.h>
#include <sha1.h>
#include <fat.h>
#include <i2c.h>

#include <sboot.h>

/* spl_image defined in spl.c */
void spl_sboot_extend(void)
{
	uint32_t result;

	uint8_t csum[20];
	uint8_t out_digest[20];

	uint8_t image_buffer[SBOOT_SPL_READ_SIZE];
	uint32_t i;
	SHA1_CTX ctx;

	sha1_starts(&ctx);
	/* Only support MMC/FAT */
#if defined(CONFIG_SPL_MMC_SUPPORT) && defined(CONFIG_SPL_FAT_SUPPORT)
	for (i = 0; i * SBOOT_SPL_READ_SIZE < spl_image.size; ++i) {
		/* Consistent memory before read, take care of a short read */
		memset(image_buffer, 0, SBOOT_SPL_READ_SIZE);
		/* filename, start_at, buffer, max_size */
		result = file_fat_read_at(CONFIG_SPL_FAT_LOAD_PAYLOAD_NAME,
				i * SBOOT_SPL_READ_SIZE, image_buffer, SBOOT_SPL_READ_SIZE);
		if (result != 0) {
			puts("SPL: (sboot) error while reading image\n");
			return;
		}
		sha1_update(&ctx, image_buffer, SBOOT_SPL_READ_SIZE);
	}
#endif
	sha1_finish(&ctx, csum);

	result = sboot_extend(SBOOT_PCR_UBOOT, csum, out_digest);
	if (result != TPM_SUCCESS) {
		puts("SPL: (sboot) error while extending UBOOT PCR\n");
		return;
	}

	sha1_starts(&ctx);
	/* Extend EEPROM, support I2C only */
#ifdef CONFIG_ENV_EEPROM_IS_ON_I2C
	for (i = 0; i * SBOOT_SPL_READ_SIZE < CONFIG_SYS_I2C_EEPROM_SIZE; ++i) {
		memset(image_buffer, 0, SBOOT_SPL_READ_SIZE);
		if (i2c_read(CONFIG_SYS_I2C_EEPROM_ADDR, 0, CONFIG_SYS_I2C_EEPROM_ADDR_LEN,
				image_buffer, SBOOT_SPL_READ_SIZE)) {
			puts("SPL: (sboot) could not read the EEPROM\n");
			return;
		}
		sha1_update(&ctx, image_buffer, SBOOT_SPL_READ_SIZE);
	}
#endif
	sha1_finish(&ctx, csum);

	result = sboot_extend(SBOOT_PCR_CHIPSET_CONFIG, csum, out_digest);
	if (result != TPM_SUCCESS) {
		puts("SPL: (sboot) error while extending CHIPSET CONFIG PCR\n");
		return;
	}
}

void spl_sboot_check_image(void)
{
	uint8_t result;

#ifndef CONFIG_SBOOT_UBOOT_SEAL_INDEX
	puts("SPL: no uboot seal index defined\n");
	return;
#endif

	result = sboot_check(CONFIG_SBOOT_UBOOT_SEAL_INDEX);
	if (result != SBOOT_SUCCESS) {
		puts("SPL: failed to unseal UBOOT\n");
	}
}
