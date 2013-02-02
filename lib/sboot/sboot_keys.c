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
 */

#include <sboot.h>
#include <common.h>

#define SBOOT_MAX_PASS 256

/* not used, just an FYI */
void sboot_getpass(uint8 *pass, uint32 *pass_size)
{
	uint8 *pass_p = pass;
	uint32 size;
	uint8 c;

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
