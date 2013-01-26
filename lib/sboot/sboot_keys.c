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


