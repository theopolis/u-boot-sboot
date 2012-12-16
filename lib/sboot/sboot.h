/* Secure Boot implemented with a Static Root of Trust Measurement (SRTM).
 * The Static Root is assuming to be implemented in SPL (Second Phase Loader),
 * thus we can implement a trusted or secure boot with relying on chip or board
 * manufactures. The implementor must ensure the SPL executes from Read-Only NV storage.
 *
 * BeagleBone implementation of SRTM using SPL:
 * 	 Public ROM (operating in public-CPU mode) boots from a hard-order: mmc0, spi0, uart0, usb0.
 * 	 By loading SPL on MMC0, and pulling the WP pin on MMC0 high we prevent modification to the SPL.
 * 	 (This can also be implemented using spi0, or uart0, without attaching an MMC0.)
 * 	 U-Boot, boot configuration data (i.e., uEnv.txt), kernel, and disk are located on MMC1.
 *
 * TPM Operations (Baseline Trusted Boot Components):
 *   SPL: sboot_init() -> initialize TPM, run SelfTest, enable physical presence
 *   SPL: sboot_read_uboot() -> PCR Extend for load loader
 *   UBT: sboot_read_bootoptions() -> PCR Extend for boot configuration data
 *   UBT: sboot_read_kernel() -> PCR Extend for Linux kernel
 *   UBT: sboot_seal() -> Save PCR context using Skey^i to trusted store
 *   	- verify key can be used for secure storage
 *   	- create context using key and PCR values (uboot, config, kernel)
 *   	- generate symmetric encryption key (FSkey) for filesystem
 *   	- encrypt, store, and return FSkey
 *   	- optionally encrypt FS on MMC1
 *
 * TPM Operations (Booting Securely):
 *   SPL: sboot_init() -> initialize TPM, run SelfTest, enable physical presence
 *   SPL: sboot_read_uboot() -> PCR Extend for boot loader
 *   	- read u-boot binary from mmc1
 *   	- calculate SHA1, extend SBOOT_PCR_UBOOT
 *   UBT: sboot_read_bootoptions() -> PCR Extend for boot configuration data
 *   	- read uEnv.txt from mmc1
 *   	- calculate SHA1, extend SBOOT_PCR_UBOOT
 *   UBT: sboot_read_kernel() -> PCR Extend for Linux kernel
 *   	- read uImage from mmc1
 *   	- calculate SHA1, extend SBOOT_PCR_KERNEL
 *   KRN: sboot_unseal() -> [or UBT] Decrypt filesystem symmetric encryption key.
 *   	- use SKey^i and PCRs to unseal protected storage
 *   KRN: sboot_lock_pcrs() -> extend all used PCRs with random data
 *   KRN: sboot_finish() -> optionally remove physical presence
 *
 */
#ifndef SBOOT_H_
#define SBOOT_H_

#include <common.h>
#include <tpm.h>

/* From vboot */
#include <tlcl.h>

/* TSS-defined (section here) PCR locations for UBOOT and OS Kernel */
#define SBOOT_PCR_UBOOT 0x3
#define SBOOT_PCR_KERNEL 0x4

/* may not be exposed */
static uint8_t sboot_seal(void);
static uint8_t sboot_unseal(void);

/* Initialization steps needed for TPM:
 * 	TlclStartup()
 * 	TlclSelfTestFull() //optional
 * 	TlclAssertPhysicalPresence() //this is implicit for SPL
 */
static uint8_t sboot_init(void);

static uint8_t sboot_check(void);

/* Performs a TlclExtend (TPM PCR Extend) with the given 20 byte hash */
static uint8_t sboot_extend(uint8_t pcr, const uint8_t* in_digest, uint8_t* out_digest);

static uint8_t sboot_read_uboot(const uint8_t* in_digest);
static uint8_t sboot_read_kernel(const uint8_t* in_digest);
static uint8_t sboot_read_bootoptions(const uint8_t* in_digest);

/* After system is booted, lock PCRS by extending with random data. */
static uint8_t sboot_lock_pcrs(void);

/* May turn off physical presence, may allow for a trusted boot instead of secure. */
static uint8_t sboot_finish(void);

#endif /* SBOOT_H_ */
