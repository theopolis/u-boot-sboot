/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* A lightweight TPM command library.
 *
 * The general idea is that TPM commands are array of bytes whose
 * fields are mostly compile-time constant.  The goal is to build much
 * of the commands at compile time (or build time) and change some of
 * the fields at run time as needed.  The code in
 * utility/tlcl_generator.c builds structures containing the commands,
 * as well as the offsets of the fields that need to be set at run
 * time.
 */

#include <tlcl.h>
#include <sha1.h>
#include <malloc.h>

#include "oiaposap.h"
#include "tlcl_internal.h"
#include "tlcl_structures.h"

#undef _DEBUG
#define _DEBUG 1

#ifdef EXTRA_LOGGING
static void inline DATA_DEBUG(const char *label, const uint8_t *data, uint32_t size) {
	uint16_t i;

	debug("[TPM] %s ", label);
	for (i=0; i<size && i < size; ++i) {
		debug("%x ", data[i]);
		if (i % 20 == 0 && i != 0) {
			printf("\n%d:\t ", i);
		}
	}
	debug("\n");
}
#else
static void inline DATA_DEBUG(const char *label, const uint8_t *data, uint32_t size) {
	/* nothing */
}
#endif

/* Sets the size field of a TPM command. */
static inline void SetTpmCommandSize(uint8_t* buffer, uint32_t size) {
  ToTpmUint32(buffer + sizeof(uint16_t), size);
}

/* Gets the size field of a TPM command. */
__attribute__((unused)) static inline int TpmCommandSize(const uint8_t* buffer) {
  uint32_t size;
  FromTpmUint32(buffer + sizeof(uint16_t), &size);
  return (int) size;
}

/* Gets the code field of a TPM command. */
static inline int TpmCommandCode(const uint8_t* buffer) {
  uint32_t code;
  FromTpmUint32(buffer + sizeof(uint16_t) + sizeof(uint32_t), &code);
  return code;
}

/* Gets the return code field of a TPM result. */
static inline int TpmReturnCode(const uint8_t* buffer) {
  return TpmCommandCode(buffer);
}

/* Like TlclSendReceive below, but do not retry if NEEDS_SELFTEST or
 * DOING_SELFTEST errors are returned.
 */
static uint32_t TlclSendReceiveNoRetry(const uint8_t* request,
                                       uint8_t* response, int max_length) {

  uint32_t response_length = max_length;
  uint32_t result;

#ifdef EXTRA_LOGGING
  debug("TPM: command: %x %x, %x %x %x %x, %x %x %x %x (%d)\n",
           request[0], request[1],
           request[2], request[3], request[4], request[5],
           request[6], request[7], request[8], request[9], TpmCommandSize(request));
  if (TpmCommandSize(request) > 10)
	  DATA_DEBUG("and: ", request+10, TpmCommandSize(request)-10);
#endif

  result = tis_sendrecv(request, TpmCommandSize(request),
                              response, &response_length);
  if (0 != result) {
    /* Communication with TPM failed, so response is garbage */
    debug("TPM: command 0x%x send/receive failed: 0x%x\n",
             TpmCommandCode(request), result);
    return result;
  }
  /* Otherwise, use the result code from the response */
  result = TpmReturnCode(response);

  /* TODO: add paranoia about returned response_length vs. max_length
   * (and possibly expected length from the response header).  See
   * crosbug.com/17017 */

#ifdef EXTRA_LOGGING
  debug("TPM: response: %x %x, %x %x %x %x, %x %x %x %x (%d)\n",
           response[0], response[1],
           response[2], response[3], response[4], response[5],
           response[6], response[7], response[8], response[9], TpmCommandSize(response));
  if (TpmCommandSize(response) > 10)
	  DATA_DEBUG("and: ", response+10, TpmCommandSize(response)-10);
#endif

  debug("TPM: command 0x%x returned 0x%x\n", TpmCommandCode(request), result);

  return result;
}


/* Sends a TPM command and gets a response.  Returns 0 if success or the TPM
 * error code if error. In the firmware, waits for the self test to complete
 * if needed. In the host, reports the first error without retries. */
uint32_t TlclSendReceive(const uint8_t* request, uint8_t* response,
                                int max_length) {
  uint32_t result = TlclSendReceiveNoRetry(request, response, max_length);
  /* When compiling for the firmware, hide command failures due to the self
   * test not having run or completed. */
#ifndef CHROMEOS_ENVIRONMENT
  /* If the command fails because the self test has not completed, try it
   * again after attempting to ensure that the self test has completed. */
  if (result == TPM_E_NEEDS_SELFTEST || result == TPM_E_DOING_SELFTEST) {
    result = TlclContinueSelfTest();
    if (result != TPM_SUCCESS) {
      return result;
    }
#if defined(TPM_BLOCKING_CONTINUESELFTEST) || defined(VB_RECOVERY_MODE)
    /* Retry only once */
    result = TlclSendReceiveNoRetry(request, response, max_length);
#else
    /* This needs serious testing.  The TPM specification says: "iii. The
     * caller MUST wait for the actions of TPM_ContinueSelfTest to complete
     * before reissuing the command C1."  But, if ContinueSelfTest is
     * non-blocking, how do we know that the actions have completed other than
     * trying again? */
    do {
      result = TlclSendReceiveNoRetry(request, response, max_length);
    } while (result == TPM_E_DOING_SELFTEST);
#endif
  }
#endif  /* ! defined(CHROMEOS_ENVIRONMENT) */
  return result;
}

/* Sends a command and returns the error code. */
uint32_t Send(const uint8_t* command) {
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  return TlclSendReceive(command, response, sizeof(response));
}

/* Exported functions. */

uint32_t TlclLibInit(void) {
	if (tis_init()) {
		return -1;
	}

	return tis_open();
}

uint32_t TlclLibClose(void) {
  return tis_close();
}

uint32_t TlclStartup(void) {
  debug("TPM: Startup\n");
  TlclLibInit();
  return Send(tpm_startup_cmd.buffer);
}

uint32_t TlclSaveState(void) {
  debug("TPM: SaveState\n");
  return Send(tpm_savestate_cmd.buffer);
}

uint32_t TlclResume(void) {
  debug("TPM: Resume\n");
  return Send(tpm_resume_cmd.buffer);
}

uint32_t TlclSelfTestFull(void) {
  debug("TPM: Self test full\n");
  return Send(tpm_selftestfull_cmd.buffer);
}

uint32_t TlclContinueSelfTest(void) {
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  debug("TPM: Continue self test\n");
  /* Call the No Retry version of SendReceive to avoid recursion. */
  return TlclSendReceiveNoRetry(tpm_continueselftest_cmd.buffer,
                                response, sizeof(response));
}

uint32_t TlclDefineSpace(uint32_t index, uint32_t perm, uint32_t size) {
  struct s_tpm_nv_definespace_cmd cmd;
  debug("TPM: TlclDefineSpace(0x%x, 0x%x, %d)\n", index, perm, size);
  memcpy(&cmd, &tpm_nv_definespace_cmd, sizeof(cmd));
  ToTpmUint32(cmd.buffer + tpm_nv_definespace_cmd.index, index);
  ToTpmUint32(cmd.buffer + tpm_nv_definespace_cmd.perm, perm);
  ToTpmUint32(cmd.buffer + tpm_nv_definespace_cmd.size, size);
  return Send(cmd.buffer);
}

uint32_t TlclWrite(uint32_t index, const void* data, uint32_t length) {
  struct s_tpm_nv_write_cmd cmd;
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  const int total_length =
    kTpmRequestHeaderLength + kWriteInfoLength + length;

  debug("TPM: TlclWrite(0x%x, %d)\n", index, length);
  memcpy(&cmd, &tpm_nv_write_cmd, sizeof(cmd));
  assert(total_length <= TPM_LARGE_ENOUGH_COMMAND_SIZE);
  SetTpmCommandSize(cmd.buffer, total_length);

  ToTpmUint32(cmd.buffer + tpm_nv_write_cmd.index, index);
  ToTpmUint32(cmd.buffer + tpm_nv_write_cmd.length, length);
  memcpy(cmd.buffer + tpm_nv_write_cmd.data, data, length);

  return TlclSendReceive(cmd.buffer, response, sizeof(response));
}

uint32_t TlclRead(uint32_t index, void* data, uint32_t length) {
  struct s_tpm_nv_read_cmd cmd;
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  uint32_t result_length;
  uint32_t result;

  debug("TPM: TlclRead(0x%x, %d)\n", index, length);
  memcpy(&cmd, &tpm_nv_read_cmd, sizeof(cmd));
  ToTpmUint32(cmd.buffer + tpm_nv_read_cmd.index, index);
  ToTpmUint32(cmd.buffer + tpm_nv_read_cmd.length, length);

  result = TlclSendReceive(cmd.buffer, response, sizeof(response));
  if (result == TPM_SUCCESS && length > 0) {
    uint8_t* nv_read_cursor = response + kTpmResponseHeaderLength;
    FromTpmUint32(nv_read_cursor, &result_length);
    nv_read_cursor += sizeof(uint32_t);
    memcpy(data, nv_read_cursor, result_length);
  }

  return result;
}

/* read PCR i into data, not sure about index */
uint32_t TlclPCRRead(uint32_t index, void* data, uint32_t length) {
  struct s_tpm_nv_read_cmd cmd;
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  uint32_t result;

  debug("TPM: TlclPCRRead(0x%x, %d)\n", index, length);
  if (length < kPcrDigestLength) {
    return TPM_E_IOERROR;
  }
  memcpy(&cmd, &tpm_pcr_read_cmd, sizeof(cmd));
  ToTpmUint32(cmd.buffer + tpm_pcr_read_cmd.pcrNum, index);

  result = TlclSendReceive(cmd.buffer, response, sizeof(response));
  if (result == TPM_SUCCESS) {
    uint8_t* pcr_read_cursor = response + kTpmResponseHeaderLength;
    memcpy(data, pcr_read_cursor, kPcrDigestLength);
  }

  return result;
}

uint32_t TlclWriteLock(uint32_t index) {
  debug("TPM: Write lock 0x%x\n", index);
  return TlclWrite(index, NULL, 0);
}

uint32_t TlclReadLock(uint32_t index) {
  debug("TPM: Read lock 0x%x\n", index);
  return TlclRead(index, NULL, 0);
}

uint32_t TlclAssertPhysicalPresence(void) {
  debug("TPM: Asserting physical presence\n");
  return Send(tpm_ppassert_cmd.buffer);
}

uint32_t TlclPhysicalPresenceCMDEnable(void) {
  debug("TPM: Enable the physical presence command\n");
  return Send(tpm_ppenable_cmd.buffer);
}

uint32_t TlclFinalizePhysicalPresence(void) {
  debug("TPM: Enable PP cmd, disable HW pp, and set lifetime lock\n");
  return Send(tpm_finalizepp_cmd.buffer);
}

uint32_t TlclAssertPhysicalPresenceResult(void) {
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  return TlclSendReceive(tpm_ppassert_cmd.buffer, response, sizeof(response));
}

uint32_t TlclLockPhysicalPresence(void) {
  debug("TPM: Lock physical presence\n");
  return Send(tpm_pplock_cmd.buffer);
}

uint32_t TlclSetNvLocked(void) {
  debug("TPM: Set NV locked\n");
  return TlclDefineSpace(TPM_NV_INDEX_LOCK, 0, 0);
}

int TlclIsOwned(void) {
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE + TPM_PUBEK_SIZE];
  uint32_t result;
  result = TlclSendReceive(tpm_readpubek_cmd.buffer,
                           response, sizeof(response));
  return (result != TPM_SUCCESS);
}

uint32_t TlclForceClear(void) {
  debug("TPM: Force clear\n");
  return Send(tpm_forceclear_cmd.buffer);
}

uint32_t TlclSetEnable(void) {
  debug("TPM: Enabling TPM\n");
  return Send(tpm_physicalenable_cmd.buffer);
}

uint32_t TlclClearEnable(void) {
  debug("TPM: Disabling TPM\n");
  return Send(tpm_physicaldisable_cmd.buffer);
}

uint32_t TlclSetDeactivated(uint8_t flag) {
  struct s_tpm_physicalsetdeactivated_cmd cmd;
  debug("TPM: SetDeactivated(%d)\n", flag);
  memcpy(&cmd, &tpm_physicalsetdeactivated_cmd, sizeof(cmd));
  *(cmd.buffer + cmd.deactivated) = flag;
  return Send(cmd.buffer);
}

uint32_t TlclGetPermanentFlags(TPM_PERMANENT_FLAGS* pflags) {
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  uint32_t size;
  uint32_t result =
    TlclSendReceive(tpm_getflags_cmd.buffer, response, sizeof(response));
  if (result != TPM_SUCCESS)
    return result;
  FromTpmUint32(response + kTpmResponseHeaderLength, &size);

  /* Edge-case, chip supports less than len(FLAGS). */
  memset(pflags, 0, sizeof(TPM_PERMANENT_FLAGS));
  memcpy(pflags,
         response + kTpmResponseHeaderLength + sizeof(size),
         size);
  return result;
}

uint32_t TlclGetSTClearFlags(TPM_STCLEAR_FLAGS* vflags) {
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  uint32_t size;
  uint32_t result =
    TlclSendReceive(tpm_getstclearflags_cmd.buffer, response, sizeof(response));
  if (result != TPM_SUCCESS)
    return result;
  FromTpmUint32(response + kTpmResponseHeaderLength, &size);
  /* Ugly assertion, but the struct is padded up by one byte. */
  assert(size == 7 && sizeof(TPM_STCLEAR_FLAGS) - 1 == 7);
  memcpy(vflags,
         response + kTpmResponseHeaderLength + sizeof(size),
         sizeof(TPM_STCLEAR_FLAGS));
  return result;
}

uint32_t TlclGetFlags(uint8_t* disable,
                      uint8_t* deactivated,
                      uint8_t *nvlocked) {
  TPM_PERMANENT_FLAGS pflags;
  uint32_t result = TlclGetPermanentFlags(&pflags);
  if (result == TPM_SUCCESS) {
    if (disable)
      *disable = pflags.disable;
    if (deactivated)
      *deactivated = pflags.deactivated;
    if (nvlocked)
      *nvlocked = pflags.nvLocked;
    debug("TPM: Got flags disable=%d, deactivated=%d, nvlocked=%d\n",
             pflags.disable, pflags.deactivated, pflags.nvLocked);
  }
  return result;
}

uint32_t TlclSetGlobalLock(void) {
  uint32_t x;
  debug("TPM: Set global lock\n");
  return TlclWrite(TPM_NV_INDEX0, (uint8_t*) &x, 0);
}

uint32_t TlclExtend(int pcr_num, const uint8_t* in_digest,
                    uint8_t* out_digest) {
  struct s_tpm_extend_cmd cmd;
  uint8_t response[kTpmResponseHeaderLength + kPcrDigestLength];
  uint32_t result;

  memcpy(&cmd, &tpm_extend_cmd, sizeof(cmd));
  ToTpmUint32(cmd.buffer + tpm_extend_cmd.pcrNum, pcr_num);
  memcpy(cmd.buffer + cmd.inDigest, in_digest, kPcrDigestLength);

  result = TlclSendReceive(cmd.buffer, response, sizeof(response));
  if (result != TPM_SUCCESS)
    return result;

  memcpy(out_digest, response + kTpmResponseHeaderLength, kPcrDigestLength);
  return result;
}

uint32_t TlclGetPermissions(uint32_t index, uint32_t* permissions) {
  struct s_tpm_getpermissions_cmd cmd;
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  uint8_t* nvdata;
  uint32_t result;
  uint32_t size;

  memcpy(&cmd, &tpm_getpermissions_cmd, sizeof(cmd));
  ToTpmUint32(cmd.buffer + tpm_getpermissions_cmd.index, index);
  result = TlclSendReceive(cmd.buffer, response, sizeof(response));
  if (result != TPM_SUCCESS)
    return result;

  nvdata = response + kTpmResponseHeaderLength + sizeof(size);
  FromTpmUint32(nvdata + kNvDataPublicPermissionsOffset, permissions);
  return result;
}

uint32_t TlclGetOwnership(uint8_t* owned) {
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  uint32_t size;
  uint32_t result =
    TlclSendReceive(tpm_getownership_cmd.buffer, response, sizeof(response));
  if (result != TPM_SUCCESS)
    return result;
  FromTpmUint32(response + kTpmResponseHeaderLength, &size);
  assert(size == sizeof(*owned));
  memcpy(owned,
         response + kTpmResponseHeaderLength + sizeof(size),
         sizeof(*owned));
  return result;
}

/* request 'length' random bytes to 'data', 'size' will return length of bytes */
uint32_t TlclGetRandom(uint8_t* data, uint32_t length, uint32_t *size) {
  struct s_tpm_get_random_cmd cmd;
  uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
  uint32_t result;

  debug("TPM: TlclGetRandom(%d)\n", length);
  memcpy(&cmd, &tpm_get_random_cmd, sizeof(cmd));
  ToTpmUint32(cmd.buffer + tpm_get_random_cmd.bytesRequested, length);
  /* There must be room in the response buffer for the bytes. */
  if (length > TPM_LARGE_ENOUGH_COMMAND_SIZE - kTpmResponseHeaderLength
               - sizeof(uint32_t)) {
    return TPM_E_IOERROR;
  }

  result = TlclSendReceive(cmd.buffer, response, sizeof(response));
  if (result == TPM_SUCCESS) {
    uint8_t* get_random_cursor;
    FromTpmUint32(response + kTpmResponseHeaderLength, size);

    /* There must be room in the target buffer for the bytes. */
    if (*size > length) {
      return TPM_E_RESPONSE_TOO_LARGE;
    }
    get_random_cursor = response + kTpmResponseHeaderLength
                                 + sizeof(uint32_t);
    memcpy(data, get_random_cursor, *size);
  }

  return result;
}

/* tpm seal/unseal commands */

uint32_t TlclSeal(uint32_t keyHandle,
		const uint8_t *pcrInfo, uint32_t pcrInfoSize,
		const uint8_t *keyAuth, const uint8_t *dataAuth,
		const uint8_t *data, uint32_t dataSize,
		uint8_t *blob, uint32_t *blobSize)
{
	uint16_t i;
	uint32_t result;
	uint8_t command[TPM_LARGE_ENOUGH_COMMAND_SIZE] = {0x0, 0xC2};
	uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];

	struct tss_osapsess sess;
	uint8_t encAuth[TPM_HASH_SIZE];
	uint8_t pubAuth[TPM_HASH_SIZE];
	uint32_t size, sealInfoSize, encDataSize, storedSize;
	uint8_t nonceOdd[TPM_NONCE_SIZE];

	/* might not use */
	uint8_t xorWork[TPM_HASH_SIZE * 2];
	uint8_t xorHash[TPM_HASH_SIZE];
	SHA1_CTX ctx;

	uint16_t keyType; /* for keyHandle */

	/* TPM (big-endian data) for authentication HMAC */
	uint8_t tpm_hmac_data[TPM_U32_SIZE];
	uint8_t authHmacDigest[TPM_HASH_SIZE];
	uint8_t c;

	debug("TPM: Seal\n");

#ifdef EXTRA_LOGGING
	DATA_DEBUG("keyAuth", keyAuth, TPM_HASH_SIZE);
	DATA_DEBUG("dataAuth", dataAuth, TPM_HASH_SIZE);
	debug("TPM: Seal: keyHandle 0x%x\n", keyHandle);
#endif

	/* Input data checking */
	if (data == NULL || blob == NULL) {
		/* Todo: return error */
		return -22; /* EINVAL */
	}
	if (pcrInfoSize != 0 && pcrInfo == NULL) {
		/* Todo: return error */
		return -22; /* EINVAL */
	}

	if (keyHandle == 0x40000000) {
		keyType = 0x0004;
		debug("TPM: seal using SRK.\n");
	} else {
		keyType = 0x0001;
	}
	/* handle null auth for key and data, for now only use non-null passwords */
	/* assert(keyAuth != NULL && dataAuth != NULL); */

	result = TSS_OSAPopen(&sess, keyAuth, keyType, keyHandle);
	if (result != 0) {
		/* This will fail is key does not exist or TPM has not run TakeOwnership. */
		debug("TPM: TSS_OSAPopen failed\n");
		return result;
	}

	debug("TPM: Seal, OSAP finished, calculating xor\n");

	/* calculate encrypted authorization value */
	memcpy(xorWork, sess.ssecret, TPM_HASH_SIZE);
	memcpy(xorWork + TPM_HASH_SIZE, sess.enonce, TPM_HASH_SIZE);
	sha1_starts(&ctx);
	sha1_update(&ctx, xorWork, TPM_HASH_SIZE * 2);
	sha1_finish(&ctx, xorHash);

#ifdef EXTRA_LOGGING
	DATA_DEBUG("xorHash", xorHash, TPM_HASH_SIZE);
#endif

	/* generate odd nonce */
	TlclGetRandom(nonceOdd, TPM_NONCE_SIZE, &size);

#ifdef EXTRA_LOGGING
	DATA_DEBUG("sess.ssecret", sess.ssecret, TPM_HASH_SIZE);
	DATA_DEBUG("sess.enonce", sess.enonce, TPM_HASH_SIZE);
	DATA_DEBUG("nonceOdd:", nonceOdd, TPM_NONCE_SIZE);
#endif

	/* encrypt data authorization key, expects dataAuth to be as hash */
	for (i = 0; i < TPM_HASH_SIZE; ++i) {
		encAuth[i] = xorHash[i] ^ dataAuth[i];
	}

#ifdef EXTRA_LOGGING
	DATA_DEBUG("encAuth", encAuth, TPM_HASH_SIZE);
#endif

	/* calculate authorization HMAC */
	c = 0;
	sha1_starts(&ctx);
	ToTpmUint32(tpm_hmac_data, 0x17);
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	sha1_update(&ctx, encAuth, TPM_HASH_SIZE);
	ToTpmUint32(tpm_hmac_data, pcrInfoSize);
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	if (pcrInfoSize > 0) {
		/* PCRs */
		sha1_update(&ctx, pcrInfo, pcrInfoSize); /* this time include pcrInfo */
	}
	ToTpmUint32(tpm_hmac_data, dataSize);
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	sha1_update(&ctx, data, dataSize);
	sha1_finish(&ctx, authHmacDigest);

	hmac_starts(&ctx, sess.ssecret, TPM_HASH_SIZE);
	hmac_update(&ctx, authHmacDigest, TPM_HASH_SIZE);
	hmac_update(&ctx, sess.enonce, TPM_NONCE_SIZE);
	hmac_update(&ctx, nonceOdd, TPM_NONCE_SIZE);
	hmac_update(&ctx, &c, 1);
	hmac_finish(&ctx, sess.ssecret, TPM_HASH_SIZE, pubAuth);

#ifdef EXTRA_LOGGING
	DATA_DEBUG("authHmacDigest", authHmacDigest, TPM_HASH_SIZE);
	DATA_DEBUG("pubAuth", pubAuth, TPM_HASH_SIZE);
#endif

	/*unsigned char seal_fmt[] = "00 C2 T l(ordinal) l(keyHandle)
	  %(TPM_HASH_SIZE,encAuth) @(pcrInfoSize, pcrInfo) @(dataLen, data)
	  l(sess.handle) %(TPM_NONCE_SIZE, nonceodd) o(c) %(TPM_HASH_SIZE, pubAuth)"; */

	/* Build command */
	size = 2 /*tag*/ + 12 /*paramSize,ordinal,keyHandle*/ + TPM_HASH_SIZE /*encAuth*/ +
		pcrInfoSize + 4 /*size included*/ + dataSize + 4 + 4 /*authHandle*/ + TPM_NONCE_SIZE +
		1 /*authSess bool*/ + TPM_HASH_SIZE;
	ToTpmUint32(command + 2, size);
	ToTpmUint32(command + 6, 0x17);
	ToTpmUint32(command + 10, keyHandle);
	memcpy(command + 14, encAuth, TPM_HASH_SIZE);
	ToTpmUint32(command + 14 + TPM_HASH_SIZE, pcrInfoSize);
	if (pcrInfoSize > 0) {
		memcpy(command + 18 + TPM_HASH_SIZE, pcrInfo, pcrInfoSize);
	}
	ToTpmUint32(command + 18 + TPM_HASH_SIZE + pcrInfoSize, dataSize);
	memcpy(command + 22 + TPM_HASH_SIZE + pcrInfoSize, data, dataSize);
	ToTpmUint32(command + 22 + TPM_HASH_SIZE + pcrInfoSize + dataSize, sess.handle);
	memcpy(command + 26 + TPM_HASH_SIZE + pcrInfoSize + dataSize, nonceOdd, TPM_NONCE_SIZE);
	memset(command + 26 + TPM_HASH_SIZE + pcrInfoSize + dataSize + TPM_NONCE_SIZE, 0, 1);
	memcpy(command + 27 + TPM_HASH_SIZE + pcrInfoSize + dataSize + TPM_NONCE_SIZE, pubAuth, TPM_HASH_SIZE);

	//DATA_DEBUG("command", command, size);

	result = TlclSendReceive(command, response, sizeof(response));

	//DATA_DEBUG("result", response, TpmCommandSize(response));

	if (result == TPM_SUCCESS) {
		/* first 32bit after the header is the size of return */
		FromTpmUint32(response + kTpmResponseHeaderLength, &size);
		printf("blob size: %d\n", size);
		FromTpmUint32(response + kTpmResponseHeaderLength + TPM_U32_SIZE, &sealInfoSize);
		printf("seal info size: %d\n", sealInfoSize);
		FromTpmUint32(response + kTpmResponseHeaderLength + TPM_U32_SIZE + TPM_U32_SIZE, &encDataSize);
		printf("enc data size: %d\n", encDataSize);
		storedSize = TPM_U32_SIZE * 3 + sealInfoSize + encDataSize;
		printf("stored size: %d\n", storedSize);

		/* todo: should check HMAC here (ordinal, nonceOdd, sess.ssecret, storedSize) */
		/* set output param values */

		memcpy(blob, response + kTpmResponseHeaderLength, storedSize);
		*blobSize = storedSize;
	}

	TSS_OSAPclose(&sess);

	return result;
}

uint32_t TSS_GenPCRInfo(uint32_t pcrMap, uint8_t *pcrInfo, uint32_t *size)
{
	uint32_t result;

	struct pcrInfo {
		uint8_t selSize[TPM_U16_SIZE]; /* uint16_t */
		uint8_t select[TPM_PCR_MASK_SIZE];
		uint8_t relHash[TPM_HASH_SIZE];
		uint8_t crtHash[TPM_HASH_SIZE];
	} info;

	uint16_t i, j, numRegs;
	uint32_t pcrMapTemp;
	uint8_t *pcrValues, valueSize[TPM_U32_SIZE];
	SHA1_CTX ctx;

	/* must be valid pointers */
	if (pcrInfo == NULL || size == NULL) {
		return TPM_E_NULL_ARG;
	}

	/* build PCR selection matrix */
	pcrMapTemp = pcrMap;
	memset(info.select, 0, TPM_PCR_MASK_SIZE);
	for (i = 0; i < TPM_PCR_MASK_SIZE; ++i) {
		info.select[i] = pcrMapTemp & 0x000000FF;
		pcrMapTemp = pcrMapTemp >> 8;
	}

	/* calculate number of PCR registers requested */
	numRegs = 0;
	pcrMapTemp = pcrMap;
	for (i = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i) {
		if (pcrMapTemp & 1) ++numRegs;
		pcrMapTemp = pcrMapTemp >> 1;
	}

	/* check for 0 registers */
	if (numRegs == 0) {
		*size = 0;
		return 0;
	}

	/* create a matrix of PCR values */
	pcrValues = (uint8_t *) malloc(TPM_HASH_SIZE * numRegs);
	pcrMapTemp = pcrMap;
	for (i = 0, j = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i, pcrMapTemp = pcrMapTemp >> 1) {
		if ((pcrMapTemp & 1) == 0) continue;
		result = TlclPCRRead(i, &(pcrValues[(j * TPM_HASH_SIZE)]), kPcrDigestLength);
		if (result != 0) {
			/* todo: print trace */
			return result;
		}
		++j;
	}

	ToTpmUint16(info.selSize, TPM_PCR_MASK_SIZE);
	ToTpmUint32(valueSize, numRegs * TPM_HASH_SIZE);

	/* composite hash of selected PCR values */
	sha1_starts(&ctx);
	sha1_update(&ctx, info.selSize, TPM_U16_SIZE);
	sha1_update(&ctx, info.select, TPM_PCR_MASK_SIZE);
	sha1_update(&ctx, valueSize, TPM_U32_SIZE);
	for (i = 0; i < numRegs; ++i) {
		sha1_update(&ctx, &(pcrValues[(i * TPM_HASH_SIZE)]), TPM_HASH_SIZE);
	}
	sha1_finish(&ctx, info.relHash);
	memcpy(info.crtHash, info.relHash, TPM_HASH_SIZE);

	/* copy to input params */
	memcpy(pcrInfo, &info, sizeof(struct pcrInfo));
	*size = sizeof(struct pcrInfo);

	return 0;
}


uint32_t TlclSealPCR(uint32_t keyHandle, uint32_t pcrMap,
		const uint8_t *keyAuth, const uint8_t *dataAuth,
		const uint8_t *data, uint32_t dataSize,
		uint8_t *blob, uint32_t *blobSize)
{
	uint32_t result;

	uint8_t pcrInfo[TPM_MAX_PCR_INFO_SIZE];
	uint32_t pcrSize;

	result = TSS_GenPCRInfo(pcrMap, pcrInfo, &pcrSize);
	if (result != 0) {
		return result;
	}

	return TlclSeal(keyHandle, pcrInfo, pcrSize, keyAuth, dataAuth, data,
		dataSize, blob, blobSize);
}

uint32_t TlclUnseal(uint32_t keyHandle,
		const uint8_t *keyAuth, const uint8_t *dataAuth,
		const uint8_t *blob, uint32_t blobSize,
		uint8_t *rawData, uint32_t *dataSize)
{
	uint32_t result;
	uint8_t command[TPM_LARGE_ENOUGH_COMMAND_SIZE] = {0x0, 0xC3};
	uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];

	uint32_t keyAuthHandle, dataAuthHandle, size;
	uint8_t keyAuthData[TPM_HASH_SIZE], dataAuthData[TPM_HASH_SIZE];
	uint8_t enonceKey[TPM_NONCE_SIZE], enonceData[TPM_NONCE_SIZE];
	uint8_t nonceOdd[TPM_NONCE_SIZE];
	uint8_t authHmacDigest[TPM_HASH_SIZE];
	uint8_t c;
	SHA1_CTX ctx;

	/* used to convert host-endianess to TPM-endianess (big) */
	uint8_t tpm_hmac_data[TPM_U32_SIZE];

	/* check input params */
	if (rawData == NULL || blob == NULL) {
		return TPM_E_NULL_ARG;
	}

	/* todo: this assumes there is a provided keyAuth (and data) */
	if (keyAuth != NULL) {
		result = TSS_OIAPopen(&keyAuthHandle, enonceKey);
		DATA_DEBUG("keyAuthHandle", &keyAuthHandle, 4);
	}
	result = TSS_OIAPopen(&dataAuthHandle, enonceData);

	DATA_DEBUG("dataAuthHandle", &dataAuthHandle, 4);
	DATA_DEBUG("enonceKey", enonceKey, 20);
	DATA_DEBUG("enonceData", enonceData, 20);


	/* generate odd nonce */
	TlclGetRandom(nonceOdd, TPM_NONCE_SIZE, &size);
	/* todo: is it OK to use the same odd nonce? */

	c = 0;
	ToTpmUint32(tpm_hmac_data, 0x18);
	/* calculate key authorization HMAC */
	sha1_starts(&ctx);
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	sha1_update(&ctx, blob, blobSize);
	sha1_finish(&ctx, authHmacDigest);

	DATA_DEBUG("authHmacDigest", authHmacDigest, 20);

	debug("TPM: unseal, calculating HMACs\n");

	if (keyAuth != NULL) {
		hmac_starts(&ctx, keyAuth, TPM_HASH_SIZE);
		hmac_update(&ctx, authHmacDigest, TPM_HASH_SIZE);
		hmac_update(&ctx, enonceKey, TPM_NONCE_SIZE);
		hmac_update(&ctx, nonceOdd, TPM_NONCE_SIZE);
		hmac_update(&ctx, &c, 1);
		hmac_finish(&ctx, keyAuth, TPM_HASH_SIZE, keyAuthData);

		DATA_DEBUG("keyAuth", keyAuth, 20);
	}

	/* calculate data authorization HMAC */
	hmac_starts(&ctx, dataAuth, TPM_HASH_SIZE);
	hmac_update(&ctx, authHmacDigest, TPM_HASH_SIZE);
	hmac_update(&ctx, enonceData, TPM_NONCE_SIZE);
	hmac_update(&ctx, nonceOdd, TPM_NONCE_SIZE);
	hmac_update(&ctx, &c, 1);
	hmac_finish(&ctx, dataAuth, TPM_HASH_SIZE, dataAuthData);

	DATA_DEBUG("dataAuth", dataAuth, 20);
	/*DATA_DEBUG("blob(16)", blob, 16);
	DATA_DEBUG("blob+16(40)", blob+16, 40);*/

	/* unsigned char unseal_fmt[] = "00 C3 T(size) l(ordinal) l(keyHandle)
	 * %(blob, blobSize) l(keyAuthHandle) %(nonceOdd, TPM_NONCE_SIZE
	 * o(c, 1) %(keyAuthData, TPM_HASH_SIZE l(dataAuthHandle)
	 * %(nonceOdd, TPM_NONCE_SIZE) o(c, 1) %(dataAuthData, TPM_HASH_SIZE)"; */
	/* build command buffer */
	size = 2 /*tag*/ + TPM_U32_SIZE * 3 /*paramSize, ordinal, keyHandle*/ +
		blobSize + TPM_U32_SIZE + TPM_NONCE_SIZE + 1 + TPM_HASH_SIZE;

	if (keyAuth == NULL) {
		size += TPM_U32_SIZE + TPM_NONCE_SIZE + 1 + TPM_HASH_SIZE;
		memset(command, 0x00, 1);
		memset(command + 1, 0xc2, 1);
	}

	ToTpmUint32(command + 2, size);
	ToTpmUint32(command + 6, 0x18);
	ToTpmUint32(command + 10, keyHandle);
	//ToTpmUint32(command + 10, blobSize);
	/* todo: might be some fields missing here, check TPM commands spec */
	memcpy(command + 14, blob, blobSize); /* assumed a static 256? */

	/* key auth params: handle, nonceOdd, continue_bool, keyAuthHMAC */
	if (keyAuth != NULL) {
		ToTpmUint32(command + 14 + blobSize, keyAuthHandle);
		memcpy(command + 18 + blobSize, nonceOdd, TPM_NONCE_SIZE);
		memcpy(command + 18 + blobSize + TPM_NONCE_SIZE, &c, 1);
		memcpy(command + 19 + blobSize + TPM_NONCE_SIZE, keyAuthData, TPM_HASH_SIZE);
	}

	/* data auth params: handle, nonceOdd, continue_bool, dataAuthHMAC */
	ToTpmUint32(command + 19 + blobSize + TPM_NONCE_SIZE + TPM_HASH_SIZE, dataAuthHandle);
	memcpy(command + 23 + blobSize + TPM_NONCE_SIZE + TPM_HASH_SIZE, nonceOdd, TPM_NONCE_SIZE);
	memcpy(command + 23 + blobSize + TPM_NONCE_SIZE * 2 + TPM_HASH_SIZE, &c, 1);
	memcpy(command + 24 + blobSize + TPM_NONCE_SIZE * 2 + TPM_HASH_SIZE, dataAuthData, TPM_HASH_SIZE);

	//DATA_DEBUG("command", command, size);

	result = TlclSendReceive(command, response, sizeof(response));

	//DATA_DEBUG("result", response, TpmCommandSize(response));

	if (result == TPM_SUCCESS) {
		/* first 32bit after the header is the size of return */
		/* size of returned data blob */
		FromTpmUint32(response + kTpmResponseHeaderLength, dataSize);

#ifdef EXTRA_LOGGING
	debug("TPM: Unseal return size %d", *dataSize);
	DATA_DEBUG("unseal return", response + kTpmResponseHeaderLength + TPM_U32_SIZE, *dataSize);
#endif

		/* todo: should check HMAC here (AUTH2) */
		/* set output param values */
		memcpy(rawData, response + kTpmResponseHeaderLength + TPM_U32_SIZE, *dataSize);
	}

	return result;
}

uint32_t TlclTakeOwnership(uint8_t *ownerPass, uint8_t *srkPass)
{
	uint32_t result;

	/*uint8_t nonceEven[TPM_HASH_SIZE];
	uint8_t nonceOdd[TPM_HASH_SIZE];
	uint8_t authData[TPM_HASH_SIZE];

	uint32_t srkParamSize;
	uint32_t ownerEncSize, srkEncSize, authHandle;*/

	/* need RSA encryption functions to continue */
	result = 0;
	return result;
}


/* end tpm seal/unseal commands */

