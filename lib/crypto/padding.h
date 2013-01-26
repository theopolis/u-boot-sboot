/*
 * Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef _CRYPTOLIB_PADDING_H_
#define _CRYPTOLIB_PADDING_H_

extern const uint8_t paddingRSA1024_SHA1[];
extern const uint8_t paddingRSA1024_SHA256[];
extern const uint8_t paddingRSA1024_SHA512[];
extern const uint8_t paddingRSA2048_SHA1[];
extern const uint8_t paddingRSA2048_SHA256[];
extern const uint8_t paddingRSA2048_SHA512[];
extern const uint8_t paddingRSA4096_SHA1[];
extern const uint8_t paddingRSA4096_SHA256[];
extern const uint8_t paddingRSA4096_SHA512[];
extern const uint8_t paddingRSA8192_SHA1[];
extern const uint8_t paddingRSA8192_SHA256[];
extern const uint8_t paddingRSA8192_SHA512[];

extern const int kNumAlgorithms;

extern const int digestinfo_size_map[];
extern const int siglen_map[];
extern const uint8_t* const padding_map[];
extern const int padding_size_map[];
extern const int hash_type_map[];
extern const int hash_size_map[];
extern const int hash_blocksize_map[];
extern const uint8_t* const hash_digestinfo_map[];
extern const char* const algo_strings[];

#endif
