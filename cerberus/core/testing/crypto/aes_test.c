// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing/crypto/aes_testing.h"


const uint8_t AES_KEY[] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

const uint8_t AES_IV[] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
};

const uint8_t AES_PLAINTEXT[] = {
	0x30,0x77,0x02,0x01,0x01,0x04,0x20,0x64,0x85,0x0c,0x50,0x94,0x58,0x9f,0x4b,0x7e,
	0x1a,0xd7,0x58,0x63,0x82,0xc8,0xbc,0xa5,0x16,0x96,0x6a,0x4e,0x87,0xd6,0xc6,0x23,
	0xa8,0x27,0xdc,0xb5,0x89,0x25,0x99,0xa0,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,
	0x03,0x01,0x07,0xa1,0x44,0x03,0x42,0x00,0x04,0xe3,0x51,0xfa,0x63,0x3c,0x37,0xbe,
	0xe6,0xde,0x7f,0x65,0x8e,0xdd,0xbd,0xd6,0xd5,0x31,0xef,0x9c,0xd6,0xb5,0x14,0xc2,
	0x28,0xb1,0x08,0x8b,0x0b,0xe4,0x29,0xc3,0x03,0x67,0x0e,0x28,0xc2,0xb2,0x8b,0xd0,
	0x9b,0xc0,0xe4,0x33,0xa6,0x23,0x5a,0xa9,0x7a,0xeb,0x3a,0x65,0x15,0x95,0x08,0xac,
	0x7a,0xde,0x27,0x36,0x71,0xe4,0x4c,0xde,0x4e
};

const size_t AES_PLAINTEXT_LEN = sizeof (AES_PLAINTEXT);

const uint8_t AES_CIPHERTEXT[] = {
	0xe2,0x4d,0xa4,0x71,0x6d,0x9c,0x3a,0x6a,0x9f,0x70,0x12,0x5a,0x99,0x87,0xbf,0x87,
	0xca,0x9e,0xb4,0xff,0x05,0x48,0xdf,0x4b,0x7a,0x60,0x06,0x5c,0xce,0x5c,0x98,0x2a,
	0xdd,0xa9,0x39,0xb1,0x07,0x00,0xac,0x7a,0x1e,0xfb,0x66,0xb8,0xde,0x41,0xd1,0xf5,
	0xe1,0x2b,0xeb,0x2f,0xde,0x3f,0x6f,0x61,0xca,0x81,0x2e,0xe7,0x2f,0x8e,0x3d,0x63,
	0x3e,0xf8,0xb2,0x6e,0x18,0x4a,0x58,0x40,0x5e,0x5b,0x06,0xbb,0x6d,0xe8,0x2d,0xa3,
	0xfd,0x26,0x3b,0x8f,0xbc,0x1f,0xaf,0xdd,0xcc,0x28,0xcc,0x02,0xd8,0xae,0x15,0x0c,
	0x99,0x94,0xca,0x65,0x6e,0x67,0xc4,0x5a,0xb3,0x77,0x9e,0x62,0xb6,0x63,0xc5,0xbf,
	0x0a,0x4f,0xa8,0x74,0xe0,0x3a,0xe3,0xd3,0x1e
};

const size_t AES_CIPHERTEXT_LEN = sizeof (AES_CIPHERTEXT);

const uint8_t AES_GCM_TAG[] = {
	0xfa,0xa6,0x3c,0x2d,0xe5,0x58,0xe1,0x10,0x52,0x92,0x7a,0xf0,0x06,0x30,0xd1,0x54
};

const uint8_t AES_RSA_PRIVKEY_DER[] = {
	0xe2,0xb8,0xa2,0xd3,0x6e,0x99,0x1a,0x0c,0x98,0x7d,0x43,0xce,0x08,0x5c,0x78,0xb9,
	0xbc,0x56,0x88,0x11,0x4c,0x21,0xa4,0xd5,0x78,0x42,0xe5,0xc3,0x6c,0xdd,0x14,0x54,
	0xa0,0x24,0xc9,0x1b,0x0e,0x06,0x16,0x26,0xd6,0x27,0x92,0xee,0xfe,0xa4,0x2a,0x4b,
	0x49,0xb8,0xf7,0xff,0x9f,0x86,0x58,0x70,0xd0,0xbf,0x1f,0x37,0xab,0x0c,0x9b,0xe2,
	0x35,0x8c,0x2e,0x48,0x81,0xbf,0x60,0xbf,0x76,0xdc,0x68,0x5f,0xbb,0x9d,0xdd,0xa0,
	0x64,0xee,0x40,0x9a,0x26,0xa1,0xfe,0x19,0xde,0x65,0xe6,0xfd,0xd6,0x3e,0xab,0xf7,
	0xdd,0xef,0xd9,0x34,0x17,0x03,0x87,0x49,0xd6,0x20,0x3e,0x5c,0xf7,0x03,0x6a,0x79,
	0x49,0x5a,0xe4,0xa2,0x34,0x66,0xa5,0xad,0x56,0x61,0xeb,0xd7,0xf6,0x3c,0xcb,0xa1,
	0x94,0x1e,0xf5,0x99,0x65,0x2b,0x0c,0x1c,0xd4,0x5e,0x0b,0x5c,0x46,0x18,0x43,0xe6,
	0x77,0xb6,0x01,0x77,0x4f,0x47,0x9b,0x83,0x18,0xe8,0xb8,0x82,0xdb,0x97,0x47,0x55,
	0xed,0x8f,0x48,0x85,0x41,0x29,0x3e,0xfd,0x3c,0xdc,0x39,0xc8,0x52,0x2b,0xf6,0x36,
	0xe9,0x63,0xae,0xce,0x2a,0xbf,0x1f,0x53,0xf8,0xdf,0x70,0x12,0xa6,0xa9,0xf0,0x0c,
	0xea,0x14,0xda,0x3b,0x4a,0xff,0x49,0x09,0xd0,0x82,0x72,0xe4,0xb7,0x74,0x24,0x13,
	0xef,0x31,0x61,0x0e,0xa0,0x39,0xc5,0x24,0x2d,0x80,0x0c,0x3f,0xf4,0x2e,0x2f,0xf8,
	0x51,0x46,0xec,0x09,0xa7,0x78,0xea,0x75,0xe2,0xd7,0xc9,0xdc,0xc8,0x92,0xdf,0x49,
	0x23,0x31,0xda,0x73,0x6e,0x54,0x85,0x7a,0xc6,0x4f,0x4e,0x15,0xa8,0x2d,0xb2,0xcc,
	0x6a,0x8e,0xf8,0xf3,0xbe,0xa8,0xc1,0x6a,0x2a,0x55,0x03,0xf8,0xbc,0xf1,0x9b,0xc1,
	0xfb,0xc3,0x40,0x18,0x20,0x67,0x70,0xee,0xc9,0x05,0x74,0x50,0xfb,0x4e,0xe4,0x05,
	0x04,0xd4,0x6f,0xa8,0x0b,0x34,0xac,0x13,0x44,0xcd,0xbb,0xb2,0x4a,0xec,0xf2,0xb5,
	0x1f,0x4f,0x40,0x0b,0x3f,0xb1,0xc2,0x65,0x51,0x28,0xfd,0xec,0x2c,0xcf,0xdc,0x75,
	0x10,0xaa,0xc9,0x69,0x15,0x50,0x86,0x83,0x08,0xe0,0xdb,0x72,0x87,0x9c,0x8d,0x0e,
	0x6b,0x11,0x1c,0x59,0xe6,0xc7,0xaa,0x83,0x45,0x2b,0x8f,0x8e,0x94,0x34,0x65,0x55,
	0x96,0xc5,0xe9,0x3b,0xd1,0x64,0xf7,0x26,0x0b,0xf1,0x00,0x42,0x45,0x64,0x3a,0xcf,
	0x6b,0x2c,0x3f,0x30,0xde,0xad,0xa8,0xdf,0x72,0xe7,0x03,0x58,0xcf,0x5d,0xbf,0xcf,
	0x21,0x03,0xfd,0x19,0xd8,0xc5,0xb8,0x38,0x32,0x1c,0xf1,0x84,0xa0,0x3f,0xe8,0x15,
	0x5c,0x6e,0x23,0xd3,0xcb,0xd8,0xda,0xb2,0x7b,0x85,0xef,0x51,0x14,0xec,0x4c,0x8f,
	0x2a,0x33,0xa8,0x01,0xef,0x19,0xf0,0x81,0xfa,0xb8,0xbb,0x48,0xcc,0x08,0x5c,0x29,
	0x64,0xb8,0xb3,0x02,0x4f,0xe4,0x20,0x05,0x24,0xe5,0x81,0xaa,0xf7,0x32,0xee,0xf4,
	0x41,0x55,0x09,0x99,0x19,0x14,0xde,0x0d,0x4b,0xe8,0x41,0x75,0x27,0x65,0xb6,0x38,
	0x69,0xca,0xf9,0xf5,0xf1,0x5a,0xb6,0x6f,0xe9,0xef,0x8c,0xd1,0x36,0x7e,0x14,0xcf,
	0x55,0x1c,0x07,0x33,0x44,0xae,0x83,0x9d,0x57,0xd8,0xc8,0x9e,0xaa,0xd2,0x68,0x7d,
	0x81,0x0f,0x30,0x43,0x4b,0x65,0x6f,0xd9,0x63,0xa6,0x4a,0x19,0xe8,0xbb,0xf1,0x12,
	0x98,0xf6,0x05,0x8a,0xc3,0x1e,0x4e,0x8f,0x5b,0xf4,0x00,0xd0,0xd2,0xa9,0x8d,0x5a,
	0xe2,0x50,0x1e,0xf6,0x3e,0xa4,0x98,0x25,0x6f,0xa3,0xec,0x3e,0x85,0x4a,0x48,0x7e,
	0x96,0x15,0x6c,0xa9,0xaa,0x02,0x0e,0x30,0x4a,0x43,0x91,0xdc,0x67,0xdf,0xb2,0xd2,
	0x2a,0x27,0x01,0x02,0x17,0x4b,0x2b,0xd5,0x61,0xed,0x47,0x07,0x95,0x0e,0x6f,0x9b,
	0x31,0xab,0x08,0x42,0xa4,0x46,0x4b,0xe1,0x07,0xa6,0x79,0x32,0x8c,0x2a,0xd7,0x95,
	0x8e,0xbb,0xe0,0x5a,0x4b,0x85,0x39,0xf2,0x41,0x5b,0x1d,0x6d,0x54,0x08,0xbd,0x91,
	0x06,0xf1,0x5d,0xdb,0x14,0x3b,0x7a,0x7a,0x67,0x92,0x0c,0xe6,0x85,0xe2,0xd5,0xec,
	0xa8,0xc6,0x22,0xe6,0x1e,0x7a,0x30,0xf0,0x3c,0xf2,0xa6,0xb6,0xb7,0x40,0xb7,0x9e,
	0x4f,0x12,0xfa,0xe3,0x86,0x96,0x60,0x9c,0x3d,0xde,0x69,0x12,0x0b,0x45,0x06,0x4f,
	0x5d,0x7a,0x16,0x55,0x7a,0xc5,0xaf,0x68,0xf4,0x37,0xea,0x06,0x78,0x68,0xbb,0x9b,
	0x80,0xcd,0x4e,0xcc,0xb3,0x71,0xe6,0x60,0xe7,0x11,0x47,0x4e,0xe7,0xfa,0x08,0xb7,
	0x79,0x4c,0x1e,0x46,0x31,0x15,0xcc,0xa4,0x65,0x4c,0xc4,0x44,0xc7,0x6e,0x0b,0xd8,
	0x93,0x19,0x63,0x31,0xae,0x4d,0x64,0x85,0x51,0x2c,0x1b,0xeb,0xc9,0x10,0x53,0x88,
	0x3d,0xbd,0xd5,0x07,0x4a,0x3c,0x9a,0xcf,0xb9,0x86,0x5c,0xb3,0x17,0x69,0xa5,0xa6,
	0x0a,0xb7,0x64,0x49,0x71,0x03,0xaa,0x01,0x07,0x96,0x7e,0xd6,0xee,0x48,0x31,0xa4,
	0x77,0xb3,0x11,0x02,0xc9,0xcd,0xca,0x65,0xbb,0x6a,0xd0,0x3a,0x91,0x14,0xe3,0x5e,
	0xe2,0x2f,0x58,0x62,0xbf,0x02,0x14,0x90,0xba,0x70,0xf4,0x4f,0x6d,0x2c,0x00,0x72,
	0x9b,0x55,0xa9,0x34,0x9f,0x0d,0xa3,0x88,0x5a,0x3e,0x26,0x4b,0xa2,0xf0,0xfc,0x50,
	0xe8,0xeb,0x66,0xdf,0x0c,0xd3,0xbe,0xe7,0x27,0xc0,0x56,0xa5,0x3b,0x9b,0x26,0x8f,
	0x21,0xa4,0xd8,0x1e,0x74,0xa1,0x27,0x7f,0x64,0x06,0x6b,0xde,0xdb,0x69,0x28,0xf6,
	0x29,0xe3,0xdf,0x24,0xb4,0x7a,0xa8,0x22,0xbc,0x34,0x16,0xbd,0x8e,0x8f,0x7f,0xeb,
	0x21,0x67,0x30,0xa4,0x28,0x1f,0xe4,0xc3,0x8a,0xcc,0xaa,0x18,0x68,0x79,0x63,0x22,
	0x72,0xf7,0xdd,0xe3,0xf9,0x8e,0x75,0x93,0x4a,0x54,0x2c,0x9e,0x9f,0x2d,0x59,0x58,
	0x88,0xf5,0x15,0x3b,0xa0,0x84,0x84,0xa8,0xf9,0xee,0xc9,0xd5,0x4d,0x8c,0xb0,0xa6,
	0xa2,0x8b,0xf3,0xda,0xd9,0x17,0x5c,0x69,0x1f,0x7f,0x52,0xf4,0x7d,0x22,0xfc,0xdc,
	0x9b,0x60,0xed,0x22,0x34,0xbc,0xdd,0x16,0x11,0xb5,0x80,0xcb,0x58,0xc8,0xc8,0xf5,
	0x60,0xd9,0xfc,0x23,0x61,0x92,0x4b,0xc4,0x37,0x52,0x59,0xc2,0x45,0xea,0x91,0x11,
	0x35,0x3b,0x2f,0xeb,0xf2,0x33,0x66,0x81,0xc3,0x26,0x8b,0xc8,0x71,0x6d,0x81,0x89,
	0x70,0x22,0x98,0x16,0xcc,0x77,0x6c,0xaf,0xc0,0xaa,0x9b,0xf2,0xf0,0xd5,0xec,0x49,
	0xea,0xf3,0x4f,0x59,0x1e,0x22,0xa8,0x12,0xc3,0x1a,0xb2,0x31,0xf8,0x10,0x69,0x50,
	0xd3,0xb1,0xe4,0xf1,0xa3,0x6a,0xd8,0x51,0xf5,0x48,0xd8,0xdc,0x09,0x6b,0x9c,0x3b,
	0x80,0x30,0x66,0x97,0x7e,0x6c,0x72,0x20,0x93,0x3f,0x9f,0xaf,0x1d,0x0e,0x54,0x98,
	0xd7,0xf2,0xde,0x64,0x0c,0x30,0xef,0x48,0x87,0x2f,0x88,0x75,0x5d,0xbd,0x1a,0x71,
	0x88,0xc1,0x54,0x2a,0xa5,0x2f,0xe1,0x7a,0xd1,0xef,0xd0,0x63,0x7e,0x4e,0xda,0xc8,
	0x3f,0x5c,0xce,0xa1,0x6b,0xf8,0x0c,0x5f,0xb7,0x46,0x81,0xa5,0xfa,0x66,0xd4,0x08,
	0x78,0x34,0x5d,0x2e,0x79,0xc0,0x93,0x3b,0xe1,0x4b,0xed,0xc5,0x32,0x3f,0x32,0x3c,
	0x7d,0x0b,0xb1,0x3d,0x43,0x16,0x4b,0xb4,0x7f,0xdb,0x6c,0x36,0xe2,0x26,0x08,0x15,
	0xdf,0xfa,0x0c,0x99,0x0b,0x2e,0xf7,0xad,0xac,0x5c,0x6a,0xac,0xfb,0xba,0xe1,0xa8,
	0x84,0x10,0xac,0xea,0xd3,0x86,0x36,0x86,0x3d,0xdb,0x01,0x35,0x59,0xc4,0xb9,0xfa,
	0xbf,0xbd,0x2d,0x0c,0x1d,0x93,0x73,0x52,0xbe,0xa5,0xf9,0xe4,0x04,0x0f,0xea,0x96,
	0x17,0x06,0xf2,0xd1,0xc8,0x03,0x3a,0x7f,0x26,0xeb,0x8e,0x48,0x1a,0xc3,0x61,0x0c,
	0x12,0xc7,0x73,0xb4,0x95,0x84,0xff,0x97,0xe3,0xde,0x73,0x64,0x82,0x40,0x71,0xbe,
	0xfe,0xd5,0x65,0x12,0xf3,0x65,0x68
};

const size_t AES_RSA_PRIVKEY_DER_LEN = sizeof (AES_RSA_PRIVKEY_DER);

const uint8_t AES_RSA_PRIVKEY_GCM_TAG[] = {
	0x77,0x0e,0x01,0xf8,0xfb,0xf6,0x26,0x72,0x2a,0x1d,0x78,0xec,0x83,0xff,0xcf,0x4c
};


const uint8_t AES_TESTING_CBC_SINGLE_BLOCK_KEY[] ={
	0x6e,0xd7,0x6d,0x2d,0x97,0xc6,0x9f,0xd1,0x33,0x95,0x89,0x52,0x39,0x31,0xf2,0xa6,
	0xcf,0xf5,0x54,0xb1,0x5f,0x73,0x8f,0x21,0xec,0x72,0xdd,0x97,0xa7,0x33,0x09,0x07
};

const uint8_t AES_TESTING_CBC_SINGLE_BLOCK_IV[] = {
	0x85,0x1e,0x87,0x64,0x77,0x6e,0x67,0x96,0xaa,0xb7,0x22,0xdb,0xb6,0x44,0xac,0xe8
};

const uint8_t AES_TESTING_CBC_SINGLE_BLOCK_PLAINTEXT[] = {
	0x62,0x82,0xb8,0xc0,0x5c,0x5c,0x15,0x30,0xb9,0x7d,0x48,0x16,0xca,0x43,0x47,0x62
};

const uint8_t AES_TESTING_CBC_SINGLE_BLOCK_CIPHERTEXT[] = {
	0x6a,0xcc,0x04,0x14,0x2e,0x10,0x0a,0x65,0xf5,0x1b,0x97,0xad,0xf5,0x17,0x2c,0x41
};

const size_t AES_TESTING_CBC_SINGLE_BLOCK_LEN = sizeof (AES_TESTING_CBC_SINGLE_BLOCK_PLAINTEXT);

const uint8_t AES_TESTING_CBC_MULTI_BLOCK_KEY[] ={
	0x04,0x93,0xff,0x63,0x71,0x08,0xaf,0x6a,0x5b,0x8e,0x90,0xac,0x1f,0xdf,0x03,0x5a,
	0x3d,0x4b,0xaf,0xd1,0xaf,0xb5,0x73,0xbe,0x7a,0xde,0x9e,0x86,0x82,0xe6,0x63,0xe5
};

const uint8_t AES_TESTING_CBC_MULTI_BLOCK_IV[] = {
	0xc0,0xcd,0x2b,0xeb,0xcc,0xbb,0x6c,0x49,0x92,0x0b,0xd5,0x48,0x2a,0xc7,0x56,0xe8
};

const uint8_t AES_TESTING_CBC_MULTI_BLOCK_PLAINTEXT[] = {
	0x8b,0x37,0xf9,0x14,0x8d,0xf4,0xbb,0x25,0x95,0x6b,0xe6,0x31,0x0c,0x73,0xc8,0xdc,
	0x58,0xea,0x97,0x14,0xff,0x49,0xb6,0x43,0x10,0x7b,0x34,0xc9,0xbf,0xf0,0x96,0xa9,
	0x4f,0xed,0xd6,0x82,0x35,0x26,0xab,0xc2,0x7a,0x8e,0x0b,0x16,0x61,0x6e,0xee,0x25,
	0x4a,0xb4,0x56,0x7d,0xd6,0x8e,0x8c,0xcd,0x4c,0x38,0xac,0x56,0x3b,0x13,0x63,0x9c
};

const uint8_t AES_TESTING_CBC_MULTI_BLOCK_CIPHERTEXT[] = {
	0x05,0xd5,0xc7,0x77,0x29,0x42,0x1b,0x08,0xb7,0x37,0xe4,0x11,0x19,0xfa,0x44,0x38,
	0xd1,0xf5,0x70,0xcc,0x77,0x2a,0x4d,0x6c,0x3d,0xf7,0xff,0xed,0xa0,0x38,0x4e,0xf8,
	0x42,0x88,0xce,0x37,0xfc,0x4c,0x4c,0x7d,0x11,0x25,0xa4,0x99,0xb0,0x51,0x36,0x4c,
	0x38,0x9f,0xd6,0x39,0xbd,0xda,0x64,0x7d,0xaa,0x3b,0xda,0xda,0xb2,0xeb,0x55,0x94
};

const size_t AES_TESTING_CBC_MULTI_BLOCK_LEN = sizeof (AES_TESTING_CBC_MULTI_BLOCK_PLAINTEXT);

const uint8_t AES_TESTING_CBC_LONG_DATA_KEY[] ={
	0x48,0xbe,0x59,0x7e,0x63,0x2c,0x16,0x77,0x23,0x24,0xc8,0xd3,0xfa,0x1d,0x9c,0x5a,
	0x9e,0xcd,0x01,0x0f,0x14,0xec,0x5d,0x11,0x0d,0x3b,0xfe,0xc3,0x76,0xc5,0x53,0x2b
};

const uint8_t AES_TESTING_CBC_LONG_DATA_IV[] = {
	0xd6,0xd5,0x81,0xb8,0xcf,0x04,0xeb,0xd3,0xb6,0xea,0xa1,0xb5,0x3f,0x04,0x7e,0xe1
};

const uint8_t AES_TESTING_CBC_LONG_DATA_PLAINTEXT[] = {
	0x0c,0x63,0xd4,0x13,0xd3,0x86,0x45,0x70,0xe7,0x0b,0xb6,0x61,0x8b,0xf8,0xa4,0xb9,
	0x58,0x55,0x86,0x68,0x8c,0x32,0xbb,0xa0,0xa5,0xec,0xc1,0x36,0x2f,0xad,0xa7,0x4a,
	0xda,0x32,0xc5,0x2a,0xcf,0xd1,0xaa,0x74,0x44,0xba,0x56,0x7b,0x4e,0x7d,0xaa,0xec,
	0xf7,0xcc,0x1c,0xb2,0x91,0x82,0xaf,0x16,0x4a,0xe5,0x23,0x2b,0x00,0x28,0x68,0x69,
	0x56,0x35,0x59,0x98,0x07,0xa9,0xa7,0xf0,0x7a,0x1f,0x13,0x7e,0x97,0xb1,0xe1,0xc9,
	0xda,0xbc,0x89,0xb6,0xa5,0xe4,0xaf,0xa9,0xdb,0x58,0x55,0xed,0xaa,0x57,0x50,0x56,
	0xa8,0xf4,0xf8,0x24,0x22,0x16,0x24,0x2b,0xb0,0xc2,0x56,0x31,0x0d,0x9d,0x32,0x98,
	0x26,0xac,0x35,0x3d,0x71,0x5f,0xa3,0x9f,0x80,0xce,0xc1,0x44,0xd6,0x42,0x45,0x58,
	0xf9,0xf7,0x0b,0x98,0xc9,0x20,0x09,0x6e,0x0f,0x2c,0x85,0x5d,0x59,0x48,0x85,0xa0,
	0x06,0x25,0x88,0x0e,0x9d,0xfb,0x73,0x41,0x63,0xce,0xce,0xf7,0x2c,0xf0,0x30,0xb8
};

const uint8_t AES_TESTING_CBC_LONG_DATA_CIPHERTEXT[] = {
	0xfc,0x58,0x73,0xe5,0x0d,0xe8,0xfa,0xf4,0xc6,0xb8,0x4b,0xa7,0x07,0xb0,0x85,0x4e,
	0x9d,0xb9,0xab,0x2e,0x9f,0x7d,0x70,0x7f,0xbb,0xa3,0x38,0xc6,0x84,0x3a,0x18,0xfc,
	0x6f,0xac,0xeb,0xaf,0x66,0x3d,0x26,0x29,0x6f,0xb3,0x29,0xb4,0xd2,0x6f,0x18,0x49,
	0x4c,0x79,0xe0,0x9e,0x77,0x96,0x47,0xf9,0xba,0xfa,0x87,0x48,0x96,0x30,0xd7,0x9f,
	0x43,0x01,0x61,0x0c,0x23,0x00,0xc1,0x9d,0xbf,0x31,0x48,0xb7,0xca,0xc8,0xc4,0xf4,
	0x94,0x41,0x02,0x75,0x4f,0x33,0x2e,0x92,0xb6,0xf7,0xc5,0xe7,0x5b,0xc6,0x17,0x9e,
	0xb8,0x77,0xa0,0x78,0xd4,0x71,0x90,0x09,0x02,0x17,0x44,0xc1,0x4f,0x13,0xfd,0x2a,
	0x55,0xa2,0xb9,0xc4,0x4d,0x18,0x00,0x06,0x85,0xa8,0x45,0xa4,0xf6,0x32,0xc7,0xc5,
	0x6a,0x77,0x30,0x6e,0xfa,0x66,0xa2,0x4d,0x05,0xd0,0x88,0xdc,0xd7,0xc1,0x3f,0xe2,
	0x4f,0xc4,0x47,0x27,0x59,0x65,0xdb,0x9e,0x4d,0x37,0xfb,0xc9,0x30,0x44,0x48,0xcd
};

const size_t AES_TESTING_CBC_LONG_DATA_LEN = sizeof (AES_TESTING_CBC_LONG_DATA_PLAINTEXT);
