// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_H_
#define ATTESTATION_H_

#include <stdint.h>
#include "status/rot_status.h"


#define ATTESTATION_NONCE_LEN 				   SHA256_HASH_LENGTH


/**
 * Key exchange algorithms
 */
enum {
	ATTESTATION_KEY_EXCHANGE_NONE = 0,			/**< No key exchange requested */
	ATTESTATION_ECDHE_KEY_EXCHANGE,				/**< ECDHE key exchange */
	NUM_ATTESTATION_KEY_EXCHANGE_ALGORITHMS		/**< Number of key exchange algorithms */
};

/**
 * Slot numbers for each supported certificate chain
 */
enum {
	ATTESTATION_RIOT_SLOT_NUM = 0,				/**< Slot number for the RIoT certificate chain */
	ATTESTATION_AUX_SLOT_NUM,					/**< Slot number for the auxiliary certificate chain */
	ATTESTATION_MAX_SLOT_NUM = 7				/**< The maximum allowed ceritifate slot number */
};

/**
 * Certificate chain digests
 */
struct attestation_chain_digest {
	uint8_t *digest;							/**< Certificates digest buffer. */
	uint8_t digest_len;							/**< Certificates digest length. */
	uint8_t num_cert;							/**< Number of certificates in digest chain. */
};

#pragma pack(push, 1)
/**
 * Challenge nonce.  This follows the format in the Cerberus protocol.
 */
struct attestation_challenge {
	uint8_t slot_num;							/**< The slot number of the chain to use. */
	uint8_t reserved;							/**< Reserved */
	uint8_t nonce[ATTESTATION_NONCE_LEN];		/**< Nonce chosen by requestor. */
};

#define ATTESTATION_CHALLENGE_LEN 				(sizeof (struct attestation_challenge))

/**
 * Challenge attestation response.  This follows the format in the Cerberus protocol.
 */
struct attestation_response {
	uint8_t slot_num;							/**< The slot number of the chain used when generating response. */
	uint8_t slot_mask;							/**< The certificate slot mask. */
	uint8_t min_protocol_version;				/**< Minimum protocol version supported by device. */
	uint8_t max_protocol_version;				/**< Maximum protocol version supported by device. */
	uint16_t reserved;							/**< Reserved. */
	uint8_t nonce[ATTESTATION_NONCE_LEN];		/**< Nonce chosen by responder. */
	uint8_t num_digests;						/**< Number of components used to generate PMR digest. */
	uint8_t digests_size;						/**< Length of PMR digests in bytes. */
};

#define ATTESTATION_CHALLENGE_RSP_LEN 			(sizeof (struct attestation_response))
#pragma pack(pop)


#define	ATTESTATION_ERROR(code)					ROT_ERROR (ROT_MODULE_ATTESTATION, code)

/**
 * Error codes that can be generated by the attestation manager.
 */
enum {
	ATTESTATION_INVALID_ARGUMENT = ATTESTATION_ERROR (0x00),				/**< Input parameter is null or not valid. */
	ATTESTATION_NO_MEMORY = ATTESTATION_ERROR (0x01),						/**< Memory allocation failed. */
	ATTESTATION_INVALID_SLOT_NUM = ATTESTATION_ERROR (0x02),				/**< Unsupported certificate slot number. */
	ATTESTATION_INVALID_STATE = ATTESTATION_ERROR (0x03),					/**< Invalid state. */
	ATTESTATION_INVALID_DEVICE_NUM = ATTESTATION_ERROR (0x04),				/**< Invalid device number. */
	ATTESTATION_INVALID_CERT_NUM = ATTESTATION_ERROR (0x05),				/**< Invalid certificate number. */
	ATTESTATION_INVALID_DEVICE_ADDR = ATTESTATION_ERROR (0x06),				/**< Unsupported device address. */
	ATTESTATION_UNSUPPORTED_PROTOCOL_VERSION = ATTESTATION_ERROR (0x07),	/**< Unsupported protocol version. */
	ATTESTATION_INVALID_CERT_CHAIN = ATTESTATION_ERROR (0x08),				/**< Invalid certificate chain. */
	ATTESTATION_UNSUPPORTED_ALGORITHM = ATTESTATION_ERROR (0x09),			/**< Unsupported algorithm. */
	// ATTESTATION_INVALID_MEASUREMENT = ATTESTATION_ERROR (0x0A),			/**< Invalid platform measurement. */
	ATTESTATION_BUF_TOO_SMALL = ATTESTATION_ERROR (0x0B),					/**< Provided buffer too small for output. */
	ATTESTATION_CERT_NOT_AVAILABLE = ATTESTATION_ERROR (0x0C),				/**< Certificate queried not found. */
	ATTESTATION_BAD_LENGTH = ATTESTATION_ERROR (0x0D),						/**< The payload length is wrong for the request. */
	ATTESTATION_UNSUPPORTED_OPERATION = ATTESTATION_ERROR (0x0E),			/**< The requested operation is not supported. */
	ATTESTATION_NO_CFM = ATTESTATION_ERROR (0x0F),							/**< No active CFM found. */
	ATTESTATION_COMPONENT_TYPE_NOT_SET = ATTESTATION_ERROR (0x10),			/**< Component to attest has no component type set in device manager. */
};


#endif // ATTESTATION_H_