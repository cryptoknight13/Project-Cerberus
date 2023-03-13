// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef OCP_RECOVERY_SMBUS_H_
#define OCP_RECOVERY_SMBUS_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "ocp_recovery_device.h"


#pragma pack(push, 1)
/**
 * The buffer to use for sending and receiving SMBus commands.
 */
union ocp_recovery_smbus_cmd_buffer {
	/**
	 * Payload structure of an SMBus block write or read command.
	 */
	struct ocp_recovery_smbus_block_cmd {
		uint8_t byte_count;								/**< The number of bytes being transmitted. */
		union ocp_recovery_device_cmd_buffer payload;	/**< The command payload. */
		uint8_t pec;									/**< Placeholder for the CRC8 checksum of the entire transaction. */
	} block_cmd;										/**< SMBus block write or read command. */
	uint8_t bytes[257];									/**< Raw byte access to the data. */
};
#pragma pack(pop)

/**
 * Variable context for the recovery SMBus protocol handler.
 */
struct ocp_recovery_smbus_state {
	uint8_t crc;								/**< CRC8 value of the current command. */
	int rx_bytes;								/**< The number of command bytes received. */
	union ocp_recovery_smbus_cmd_buffer cmd;	/**< Data buffer for the current command. */
};

/**
 * SMBus protocol layer for handling OCP Recovery commands.
 */
struct ocp_recovery_smbus {
	struct ocp_recovery_smbus_state *state;		/**< The variable context for the handler. */
	const struct ocp_recovery_device *device;	/**< The device handler for recovery commands. */
};


/**
 * Initialize a static instance of an OCP Recovery SMBus handler.  This does not initialize the
 * handler state.  That will need to be initialized separately with ocp_recovery_smbus_init_state.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the SMBus handler.
 * @param device_ptr The device handler for the recovery protocol.  This can be a constant instance.
 */
#define	ocp_recovery_smbus_static_init(state_ptr, device_ptr)	{ \
		.state = state_ptr, \
		.device = device_ptr \
	}

int ocp_recovery_smbus_init (struct ocp_recovery_smbus *smbus,
	struct ocp_recovery_smbus_state *state, const struct ocp_recovery_device *device);
int ocp_recovery_smbus_init_state (const struct ocp_recovery_smbus *smbus);
void ocp_recovery_smbus_release (const struct ocp_recovery_smbus *smbus);

void ocp_recovery_smbus_start (const struct ocp_recovery_smbus *smbus, uint8_t smbus_addr);
void ocp_recovery_smbus_stop (const struct ocp_recovery_smbus *smbus);

int ocp_recovery_smbus_receive_byte (const struct ocp_recovery_smbus *smbus, uint8_t data);
int ocp_recovery_smbus_transmit_bytes (const struct ocp_recovery_smbus *smbus, uint8_t smbus_addr,
	const union ocp_recovery_smbus_cmd_buffer **data);


#define	OCP_RECOVERY_SMBUS_ERROR(code)		ROT_ERROR (ROT_MODULE_OCP_RECOVERY_SMBUS, code)

/**
 * Error codes that can be generated by an OCP recovery SMBus layer.
 */
enum {
	OCP_RECOVERY_SMBUS_INVALID_ARGUMENT = OCP_RECOVERY_SMBUS_ERROR (0x00),	/**< Input parameter is null or not valid. */
	OCP_RECOVERY_SMBUS_NO_MEMORY = OCP_RECOVERY_SMBUS_ERROR (0x01),			/**< Memory allocation failed. */
	OCP_RECOVERY_SMBUS_OVERFLOW = OCP_RECOVERY_SMBUS_ERROR (0x02),			/**< A block write has received too many bytes. */
	OCP_RECOVERY_SMBUS_NACK = OCP_RECOVERY_SMBUS_ERROR (0x03),				/**< The received data is for an invalid command. */
};


#endif /* OCP_RECOVERY_SMBUS_H_ */
