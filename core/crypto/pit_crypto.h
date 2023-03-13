#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecdh.h"

#define SUCESS 1

/**
 * Generates a key pair, sets the state appropriately
 * @param key_length The length of key to use in bytes. 256, 381, 521 bits (so X / 8 bytes) are the supported lengths
 * @param privkey Output for the initialized private key
 * @param pubkey Output for the initialized public key
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int pit_keygenstate(size_t key_length, struct ecc_private_key *privkey, struct ecc_public_key *pubkey, int *state);


/**
 * Generates a secret key - AES Shared Key
 * @param privkey The private key used to generate the secret
 * @param pubkey The public key used to generate the secret
 * @param secret An non-null output buffer to hold the generated shared secret
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int pit_secretkey(struct ecc_private_key *privkey, struct ecc_public_key *pubkey, uint8_t *secret, int *state);


/**
 * Uses AES-GCM encryption to encrypt a message into ciphertext using a secret key
 * @param msg A plaintext message you would like to encrypt
 * @param msg_size The size of the plaintext message
 * @param secret A secret key to use for encryption
 * @param secret_length The size of the secret key
 * @param AESIV An IV to use for encryption. A 12-byte IV is best (meets NIST standards)
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The buffer to hold the GCM authentication tag. All tags will be 16 bytes
 * @param ciphertext An empty output buffer to hold the encrypted data. The ciphertext will be the same length as the plaintext
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int pit_encryption(uint8_t *msg, size_t msg_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *ciphertext, int *state);


/**
 * Uses AES-GCM encryption to decrypt a message from ciphertext using a secret key
 * @param ciphertext The ciphertext you would like to decrypt
 * @param ciphertext_size The size of the ciphertext message
 * @param secret A secret key to use for encryption
 * @param secret_length The size of the secret key
 * @param AESIV An IV to use for encryption. A 12-byte IV is best (meets NIST standards)
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The buffer to hold the GCM authentication tag. All tags will be 16 bytes
 * @param plaintext The buffer to hold the decrypted ciphertext (Will be the same size as the ciphertext)
 * @return 1 on success
*/
int pit_decryption(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *plaintext, int *state);

/**
 * A function to generate a random string representing OTP. Additionally, this function will encrypt that OTP using AES-GCM encryption, using the secret key for the AES encryption.
 * @param secret The secret key to encrypt the OTP with
 * @param secret_size The size of the secret key
 * @param AESIV An IV to use for encryption. A 12-byte IV is best (meets NIST standards)
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The output buffer to hold the GCM authentication tag. All tags will be 16 bytes
 * @param OTP An output buffer to hold a randomly generated OTP into
 * @param OTPSize The size the randomly generated OTP should be
 * @param OTPs An initialized but empty buffer to hold the encrypted OTP in (OTPs and OTP will be the same size)
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int pit_OTPgen(uint8_t *secret,  size_t secret_size, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *OTP, size_t OTPSize, uint8_t *OTPs, int *state);

/**
 * Decrypts an encrypted OTP and compares it to a valid version of the OTP. If the OTP decrypts successfully and matches the valid OTP, the result parameter contains true.
 * @param secret The secret key used to decrypt OTPs
 * @param secret_size The size of the secret key
 * @param AESIV An IV to use for decryption. Must be the same as the IV provided to encrypt
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The AES-GCM tag for the ciphertext
 * @param OTPs A full buffer holding the value for OTPs (an encrypted OTP to validate against)
 * @param OTPs_size The size of OTPs
 * @param valOTP OTP to be validated against the decrypted OTP
 * @param result A boolean value to check whether the OTP was successfully validated
 * @param An int to hold the numerical value of the state
 * @return 1 on success
*/
int pit_OTPvalidation(uint8_t * secret, size_t secret_size, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *OTPs, size_t OTPs_size, uint8_t *valOTP, bool *result, int *state);

#define	PIT_CRYPTO_ERROR(code)		ROT_ERROR (ROT_MODULE_PIT_CRYPTO, code)

/**
 * Error codes that can be generated by a hash or HMAC engine.
 */
enum {
  PIT_CRYPTO_DECRYPTION_FAILED = PIT_CRYPTO_ERROR (0x00),	/** Decryption failed*/
  PIT_CRYPTO_ENCRYPTION_FAILED = PIT_CRYPTO_ERROR (0x01),	/** Encryption failed*/
  PIT_CRYPTO_SECRET_KEY_NOT_EXPECTED_LENGTH = PIT_CRYPTO_ERROR (0x02), /** Failed to compute secret key*/
  PIT_CRYPTO_KEY_GENERATION_FAILED = PIT_CRYPTO_ERROR (0x03), /** Failed to generate a keypair*/
  PIT_CRYPTO_OTP_GENERATION_FAILED = PIT_CRYPTO_ERROR (0x04),
  PIT_CRYPTO_OTP_INVALID = PIT_CRYPTO_ERROR (0x05), /** SHOULD ALSO BE ERROR*/
};