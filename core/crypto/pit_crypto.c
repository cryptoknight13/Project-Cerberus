#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/aes_mbedtls.h"
#include "mbedtls/pk.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "crypto/rng_mbedtls.h"
#include <stdbool.h>
#include "pit/pit.h"
#include <arpa/inet.h>
#include "i2c/pit_i2c.h"
#include "pit_crypto.h"


int pit_keygenstate(size_t key_length, struct ecc_private_key *privkey, struct ecc_public_key *pubkey, int *state){
  // Do the computation and generate privkey and pubkey
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  int status = engine.base.generate_key_pair (&engine.base, key_length, privkey, pubkey);
  
  *state = 1;
  ecc_mbedtls_release (&engine);
  if(status == 0){
    return SUCESS;
  }
  else{
    return PIT_CRYPTO_KEY_GENERATION_FAILED;
  }
  
}


//Let's update the names to be more "api" like - pit_secret_key_gen or something similar...
int pit_secretkey(struct ecc_private_key *privkey, struct ecc_public_key *pubkey, uint8_t *secret, int *state){
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  int shared_length = engine.base.get_shared_secret_max_length(&engine.base, privkey);
  uint8_t out[shared_length];
  int status = engine.base.compute_shared_secret (&engine.base, privkey, pubkey, out, sizeof (out));
  ecc_mbedtls_release (&engine);

  memcpy(secret, out, shared_length);

  if(shared_length != status){
    return PIT_CRYPTO_SECRET_KEY_NOT_EXPECTED_LENGTH;
  }
  *state = 3;
  return SUCESS;
}

int pit_encryption(uint8_t *msg, size_t msg_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *ciphertext, int *state){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);


  aes_engine.base.set_key(&aes_engine.base, secret, secret_length);
  int status = aes_engine.base.encrypt_data (&aes_engine.base, msg, msg_size, AESIV,
		      AESIV_SIZE, ciphertext, msg_size, tag, 16);
  aes_mbedtls_release(&aes_engine);

  *state = 4;
  if(status != 0){
    return PIT_CRYPTO_ENCRYPTION_FAILED;
  }
  return SUCESS;

}

int pit_decryption(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *plaintext, int *state){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  aes_engine.base.set_key (&aes_engine.base, secret, secret_length);

  int stat = aes_engine.base.decrypt_data (&aes_engine.base, ciphertext, ciphertext_size,
		tag, AESIV, AESIV_SIZE, plaintext, ciphertext_size);
  *state = 5;
  if(stat != 0){
    return PIT_CRYPTO_DECRYPTION_FAILED;
  }
  return SUCESS;
}

int pit_OTPgen(uint8_t *secret,  size_t secret_size, uint8_t *AESIV, size_t aesiv_size, uint8_t *tag, uint8_t *OTP, size_t OTPsize, uint8_t *OTPs, int *state){
  struct rng_engine_mbedtls engine;
	int status;
	status = rng_mbedtls_init (&engine);
	status = engine.base.generate_random_buffer (&engine.base, OTPsize, OTP);
  if(status != 0){
    return PIT_CRYPTO_OTP_GENERATION_FAILED;
  }

status = pit_encryption(OTP, OTPsize, secret, secret_size, AESIV, aesiv_size, tag, OTPs, state);

if(status != 1){
  return PIT_CRYPTO_ENCRYPTION_FAILED;
}

*state = 6;
return SUCESS;
}


int pit_OTPvalidation(uint8_t * secret, size_t secret_size, uint8_t *AESIV, size_t AESIV_size, uint8_t *tag, uint8_t *OTPs, size_t OTPs_size, uint8_t *valOTP, bool *result, int *state){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  aes_engine.base.set_key (&aes_engine.base, secret, secret_size);

  uint8_t plaintext[OTPs_size];
  int stat = aes_engine.base.decrypt_data (&aes_engine.base, OTPs, OTPs_size,
		tag, AESIV, AESIV_size, plaintext, OTPs_size);

  if(stat != 0){
    return PIT_CRYPTO_DECRYPTION_FAILED;
  }

  
  bool flag = true;

  for(int i = 0; i < (int)OTPs_size; i++){
    if(plaintext[i] != valOTP[i]){
      flag = false;
      break;
    }
  }

  *result = flag;
  *state = 7;
  if(flag){
    return SUCESS;
  }
  return PIT_CRYPTO_OTP_INVALID;
}


