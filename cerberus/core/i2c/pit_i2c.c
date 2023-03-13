#include <arpa/inet.h>
#include "i2c/pit_i2c.h"
#include "crypto/ecc_mbedtls.h"
#include "mbedtls/ecdh.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int pit_connect(int desired_port){
  // Communicate w/ server, (will be i2c in final version, must be overwritten) (expand on this)
  char* ip = "127.0.0.1";
  int port = desired_port;

  int sock;
  struct sockaddr_in addr;


  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0){

    return PIT_I2C_CONNECTION_FAILURE;

  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);

  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {

    return PIT_I2C_CONNECTION_FAILURE;
  }



  return sock;
}


//May need to override depending on how pit_connect is implemented
int keyexchangestate(uint8_t *pubkey_cli, size_t pubkey_der_length, uint8_t *pubkey_serv){
  int sock = pit_connect(5572);

  send(sock, pubkey_cli, pubkey_der_length, 0); //Will always be length 91 for this curve, send client public key (DER Format)

  recv(sock, pubkey_serv, pubkey_der_length, 0); //Receive the server's public key (DER Format)

  return SUCESS;
}



int send_unlock_info(uint8_t *OTPs, size_t OTPs_size, uint8_t *unlock_aes_iv, size_t unlock_aes_iv_size, uint8_t *OTP_tag, uint8_t *server_encrypted_message, uint8_t *server_tag){
  int sock = pit_connect(5573);
  send(sock, OTPs, OTPs_size, 0);                    //Send OTPs
  send(sock, unlock_aes_iv, unlock_aes_iv_size, 0);  //Send the IV for the AES cipher
  send(sock, OTP_tag, 16, 0);                        //Send AES-GCM tag

  //recv(sock, server_encrypted_message, OTPs_size, 0);      //Received server's encrypted message (OTPs)
  printf("Please Enter your OTP:\n");
  scanf("%d", &server_encrypted_message);
  recv(sock, server_tag, 16, 0);                      //Receive server's message tag

  return SUCESS;
}


int receive_product_info(uint8_t *EncryptedProductID, uint8_t *EncryptedProductIDTag, size_t ProductIDSize, uint8_t *aes_iv, size_t aes_iv_size){
  //printf("Trying to connect in receive_product_info...\n");
  int sock = pit_connect(5574);
  send(sock, aes_iv, aes_iv_size, 0);
  recv(sock, EncryptedProductID, ProductIDSize, 0);
  recv(sock, EncryptedProductIDTag, 16, 0);
  return SUCESS;

}