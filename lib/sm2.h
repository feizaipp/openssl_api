#ifndef __RPMMULTI_SM2_
#define __RPMMULTI_SM2_
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>

int do_sm2_sign(unsigned char *data, int datalen, unsigned char *outdata, int *outlen, EC_KEY *key);
int do_sm2_verify(unsigned char *data, int datalen, unsigned char *outdata, int outlen, EC_KEY *key);
int do_sm2_encrypt(unsigned char *data, int datalen, unsigned char *outdata, int *outlen, EC_KEY *key);
int do_sm2_decrypt(unsigned char *data, int datalen, unsigned char *outdata, int *outlen, EC_KEY *key);

#endif