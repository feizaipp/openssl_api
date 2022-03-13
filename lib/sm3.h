#ifndef __RPMMULTI_SM3_
#define __RPMMULTI_SM3_
#include <openssl/sm3.h>

int do_sm3_digest(unsigned char *data, int datalen, unsigned char *hash);

#endif