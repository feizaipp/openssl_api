#ifndef __RPMMULTI_UKEY_
#define __RPMMULTI_UKEY_

#include "XdjaKeyApi.h"

struct sm2_key {
    XDJA_SM2_PARAM param;
    XDJA_SM2_PRIKEY priv;
    XDJA_SM2_PUBKEY pub;
};

int do_backup_param(char *path, char *pin);
int do_insert_ukey(char *path, char *pass, char *pin);
int do_sign_with_ukey(char *pin, unsigned char *data, int datalen, unsigned char *outdata, int *outlen);

#endif