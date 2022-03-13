#include "sm2.h"
#include "errs.h"

int do_sm2_sign(unsigned char *data, int datalen, unsigned char *outdata, int *outlen, EC_KEY *key)
{
    int val = -1;

    // val = ECDSA_sign(0, data, datalen, outdata, outlen, key);
    val = SM2_sign(NID_undef, data, datalen, outdata, outlen, key);
    EC_KEY_free(key);
    if (val == 1) {
        return SIGN_SUCC;
    } else {
        return SIGN_ERR;
    }
}

int do_sm2_verify(unsigned char *data, int datalen, unsigned char *sig, int siglen, EC_KEY *key)
{
    int val = -1;

    // val = ECDSA_verify(0, data, datalen, sig, siglen, key);
    val = SM2_verify(NID_undef, data, datalen, sig, siglen, key);
    EC_KEY_free(key);
    if (val == 1) {
        return VERIFY_SUCC;
    } else {
        return VERIFY_ERR;
    }
}

int do_sm2_encrypt(unsigned char *data, int datalen, unsigned char *outdata, int *outlen, EC_KEY *key)
{
    int val = -1;

    val = SM2_encrypt(NID_sm3, data, datalen, outdata, outlen, key);
    return val;
}

int do_sm2_decrypt(unsigned char *data, int datalen, unsigned char *outdata, int *outlen, EC_KEY *key)
{
    int val = -1;

    val = SM2_decrypt(NID_sm3, data, datalen, outdata, *outlen, key);
    return val;
}
