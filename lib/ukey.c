#include "ukey.h"
#include "utils.h"
#include "errs.h"
#include <string.h>
#include "log.h"

const static unsigned char p[32] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

const static unsigned char a[32] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};

const static unsigned char b[32] = {0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B,
                                            0xCF, 0x65, 0x09, 0xA7, 0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
                                            0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93};

const static unsigned char n[32] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
                                            0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23};

const static unsigned char x[32] = {0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46,
                                            0x6A, 0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
                                            0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7};

const static unsigned char y[32] = {0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3,
                                            0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
                                            0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0};


#define PRIV_ID "\x00\x58"
#define PUB_ID "\x00\x57"

static int gen_sm2_key(unsigned char *priv_key, unsigned char *pub_key, struct sm2_key *key)
{
    memcpy(key->param.p, p, KEY_LEN_SM2);
    memcpy(key->param.a, a, KEY_LEN_SM2);
    memcpy(key->param.b, b, KEY_LEN_SM2);
    memcpy(key->param.n, n, KEY_LEN_SM2);
    memcpy(key->param.x, x, KEY_LEN_SM2);
    memcpy(key->param.y, y, KEY_LEN_SM2);

    memcpy(key->priv.d, priv_key, KEY_LEN_SM2);
    memcpy(key->pub.x, pub_key, KEY_LEN_SM2);
    memcpy(key->pub.y, pub_key + 32, KEY_LEN_SM2);

    return RET_OK;
}

static int import_sm2_key(char *pin, struct sm2_key *key)
{
    int ret;
    int val = RET_OK;
    int devNum = 0;
    XKF_HANDLE handle;
    XDJA_SM2_PUBKEY pubkey = {0};
    XDJA_SM2_PRIKEY privkey = {0};

    ret = XKF_EnumDev(CT_ALL, &devNum);
    if (ret != XKR_OK) {
        LOGE("XKF_EnumDev failed %d.\n", ret);
        return -1;
    }
    if (devNum > 1) {
        return PLUG_TOO_MANY;
    }
    if (devNum == 0) {
        return NO_PLUG_UKEY;
    }

    ret = XKF_OpenDev(0, &handle);
    if (ret != XKR_OK) {
        LOGE("XKF_OpenDev failed : %d.\n", ret);
        return -1;
    }

    ret = XKF_VerifyPIN(handle, ROLE_Q, pin, strlen(pin));
    if (ret != XKR_OK) {
        LOGE("XKF_VerifyPIN failed : %d.\n", ret);
        val = ret;
        goto out;
    }

    ret = XKF_WriteSm2PubKey(handle, PUB_ID, &key->pub);
    if (ret != XKR_OK) {
        LOGE("XKF_WriteSm2PubKey failed : %d.\n", ret);
        val = -1;
        goto out;
    }

    ret = XKF_WriteSm2PriKey(handle, PRIV_ID, &key->priv);
    if (ret != XKR_OK) {
        LOGE("XKF_WriteSm2PriKey failed : %d.\n", ret);
        val = -1;
        goto out;
    }

    ret = XKF_SetSM2Param(handle, &key->param);
    if (ret != XKR_OK) {
        LOGE("XKF_SetSM2Param failed : %d.\n", ret);
        val = -1;
        goto out;
    }

out:
    ret  = XKF_CardReset(handle);
    if (ret != XKR_OK) {
        LOGE("XKF_CardReset failed : %d.\n", ret);
    }
    ret = XKF_CloseDev(handle);
    if (ret != XKR_OK) {
        LOGE("close dev failed : %d.\n", ret);
        return -1;
    }
    return val;
}

int get_sm2_key(const char *path, const char *pass, struct sm2_key *sm2)
{
    int ret = RET_OK;
    void *key = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    size_t privlen = 0, publen = 0;

    if (!file_exists(path)) {
        ret = FILE_NO_EXIST;
        goto out;
    }

    ret = get_privkey_from_file1(pass, path, &key);
    if (ret != RET_OK) {
        goto out;
    }

    if (key) {
        if (EC_KEY_get0_public_key(key) != NULL) {
            publen = EC_KEY_key2buf(key, EC_KEY_get_conv_form(key), &pub, NULL);
        }
        if (EC_KEY_get0_private_key(key) != NULL) {
            privlen = EC_KEY_priv2buf(key, &priv);
        }
        if (priv != NULL && pub != NULL) {
            gen_sm2_key(priv, pub + 1, sm2);
        }
        OPENSSL_clear_free(priv, privlen);
        OPENSSL_free(pub);
        EC_KEY_free(key);
    }

out:
    return ret;
}

int do_sign_with_ukey(char *pin, unsigned char *data, int datalen, unsigned char *outdata, int *outlen)
{
    int ret;
    int val = RET_OK;
    int devNum = 0;
    XKF_HANDLE handle;

    ret = XKF_EnumDev(CT_ALL, &devNum);
    if (ret != XKR_OK) {
        LOGE("XKF_EnumDev failed %d.\n", ret);
        return -1;
    }
    if (devNum > 1) {
        return PLUG_TOO_MANY;
    }
    if (devNum == 0) {
        return NO_PLUG_UKEY;
    }

    ret = XKF_OpenDev(0, &handle);
    if (ret != XKR_OK) {
        LOGE("XKF_OpenDev failed : %d.\n", ret);
        return -1;
    }

    ret = XKF_VerifyPIN(handle, ROLE_Q, pin, strlen(pin));
    if (ret != XKR_OK) {
        val = ret;
        LOGE("XKF_VerifyPIN failed : %d.\n", ret);
        goto out;
    }

    ret = XKF_SM2Sign(handle, PUB_ID, PRIV_ID, SIGN_NOHASH, data, datalen, outdata, outlen);
    if (ret != XKR_OK) {
        LOGE("XKF_SM2Sign failed. ret:%d\n", ret);
        val = -1;
        goto out;
    }

out:
    ret  = XKF_CardReset(handle);
    if (ret != XKR_OK) {
        LOGE("XKF_CardReset failed : %d.\n", ret);
    }
    ret = XKF_CloseDev(handle);
    if (ret != XKR_OK) {
        LOGE("close dev failed : %d.\n", ret);
        return -1;
    }
    return val;
}

static int get_sm2_param(char *pin, XDJA_SM2_PUBKEY *param)
{
    int ret;
    int val = RET_OK;
    int devNum = 0;
    XKF_HANDLE handle;

    ret = XKF_EnumDev(CT_ALL, &devNum);
    if (ret != XKR_OK) {
        LOGE("XKF_EnumDev failed %d.\n", ret);
        return -1;
    }
    if (devNum > 1) {
        return PLUG_TOO_MANY;
    }
    if (devNum == 0) {
        return NO_PLUG_UKEY;
    }

    ret = XKF_OpenDev(0, &handle);
    if (ret != XKR_OK) {
        LOGE("XKF_OpenDev failed : %d.\n", ret);
        return -1;
    }

    ret = XKF_VerifyPIN(handle, ROLE_Q, pin, strlen(pin));
    if (ret != XKR_OK) {
        val = ret;
        LOGE("XKF_VerifyPIN failed : %d.\n", ret);
        goto out;
    }

    ret = XKF_GetSM2Param(handle, param);
    if (ret != XKR_OK) {
        LOGE("XKF_SetSM2Param failed : %d.\n", ret);
        val = -1;
        goto out;
    }

out:
    ret  = XKF_CardReset(handle);
    if (ret != XKR_OK) {
        LOGE("XKF_CardReset failed : %d.\n", ret);
    }
    ret = XKF_CloseDev(handle);
    if (ret != XKR_OK) {
        LOGE("close dev failed : %d.\n", ret);
        return -1;
    }
    return val;
}

int do_backup_param(char *path, char *pin)
{
    int ret = RET_OK;
    XDJA_SM2_PUBKEY param;
    char *dname;
    char *file = NULL;
    FILE *fp = NULL;
	int count;
    unsigned char encode_param[4096] = {0};
    int encode_len;
    // int i;

    file = strdup(path);
    dname = dirname(file);
    if (!dir_exists(dname)) {
        ret = DIR_NO_EXIST;
        goto out;
    }
    if (file_exists(path)) {
        ret = FILE_ALREADY_EXIST;
        goto out;
    }

    ret = get_sm2_param(pin, &param);
    // for (i=0; i<sizeof(param); i++) {
    //     LOGE("0x%02x", ((unsigned char *)&param)[i]);
    // }
    // LOGE("\n");

    encode_len = base64_encode(&param, sizeof(param), encode_param);
    if (ret == XKR_OK) {
        // 写入文件
        fp = fopen(path, "w+");
        if (fp == NULL) {
            LOGE("open or create %s failed.\n", path);
            ret = -1;
            goto out;
        }
        count = fwrite(encode_param, encode_len, 1, fp);
        if (count <= 0) {
            LOGE("write file %s failed.\n", path);
            ret = -1;
            goto out1;
        }
        fsync(fileno(fp));
    }

out1:
    fclose(fp);
out:
    if (file) free(file);
    return ret;
}

int do_insert_ukey(char *path, char *pass, char *pin)
{
    int ret;
    struct sm2_key key;

    if (!file_exists(path)) {
        ret = FILE_NO_EXIST;
        goto out;
    }
    ret = get_sm2_key(path, pass, &key);
    if (ret != RET_OK) {
        LOGE("get_sm2_key failed ret :%d.\n", ret);
        goto out;
    }
    ret = import_sm2_key(pin, &key);

out:
    return ret;
}