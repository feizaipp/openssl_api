#include "callback.h"
#include "sqlite_helper.h"
#include "utils.h"
#include "sm3.h"
#include "sm2.h"
#include "log.h"
#include "errs.h"
#include <dirent.h>
// #include "ukey.h"
#include <openssl/gmapi.h>

#define IPC_CODE "528467391"

gboolean on_handle_get_rpminfos(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    gpointer user_data)
{
    GVariantBuilder builder;
    GVariant *ret = NULL;
    gint count, i;
    gchar *name = NULL;
    gchar *cert = NULL;
    gchar *hash = NULL;

    if (strcmp(code, IPC_CODE)) {
        rpm_multi_base_complete_get_rpminfos(skeleton, invocation, NULL);

        return TRUE;
    }
    g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(sss)"));
    count = query_count();
    for (i=0; i<count; i++) {
        _get_rpminfo_by_index(i, &cert, &name, &hash);
        g_variant_builder_add (&builder, "(sss)", cert, name, hash);
        g_free(name);
        g_free(cert);
        g_free(hash);
    }
    ret = g_variant_builder_end (&builder);
    rpm_multi_base_complete_get_rpminfos(skeleton, invocation, ret);

    return TRUE;
}

gboolean on_handle_get_rpminfo(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *hash,
                                                    gpointer user_data)
{
    gchar *cert;
    gchar *name;
    gchar *before;
    gchar *after;
    gchar *time;

    if (strcmp(code, IPC_CODE)) {
        rpm_multi_base_complete_get_rpminfo(skeleton, invocation, NULL, NULL, NULL, NULL, NULL);

        return TRUE;
    }
    _get_rpminfo_by_hash(hash, &cert, &name, &before, &after, &time);
    rpm_multi_base_complete_get_rpminfo(skeleton, invocation, cert, name, before, after, time);
    g_free(cert);
    g_free(name);
    g_free(before);
    g_free(after);
    g_free(time);

    return TRUE;
}

gboolean on_handle_insert_cert(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *path,
                                                    const gchar *name,
                                                    gpointer user_data)
{
    int cert_len;
    unsigned char *cert = NULL;
    char before[1024] = {0};
    char after[1024] = {0};
    char time[1024] = {0};
    unsigned char hash[SM3_DIGEST_LENGTH] = {0};
    char encode_hash[1024] = {0};
    X509 *x = NULL;
    int ret;
    int i;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_insert_cert(skeleton, invocation, ret);

        return TRUE;
    }
    x = get_x509_from_file(path);
    if (!x) {
        ret = CERT_INVALID;
        goto err;
    }
    cert = read_data(path, &cert_len);
    ret = verify_cert_chain(x);
    if (!ret) {
        ret = CERT_INVALID;
        goto err;
    }
    cert_encode(cert, cert_len);
    get_cert_before(x, before, sizeof(before));
    get_cert_after(x, after, sizeof(after));
    do_sm3_digest(cert, cert_len, hash);
    get_curr_date(time, sizeof(time));
    base64_encode(hash, sizeof(hash), (uint8 *)encode_hash);

    if (query_by_hash(encode_hash)) {
        ret = CERT_EXIST;
        goto err;
    }
    if (query_by_name(name)) {
        ret = NAME_EXIST;
        goto err;
    }
    ret = insert_table(cert, name, before, after, time, encode_hash);

err:
    free(cert);
    X509_free(x);
    rpm_multi_base_complete_insert_cert(skeleton, invocation, ret);

    return TRUE;
}

gboolean on_handle_delete_cert(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *hash,
                                                    gpointer user_data)
{
    int ret;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_delete_cert(skeleton, invocation, ret);

        return TRUE;
    }
    ret = delete_by_hash(hash);
    rpm_multi_base_complete_delete_cert(skeleton, invocation, ret);

    return TRUE;
}

gboolean on_handle_insert_ukey(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *path,
                                                    const gchar *pass,
                                                    const gchar *pin,
                                                    gpointer user_data)
{
    int ret;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_insert_ukey(skeleton, invocation, ret);

        return TRUE;
    }

    ret = do_insert_ukey(path, pass, pin);

    rpm_multi_base_complete_insert_ukey(skeleton, invocation, ret);

    return TRUE;
}

gboolean on_handle_sm3_digest(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *path,
                                                    gpointer user_data)
{
    int ret;
    unsigned char hash[SM3_DIGEST_LENGTH] = {0};
    unsigned char encode_hash[1024] = {0};
    unsigned char *data = NULL;
    int datalen;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_sm3_digest(skeleton, invocation, ret, NULL);

        return TRUE;
    }
    data = read_data(path, &datalen);
    ret = do_sm3_digest(data, datalen, hash);
    base64_encode(hash, sizeof(hash), (uint8 *)encode_hash);
    rpm_multi_base_complete_sm3_digest(skeleton, invocation, ret, encode_hash);
    free(data);

    return TRUE;
}

gboolean on_handle_sm2_sign(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *pass,
                                                    const gchar *hash,
                                                    gpointer user_data)
{
    int ret = RET_OK;
    unsigned char sig[256] = {0};
    unsigned char decode_hash[SM3_DIGEST_LENGTH] = {0};
    unsigned char encode_sig[1024] = {0};
    int len_sig;
    void *key = NULL;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_sm2_sign(skeleton, invocation, ret, NULL);

        return TRUE;
    }
    ret = get_privkey_from_file(pass, &key);
    if (ret != RET_OK) {
        rpm_multi_base_complete_sm2_sign(skeleton, invocation, ret, NULL);
        goto end;
    }
    if (key) {
        base64_decode(hash, strlen(hash), (uint8 *)decode_hash);
        ret = do_sm2_sign(decode_hash, SM3_DIGEST_LENGTH, sig, &len_sig, key);
        if (ret == SIGN_SUCC) {
            // DER-->ECCSignature
            const unsigned char *p = sig;
            ECCSignature ecc_sig;
            ECDSA_SIG *ec_sig = NULL;
            ec_sig = ECDSA_SIG_new();
            d2i_ECDSA_SIG(&ec_sig, &p, len_sig);
            ECDSA_SIG_get_ECCSignature(ec_sig, &ecc_sig);
            ECDSA_SIG_free(ec_sig);

            memset(sig, 0, sizeof(sig));
            memcpy(sig, ecc_sig.r, ECCref_MAX_LEN);
            memcpy(sig + ECCref_MAX_LEN, ecc_sig.s, ECCref_MAX_LEN);
            len_sig = ECCref_MAX_LEN * 2;
            base64_encode(sig, len_sig, encode_sig);
            rpm_multi_base_complete_sm2_sign(skeleton, invocation, ret, encode_sig);
        } else {
            rpm_multi_base_complete_sm2_sign(skeleton, invocation, ret, NULL);
        }
    }

end:
    return TRUE;
}

gboolean on_handle_sm2_verify(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *hash,
                                                    const gchar *sig,
                                                    gpointer user_data)
{
    int ret = 0;
    unsigned char decode_hash[SM3_DIGEST_LENGTH] = {0};
    unsigned char decode_sig[256] = {0};
    unsigned char* der_sig = NULL;
    int der_len;
    int hash_len;
    int sig_len;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_sm2_verify(skeleton, invocation, ret);

        return TRUE;
    }
    hash_len = base64_decode(hash, strlen(hash), (uint8 *)decode_hash);
    sig_len = base64_decode(sig, strlen(sig), (uint8 *)decode_sig);
    // ECCSignature-->DER
    der_len = i2d_ECCSignature(decode_sig, &der_sig);
    if (der_sig) {
        ret = get_cert_to_verify(decode_hash, hash_len, der_sig, der_len, do_sm2_verify);
        free(der_sig);
    }
    rpm_multi_base_complete_sm2_verify(skeleton, invocation, ret);

    return TRUE;
}

gboolean on_handle_import_privkey(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *pass,
                                                    const gchar *path,
                                                    const gchar *filename,
                                                    gpointer user_data)
{
    int ret = 0;
    void *key = NULL;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_import_privkey(skeleton, invocation, ret);
        return TRUE;
    }
    ret = get_privkey_from_file1(pass, path, &key);
    if (ret != RET_OK) {
        rpm_multi_base_complete_import_privkey(skeleton, invocation, ret);
        return TRUE;
    }
    if (key) {
        EC_KEY_free(key);
    }

    ret = copy_privfile(path, filename);

    rpm_multi_base_complete_import_privkey(skeleton, invocation, ret);

    return TRUE;
}

gboolean on_handle_get_privkeys(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    gpointer user_data)
{
    DIR *dir;
    struct dirent *dir_entry;
    GVariantBuilder builder;
    GVariant *ret = NULL;

    if (strcmp(code, IPC_CODE)) {
        rpm_multi_base_complete_get_privkeys(skeleton, invocation, NULL);
        return TRUE;
    }

    dir = opendir(PRIV_PATH);
    if (dir == NULL) {
        rpm_multi_base_complete_get_privkeys(skeleton, invocation, NULL);
        return TRUE;
    }
    g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(s)"));
    while((dir_entry = readdir(dir)) != NULL) {
        if (dir_entry->d_type & DT_REG) {
            g_variant_builder_add (&builder, "(s)", dir_entry->d_name);
        }
    }
    ret = g_variant_builder_end (&builder);
    rpm_multi_base_complete_get_privkeys(skeleton, invocation, ret);
    closedir(dir);

    return TRUE;
}

gboolean on_handle_set_privkey(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *name,
                                                    gpointer user_data)
{
    int ret = 0;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_import_privkey(skeleton, invocation, ret);
        return TRUE;
    }

    ret = set_privfile(name);
    rpm_multi_base_complete_import_privkey(skeleton, invocation, ret);
    return TRUE;
}

gboolean on_handle_backup_param(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *path,
                                                    const gchar *pin,
                                                    gpointer user_data)
{
    int ret = 0;

    if (strcmp(code, IPC_CODE)) {
        ret = CODE_ERR;
        rpm_multi_base_complete_backup_param(skeleton, invocation, ret);
        return TRUE;
    }

    ret = do_backup_param(path, pin);
    rpm_multi_base_complete_backup_param(skeleton, invocation, ret);
    return TRUE;
}
