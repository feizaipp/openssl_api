#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sqlite3.h>
#include <errno.h>
#include <syslog.h>
#include "sqlite_helper.h"
#include "log.h"
#include "errs.h"
#include "utils.h"

#define DB_PATH "/var/lib/rpmmultiservice/rpm-multi.db"

#define CREATE_RPMMULTI_TABLE \
    "CREATE TABLE IF NOT EXISTS rpmmulti_table" \
    "(ID INTEGER primary key autoincrement," \
    "cert TEXT," \
    "name TEXT," \
    "before TEXT," \
    "after TEXT," \
    "time TEXT," \
    "hash TEXT," \
    "tmp1 TEXT," \
    "tmp2 TEXT," \
    "tmp3 INTEGER" \
    ")"

#define INSERT_RPMMULTI_TABLE \
    "INSERT INTO rpmmulti_table" \
    "(cert, name, before, after, time, hash, tmp1, tmp2, tmp3)" \
    "VALUES" \
    "(?, ?, ?, ?, ?, ?, ?, ?, ?)"

#define DELETE_BY_HASH "DELETE FROM rpmmulti_table WHERE hash=?"
#define QUERY_RPMINFOS "SELECT * FROM rpmmulti_table"
#define QUERY_TABLE_EXIST "SELECT count(*) FROM sqlite_master WHERE type='table' and name=?"

static struct listnode rpminfo_list;

static sqlite3 *open_db()
{
    int ret;
    sqlite3 *handle = NULL;

    ret = sqlite3_open(DB_PATH, &handle);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "open db (%s) failed.", DB_PATH);
        return NULL;
    }

    return handle;
}

static int close_db(sqlite3 *handle)
{
    if (handle) {
        sqlite3_close(handle);
    }
    return 0;
}

int create_table()
{
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_exec(handle, CREATE_RPMMULTI_TABLE, NULL, NULL, NULL);
    if (ret != SQLITE_OK) {
        LOGE("create table (%s) failed (%d).", CREATE_RPMMULTI_TABLE, ret);
    }

    ret = close_db(handle);
    return ret;
}

int insert_table(const char *cert, const char *name, const char *before, const char *after, 
                        const char *time, const char *hash)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, INSERT_RPMMULTI_TABLE, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare insert table (%s) failed (%d).", INSERT_RPMMULTI_TABLE, ret);
        goto end;
    }
    ret = sqlite3_bind_text(pstmt, 1, cert, -1, SQLITE_STATIC);
    ret = sqlite3_bind_text(pstmt, 2, name, -1, SQLITE_STATIC);
    ret = sqlite3_bind_text(pstmt, 3, before, -1, SQLITE_STATIC);
    ret = sqlite3_bind_text(pstmt, 4, after, -1, SQLITE_STATIC);
    ret = sqlite3_bind_text(pstmt, 5, time, -1, SQLITE_STATIC);
    ret = sqlite3_bind_text(pstmt, 6, hash, -1, SQLITE_STATIC);
    ret = sqlite3_step(pstmt);
    if (ret != SQLITE_DONE) {
        syslog(LOG_ERR, "insert table (%s) failed (%d).", INSERT_RPMMULTI_TABLE, ret);
        goto end1;
    }

    ret = insert_rpminfos(cert, name, before, after, time, hash);
end1:
    ret = sqlite3_finalize(pstmt);
end:
    ret = close_db(handle);
    return ret;
}

static int _table_exist(char *table)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;
    int exist = 0;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, QUERY_TABLE_EXIST, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed.", QUERY_TABLE_EXIST);
        goto out;
    }

    ret = sqlite3_bind_text(pstmt, 1, table, -1, SQLITE_STATIC);

    ret = sqlite3_step(pstmt);
    if ((SQLITE_OK != ret) && (SQLITE_DONE != ret) && (SQLITE_ROW != ret))
    {
        exist = 1;
        goto out1;
    }

    exist = sqlite3_column_int(pstmt, 0);
out1:
    ret = sqlite3_finalize(pstmt);
out:
    ret = close_db(handle);

    return exist;
}

int table_exist(void)
{
    return _table_exist("rpmmulti_table");
}

int delete_by_hash(const char *hash)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, DELETE_BY_HASH, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed.", DELETE_BY_HASH);
        goto out;
    }

    ret = sqlite3_bind_text(pstmt, 1, hash, -1, SQLITE_STATIC);

    ret = sqlite3_step(pstmt);
    ret = sqlite3_finalize(pstmt);
    ret = delete_rpminfos_by_hash(hash);
out:
    ret = close_db(handle);
    return ret;
}

// modify
int cache_rpminfos(void)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, QUERY_RPMINFOS, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed", QUERY_RPMINFOS);
        goto out;
    }

    list_init(&rpminfo_list);
    for (;;) {
        ret = sqlite3_step(pstmt);
        if (ret == SQLITE_ROW) {
            const char *tmp;
            RpmInfo *ri = calloc(1, sizeof(RpmInfo));
            if (ri) {
                tmp = sqlite3_column_text(pstmt, 1); /* column 0 is id(primary key) */
                ri->cert = g_strdup(tmp);

                tmp = sqlite3_column_text(pstmt, 2);
                ri->name = g_strdup(tmp);

                tmp = sqlite3_column_text(pstmt, 3);
                ri->before = g_strdup(tmp);

                tmp = sqlite3_column_text(pstmt, 4);
                ri->after = g_strdup(tmp);

                tmp = sqlite3_column_text(pstmt, 5);
                ri->time = g_strdup(tmp);

                tmp = sqlite3_column_text(pstmt, 6);
                ri->hash = g_strdup(tmp);

                list_add_tail(&rpminfo_list, &ri->list);
            }
        } else {
            break;
        }
    }

    ret = sqlite3_finalize(pstmt);
out:
    ret = close_db(handle);
    return ret;
}

// modify
int delete_rpminfos_by_hash(const char *hash)
{
    int ret = 0;
    struct listnode *node, *n;
    list_for_each_safe(node, n, &rpminfo_list) {
        RpmInfo *ri = node_to_item(node, RpmInfo, list);
        if (!strcmp(ri->hash, hash)) {
            list_remove(&ri->list);
            free(ri->cert);
            free(ri->name);
            free(ri->before);
            free(ri->after);
            free(ri->time);
            free(ri->hash);
            free(ri);
        }
    }

    return ret;
}

// modify
int insert_rpminfos(const char *cert, const char *name, const char *before, const char *after, 
                                const char *time, const char *hash)
{
    int ret = 0;
    RpmInfo *ri;

    ri = calloc(1, sizeof(RpmInfo));
    if (ri) {
        ri->cert = g_strdup(cert);
        ri->name = g_strdup(name);
        ri->before = g_strdup(before);
        ri->after = g_strdup(after);
        ri->time = g_strdup(time);
        ri->hash = g_strdup(hash);
        list_add_tail(&rpminfo_list, &ri->list);
    }

    return ret;
}

// modify
int _get_rpminfo_by_hash(const char *hash, char **cert, char **name, char **before, char **after, char **time)
{
    int ret = 0;
    struct listnode *node, *n;
    list_for_each_safe(node, n, &rpminfo_list) {
        RpmInfo *ri = node_to_item(node, RpmInfo, list);
        if (!strcmp(hash, ri->hash)) {
            *cert = g_strdup(ri->cert);
            *name = g_strdup(ri->name);
            *before = g_strdup(ri->before);
            *after = g_strdup(ri->after);
            *time = g_strdup(ri->time);
            break;
        }
    }

    return ret;
}

// modify
int _get_rpminfo_by_index(int index, char **cert, char **name, const char **hash)
{
    int ret = 0;
    int num = 0;
    struct listnode *node, *n;
    list_for_each_safe(node, n, &rpminfo_list) {
        RpmInfo *ri = node_to_item(node, RpmInfo, list);
        if (num == index) {
            *cert = g_strdup(ri->cert);
            *name = g_strdup(ri->name);
            *hash = g_strdup(ri->hash);
            break;
        }
        num++;
    }

    return ret;
}

int query_count(void)
{
    int num = 0;
    struct listnode *node, *n;

    list_for_each_safe(node, n, &rpminfo_list) {
        num++;
    }

    return num;
}

int query_by_hash(char *hash)
{
    int ret = 0;
    struct listnode *node, *n;
    list_for_each_safe(node, n, &rpminfo_list) {
        RpmInfo *ri = node_to_item(node, RpmInfo, list);
        if (!strcmp(hash, ri->hash)) {
            return 1;
        }
    }

    return ret;
}

int query_by_name(char *name)
{
    int ret = 0;
    struct listnode *node, *n;
    list_for_each_safe(node, n, &rpminfo_list) {
        RpmInfo *ri = node_to_item(node, RpmInfo, list);
        if (!strcmp(name, ri->name)) {
            return 1;
        }
    }

    return ret;
}

int get_cert_to_verify(unsigned char *hash, int hashlen, unsigned char *sig, int siglen, verify_cb *cb)
{
    int ret = 0;
    struct listnode *node, *n;
    void *key = NULL;
    char *cert = NULL;

    list_for_each_safe(node, n, &rpminfo_list) {
        RpmInfo *ri = node_to_item(node, RpmInfo, list);
        cert = g_strdup(ri->cert);
        key = get_pubkey_from_cert(cert);
        if (key) {
            ret = cb(hash, hashlen, sig, siglen, key);
            if (ret == VERIFY_SUCC) {
                int val = 0;
                int len;
                X509 *x = NULL;

                len = strlen(cert);
                cert_decode(cert, len);
                x = get_x509_from_buf(cert);
                if (x) {
                    val = verify_cert_chain(x);
                    if (val == 1) {
                        g_free(cert);
                        break;
                    } else {
                        ret = VERIFY_ERR;
                    }
                } else {
                    ret = VERIFY_ERR;
                }
            }
        }
        g_free(cert);
    }

    return ret;
}

int import_xdja_cert(char *cert)
{
    X509 *x = NULL;
    int val = 0;
    int ret = 0;
    char *tmp = NULL;
    int cert_len;
    char before[1024] = {0};
    char after[1024] = {0};
    unsigned char hash[32] = {0};
    char encode_hash[1024] = {0};
    char time[1024] = {0};

    tmp = g_strdup(cert);
    x = get_x509_from_buf(tmp);
    if (x) {
        val = verify_cert_chain(x);
        if (val != 1) {
            ret = VERIFY_ERR;
            goto out;
        }

        cert_len = strlen(cert);
        cert_encode(tmp, cert_len);
        get_cert_before(x, before, sizeof(before));
        get_cert_after(x, after, sizeof(after));
        do_sm3_digest(tmp, cert_len, hash);
        get_curr_date(time, sizeof(time));
        base64_encode(hash, sizeof(hash), (uint8 *)encode_hash);
        if (query_by_hash(encode_hash)) {
            ret = CERT_EXIST;
            goto out;
        }
        if (query_by_name(XDJA_CERT)) {
            ret = NAME_EXIST;
            goto out;
        }
        ret = insert_table(tmp, XDJA_CERT, before, after, time, encode_hash);
    } else {
        LOGE("get xdja cert failed.\n");
        ret = -1;
    }

out:
    free(tmp);
    return ret;
}