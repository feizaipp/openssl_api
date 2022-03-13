#ifndef __RPMMULTI_SQLITE_
#define __RPMMULTI_SQLITE_

#include <sqlite3.h>
#include "list.h"

typedef int verify_cb(unsigned char *hash, int hashlen, unsigned char *sig, int siglen, void *key);

#define XDJA_CERT "xdja-cert"

typedef struct _RpmInfo RpmInfo;
struct _RpmInfo {
    struct listnode list;
    char *cert;
    char *name;
    char *before;
    char *after;
    char *time;
    char *hash;
};

int create_table();
int insert_table(const char *cert, const char *name, const char *before, const char *after, 
                        const char *time, const char *hash);
int db_created(const char *name, const char *owner);
int table_exist(void);
int delete_by_hash(const char *hash);
int db_opened(const char *name, const char *owner);
int cache_rpminfos(void);
int delete_rpminfos_by_hash(const char *hash);
int insert_rpminfos(const char *cert, const char *name, const char *before, const char *after, 
                                const char *time, const char *hash);
int _get_rpminfo_by_hash(const char *hash, char **cert, char **name, char **before, char **after, char **time);
int _get_rpminfo_by_index(int index, char **cert, char **name, const char **hash);
int query_count(void);
int query_by_hash(char *hash);
int query_by_name(char *name);
int get_cert_to_verify(unsigned char *hash, int hashlen, unsigned char *sig, int siglen, verify_cb *cb);
int import_xdja_cert(char *cert);

#endif