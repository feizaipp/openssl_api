#ifndef __RPMMULTI_API_
#define __RPMMULTI_API_

#include <glib.h>

int insert_cert(char *path, char *name);
void get_rpminfo(char *hash, char **cert, char **name, char **before, char **after, char **time);
int delete_cert(char *hash);
int sm3_digest(char *path, char **hash);
int sm2_sign(char *pass, char *hash, char **sig);
int sm2_verify(char *hash, char *sig);


#endif