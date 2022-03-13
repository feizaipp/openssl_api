#ifndef __RPMMULTI_UTILS_
#define __RPMMULTI_UTILS_
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
typedef unsigned char     uint8;
typedef unsigned long    uint32;

#define RPM_CONFIG_PATH "/etc/rpm.config"
#define PATH_KEY "path"
#define ROOT_CERT_PATH "/var/lib/rpmmultiservice/.rootcert"
#define PRIV_PATH "/etc/rpmmultikey"
#define SWITCH "switch"
#define STATUS "status"

#define GPGMODE (0)
#define USBKEY  (1)
#define SM2SOFT  (2)

uint32 base64_encode(const uint8 *text, uint32 text_len, uint8 *encode);
uint32 base64_decode(const uint8 *code, uint32 code_len, uint8 *plain);
X509 *get_x509_from_buf(unsigned char *buf);
X509 *get_x509_from_file(const char *path);
EVP_PKEY *get_pubkey_from_x509(X509 *cert);
int get_privkey(unsigned char* key, const char *passphrase, EVP_PKEY **privkey);
EC_KEY *get_ec_key(EVP_PKEY *key);
int verify_cert_chain(X509 *verify);
int dir_exists(const char *path);
int file_exists(const char *path);
long get_file_len(char *path);
uint8 *read_data(char *path, long *data_len);
int get_cert_time(ASN1_TIME *tm, char *buf, int len);
int get_cert_before(X509 *cert, char *buf, int len);
int get_cert_after(X509 *cert, char *buf, int len);
int get_curr_date(char *data, int len);
void cert_encode(unsigned char *data, int len);
void cert_decode(unsigned char *data, int len);
int get_privkey_from_file(const char *pass, EC_KEY **priv_ec_key);
EC_KEY *get_pubkey_from_cert(char *cert);
int copy_privfile(const char *path, const char *filename);
int set_privfile(const char *filename);
int get_privkey_from_file1(const char *pass, const char *path, EC_KEY **priv_ec_key);
int getSwitch(void);
int getStatus(void);

#endif