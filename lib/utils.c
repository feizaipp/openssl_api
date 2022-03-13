#include "utils.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "log.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include "errs.h"
#include <jinshicfg.h>
#include<openssl/ossl_typ.h>

#define TMP_BUFFER_SIZE 1024

char root_cert[] = "-----BEGIN CERTIFICATE-----\n"
                            "MIIBoDCCAUYCCQCMRyFv3rok4jAKBggqgRzPVQGDdTBYMQswCQYDVQQGEwJDTjEN\n"
                            "MAsGA1UECAwEdGVzdDEOMAwGA1UEBwwFWGknYW4xEDAOBgNVBAoMB3ByaXZhdGUx\n"
                            "CzAJBgNVBAsMAnpwMQswCQYDVQQDDAJjYTAeFw0yMDEyMTQwODA0MDZaFw0zMDEy\n"
                            "MTIwODA0MDZaMFgxCzAJBgNVBAYTAkNOMQ0wCwYDVQQIDAR0ZXN0MQ4wDAYDVQQH\n"
                            "DAVYaSdhbjEQMA4GA1UECgwHcHJpdmF0ZTELMAkGA1UECwwCenAxCzAJBgNVBAMM\n"
                            "AmNhMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE66+vU/TAkpPTRHu2TK3mm6D5\n"
                            "S8vlPgoQBVyAzLwe+QR+toPr92L9XHAJ3JfNPBJRz+EtUMCp7TDppCF+JXg7PjAK\n"
                            "BggqgRzPVQGDdQNIADBFAiEAkgy3OzlYq5lD3ETda1ujBqjalPTUXd8Fm+YNMrRB\n"
                            "i0MCIGhiK3mYXdlRRQGJit8qn58DlYGBfJUBfjZwwpirC5GF\n"
                            "-----END CERTIFICATE-----\n";

static uint8 alphabet_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static uint8 reverse_map[] =
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255,
	255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
	255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255
};

const char *_asn1_mon[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


struct openssl_key_password {
	char *key;
	int len;
};

static int openssl_key_password_cb(char *buf, int size, int rwflag, void *userdata)
{
	struct openssl_key_password *password = userdata;

	if (password == NULL || password->key == NULL) {
		return -1;
	}

	size = (password->len > size) ? size : password->len;
	memcpy(buf, password->key, size);

	return size;
}

uint32 base64_encode(const uint8 *text, uint32 text_len, uint8 *encode)
{
	uint32 i, j;
	for (i = 0, j = 0; i + 3 <= text_len; i += 3)
	{
		encode[j++] = alphabet_map[text[i] >> 2];
		encode[j++] = alphabet_map[((text[i] << 4) & 0x30) | (text[i + 1] >> 4)];
		encode[j++] = alphabet_map[((text[i + 1] << 2) & 0x3c) | (text[i + 2] >> 6)];
		encode[j++] = alphabet_map[text[i + 2] & 0x3f];
	}

	if (i < text_len)
	{
		uint32 tail = text_len - i;
		if (tail == 1)
		{
			encode[j++] = alphabet_map[text[i] >> 2];
			encode[j++] = alphabet_map[(text[i] << 4) & 0x30];
			encode[j++] = '=';
			encode[j++] = '=';
		}
		else
		{
			encode[j++] = alphabet_map[text[i] >> 2];
			encode[j++] = alphabet_map[((text[i] << 4) & 0x30) | (text[i + 1] >> 4)];
			encode[j++] = alphabet_map[(text[i + 1] << 2) & 0x3c];
			encode[j++] = '=';
		}
	}
	return j;
}

uint32 base64_decode(const uint8 *code, uint32 code_len, uint8 *plain)
{
	assert((code_len & 0x03) == 0);

	uint32 i, j, k = 0;
	uint8 quad[4];
	for (i = 0; i < code_len; i += 4)
	{
		for (k = 0; k < 4; k++)
		{
			quad[k] = reverse_map[code[i + k]];
		}

		assert(quad[0]<64 && quad[1]<64);

		plain[j++] = (quad[0] << 2) | (quad[1] >> 4);

		if (quad[2] >= 64)
			break;
		else if (quad[3] >= 64)
		{
			plain[j++] = (quad[1] << 4) | (quad[2] >> 2);
			break;
		}
		else
		{
			plain[j++] = (quad[1] << 4) | (quad[2] >> 2);
			plain[j++] = (quad[2] << 6) | quad[3];
		}
	}
	return j;
}

X509 *get_x509_from_buf(unsigned char *buf)
{
	X509 *cert = NULL;
    BIO* bio = NULL;

    bio = BIO_new_mem_buf(buf, -1);
    if (bio == NULL) {
        LOGE("BIO_new_mem_buf failed.\n");
        return NULL;
    }
    cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
	if (cert == NULL) {
        LOGE("unable to load certificate\n");
		goto end;
    }

end:
	BIO_free(bio);
	return cert;
}

X509 *get_x509_from_file(const char *path)
{
	X509 *cert = NULL;
    BIO *bio;

	if ((bio = BIO_new(BIO_s_file())) == NULL) {
		LOGE("BIO_new failed.\n");
        goto end;
    }

	if (BIO_read_filename(bio, path) <= 0) {
		LOGE("BIO_read_filename %s failed.\n", path);
        goto end;
	}

	//X509_free
	cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
	if (cert == NULL) {
        LOGE("PEM_read_bio_X509_AUX failed.\n");
        goto end;
    }

end:
	BIO_free(bio);
	return cert;
}

static int write_cert_to_file(char *cert, const char *file_name)
{
	FILE *fp = NULL;
	int count;
    int ret = 0;

	fp = fopen(file_name, "w+");
    if (fp == NULL) {
        LOGE("open or create %s failed.\n", file_name);
		return;
    }

	count = fwrite(cert, strlen(cert), 1, fp);
    if (count <= 0) {
        LOGE("write file %s failed.\n", file_name);
		goto out;
    }
	fsync(fileno(fp));
    ret = 1;
out:
	fclose(fp);
    return ret;
}

static int remove_cert_from_file(const char *path)
{
    int ret = 0;
    if (!file_exists(path)) {
        LOGE("file %s is not exist.\n", path);
        return ret;
    }
    ret = remove(path);
    if (!ret) {
        return 1;
    } else {
        return 0;
    }
}

EVP_PKEY *get_pubkey_from_x509(X509 *cert)
{
	EVP_PKEY *pubkey = NULL;

	// EVP_PKEY_free
	pubkey = X509_get_pubkey(cert);
	return pubkey;
}

int get_privkey(unsigned char* key, const char *passphrase, EVP_PKEY **privkey)
{
	BIO* keybio = NULL;
    struct openssl_key_password password;
    int ret = RET_OK;

	keybio = BIO_new_mem_buf(key, -1); 
	if (keybio == NULL) {
		LOGE("BIO_new_mem_buf failed.\n");
        ret = OUTOF_MEM;
		goto end;
	}

    password.key = passphrase;
	password.len = strlen(passphrase);
	*privkey = PEM_read_bio_PrivateKey(keybio, NULL, openssl_key_password_cb, &password);
	if (*privkey == NULL) {
        ret = PRIVKEY_ERR;
		LOGE("Failed to Get Key\n");
	}

	BIO_free(keybio);
end:
	return ret;
}

EC_KEY *get_ec_key(EVP_PKEY *key)
{
	return EVP_PKEY_get1_EC_KEY(key);
}

int verify_cert_chain(X509 *verify)
{
	int ret = 0;
	X509_STORE *store = NULL;
	X509_STORE_CTX *ctx = NULL;
    X509_LOOKUP *lookup;

	store = X509_STORE_new();
    if (store == NULL) {
        LOGE("X509_STORE_new errno:%d\n", errno);
        return ret;
    }

	ret = write_cert_to_file(root_cert, ROOT_CERT_PATH);
    if (!ret) {
        LOGE("write_cert_to_file errno:%d\n", errno);
        goto out1;
    }
	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (!X509_LOOKUP_load_file(lookup, ROOT_CERT_PATH, X509_FILETYPE_PEM)) {
		LOGE("Error loading file %s\n", ROOT_CERT_PATH);
        goto out2;
	}

	ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        LOGE("X509_STORE_new errno:%d\n", errno);
        goto out3;
    }

	X509_STORE_set_flags(store, 0);

	X509_STORE_CTX_init(ctx, store, verify, NULL);

	ret = X509_verify_cert(ctx);
	if (ret != 1) {
		int code = X509_STORE_CTX_get_error(ctx);
		const char *error = X509_verify_cert_error_string(code);
		LOGE("error:%s\n", error);
	}

out3:
    X509_STORE_CTX_free(ctx);
out2:
    remove_cert_from_file(ROOT_CERT_PATH);
out1:
    X509_STORE_free(store);
	return ret;
}

int get_privkey_from_file(const char *pass, EC_KEY **priv_ec_key)
{
    char value[1024] = {0};
    char path[1024] = {0};
    char *data = NULL;
    int datalen;
    EVP_PKEY *privkey = NULL;
    int ret = RET_OK;

    jinshicfg_get(RPM_CONFIG_PATH, PATH_KEY, value, sizeof(value));
    snprintf(path, sizeof(path), "%s/%s", PRIV_PATH, value);

    if (value[0] == 0) {
        return NO_SET_PRIVKEY;
    }

    if (!file_exists(path)) {
        return FILE_NO_EXIST;
    }

    data = read_data(path, &datalen);
    if (data) {
        ret = get_privkey(data, pass, &privkey);
        if (privkey) {
            *priv_ec_key = get_ec_key(privkey);
            EVP_PKEY_free(privkey);
        } else {
            ret = PASS_ERR;
        }
        free(data);
    } else {
        ret = FILE_NO_EXIST;
    }

    return ret;
}

int get_privkey_from_file1(const char *pass, const char *path, EC_KEY **priv_ec_key)
{
    char *data = NULL;
    int datalen;
    EVP_PKEY *privkey = NULL;
    int ret = RET_OK;

    if (!file_exists(path)) {
        return FILE_NO_EXIST;
    }

    data = read_data(path, &datalen);
    if (data) {
        ret = get_privkey(data, pass, &privkey);
        if (privkey) {
            *priv_ec_key = get_ec_key(privkey);
            EVP_PKEY_free(privkey);
        }
        free(data);
    } else {
        ret = FILE_NO_EXIST;
    }

    return ret;
}

EC_KEY *get_pubkey_from_cert(char *cert)
{
    X509 *x = NULL;
    EVP_PKEY *pubkey = NULL;
    EC_KEY *pub_ec_key = NULL;
    int len;

    len = strlen(cert);
    cert_decode(cert, len);
    x = get_x509_from_buf(cert);
    if (x) {
        pubkey = get_pubkey_from_x509(x);
        if (pubkey) {
            pub_ec_key = get_ec_key(pubkey);
            EVP_PKEY_free(pubkey);
        }
        X509_free(x);
    }

    return pub_ec_key;
}

int dir_exists(const char *path)
{
    struct stat buf;

    if (stat(path, &buf) < 0)
        return 0;
    return S_ISDIR(buf.st_mode);
}

int file_exists(const char *path)
{
    struct stat buf;

    if (stat(path, &buf) < 0)
        return 0;
    return S_ISREG(buf.st_mode);
}

long get_file_len(char *path)
{
    FILE *pFile;
    long size = 0;

    pFile = fopen(path, "rb");
    if (pFile==NULL) {
        LOGE("open %s file failed.\n", path);
    } else {
        fseek(pFile, 0, SEEK_END);
        size = ftell(pFile);
        fclose(pFile);
    }
    return size;
}

uint8 *read_data(char *path, long *data_len)
{
    uint8 *data = NULL;
    long len = 0;
    int fd = -1;

    len = get_file_len(path);
    data = malloc(len + 1);
    if (data == NULL) {
        LOGE("malloc failed\n");
        return NULL;
    }
    memset(data, 0, len + 1);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOGE("open %s failed.\n", path);
        return NULL;
    }
    read(fd, data, len);
    close(fd);
    *data_len = len;
    return data;
}


static int get_asn1_utctime_time(const ASN1_UTCTIME *tm, char *buf, int len)
{
    const char *v;
    int gmt = 0;
    int i;
    int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;

    i = tm->length;
    v = (const char *)tm->data;

    if (i < 10)
        goto err;
    if (v[i - 1] == 'Z')
        gmt = 1;
    for (i = 0; i < 10; i++)
        if ((v[i] > '9') || (v[i] < '0'))
            goto err;
    y = (v[0] - '0') * 10 + (v[1] - '0');
    if (y < 50)
        y += 100;
    M = (v[2] - '0') * 10 + (v[3] - '0');
    if ((M > 12) || (M < 1))
        goto err;
    d = (v[4] - '0') * 10 + (v[5] - '0');
    h = (v[6] - '0') * 10 + (v[7] - '0');
    m = (v[8] - '0') * 10 + (v[9] - '0');
    if (tm->length >= 12 &&
                (v[10] >= '0') && (v[10] <= '9') && (v[11] >= '0') && (v[11] <= '9'))
        s = (v[10] - '0') * 10 + (v[11] - '0');

    snprintf(buf, len, "%s %2d %02d:%02d:%02d %d%s",
                _asn1_mon[M - 1], d, h, m, s, y + 1900, (gmt) ? " GMT" : "");
    return (1);
err:
    return (0);
}


static int get_asn1_generalizedtime_time(const ASN1_GENERALIZEDTIME *tm, char *buf, int len)
{
    char *v;
    int gmt = 0;
    int i;
    int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;
    char *f = NULL;
    int f_len = 0;

    i = tm->length;
    v = (char *)tm->data;

    if (i < 12)
        goto err;
    if (v[i - 1] == 'Z')
        gmt = 1;
    for (i = 0; i < 12; i++)
        if ((v[i] > '9') || (v[i] < '0'))
            goto err;
    y = (v[0] - '0') * 1000 + (v[1] - '0') * 100
    + (v[2] - '0') * 10 + (v[3] - '0');
    M = (v[4] - '0') * 10 + (v[5] - '0');
    if ((M > 12) || (M < 1))
        goto err;
    d = (v[6] - '0') * 10 + (v[7] - '0');
    h = (v[8] - '0') * 10 + (v[9] - '0');
    m = (v[10] - '0') * 10 + (v[11] - '0');
    if (tm->length >= 14 &&
                (v[12] >= '0') && (v[12] <= '9') &&
                (v[13] >= '0') && (v[13] <= '9')) {
        s = (v[12] - '0') * 10 + (v[13] - '0');
        /* Check for fractions of seconds. */
        if (tm->length >= 15 && v[14] == '.') {
            int l = tm->length;
            f = &v[14];         /* The decimal point. */
            f_len = 1;
            while (14 + f_len < l && f[f_len] >= '0' && f[f_len] <= '9')
                ++f_len;
        }
    }

    snprintf(buf, len, "%s %2d %02d:%02d:%02d%.*s %d%s",
                _asn1_mon[M - 1], d, h, m, s, f_len, f, y,
                (gmt) ? " GMT" : "");
    return (1);
err:
    return (0);
}

int get_cert_time(ASN1_TIME *tm, char *buf, int len)
{
    if (tm->type == V_ASN1_UTCTIME)
        return get_asn1_utctime_time(tm, buf, len);
    if (tm->type == V_ASN1_GENERALIZEDTIME)
        return get_asn1_generalizedtime_time(tm, buf, len);
    return (0);
}

int get_cert_before(X509 *cert, char *buf, int len)
{
	ASN1_TIME *before;
    //ASN1_TIME_free
	before = X509_get_notBefore(cert);
	get_cert_time(before, buf, len);
    //ASN1_TIME_free(before);
	return 0;
}

int get_cert_after(X509 *cert, char *buf, int len)
{
	ASN1_TIME *after;

    after = X509_get_notAfter(cert);
	get_cert_time(after, buf, len);
    //ASN1_TIME_free(after);
	return 0;
}

int get_curr_date(char *data, int len)
{
    time_t timep;
    struct tm *p;

    time(&timep);
    p = localtime(&timep);
    snprintf(data, len, "%04d-%02d-%02d %02d:%02d:%02d", 1900+p->tm_year, 1+p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);

    return 0;
}

void cert_encode(unsigned char *data, int len)
{
    int i;

    // '\n' -> '#'
    for (i=0;i<len;i++) {
        if (data[i] == 10) {
            data[i] = '#';
        }
    }
}

void cert_decode(unsigned char *data, int len)
{
    int i;

    // '#' -> '\n'
    for (i=0;i<len;i++) {
        if (data[i] == '#') {
            data[i] = 10;
        }
    }
}

int copy_privfile(const char *path, const char *filename)
{
    int ret = RET_OK;
    unsigned char buff[4096];
    FILE *fp = NULL;
    FILE *fp_out = NULL;
    char path_out[1024] = {0};

    if (!file_exists(path)) {
        ret = FILE_NO_EXIST;
        goto out;
    }
    snprintf(path_out, sizeof(path_out), "%s/%s", PRIV_PATH, filename);
    if (file_exists(path_out)) {
        ret = FILE_ALREADY_EXIST;
        goto out;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        LOGE("fopen path:%s error.\n", path);
        ret = FILE_NO_EXIST;
        goto out;
    }
    fp_out = fopen(path_out, "w+");
    if (fp_out == NULL) {
        LOGE("fopen path:%s error.\n", path_out);
        ret = FILE_NO_EXIST;
        goto out1;
    }

    while (!feof(fp)) {
        int len = fread(buff, sizeof(unsigned char), sizeof(buff), fp);
        fwrite(buff, sizeof(unsigned char), len, fp_out);
    }
    fclose(fp_out);

out1:
    fclose(fp);
out:
    return ret;
}

int set_privfile(const char *filename)
{
    char path[1024] = {0};

    snprintf(path, sizeof(path), "%s/%s", PRIV_PATH, filename);
    if (!file_exists(path)) {
        LOGE("file %s is not exist.\n", path);
        return FILE_NO_EXIST;
    }
    jinshicfg_set(RPM_CONFIG_PATH, PATH_KEY, filename);

    return 0;
}


int getSwitch(void)
{
    int ret;
    char value[128];
    int val;
    /* 
      * 0:dont verify sign
      * 1:verify sign
      */
    ret = jinshicfg_get(RPM_CONFIG_PATH, SWITCH, value, sizeof(value));
    if (!ret) {
        sscanf(value, "%d", &val);
        return val;
    }
    return 1;
}

int getStatus(void)
{
    int ret;
    char value[128];
    int val;
    /* 
      * 0:gpg
      * 1:usbkey
      */
    ret = jinshicfg_get(RPM_CONFIG_PATH, STATUS, value, sizeof(value));
    if (!ret) {
        sscanf(value, "%d", &val);
        return val;
    }
    return 0;
}
