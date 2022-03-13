#include<openssl/pem.h>
#include<openssl/ssl.h>
#include<openssl/rsa.h>
#include<openssl/evp.h>
#include<openssl/bio.h>
#include<openssl/err.h>
#include <stdio.h> 
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <glib.h>
#include "lib/errs.h"
#include "lib/rpmmulti-generated.h"
#include <libgen.h>

#define IPC_CODE "528467391"

static void usage(char *name)
{
    printf("\
Usage: %s [OPTION]... [FILE]\n\
\t%-20s\t\thelp info\n\
\t%-20s\t\tlist all certification\n\
\t%-20s\t\timport certification to database, need --name option\n\
\t%-20s\t\tcertification's name\n\
\t%-20s\t\tdelete certification from database\n\
\t%-20s\t\timport private key to usbkey\n\
\t%-20s\t\timport private key to file system\n\
\t%-20s\t\tlist all privkey\n\
\t%-20s\t\tset privkey\n\
\t%-20s\t\tbackup sm2 param\n\
\t%-20s\t\tlist detail information\n", name, "-h, --help", "-l, --list", "-i, --import [path]", "-n, --name [name]", "-d, --delete [hash]", "-H, --hard [path]", "-p, --privkey [path]", "-P, --Privkey", "-s, --set [name]", "-b, --backup [path]", "-D, --Detail [hash]");
    exit(1);
}

static struct option const long_options[] =
{
    {"help", no_argument, 0, 'h'},
    {"list", no_argument, 0, 'l'},
    {"import", required_argument, 0, 'i'},
    {"name", required_argument, 0, 'n'},
    {"delete", required_argument, 0, 'd'},
    {"hard", required_argument, 0, 'H'},
    {"privkey", required_argument, 0, 'p'},
    {"Privkey", no_argument, 0, 'P'},
    {"detail", required_argument, 0, 'D'},
    {"backup", required_argument, 0, 'b'},
    {NULL, 0, NULL, 0}
};

static analysis_ret(int ret)
{
    switch (ret)
    {
    case CERT_EXIST:
        printf("cert is already exist.\n");
        break;

    case NAME_EXIST:
        printf("name is already exist.\n");
        break;

    case CERT_INVALID:
        printf("cert is invalid.\n");
        break;

    case FILE_NO_EXIST:
        printf("file is not exist.\n");
        break;

    case PRIVKEY_ERR:
        printf("privkey file is invalid or passwor error.\n");
        break;

    case FILE_ALREADY_EXIST:
        printf("privkey file name already exist, please change filename and retry.\n");
        break;
    default:
        break;
    }
}


static void get_rpminfos(void)
{
    RpmMultiBase *proxy = NULL;
    GError *error = NULL;
    GVariant *ret;
    GVariantIter iter;
    char *cert;
    char *name;
    char *hash;

    proxy = rpm_multi_base_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                                            G_DBUS_PROXY_FLAGS_NONE,
                                                            "org.freedesktop.RpmMultiService",
                                                            "/org/freedesktop/RpmMultiService/Base",
                                                            NULL,
                                                            &error);
    if (proxy == NULL) {
        printf("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_get_rpminfos_sync(proxy, IPC_CODE, &ret, NULL, &error);
    g_variant_iter_init(&iter, ret);
    while (g_variant_iter_next(&iter, "(sss)", &cert, &name, &hash)) {
        cert_decode(cert, strlen(cert));
        printf("name:%s\n", name);
        printf("hash:%s\n", hash);
        printf("----------------------------------------------------------\n");
        free(name);
        free(cert);
        free(hash);
    }
    g_variant_unref(ret);
}

static void get_privkeys(void)
{
    RpmMultiBase *proxy = NULL;
    GError *error = NULL;
    GVariant *ret;
    GVariantIter iter;
    char *privkey;

    proxy = rpm_multi_base_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                                            G_DBUS_PROXY_FLAGS_NONE,
                                                            "org.freedesktop.RpmMultiService",
                                                            "/org/freedesktop/RpmMultiService/Base",
                                                            NULL,
                                                            &error);
    if (proxy == NULL) {
        printf("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_get_privkeys_sync(proxy, IPC_CODE, &ret, NULL, &error);
    g_variant_iter_init(&iter, ret);
    printf("privkeys:\n");
    while (g_variant_iter_next(&iter, "(s)", &privkey)) {
        printf("%s\n", privkey);
        free(privkey);
    }
    g_variant_unref(ret);
}

static int import_privkey(char *pass, char *path, char *filename)
{
    RpmMultiBase *proxy = NULL;
    GError *error = NULL;
    int ret;

    proxy = rpm_multi_base_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                                            G_DBUS_PROXY_FLAGS_NONE,
                                                            "org.freedesktop.RpmMultiService",
                                                            "/org/freedesktop/RpmMultiService/Base",
                                                            NULL,
                                                            &error);
    if (proxy == NULL) {
        printf("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_import_privkey_sync(proxy, IPC_CODE, pass, path, filename, &ret, NULL, &error);
    return ret;
}

static int set_privkey(char *name)
{
    RpmMultiBase *proxy = NULL;
    GError *error = NULL;
    int ret;

    proxy = rpm_multi_base_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                                            G_DBUS_PROXY_FLAGS_NONE,
                                                            "org.freedesktop.RpmMultiService",
                                                            "/org/freedesktop/RpmMultiService/Base",
                                                            NULL,
                                                            &error);
    if (proxy == NULL) {
        printf("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_set_privkey_sync(proxy, IPC_CODE, name, &ret, NULL, &error);
    return ret;
}

static int insert_ukey(char *path, char *pass, char *pin)
{
    RpmMultiBase *proxy = NULL;
    GError *error = NULL;
    int ret;

    proxy = rpm_multi_base_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                                            G_DBUS_PROXY_FLAGS_NONE,
                                                            "org.freedesktop.RpmMultiService",
                                                            "/org/freedesktop/RpmMultiService/Base",
                                                            NULL,
                                                            &error);
    if (proxy == NULL) {
        printf("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_insert_ukey_sync(proxy, IPC_CODE, path, pass, pin, &ret, NULL, &error);
    return ret;
}

static int backup_param(char *path, char *pin)
{
    RpmMultiBase *proxy = NULL;
    GError *error = NULL;
    int ret;

    proxy = rpm_multi_base_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                                            G_DBUS_PROXY_FLAGS_NONE,
                                                            "org.freedesktop.RpmMultiService",
                                                            "/org/freedesktop/RpmMultiService/Base",
                                                            NULL,
                                                            &error);
    if (proxy == NULL) {
        printf("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_backup_param_sync(proxy, IPC_CODE, path, pin, &ret, NULL, &error);
    return ret;
}

int main(int argc, char **argv)
{
    int optc;
    char l_option = 0;
    char i_option = 0;
    char n_option = 0;
    char d_option = 0;
    char H_option = 0;
    char D_option = 0;
    char p_option = 0;
    char P_option = 0;
    char s_option = 0;
    char b_option = 0;
    char *cert_path = NULL;
    char *cert_name = NULL;
    char *cert_hash = NULL;
    char *priv_path = NULL;
    char *priv_name = NULL;
    char *bak_path = NULL;
    char resolved_path[1024] = {0};
    int ret;
    uid_t uid;

    uid = geteuid();
    if (uid != 0) {
        printf("Only root can exec rpmmulti.\n");
        return -1;
    }


    while ((optc = getopt_long(argc, argv, "hli:n:d:H:D:p:Ps:b:", long_options, NULL)) != -1) {
        switch (optc) {
        case 'h':
            usage(argv[0]);
            return 0;

        case 'l':
            l_option = 1;
            // 显示所有证书
            break;

        case 'i':
            //导入证书
            i_option = 1;
            cert_path = optarg;
            break;

        case 'n':
            //证书名字
            n_option = 1;
            cert_name = optarg;
            break;

        case 'd':
            //删除证书
            d_option = 1;
            cert_hash = optarg;
            break;

        case 'H':
            //导入私钥到 usbkey
            H_option = 1;
            priv_path = optarg;
            break;

        case 'D':
            //显示详情
            D_option = 1;
            cert_hash = optarg;
            break;

        case 'p':
            //导入私钥
            p_option = 1;
            priv_path = optarg;
            break;

        case 'P':
            //显示私钥信息
            P_option = 1;
            break;

        case 's':
            //显示详情
            s_option = 1;
            priv_name = optarg;
            break;

        case 'b':
            b_option = 1;
            bak_path = optarg;
            break;

        default:
            usage(argv[0]);
            return 0;
        }
    }
    if (l_option) {
        // 显示所有证书
        get_rpminfos();
        return 0;
    }
    if ((i_option && !n_option) || (!i_option && n_option)) {
        usage(argv[0]);
        return 0;
    }
    if (i_option && n_option) {
        realpath(cert_path, resolved_path);
        if (!file_exists(resolved_path)) {
            printf("cert is not exist.\n");
            return -1;
        }
        ret = insert_cert(resolved_path, cert_name);
        analysis_ret(ret);
        return 0;
    }
    if (d_option) {
        // 删除证书
        delete_cert(cert_hash);
        return 0;
    }
    if (H_option) {
        char *pass = NULL;
        char *pin = NULL;

        //导入私钥到 usbkey
        realpath(priv_path, resolved_path);
        pass = getpass("Enter pass phrase: ");
        pin = getpass("Enter pin phrase: ");
        ret = insert_ukey(resolved_path, pass, pin);
        printf("ret:%d\n", ret);
        return 0;
    }
    if (D_option) {
        char *cert;
        char *name;
        char *before;
        char *after;
        char *time;
        //显示详情
        get_rpminfo(cert_hash, &cert, &name, &before, &after, &time);
        cert_decode(cert, strlen(cert));
        printf("name:%s\n", name);
        printf("cert:\n%s", cert);
        printf("before:%s\n", before);
        printf("after:%s\n", after);
        printf("time:%s\n", time);
        free(cert);
        free(name);
        free(before);
        free(after);
        free(time);
        return 0;
    }
    if (p_option) {
        char *pass = NULL;
        char *file = NULL;
        char *fname = NULL;

        pass = getpass("Enter pass phrase: ");
        realpath(priv_path, resolved_path);
        file = strdup(resolved_path);
        fname = basename(file);
        ret = import_privkey(pass, resolved_path, fname);
        analysis_ret(ret);
        if (file) free(file);
        return 0;
    }
    if (P_option) {
        get_privkeys();
        return 0;
    }
    if (s_option) {
        ret = set_privkey(priv_name);
        analysis_ret(ret);
        return 0;
    }
    if (b_option) {
        char *pin = NULL;

        realpath(bak_path, resolved_path);
        pin = getpass("Enter pin phrase: ");
        ret = backup_param(resolved_path, pin);
        printf("ret:%d\n", ret);
        return 0;
    }
    usage(argv[0]);
    return -1;
}