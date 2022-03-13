#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

static void usage(char *name)
{
    printf("\
Usage: %s [OPTION]... [FILE]\n\
\t%-20s\t\thelp info\n\
\t%-20s\t\tset dir\n", name, "-h, --help", "-p, --path [path]");
    exit(1);
}

static struct option const long_options[] =
{
    {"help", no_argument, 0, 'h'},
    {"path", required_argument, 0, 'p'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
    char *hash;
    char *sig;
    int ret;
    int optc;
    char p_option = 0;
    char resolved_path[1024];
    char *path = NULL;
    char *passPhrase = NULL;

    while ((optc = getopt_long(argc, argv, "hp:", long_options, NULL)) != -1) {
        switch (optc) {
        case 'p':
            //导入证书
            p_option = 1;
            path = optarg;
            break;

        default:
            usage(argv[0]);
            return 0;
        }
    }
    if (!p_option) {
        usage(argv[0]);
        return 0;
    }
    realpath(path, resolved_path);

    ret = sm3_digest(path, &hash);
    printf("hash:%s ret:%d\n", hash, ret);

    passPhrase = getpass("Enter pass phrase: ");
    passPhrase = (passPhrase != NULL) ? strdup(passPhrase) : NULL;

    ret = sm2_sign(passPhrase, hash, &sig);
    if (ret != 10008) {
        printf("signature failed.\n");
        return -1;
    }
    printf("sig:%s ret:%d\n", sig, ret);

    ret = sm2_verify(hash, sig);
    printf("ret:%d\n", ret);
    if (ret != 10009) {
        printf("verify signature failed.\n");
        return -1;
    }
    free(hash);
    free(sig);
    if (passPhrase) {
        free(passPhrase);
    }
}