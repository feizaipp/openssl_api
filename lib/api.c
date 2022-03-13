#include "log.h"
#include "rpmmulti-generated.h"

#define IPC_CODE "528467391"

int insert_cert(char *path, char *name)
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
        LOGE("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_insert_cert_sync(proxy, IPC_CODE, path, name, &ret, NULL, &error);

    return ret;
}

void get_rpminfo(char *hash, char **cert, char **name, char **before, char **after, char **time)
{
    RpmMultiBase *proxy = NULL;
    GError *error = NULL;

    proxy = rpm_multi_base_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                                            G_DBUS_PROXY_FLAGS_NONE,
                                                            "org.freedesktop.RpmMultiService",
                                                            "/org/freedesktop/RpmMultiService/Base",
                                                            NULL,
                                                            &error);
    if (proxy == NULL) {
        LOGE("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_get_rpminfo_sync(proxy, IPC_CODE, hash, cert, name, before, after, time, NULL, &error);
}

int delete_cert(char *hash)
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
        LOGE("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_delete_cert_sync(proxy, IPC_CODE, hash, &ret, NULL, &error);

    return ret;
}

int sm3_digest(char *path, char **hash)
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
        LOGE("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_sm3_digest_sync(proxy, IPC_CODE, path, &ret, hash, NULL, &error);

    return ret;
}

int sm2_sign(char *pass, char *hash, char **sig)
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
        LOGE("Failed to create proxy: %s\n", error->message);
    }

    rpm_multi_base_call_sm2_sign_sync(proxy, IPC_CODE, pass, hash, &ret, sig, NULL, &error);

    return ret;
}

int sm2_verify(char *hash, char *sig)
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
        LOGE("Failed to create proxy: %s\n", error->message);
    }
    rpm_multi_base_call_sm2_verify_sync(proxy, IPC_CODE, hash, sig, &ret, NULL, &error);

    return ret;
}