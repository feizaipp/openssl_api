#include <stdio.h>
#include "lib/callback.h"
#include <glib/gmain.h>
#include <glib/gtypes.h>
#include "lib/sqlite_helper.h"

static GMainLoop *loop = NULL;
static gboolean opt_replace = FALSE;
static gboolean opt_no_debug = FALSE;
static gboolean opt_no_sigint = FALSE;
static GOptionEntry opt_entries[] =
{
    {"replace", 'r', 0, G_OPTION_ARG_NONE, &opt_replace, "Replace existing daemon", NULL},
    {"no-debug", 'n', 0, G_OPTION_ARG_NONE, &opt_no_debug, "Don't print debug information on stdout/stderr", NULL},
    {"no-sigint", 's', 0, G_OPTION_ARG_NONE, &opt_no_sigint, "Do not handle SIGINT for controlled shutdown", NULL},
    {NULL }
};

char xdja_cert[] = "-----BEGIN CERTIFICATE-----\n"
                        "MIIBizCCATECCQCDoUkjPejcnDAKBggqgRzPVQGDdTBYMQswCQYDVQQGEwJDTjEN\n"
                        "MAsGA1UECAwEdGVzdDEOMAwGA1UEBwwFWGknYW4xEDAOBgNVBAoMB3ByaXZhdGUx\n"
                        "CzAJBgNVBAsMAnpwMQswCQYDVQQDDAJjYTAeFw0yMDEyMTQwOTA3NDFaFw0zMDEy\n"
                        "MTIwOTA3NDFaMEMxCzAJBgNVBAYTAkNOMREwDwYDVQQIDAhwbGF0Zm9ybTEhMB8G\n"
                        "A1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoEc\n"
                        "z1UBgi0DQgAE+nIDD2/HSdD4BpPISttKRpt/Q+vqcrtCqkazPonL3I6QMF22G0ok\n"
                        "55zTJPjcV3WIlNGct+7zRT7i2uPs4UlJATAKBggqgRzPVQGDdQNIADBFAiEA+8WU\n"
                        "3pZ+cX0LrSdIuSh+dnUlYsvo1cFclsfzJ9odSNsCID+DAKAa+LLj2lOEWLXU1gIf\n"
                        "B8kYGH2LXhzOUnlAId1B\n"
                        "-----END CERTIFICATE-----\n";

static RpmMultiBase *skeleton = NULL;

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
    GError *error = NULL;

    skeleton = rpm_multi_base_skeleton_new ();
    g_signal_connect(skeleton, "handle-get-rpminfos", G_CALLBACK(on_handle_get_rpminfos), NULL);
    g_signal_connect(skeleton, "handle-get-rpminfo", G_CALLBACK(on_handle_get_rpminfo), NULL);
    g_signal_connect(skeleton, "handle-insert-cert", G_CALLBACK(on_handle_insert_cert), NULL);
    g_signal_connect(skeleton, "handle-delete-cert", G_CALLBACK(on_handle_delete_cert), NULL);
    g_signal_connect(skeleton, "handle-sm3-digest", G_CALLBACK(on_handle_sm3_digest), NULL);
    g_signal_connect(skeleton, "handle-sm2-sign", G_CALLBACK(on_handle_sm2_sign), NULL);
    g_signal_connect(skeleton, "handle-sm2-verify", G_CALLBACK(on_handle_sm2_verify), NULL);
    g_signal_connect(skeleton, "handle-import-privkey", G_CALLBACK(on_handle_import_privkey), NULL);
    g_signal_connect(skeleton, "handle-get-privkeys", G_CALLBACK(on_handle_get_privkeys), NULL);
    g_signal_connect(skeleton, "handle-set-privkey", G_CALLBACK(on_handle_set_privkey), NULL);
    g_signal_connect(skeleton, "handle-insert-ukey", G_CALLBACK(on_handle_insert_ukey), NULL);
    g_signal_connect(skeleton, "handle-backup-param", G_CALLBACK(on_handle_backup_param), NULL);
    g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(skeleton), connection,
                                                        "/org/freedesktop/RpmMultiService/Base", &error);

    if (error != NULL) {
        g_printerr("Error:failed to export object. Reason:%s\n", error->message);
        g_error_free(error);
        return;
    }
    g_printerr ("Connected to the system bus\n");
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
    g_printerr ("Lost (or failed to acquire) the name %s on the system message bus\n", name);
    g_main_loop_quit (loop);
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
    g_printerr ("Acquired the name %s on the system message bus\n", name);
}

static gboolean
on_sigint (gpointer user_data)
{
    g_main_loop_quit (loop);
    return FALSE;
}

int main(int argc, char **argv)
{
    GError *error;
    GOptionContext *opt_context;
    gint ret;
    guint name_owner_id;
    guint sigint_id;

    ret = 1;
    loop = NULL;
    opt_context = NULL;
    name_owner_id = 0;
    sigint_id = 0;

    //g_type_init ();
    
    opt_context = g_option_context_new ("RpmMultiService daemon");
    g_option_context_add_main_entries (opt_context, opt_entries, NULL);
    error = NULL;
    if (!g_option_context_parse (opt_context, &argc, &argv, &error))
    {
        g_printerr ("Error parsing options: %s\n", error->message);
        g_error_free (error);
        goto out;
    }

    loop = g_main_loop_new (NULL, FALSE);
    sigint_id = 0;
    if (!opt_no_sigint)
    {
        sigint_id = g_unix_signal_add_full (G_PRIORITY_DEFAULT,
                                            SIGINT,
                                            on_sigint,
                                            NULL,  /* user_data */
                                            NULL); /* GDestroyNotify */
    }
    name_owner_id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
                                  "org.freedesktop.RpmMultiService",
                                  G_BUS_NAME_OWNER_FLAGS_NONE,
                                  on_bus_acquired,
                                  on_name_acquired,
                                  on_name_lost,
                                  NULL,
                                  NULL);
    if (!table_exist()) {
        create_table();
    }
    cache_rpminfos();
    import_xdja_cert(xdja_cert);
    g_main_loop_run (loop);
    ret = 0;

out:
    if (sigint_id > 0)
        g_source_remove (sigint_id);
    if (skeleton != NULL)
        g_object_unref (skeleton);
    if (name_owner_id != 0)
        g_bus_unown_name (name_owner_id);
    if (loop != NULL)
        g_main_loop_unref (loop);
    if (opt_context != NULL)
        g_option_context_free (opt_context);

    return ret;
}