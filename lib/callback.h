#ifndef __RPMMULTI_CALLBACK_
#define __RPMMULTI_CALLBACK_

#include "rpmmulti-generated.h"

gboolean on_handle_get_rpminfos(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    gpointer user_data);
gboolean on_handle_get_rpminfo(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *hash,
                                                    gpointer user_data);
gboolean on_handle_insert_cert(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *path,
                                                    const gchar *name,
                                                    gpointer user_data);
gboolean on_handle_delete_cert(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *hash,
                                                    gpointer user_data);
gboolean on_handle_insert_ukey(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *path,
                                                    const gchar *pass,
                                                    const gchar *pin,
                                                    gpointer user_data);
gboolean on_handle_sm3_digest(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *path,
                                                    gpointer user_data);
gboolean on_handle_sm2_sign(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *pass,
                                                    const gchar *hash,
                                                    gpointer user_data);
gboolean on_handle_sm2_verify(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *hash,
                                                    const gchar *sig,
                                                    gpointer user_data);
gboolean on_handle_import_privkey(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *pass,
                                                    const gchar *path,
                                                    const gchar *filename,
                                                    gpointer user_data);
gboolean on_handle_get_privkeys(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    gpointer user_data);
gboolean on_handle_set_privkey(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *name,
                                                    gpointer user_data);
gboolean on_handle_backup_param(RpmMultiBase* skeleton,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *code,
                                                    const gchar *path,
                                                    const gchar *pin,
                                                    gpointer user_data);
#endif