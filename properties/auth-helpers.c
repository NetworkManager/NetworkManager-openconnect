/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 Tambet Ingo, <tambet@gmail.com>
 * Copyright (C) 2008 - 2021 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#include "nm-default.h"

#include "auth-helpers.h"

#include <nma-cert-chooser.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <openconnect.h>

void
tls_pw_init_auth_widget (GtkBuilder *builder,
                         NMSettingVpn *s_vpn,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	GtkWidget *widget;
	const char *value;
	GtkSizeGroup *group;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (changed_cb != NULL);

	group = GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ca_chooser"));
	nma_cert_chooser_add_to_size_group (NMA_CERT_CHOOSER (widget), group);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CACERT);
		if (value && strlen (value))
			nma_cert_chooser_set_cert (NMA_CERT_CHOOSER (widget), value,
									   NM_SETTING_802_1X_CK_SCHEME_PATH);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mca_cert_chooser"));
	nma_cert_chooser_add_to_size_group (NMA_CERT_CHOOSER (widget), group);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_MCACERT);
		if (value && strlen (value))
			nma_cert_chooser_set_cert (NMA_CERT_CHOOSER (widget), value,
									   g_str_has_prefix(value, "pkcs11:") ?
									   NM_SETTING_802_1X_CK_SCHEME_PKCS11 :
									   NM_SETTING_802_1X_CK_SCHEME_PATH);

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_MCAKEY);
		if (value && strlen (value))
			nma_cert_chooser_set_key (NMA_CERT_CHOOSER (widget), value,
									  g_str_has_prefix(value, "pkcs11:") ?
									  NM_SETTING_802_1X_CK_SCHEME_PKCS11 :
									  NM_SETTING_802_1X_CK_SCHEME_PATH);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "user_cert_chooser"));
	nma_cert_chooser_add_to_size_group (NMA_CERT_CHOOSER (widget), group);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_USERCERT);
		if (value && strlen (value))
			nma_cert_chooser_set_cert (NMA_CERT_CHOOSER (widget), value,
									   g_str_has_prefix(value, "pkcs11:") ?
									   NM_SETTING_802_1X_CK_SCHEME_PKCS11 :
									   NM_SETTING_802_1X_CK_SCHEME_PATH);

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PRIVKEY);
		if (value && strlen (value)) {
			nma_cert_chooser_set_key (NMA_CERT_CHOOSER (widget), value,
									  g_str_has_prefix(value, "pkcs11:") ?
									  NM_SETTING_802_1X_CK_SCHEME_PKCS11 :
									  NM_SETTING_802_1X_CK_SCHEME_PATH);

		}
	}
}

gboolean
auth_widget_check_validity (GtkBuilder *builder, GError **error)
{
	return TRUE;
}

static void
update_cert_from_filechooser (GtkBuilder *builder,
                              const char *key,
                              const char *widget_name,
                              NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	char *filename;
	char *authtype;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));

	filename = nma_cert_chooser_get_cert (NMA_CERT_CHOOSER (widget), NULL);
	if (filename && strlen(filename)) {
		nm_setting_vpn_add_data_item (s_vpn, key, filename);
		authtype = "cert";
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, key);
		authtype = "password";
	}
	/* Hack to keep older nm-auth-dialog working */
	if (!strcmp(key, NM_OPENCONNECT_KEY_USERCERT) || !strcmp(key, NM_OPENCONNECT_KEY_MCACERT))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_AUTHTYPE, authtype);
	g_free (filename);
}

static void
update_key_from_filechooser (GtkBuilder *builder,
                             const char *key,
                             const char *widget_name,
                             NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	char *filename;
	char *authtype;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));

	filename = nma_cert_chooser_get_key (NMA_CERT_CHOOSER (widget), NULL);
	if (filename && strlen(filename)) {
		nm_setting_vpn_add_data_item (s_vpn, key, filename);
		authtype = "cert";
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, key);
		authtype = "password";
	}
	g_free (filename);
}

gboolean
auth_widget_update_connection (GtkBuilder *builder,
                               const char *contype,
                               NMSettingVpn *s_vpn)
{
	update_cert_from_filechooser (builder, NM_OPENCONNECT_KEY_CACERT, "ca_chooser", s_vpn);

	update_cert_from_filechooser (builder, NM_OPENCONNECT_KEY_MCACERT, "mca_cert_chooser", s_vpn);
	update_key_from_filechooser (builder, NM_OPENCONNECT_KEY_MCAKEY, "mca_cert_chooser", s_vpn);

	update_cert_from_filechooser (builder, NM_OPENCONNECT_KEY_USERCERT, "user_cert_chooser", s_vpn);
	update_key_from_filechooser (builder, NM_OPENCONNECT_KEY_PRIVKEY, "user_cert_chooser", s_vpn);
	return TRUE;
}
