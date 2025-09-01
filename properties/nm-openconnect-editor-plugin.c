/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 - 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2005 - 2021 Red Hat, Inc.
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

#include "nm-openconnect-editor-plugin.h"

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openconnect.h>

#ifdef NM_VPN_OLD
# include "nm-openconnect-editor.h"
#else
# if NM_CHECK_VERSION(1,3,0)
#  include "nm-utils/nm-vpn-editor-plugin-call.h"
# endif
# include "nm-utils/nm-vpn-plugin-utils.h"
#endif

# define OPENCONNECT_PLUGIN_NAME    _("Multi-protocol VPN client (openconnect)")
# define OPENCONNECT_PLUGIN_DESC    _("Compatible with Cisco AnyConnect, Juniper Network Connect and Junos Pulse, and PAN GlobalProtect SSL VPNs.")

/************** plugin class **************/

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void openconnect_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenconnectEditorPlugin, openconnect_editor_plugin, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
                                               openconnect_editor_plugin_interface_init))

typedef struct {
	int nr_supported_protocols;
	struct oc_vpn_proto *supported_protocols;
} OpenconnectEditorPluginPrivate;

#define OPENCONNECT_EDITOR_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), OPENCONNECT_TYPE_EDITOR_PLUGIN, OpenconnectEditorPluginPrivate))

/************** import/export **************/

typedef enum {
	NM_OPENCONNECT_IMPORT_EXPORT_ERROR_UNKNOWN = 0,
	NM_OPENCONNECT_IMPORT_EXPORT_ERROR_NOT_OPENCONNECT,
	NM_OPENCONNECT_IMPORT_EXPORT_ERROR_BAD_DATA,
} NMOpenconnectImportError;

#define NM_OPENCONNECT_IMPORT_EXPORT_ERROR nm_openconnect_import_export_error_quark ()

static GQuark
nm_openconnect_import_export_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-openconnect-import-export-error-quark");
	return quark;
}

static NMConnection *
import (NMVpnEditorPlugin *iface, const char *path, GError **error)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	NMSettingIP4Config *s_ip4;
	GKeyFile *keyfile;
	GKeyFileFlags flags;
	const char *buf;
	gboolean bval;

	keyfile = g_key_file_new ();
	flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;

	if (!g_key_file_load_from_file (keyfile, path, flags, NULL)) {
		g_set_error (error,
		             NM_OPENCONNECT_IMPORT_EXPORT_ERROR,
		             NM_OPENCONNECT_IMPORT_EXPORT_ERROR_NOT_OPENCONNECT,
		             "does not look like a %s VPN connection (parse failed)",
		             OPENCONNECT_PLUGIN_NAME);
		return NULL;
	}

	connection = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_OPENCONNECT, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* Host */
	buf = g_key_file_get_string (keyfile, "openconnect", "Host", NULL);
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY, buf);
	} else {
		g_set_error (error,
		             NM_OPENCONNECT_IMPORT_EXPORT_ERROR,
		             NM_OPENCONNECT_IMPORT_EXPORT_ERROR_BAD_DATA,
		             "does not look like a %s VPN connection (no Host)",
		             OPENCONNECT_PLUGIN_NAME);
		g_object_unref (connection);
		return NULL;
	}

	/* Optional Settings */

	/* Description */
	buf = g_key_file_get_string (keyfile, "openconnect", "Description", NULL);
	if (buf)
		g_object_set (s_con, NM_SETTING_CONNECTION_ID, buf, NULL);

	/* CA Certificate. We have an exception for filename "(null)" because
	 * the exporter used to do that wrongly. */
	buf = g_key_file_get_string (keyfile, "openconnect", "CACert", NULL);
	if (buf && strcmp(buf, "(null)"))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_CACERT, buf);

	/* Protocol */
	buf = g_key_file_get_string (keyfile, "openconnect", "Protocol", NULL);
	if (buf)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL, buf);

	/* Proxy */
	buf = g_key_file_get_string (keyfile, "openconnect", "Proxy", NULL);
	if (buf)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PROXY, buf);

	/* UserAgent */
	buf = g_key_file_get_string (keyfile, "openconnect", "UserAgent", NULL);
	if (buf)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_USERAGENT, buf);

	/* Cisco Secure Desktop */
	bval = g_key_file_get_boolean (keyfile, "openconnect", "CSDEnable", NULL);
	if (bval)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_ENABLE, "yes");

	/* Cisco Secure Desktop wrapper */
	buf = g_key_file_get_string (keyfile, "openconnect", "CSDWrapper", NULL);
	if (buf)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_WRAPPER, buf);

	/* Reported OS */
	buf = g_key_file_get_string (keyfile, "openconnect", "ReportedOS", NULL);
	if (buf)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_REPORTED_OS, buf);

	/* Machine Certificate */
	buf = g_key_file_get_string(keyfile, "openconnect", "MachineCertificate",
								NULL);
	if (buf && strcmp(buf, "(null)"))
		nm_setting_vpn_add_data_item(s_vpn, NM_OPENCONNECT_KEY_MCACERT, buf);

	/* MCA Private Key */
	buf = g_key_file_get_string(keyfile, "openconnect", "MachinePrivateKey", NULL);
	if (buf && strcmp(buf, "(null)"))
		nm_setting_vpn_add_data_item(s_vpn, NM_OPENCONNECT_KEY_MCAKEY, buf);

    /* User Certificate */
	buf = g_key_file_get_string (keyfile, "openconnect", "UserCertificate", NULL);
	if (buf && strcmp(buf, "(null)"))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_USERCERT, buf);

	/* User Private Key */
	buf = g_key_file_get_string (keyfile, "openconnect", "PrivateKey", NULL);
	if (buf && strcmp(buf, "(null)"))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PRIVKEY, buf);

	/* FSID */
	bval = g_key_file_get_boolean (keyfile, "openconnect", "FSID", NULL);
	if (bval)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID, "yes");

	/* Prevent invalid cert */
	bval = g_key_file_get_boolean (keyfile, "openconnect", "PreventInvalidCert", NULL);
	if (bval)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PREVENT_INVALID_CERT, "yes");

	/* Disable UDP (DTLS and ESP) and use only TLS tunnel */
	bval = g_key_file_get_boolean (keyfile, "openconnect", "DisableUDP", NULL);
	if (bval)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_DISABLE_UDP, "yes");

	/* Soft token mode */
	buf = g_key_file_get_string (keyfile, "openconnect", "StokenSource", NULL);
	if (buf)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_MODE, buf);

	/* Soft token secret */
	buf = g_key_file_get_string (keyfile, "openconnect", "StokenString", NULL);
	if (buf)
		nm_setting_vpn_add_secret (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET, buf);

	return connection;
}

static gboolean
export (NMVpnEditorPlugin *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *value;
	const char *gateway = NULL;
	const char *cacert = NULL;
	const char *protocol = NULL;
	const char *proxy = NULL;
	const char *useragent = NULL;
	gboolean csd_enable = FALSE;
	const char *csd_wrapper = NULL;
	const char *reported_os = NULL;
	const char *mcacert = NULL;
	const char *mcaprivkey = NULL;
	const char *usercert = NULL;
	const char *privkey = NULL;
	gboolean pem_passphrase_fsid = FALSE;
	gboolean prevent_invalid_cert = FALSE;
	gboolean disable_udp = FALSE;
	const char *token_mode = NULL;
	const char *token_secret = NULL;
	gboolean success = FALSE;
	FILE *f;

	f = fopen (path, "w");
	if (!f) {
		g_set_error_literal (error,
		                     NM_OPENCONNECT_IMPORT_EXPORT_ERROR,
		                     NM_OPENCONNECT_IMPORT_EXPORT_ERROR_UNKNOWN,
		                     "could not open file for writing");
		return FALSE;
	}

	s_con = nm_connection_get_setting_connection (connection);

	s_vpn = nm_connection_get_setting_vpn (connection);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY);
	if (value && strlen (value))
		gateway = value;
	else {
		g_set_error_literal (error,
		                     NM_OPENCONNECT_IMPORT_EXPORT_ERROR,
		                     NM_OPENCONNECT_IMPORT_EXPORT_ERROR_BAD_DATA,
		                     "connection was incomplete (missing gateway)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CACERT);
	if (value && strlen (value))
		cacert = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL);
	if (value && strlen (value))
		protocol = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROXY);
	if (value && strlen (value))
		proxy = value;

	value = nm_setting_vpn_get_data_item(s_vpn, NM_OPENCONNECT_KEY_USERAGENT);
	if (value && strlen(value))
		useragent = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_ENABLE);
	if (value && !strcmp (value, "yes"))
		csd_enable = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_WRAPPER);
	if (value && strlen (value))
		csd_wrapper = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_REPORTED_OS);
	if (value && strlen (value))
		reported_os = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_MCACERT);
	if (value && strlen (value))
		mcacert = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_MCAKEY);
	if (value && strlen (value))
		mcaprivkey = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_USERCERT);
	if (value && strlen (value))
		usercert = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PRIVKEY);
	if (value && strlen (value))
		privkey = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID);
	if (value && !strcmp (value, "yes"))
		pem_passphrase_fsid = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PREVENT_INVALID_CERT);
	if (value && !strcmp (value, "yes"))
		prevent_invalid_cert = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_DISABLE_UDP);
	if (value && !strcmp (value, "yes"))
		disable_udp = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_MODE);
	if (value && strlen (value))
		token_mode = value;

	value = nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET);
	if (value && strlen (value))
		token_secret = value;
	else {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET);
		if (value && strlen (value))
			token_secret = value;
	}

	fprintf (f,
		 "[openconnect]\n"
		 "Description=%s\n"
		 "Host=%s\n"
		 "CACert=%s\n"
		 "Protocol=%s\n"
		 "Proxy=%s\n"
		 "UserAgent=%s\n"
		 "CSDEnable=%s\n"
		 "CSDWrapper=%s\n"
		 "ReportedOS=%s\n"
		 "MachineCertificate=%s\n"
		 "MachinePrivateKey=%s\n"
		 "UserCertificate=%s\n"
		 "PrivateKey=%s\n"
		 "FSID=%s\n"
		 "PreventInvalidCert=%s\n"
		 "DisableUDP=%s\n"
		 "StokenSource=%s\n"
		 "StokenString=%s\n",
		 /* Description */           nm_setting_connection_get_id (s_con),
		 /* Host */                  gateway,
		 /* CA Certificate */        cacert ? cacert : "",
		 /* Protocol */              protocol ? protocol : "anyconnect",
		 /* Proxy */                 proxy ? proxy : "",
		 /* User Agent */            useragent ? useragent : "",
		 /* Cisco Secure Desktop */  csd_enable ? "1" : "0",
		 /* CSD Wrapper Script */    csd_wrapper ? csd_wrapper : "",
		 /* Reported OS */           reported_os ? reported_os : "",
		 /* MCA Certificate */       mcacert ? mcacert : "",
		 /* MCA Private Key */       mcaprivkey ? mcaprivkey : "",
		 /* User Certificate */      usercert ? usercert : "",
		 /* User Private Key */      privkey ? privkey : "",
		 /* FSID */                  pem_passphrase_fsid ? "1" : "0",
		 /* Prevent invalid cert */  prevent_invalid_cert ? "1" : "0",
		 /* Disable UDP */           disable_udp ? "1" : "0",
		 /* Soft token mode */       token_mode ? token_mode : "",
		 /* Soft token secret */     token_secret ? token_secret : "");

	success = TRUE;

done:
	fclose (f);
	return success;
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return (NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT |
	        NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT |
	        NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}

#ifndef NM_VPN_OLD
#if NM_CHECK_VERSION(1,3,0)
static void
notify_plugin_info_set (NMVpnEditorPlugin *plugin,
                        NMVpnPluginInfo *plugin_info)
{
	OpenconnectEditorPluginPrivate *priv = OPENCONNECT_EDITOR_PLUGIN_GET_PRIVATE (plugin);

	if (!plugin_info)
		return;

	openconnect_free_supported_protocols(priv->supported_protocols);
	priv->supported_protocols = NULL;

	priv->nr_supported_protocols = openconnect_get_supported_protocols(&priv->supported_protocols);
	if (priv->nr_supported_protocols > 0)
		return;
}

static char **
_vt_impl_get_service_add_details (NMVpnEditorPlugin *plugin,
                                  const char *service_type)
{
	OpenconnectEditorPluginPrivate *priv = OPENCONNECT_EDITOR_PLUGIN_GET_PRIVATE (plugin);
	guint i;
	char **ret = calloc(sizeof(char *), priv->nr_supported_protocols + 1);

	for (i = 0; i < priv->nr_supported_protocols; i++)
		ret[i] = strdup(priv->supported_protocols[i].name);

	return ret;
}

static gboolean
_vt_impl_get_service_add_detail (NMVpnEditorPlugin *plugin,
                                 const char *service_type,
                                 const char *add_detail,
                                 char **out_pretty_name,
                                 char **out_description,
                                 char **out_add_detail_key,
                                 char **out_add_detail_val,
                                 guint *out_flags)
{
	OpenconnectEditorPluginPrivate *priv;
	guint i;

	if (!nm_streq (service_type, NM_VPN_SERVICE_TYPE_OPENCONNECT))
		return FALSE;

	priv = OPENCONNECT_EDITOR_PLUGIN_GET_PRIVATE (plugin);
	for (i = 0; i < priv->nr_supported_protocols; i++) {
		struct oc_vpn_proto *p = &priv->supported_protocols[i];

		if (!nm_streq (add_detail, p->name))
			continue;
		NM_SET_OUT (out_pretty_name, g_strdup_printf("%s (OpenConnect)", p->pretty_name));
		NM_SET_OUT (out_description, g_strdup (p->description));

		if (i) {
			NM_SET_OUT (out_add_detail_key, g_strdup (add_detail ? NM_OPENCONNECT_KEY_PROTOCOL : NULL));
			NM_SET_OUT (out_add_detail_val, g_strdup (add_detail));
		}
		NM_SET_OUT (out_flags, 0);
		return TRUE;
	}
	return FALSE;
}

NM_VPN_EDITOR_PLUGIN_VT_DEFINE (vt, _get_vt,
	.fcn_get_service_add_details = _vt_impl_get_service_add_details,
	.fcn_get_service_add_detail  = _vt_impl_get_service_add_detail,
)
#endif

static NMVpnEditor *
_call_editor_factory (gpointer factory,
                      NMVpnEditorPlugin *editor_plugin,
                      NMConnection *connection,
                      gpointer user_data,
                      GError **error)
{
	return ((NMVpnEditorFactory) factory) (editor_plugin,
	                                       connection,
	                                       error);
}
#endif

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	gpointer gtk3_only_symbol;
	GModule *self_module;
	const char *editor;

	g_return_val_if_fail (OPENCONNECT_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	self_module = g_module_open (NULL, 0);
	g_module_symbol (self_module, "gtk_container_add", &gtk3_only_symbol);
	g_module_close (self_module);

	if (gtk3_only_symbol) {
		editor = "libnm-vpn-plugin-openconnect-editor.so";
	} else {
		editor = "libnm-gtk4-vpn-plugin-openconnect-editor.so";
	}

#ifdef NM_VPN_OLD
	return nm_vpn_editor_new (connection, error);
#else
	return nm_vpn_plugin_utils_load_editor (editor,
	                                        "nm_vpn_editor_factory_openconnect",
	                                        _call_editor_factory,
	                                        iface,
	                                        connection,
	                                        NULL,
	                                        error);
#endif
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, OPENCONNECT_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, OPENCONNECT_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, NM_VPN_SERVICE_TYPE_OPENCONNECT);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
openconnect_editor_plugin_dispose (GObject *object)
{
	OpenconnectEditorPlugin *plugin = OPENCONNECT_EDITOR_PLUGIN (object);
	OpenconnectEditorPluginPrivate *priv = OPENCONNECT_EDITOR_PLUGIN_GET_PRIVATE (plugin);

	openconnect_free_supported_protocols(priv->supported_protocols);
	priv->supported_protocols = NULL;

	G_OBJECT_CLASS (openconnect_editor_plugin_parent_class)->dispose (object);
}

static void
openconnect_editor_plugin_class_init (OpenconnectEditorPluginClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (OpenconnectEditorPluginPrivate));

	object_class->get_property = get_property;
	object_class->dispose = openconnect_editor_plugin_dispose;

	g_object_class_override_property (object_class,
	                                  PROP_NAME,
	                                  NM_VPN_EDITOR_PLUGIN_NAME);

	g_object_class_override_property (object_class,
	                                  PROP_DESC,
	                                  NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

	g_object_class_override_property (object_class,
	                                  PROP_SERVICE,
	                                  NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
openconnect_editor_plugin_init (OpenconnectEditorPlugin *plugin)
{
}

static void
openconnect_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = import;
	iface_class->export_to_file = export;
#ifndef NM_VPN_OLD
#if NM_CHECK_VERSION(1,3,0)
	iface_class->notify_plugin_info_set = notify_plugin_info_set;
	iface_class->get_vt = _get_vt;
#endif
#endif
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	return g_object_new (OPENCONNECT_TYPE_EDITOR_PLUGIN, NULL);
}
