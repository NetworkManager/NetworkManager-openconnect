/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
 *
 * Authors: Jussi Kukkonen <jku@linux.intel.com>
 *          David Woodhouse <dwmw2@infradead.org>
 *          Jan-Michael Brummer <jan-michael.brummer1@volkswagen.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */

#include "auth-app.h"
#include "auth-app-win.h"

#include "nm-default.h"

#include <gtk/gtk.h>
#include <glib-unix.h>
#include <libsecret/secret.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "openconnect.h"
#include <webkit/webkit.h>

typedef enum {
  CERT_DENIED = -1,
  CERT_USER_NOT_READY,
  CERT_ACCEPTED,
} CertificateResponse;

struct _AuthApp {
  AdwApplication parent;

  AuthAppWindow *win;

  FILE *paramf;

  char *vpn_name;
  char *vpn_uuid;
  char *lasthost;
  char *login_uri;

  gboolean connect_urlpath;
  GHashTable *options;
  GHashTable *secrets;
  GHashTable *success_secrets;
  GHashTable *success_passwords;
  struct openconnect_info *vpninfo;

  GList *vpnhosts;

  oc_token_mode_t token_mode;
  const char *token_secret;

  int cookie_retval;

  GIOChannel *stdin_channel;
  GSource *stdin_source;
  GString *stdin_line;
  gboolean quit_seen;

  int cmd_pipe;
  gboolean cancelled; /* fully cancel the whole challenge-response series */
  gboolean getting_cookie;

  int form_grabbed;
  GQueue *form_entries; /* modified from worker thread */
  GMutex form_mutex;

  GCond form_retval_changed;
  gpointer form_retval;

  GCond form_shown_changed;
  gboolean form_shown;

  gboolean newgroup;
  gboolean group_set;

  GCond cert_response_changed;
  CertificateResponse cert_response;

  int autosubmit;
  int fields_pending;
};

G_DEFINE_TYPE (AuthApp, auth_app, ADW_TYPE_APPLICATION);

static char *vpn_uuid = NULL;
static char *vpn_name = NULL;
static char *vpn_service = NULL;
static gboolean allow_interaction = FALSE;

GOptionEntry entries[] = {
  { "allow-interaction", 'i', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &allow_interaction, "Allow interaction" },
  { "uuid", 'u', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &vpn_uuid, "VPN UUID" },
  { "name", 'n', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &vpn_name, "VPN Name" },
  { "service", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &vpn_service, "VPN Service" },
  G_OPTION_ENTRY_NULL
};


#define AUTOSUBMIT_LIMIT 5

#define AUTHGROUP_OPT(form)		(void *)(form)->authgroup_opt
#define AUTHGROUP_SELECTION(form)	(form)->authgroup_selection
#define FORMCHOICE(sopt, i)		((sopt)->choices[i])
#define IGNORE_OPT(opt)			((opt)->flags & OC_FORM_OPT_IGNORE)
#define dup_option_value(opt)		g_strdup((opt)->_value);


typedef enum {
  AUTH_DIALOG_RESPONSE_LOGIN = 1,
  AUTH_DIALOG_RESPONSE_CANCEL,
} AthDialogResponse;

struct WebviewContext {
  struct openconnect_info *vpninfo;
  WebKitWebView *webview;
  const char *login_uri;
  void *privdata;
  GMutex mutex;
  GCond cv;
  int done;
};

/* This struct holds all information we need to add a password to
 * the secret store. It’s used in success_passwords. */
typedef struct {
  char *description;
  char *password;
  char *vpn_uuid;
  char *auth_id;
  char *label;
} KeyringPassword;

typedef struct {
  GtkWidget *widget;
  GtkWidget *entry;
  GCancellable *cancel;

  struct oc_form_opt *opt;
  char *entry_text;
  int initial_selection;
  int grab_focus;

  AuthApp *self;
} UiFragmentData;

static const SecretSchema openconnect_secret_schema = {
  "org.freedesktop.NetworkManager.Connection.Openconnect",
  SECRET_SCHEMA_DONT_MATCH_NAME,
  {
    { "vpn_uuid", SECRET_SCHEMA_ATTRIBUTE_STRING },
    { "auth_id", SECRET_SCHEMA_ATTRIBUTE_STRING },
    { "label", SECRET_SCHEMA_ATTRIBUTE_STRING },
    { NULL, 0 },
  }
};

static void
keyring_password_free (gpointer data)
{
  KeyringPassword *kp = (KeyringPassword *)data;
  g_clear_pointer (&kp->description, g_free);
  g_clear_pointer (&kp->password, g_free);
  g_clear_pointer (&kp->vpn_uuid, g_free);
  g_clear_pointer (&kp->auth_id, g_free);
  g_clear_pointer (&kp->label, g_free);

  g_clear_pointer (&kp, g_free);
}


static void
write_progress (void       *cbdata,
                int         level,
                const char *fmt,
                ...);

#define LOG(x ...) write_progress (self, 1, x)

static void
ssl_box_add_notice (AuthApp    *self,
                    const char *msg)
{
  LOG ("%s: ENTER\n", G_STRFUNC);
  auth_app_window_log (self->win, 2, msg);
  LOG ("%s: EXIT\n", G_STRFUNC);
}

static void
ssl_box_add_info (AuthApp    *self,
                  const char *msg)
{
  LOG ("%s: ENTER %s\n", G_STRFUNC, msg);
  auth_app_window_add_form_info (self->win, 1, msg);
  LOG ("%s: EXIT\n", G_STRFUNC);
}

static void
ssl_box_add_error (AuthApp    *self,
                   const char *msg)
{
  LOG ("%s. ENTER\n", G_STRFUNC);
  auth_app_window_add_form_info (self->win, 0, msg);
  LOG ("%s: EXIT\n", G_STRFUNC);
}

typedef struct {
  AuthApp *self;
  char *message;
  int log_level;
} AuthAppProgressData;

static AuthAppProgressData *
auth_app_progress_data_new (AuthApp *self,
                            char    *message,
                            int      log_level)
{
  AuthAppProgressData *data = g_malloc0_n (sizeof (AuthAppProgressData), 1);

  data->self = g_object_ref (self);
  data->message = g_strdup (message);
  data->log_level = log_level;
  return data;
}

static void
auth_app_progress_data_free (AuthAppProgressData *data)
{
  g_clear_object (&data->self);
  g_clear_pointer (&data->message, g_free);
  g_clear_pointer (&data, g_free);
}

static gboolean
write_progress_real (gpointer user_data)
{
  AuthAppProgressData *data = (AuthAppProgressData *)user_data;
  AuthApp *self = AUTH_APP (data->self);
  g_autofree char *msg = NULL;

  g_return_val_if_fail (data->message, G_SOURCE_REMOVE);
  g_return_val_if_fail (data->self, G_SOURCE_REMOVE);

  /* //if (!self->win) { */
    g_print ("%d: %s", data->log_level, data->message);
  //} else {
  {
    auth_app_window_log (data->self->win, data->log_level, data->message);


    if (data->log_level == 0) {
      auth_app_window_error (data->self->win, data->message);
      return G_SOURCE_REMOVE;
    }
  }

  g_clear_pointer (&data, auth_app_progress_data_free);

  return G_SOURCE_REMOVE;
}

/* runs in worker thread */
/* _nm_printf (3, 4) */
static void
write_progress (void       *cbdata,
                int         level,
                const char *fmt,
                ...)
{
  AuthApp *self = AUTH_APP (cbdata);
  AuthAppProgressData *data;
  g_autofree char *msg = NULL;
  va_list args;

  va_start (args, fmt);
  msg = g_strdup_vprintf (fmt, args);
  va_end (args);

  data = auth_app_progress_data_new (self, msg, level);

  g_idle_add (write_progress_real, data);
}

static gboolean
auth_get_save_passwords (AuthApp *self)
{
  const char *save = g_hash_table_lookup (self->secrets, "save_passwords");

  LOG ("%s: ENTER\n", G_STRFUNC);
  if (g_strcmp0 (save, "yes") == 0) {
    LOG ("%s: EXIT: TRUE\n", G_STRFUNC);
    return TRUE;
  }

  LOG ("%s: EXIT: FALSE\n", G_STRFUNC);
  return FALSE;
}

static void
entry_changed (GtkEntry       *entry,
               UiFragmentData *data)
{
  g_free (data->entry_text);
  data->entry_text = g_strdup (gtk_editable_get_text (GTK_EDITABLE (entry)));
}

static void
entry_activate_cb (GtkWidget     *widget,
                   AuthAppWindow *self)
{
  /* gtk_dialog_response(GTK_DIALOG(self->dialog), AUTH_DIALOG_RESPONSE_LOGIN); */
}

static gboolean
ui_write_prompt (AuthApp        *self,
                 UiFragmentData *data)
{
  GtkWidget *entry;
  int visible;
  const char *label;

  LOG ("%s: ENTER\n", G_STRFUNC);

  label = data->opt->label;
  visible = (data->opt->type == OC_FORM_OPT_TEXT);

  entry = adw_entry_row_new ();
  /* gtk_widget_set_halign (entry, GTK_ALIGN_CENTER); */
  adw_preferences_group_add(ADW_PREFERENCES_GROUP (auth_app_window_get_form_box (AUTH_APP_WINDOW (self->win))), entry);
  data->entry = entry;
  /* if (!visible) { */
  /*   gtk_widget_set_sensitive (entry, FALSE); */
  /* } */
 LOG ("%s: %s\n", G_STRFUNC, label);
  adw_preferences_row_set_title (ADW_PREFERENCES_ROW (entry), label);
  if (data->entry_text) {
    LOG ("%s: %s\n", G_STRFUNC, data->entry_text);
    /* adw_preferences_row_set_title (ADW_PREFERENCES_ROW (entry), data->entry_text); */
  }
  /* If it's the first empty one, grab focus. Otherwise, if
     it's the first item of *any* kind, grab focus but don't
     admit it (so another empty entry can take focus_ */
  if (!data->entry_text && !data->self->form_grabbed) {
    data->self->form_grabbed = 1;
    gtk_widget_grab_focus (entry);
  } else if (g_queue_peek_tail (self->form_entries) == data)
    gtk_widget_grab_focus (entry);

  g_signal_connect (G_OBJECT (entry), "changed", G_CALLBACK (entry_changed), data);
  g_signal_connect (G_OBJECT (entry), "activate", G_CALLBACK (entry_activate_cb), self);

  /* data is freed in ui_flush in worker thread */

  LOG ("%s: EXIT\n", G_STRFUNC);
  return FALSE;
}

static void
do_override_label (UiFragmentData   *data,
                   struct oc_choice *choice)
{
  const char *new_label = data->opt->label;

  if (!data->entry)
    return;

  if (choice->override_name && !strcmp (choice->override_name, data->opt->name))
    new_label = choice->override_label;

  adw_preferences_row_set_title (ADW_PREFERENCES_ROW (data->entry), new_label);
}

static gboolean
do_newgroup (GtkDialog *dialog)
{
  /* gtk_dialog_response(dialog, AUTH_DIALOG_RESPONSE_LOGIN); */
  return FALSE;
}

static void
combo_changed (GtkComboBox    *combo,
               UiFragmentData *data)
{
  struct oc_form_opt_select *sopt = (void *)data->opt;
  int entry = gtk_combo_box_get_active (combo);

  if (entry < 0)
    return;

  data->entry_text = FORMCHOICE (sopt, entry)->name;

  if (entry != data->initial_selection) {
    data->self->newgroup = TRUE;
    g_idle_add ((GSourceFunc)do_newgroup, data->self);
    return;
  }

  g_queue_foreach (data->self->form_entries, (GFunc)do_override_label,
                   FORMCHOICE (sopt, entry));
}

static gboolean
ui_add_select (UiFragmentData *data)
{
  AuthApp *self = NULL; /*_self; / * FIXME global * / */
  GtkWidget *hbox, *text, *combo;
  struct oc_form_opt_select *sopt = (void *)data->opt;
  int i, user_selection = -1;

  hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
  /* gtk_box_append(GTK_BOX(data->self->ssl_box), hbox); */

  text = gtk_label_new (data->opt->label);
  gtk_box_append (GTK_BOX (hbox), text);

  combo = gtk_combo_box_text_new ();
  gtk_box_prepend (GTK_BOX (hbox), combo);

  for (i = 0; i < sopt->nr_choices; i++) {
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo), FORMCHOICE (sopt, i)->label);
    if (data->entry_text &&
        !strcmp (data->entry_text, FORMCHOICE (sopt, i)->name))
      user_selection = i;
  }

  i = data->initial_selection != -1 ? data->initial_selection :
      user_selection != -1 ? user_selection : 0;
  gtk_combo_box_set_active (GTK_COMBO_BOX (combo), i);
  g_free (data->entry_text);
  data->entry_text = FORMCHOICE (sopt, i)->name;
  data->initial_selection = i;

  if (g_queue_peek_tail (self->form_entries) == data)
    gtk_widget_grab_focus (combo);
  g_signal_connect (G_OBJECT (combo), "changed", G_CALLBACK (combo_changed), data);
  /* Hook up the 'show' signal to ensure that we override prompts on
     UI elements which may be coming later. */
  g_signal_connect (G_OBJECT (combo), "show", G_CALLBACK (combo_changed), data);

  /* data is freed in ui_flush in worker thread */

  return FALSE;
}

static gboolean
ui_show (AuthApp *self)
{
  LOG ("%s: ENTER\n", G_STRFUNC);
  /* gtk_widget_set_visible (self->getting_form_label, FALSE); */
  /* gtk_widget_set_visible (self->ssl_box, TRUE); */
  /* gtk_widget_set_sensitive (self->cancel_button, TRUE); */
  g_mutex_lock (&self->form_mutex);
  self->form_shown = TRUE;
  g_cond_signal (&self->form_shown_changed);
  g_mutex_unlock (&self->form_mutex);

  auth_app_window_show_form (self->win);
  LOG ("%s: EXIT\n", G_STRFUNC);

  return FALSE;
}

void
auth_app_login (AuthApp *self)
{
  /* ssl_box_clear(self); */

  /* if (self->getting_cookie) */
  /*  gtk_widget_show (self->getting_form_label); */
  g_mutex_lock (&self->form_mutex);
  self->form_retval = GINT_TO_POINTER (AUTH_DIALOG_RESPONSE_LOGIN);
  g_cond_signal (&self->form_retval_changed);
  g_mutex_unlock (&self->form_mutex);
}

typedef struct {
  AuthApp *self;
  struct oc_auth_form *form;
} AuthAppWindowFormData;

typedef struct cert_data {
  AuthApp *self;
  char *cert_details;
  const char *reason;
} cert_data;

static int
validate_peer_cert (void       *cbdata,
                    const char *reason)
{
  AuthApp *self = AUTH_APP (cbdata);
  int ret = 0;
  cert_data *data;
  char *certkey;
  char *accepted_hash = NULL;
  const char *fingerprint = openconnect_get_peer_cert_hash (self->vpninfo);

  LOG ("%s: ENTER\n", G_STRFUNC);
  certkey = g_strdup_printf ("certificate:%s:%d",
                             openconnect_get_hostname (self->vpninfo),
                             openconnect_get_port (self->vpninfo));

  accepted_hash = g_hash_table_lookup (self->secrets, certkey);
  if (accepted_hash && !openconnect_check_peer_cert_hash (self->vpninfo, accepted_hash))
    goto accepted;

  self->autosubmit = 0;

  data = g_malloc0 (sizeof (cert_data));
  data->self = self; /* FIXME uses global */
  data->cert_details = openconnect_get_peer_cert_details (self->vpninfo);
  data->reason = reason;

  g_mutex_lock (&self->form_mutex);

  self->cert_response = CERT_USER_NOT_READY;
  /* g_idle_add((GSourceFunc)user_validate_cert, data); */

  /* wait for user to accept or cancel */
  while (self->cert_response == CERT_USER_NOT_READY)
    g_cond_wait (&self->cert_response_changed, &self->form_mutex);

  openconnect_free_cert_info (self->vpninfo, data->cert_details);
  g_free (data);

  if (self->cert_response == CERT_ACCEPTED)
    ret = 0;
  else
    ret = -EINVAL;

  g_mutex_unlock (&self->form_mutex);

accepted:
  if (!ret) {
    g_hash_table_insert (self->secrets, certkey,
                         g_strdup (fingerprint));
    certkey = NULL;
  }

  g_free (certkey);
  LOG ("%s: EXIT\n", G_STRFUNC);
  return ret;
}

/* OK */
static void
auth_app_init (AuthApp *self)
{
  int param_fd = dup (1);

  self->paramf = fdopen (param_fd, "w");

  /* We don't want stdout from child processes / logging to confuse NM
   * so redirect it to stderr instead. */
  dup2 (2, 1);
}

/* OK */
static gboolean
get_save_passwords (AuthApp *self)
{
  const char *save = g_hash_table_lookup (self->secrets, "save_passwords");

  LOG ("%s: ENTER\n", G_STRFUNC);
  if (g_strcmp0 (save, "yes") == 0) {
    LOG ("%s: EXIT: TRUE\n", G_STRFUNC);
    return TRUE;
  }

  LOG ("%s: EXIT: FALSE\n", G_STRFUNC);
  return FALSE;
}

static gboolean
open_webview_idle (gpointer user_data)
{
  g_print ("%s: ENTER\n", G_STRFUNC);
#if 0
  struct WebviewContext *ctx = (struct WebviewContext *)user_data;
  WebKitWebView *web_view;
  WebKitWebsiteDataManager *dm = NULL;
  WebKitCookieManager *cm = NULL;
  g_autoptr (GString) storage = NULL;

  // Create a browser instance
  web_view = WEBKIT_WEB_VIEW (webkit_web_view_new());

  dm = webkit_web_view_get_website_data_manager(web_view);
  if (dm)
    cm = webkit_website_data_manager_get_cookie_manager(dm);

  if (cm)
    storage = g_string_new (g_get_user_data_dir());

  if (storage)
    storage = g_string_append(storage, "/openconnect_saml_cookies");

  if (storage) {
    webkit_cookie_manager_set_persistent_storage (cm, storage->str, WEBKIT_COOKIE_PERSISTENT_STORAGE_TEXT);
    webkit_cookie_manager_set_accept_policy (cm, WEBKIT_COOKIE_POLICY_ACCEPT_ALWAYS);
  }

  g_signal_connect(webView, "load-changed", G_CALLBACK(load_changed_cb), ctx);
  ctx->webview = webView;

  // Put the browser area into the main window
  gtk_widget_set_size_request(GTK_WIDGET(webView), 640, 480);
  gtk_box_pack_start(GTK_BOX(ui_data->ssl_box), GTK_WIDGET(webView), FALSE, FALSE, 0);
  gtk_widget_show_all(ui_data->ssl_box);

  // Load a web page into the browser instance
  webkit_web_view_load_uri(webView, ctx->login_uri);
#endif

  /* LOG ("%s: EXIT\n", G_STRFUNC); */
  return FALSE;
}

/* OK */
static int
open_webview (struct openconnect_info *vpninfo,
              const char              *login_uri,
              gpointer                 user_data)
{
  AuthApp *self = AUTH_APP (user_data);
  struct WebviewContext ctx;

  LOG ("%s: ENTER\n", G_STRFUNC);

  ctx.vpninfo = vpninfo;
  ctx.privdata = user_data;
  g_mutex_init (&ctx.mutex);
  g_cond_init (&ctx.cv);
  ctx.login_uri = login_uri;
  ctx.done = 0;

  g_mutex_lock (&ctx.mutex);
  g_idle_add(open_webview_idle, &ctx);
  while (!ctx.done) {
    g_cond_wait (&ctx.cv, &ctx.mutex);
  }
  g_mutex_unlock (&ctx.mutex);

  LOG ("%s: EXIT\n", G_STRFUNC);

  return 0;
}

static gboolean
ui_open_uri (gpointer user_data)
{
  /* GtkFileLauncher *launcher = NULL; */
  AuthApp *self = AUTH_APP (user_data);
  g_autoptr (GError) err = NULL;

  LOG ("%s: ENTER\n", G_STRFUNC);
  /* launcher = gtk_file_launcher_new (login_uri); */

  /* gtk_file_launcher_launch (launcher, NULL, NULL, NULL, NULL); */
  G_GNUC_BEGIN_IGNORE_DEPRECATIONS
  gtk_show_uri (NULL,
                self->login_uri,
                GDK_CURRENT_TIME);
  g_clear_pointer (&self->login_uri, g_free);
  G_GNUC_END_IGNORE_DEPRECATIONS
  if (err) {
    g_warning ("Failed to invoke GTK.show_uri_on_window.");
    /* write_progress (NULL, PRG_ERR, "Failed to invoke GTK.show_uri_on_window."); */
    /* write_progress (NULL, PRG_ERR, "%s.", err->message); */
    g_error_free (err);
    return G_SOURCE_CONTINUE;
  }

  LOG ("%s: EXIT\n", G_STRFUNC);
  return G_SOURCE_REMOVE;
}

/* OK */
static int
open_uri (struct openconnect_info *vpninfo,
          const char              *login_uri,
          gpointer                 user_data)
{
  AuthApp *self = AUTH_APP (user_data);

  LOG ("%s: ENTER %s\n", G_STRFUNC, login_uri);
  self->login_uri = g_strdup (login_uri);

  g_idle_add (ui_open_uri, self);
  LOG ("%s: EXIT\n", G_STRFUNC);
  return 0;
}

/* OK */
static int
write_new_config (gpointer    user_data,
                  const char *buf,
                  int         buflen)
{
  AuthApp *self = AUTH_APP (user_data);

  g_hash_table_insert (self->secrets, g_strdup ("xmlconfig"), g_base64_encode ((guchar *)buf, buflen));
  return 0;
}

/* OK */
static char *
find_form_answer (GHashTable          *secrets,
                  struct oc_auth_form *form,
                  struct oc_form_opt  *opt)
{
  g_autofree char *key = NULL;
  char *result;

  key = g_strdup_printf ("form:%s:%s", form->auth_id, opt->name);
  result = g_hash_table_lookup (secrets, key);

  return result;
}

/* OK */
/* If our stored group_list selection differs from the server default, send a
   NEWGROUP request to try to change it before rendering the form */
static gboolean
set_initial_authgroup (AuthApp             *self,
                       struct oc_auth_form *form)
{
  struct oc_form_opt *opt;

  LOG ("%s: ENTER\n", G_STRFUNC);
  if (self->group_set || !AUTHGROUP_OPT (form)) {
    LOG ("%s: EXIT\n", G_STRFUNC);
    return FALSE;
  }

  self->group_set = TRUE;

  for (opt = form->opts; opt; opt = opt->next) {
    int i;
    char *saved_group;
    struct oc_form_opt_select *sopt;

    if (opt != AUTHGROUP_OPT (form))
      continue;

    saved_group = find_form_answer (self->secrets, form, opt);
    if (!saved_group)
      return FALSE;

    sopt = (struct oc_form_opt_select *)opt;
    for (i = 0; i < sopt->nr_choices; i++) {
      struct oc_choice *ch = FORMCHOICE (sopt, i);
      if (!strcmp (saved_group, ch->name) && i != AUTHGROUP_SELECTION (form)) {
        openconnect_set_option_value (opt, saved_group);
        return TRUE;
      }
    }
  }

  LOG ("%s: EXIT\n", G_STRFUNC);
  return FALSE;
}


static void
form_autosubmit (AuthApp *self)
{
  LOG ("%s: ENTER %d == 0? %d ?\n", G_STRFUNC, self->fields_pending, self->autosubmit);
  if (self->fields_pending == 0 && self->autosubmit) {
    self->autosubmit--;
    /* gtk_button_clicked (GTK_BUTTON(self->login_button)); */
    /* gtk_widget_set_sensitive (self->login_button, FALSE); */
  }
  LOG ("%s: EXIT\n", G_STRFUNC);
}

/* OK */
/* Callback which is called when we got a reply from the secret store for any
 * password field. Updates the contents of the password field unless the user
 * entered anything in the meantime. */
static void
got_keyring_pw (GObject      *object,
                GAsyncResult *result,
                gpointer      user_data)
{
  UiFragmentData *data = (UiFragmentData *)user_data;
  GList *list;
  SecretItem *item;
  SecretValue *value = NULL;
  const char *string = NULL;

  g_print ("%s: ENTER\n", G_STRFUNC);
  return;
  data->self->fields_pending--;
  list = secret_service_search_finish (SECRET_SERVICE (object), result, NULL);
  if (list != NULL) {
    item = list->data;
    value = secret_item_get_secret (item);
    string = secret_value_get (value, NULL);
  }

  if (string != NULL) {
    if (data->entry) {
      if (!g_ascii_strcasecmp ("", gtk_editable_get_text (GTK_EDITABLE (data->entry)))) {
        gtk_editable_set_text (GTK_EDITABLE (data->entry), string);
        if (gtk_widget_has_focus (data->entry))
          gtk_editable_select_region (GTK_EDITABLE (data->entry), 0, -1);
      }
    } else {
      data->entry_text = g_strdup (string);
    }
  } else {
    data->self->autosubmit = 0;
  }

  if (value)
    secret_value_unref (value);
  g_list_free_full (list, g_object_unref);

  /* zero the cancellable so that we don’t attempt to cancel it when
   * closing the dialog */
  g_clear_object (&data->cancel);

  form_autosubmit (data->self);
  g_print ("%s: EXIT\n", G_STRFUNC);
}

typedef struct {
  AuthApp *self;
  struct oc_auth_form *form;
} AuthAppFormData;

/* This part for processing forms from openconnect directly, rather than
   through the SSL UI abstraction (which doesn't allow 'select' options) */
static gboolean
ui_form (gpointer user_data)
{
  AuthAppFormData *form_data = user_data;
  AuthApp *self = AUTH_APP (form_data->self);
  struct oc_auth_form *form = form_data->form;
  struct oc_form_opt *opt;
  int ret;

  LOG ("%s: ENTER\n", G_STRFUNC);

  g_mutex_lock (&self->form_mutex);
  while (!g_queue_is_empty (self->form_entries)) {
    UiFragmentData *fragment_data;
    fragment_data = g_queue_pop_tail (self->form_entries);
    g_free (fragment_data);
  }
  g_mutex_unlock (&self->form_mutex);

  if (form->banner)
    ssl_box_add_info (self, form->banner);
  if (form->error)
    ssl_box_add_error (self, form->error);
  if (form->message)
    ssl_box_add_info (self, form->message);

  for (opt = form->opts; opt; opt = opt->next) {
    UiFragmentData *fragment_data;

    if (opt->type == OC_FORM_OPT_HIDDEN || IGNORE_OPT (opt))
      continue;

    fragment_data = g_malloc0 (sizeof (UiFragmentData));
    fragment_data->self = self;
    fragment_data->opt = opt;

    if (opt->type == OC_FORM_OPT_PASSWORD ||
        opt->type == OC_FORM_OPT_TEXT) {
      g_mutex_lock (&self->form_mutex);
      g_queue_push_head (self->form_entries, fragment_data);
      g_mutex_unlock (&self->form_mutex);
      if (opt->type != OC_FORM_OPT_PASSWORD) {
        fragment_data->entry_text = g_strdup (find_form_answer (self->secrets, form, opt));
        if (!fragment_data->entry_text) {
          fragment_data->entry_text = dup_option_value (opt);
          self->autosubmit = 0;
        }
      } else {
        GHashTable *attrs;

        fragment_data->cancel = g_cancellable_new ();
        attrs = secret_attributes_build (&openconnect_secret_schema,
                                         "vpn_uuid", self->vpn_uuid,
                                         "auth_id", form->auth_id,
                                         "label", fragment_data->opt->name,
                                         NULL);
        self->fields_pending++;
        secret_service_search (NULL, &openconnect_secret_schema, attrs,
                               SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS,
                               fragment_data->cancel, got_keyring_pw, fragment_data);
        g_hash_table_unref (attrs);
      }

      ui_write_prompt (self, fragment_data);
    } else if (opt->type == OC_FORM_OPT_SELECT) {
      g_mutex_lock (&self->form_mutex);
      g_queue_push_head (self->form_entries, fragment_data);
      g_mutex_unlock (&self->form_mutex);
      fragment_data->entry_text = g_strdup (find_form_answer (self->secrets, form, opt));
      if (!fragment_data->entry_text)
        self->autosubmit = 0;

      if (opt == AUTHGROUP_OPT (form))
        fragment_data->initial_selection = AUTHGROUP_SELECTION (form);
      else
        fragment_data->initial_selection = -1;

      ui_add_select (fragment_data);
    } else {
      g_clear_pointer (&fragment_data, g_free);
    }
  }

  form_autosubmit (self);
  LOG ("%s: EXIT\n", G_STRFUNC);

  ret = ui_show (self);

  /* g_object_unref (self); */
  return G_SOURCE_REMOVE;
}

/* OK */
static int
nm_process_auth_form (gpointer             user_data,
                      struct oc_auth_form *form)
{
  AuthApp *self = AUTH_APP (user_data);
  AuthAppFormData form_data;
  int response;

  LOG ("%s: ENTER\n", G_STRFUNC);
  if (set_initial_authgroup (self, form))
    return OC_FORM_RESULT_NEWGROUP;

  self->newgroup = FALSE;

  form_data.self = self;
  form_data.form = form;
  g_idle_add ((GSourceFunc)ui_form, &form_data);

  g_mutex_lock (&self->form_mutex);
  LOG ("%s: wait for ui to show\n", G_STRFUNC);
  /* wait for ui to show */
  while (!self->form_shown) {
    g_cond_wait (&self->form_shown_changed, &self->form_mutex);
  }
  self->form_shown = FALSE;

  if (!self->cancelled) {
    LOG ("%s: wait for form submission or cancel\n", G_STRFUNC);
    /* wait for form submission or cancel */
    while (!self->form_retval) {
      g_cond_wait (&self->form_retval_changed, &self->form_mutex);
    }

    response = GPOINTER_TO_INT (self->form_retval);
    self->form_retval = NULL;
  } else {
    LOG ("%s: CANCEL\n", G_STRFUNC);

    response = AUTH_DIALOG_RESPONSE_CANCEL;
  }

  if (response == AUTH_DIALOG_RESPONSE_LOGIN) {
    /* set entry results and free temporary data structures */
    while (!g_queue_is_empty (self->form_entries)) {
      UiFragmentData *data;
      data = g_queue_pop_tail (self->form_entries);

      if (data->cancel)
        g_cancellable_cancel (data->cancel);

      if (data->entry_text) {
        openconnect_set_option_value (data->opt, data->entry_text);

        if (data->opt->type == OC_FORM_OPT_TEXT ||
            data->opt->type == OC_FORM_OPT_SELECT) {
          char *keyname;
          keyname = g_strdup_printf ("form:%s:%s", form->auth_id, data->opt->name);
          g_hash_table_insert (self->success_secrets, keyname, g_strdup (data->entry_text));
        }

        if (data->opt->type == OC_FORM_OPT_PASSWORD) {
          /* store the password in the secret store */
          KeyringPassword *kp = g_new (KeyringPassword, 1);
          kp->description = g_strdup_printf (_("OpenConnect: %s: %s:%s"), self->vpn_name, form->auth_id, data->opt->name);
          kp->password = g_strdup (data->entry_text);
          kp->vpn_uuid = g_strdup (self->vpn_uuid);
          kp->auth_id = g_strdup (form->auth_id);
          kp->label = g_strdup (data->opt->name);

          g_hash_table_insert (self->success_passwords, g_strdup (kp->description), kp);
        }
      }
      g_free (data);
    }
  }

  self->form_grabbed = 0;
  g_mutex_unlock (&self->form_mutex);

  if (response == AUTH_DIALOG_RESPONSE_LOGIN) {
    if (self->newgroup) {
      LOG ("%s: EXIT\n", G_STRFUNC);

      return OC_FORM_RESULT_NEWGROUP;
    }

    LOG ("%s: EXIT\n", G_STRFUNC);
    return OC_FORM_RESULT_OK;
  }

  LOG ("%s: EXIT\n", G_STRFUNC);

  return OC_FORM_RESULT_CANCELLED;
}

static int
parse_xmlconfig (AuthApp *self,
                 gchar   *xmlconfig)
{
  xmlDocPtr xml_doc;
  xmlNode *xml_node, *xml_node2;
  VPNHost *newhost;

  xml_doc = xmlReadMemory (xmlconfig, strlen (xmlconfig), "noname.xml", NULL, 0);
  if (!xml_doc)
    return -EIO;

  xml_node = xmlDocGetRootElement (xml_doc);
  for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
    if (xml_node->type == XML_ELEMENT_NODE && !strcmp ((char *)xml_node->name, "ServerList")) {
      for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
        if (xml_node->type == XML_ELEMENT_NODE && !strcmp ((char *)xml_node->name, "HostEntry")) {
          int match = 0;

          newhost = malloc (sizeof (*newhost));
          if (!newhost)
            return -ENOMEM;

          memset (newhost, 0, sizeof (*newhost));
          for (xml_node2 = xml_node->children; match >= 0 && xml_node2; xml_node2 = xml_node2->next) {
            if (xml_node2->type != XML_ELEMENT_NODE)
              continue;

            if (!strcmp ((char *)xml_node2->name, "HostName")) {
              char *content = (char *)xmlNodeGetContent (xml_node2);
              newhost->hostname = content;
            } else if (!strcmp ((char *)xml_node2->name, "HostAddress")) {
              char *content = (char *)xmlNodeGetContent (xml_node2);
              newhost->hostaddress = content;
            } else if (!strcmp ((char *)xml_node2->name, "UserGroup")) {
              char *content = (char *)xmlNodeGetContent (xml_node2);
              newhost->usergroup = content;
            }
          }

          if (newhost->hostname && newhost->hostaddress) {
            VPNHost *host = self->vpnhosts->data;
            if (!strcasecmp (newhost->hostaddress, host->hostaddress) && !strcasecmp (newhost->usergroup ?: "", host->usergroup ?: "")) {
              /* Remove originally configured host if it's in the list */
              /* struct vpnhost *tmp = vpnhosts->next; */

              /* free(vpnhosts); */
              /* vpnhosts = tmp; */
              LOG ("TODO: remove duplicate");
            }
            self->vpnhosts = g_list_append (self->vpnhosts, newhost);
          } else
            free (newhost);
        }
      }
      break;
    }
  }

  xmlFreeDoc (xml_doc);
  return 0;
}

/* OK */
static int
get_config (AuthApp *self)
{
  struct openconnect_info *vpninfo = self->vpninfo;
  char *proxy;
  char *xmlconfig;
  char *hostname;
  char *csd;
  char *mcakey, *mcacert, *mca_key_pass;
  char *sslkey, *cert;
  char *csd_wrapper;
  char *reported_os;
  char *key_pass;
  char *pem_passphrase_fsid;
  char *cafile;
  char *token_mode;
  char *token_secret;
  char *protocol;
  VPNHost *host;

  hostname = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_GATEWAY);
  if (!hostname) {
    g_warning ("No gateway configured");
    return -EINVAL;
  }

  /* add gateway to host list */
  host = g_malloc0 (sizeof (VPNHost));
  host->hostname = g_strdup (hostname);
  host->hostaddress = g_strdup (hostname);

  self->vpnhosts = g_list_append (self->vpnhosts, host);

  self->lasthost = g_hash_table_lookup (self->secrets, "lasthost");

  xmlconfig = g_hash_table_lookup (self->secrets, "xmlconfig");
  if (xmlconfig) {
    GChecksum *sha1;
    gchar *config_str;
    gsize config_len;
    const char *sha1_text;

    config_str = (gchar *)g_base64_decode (xmlconfig, &config_len);

    sha1 = g_checksum_new (G_CHECKSUM_SHA1);
    g_checksum_update (sha1, (gpointer)config_str, config_len);
    sha1_text = g_checksum_get_string (sha1);

    openconnect_set_xmlsha1 (vpninfo, (char *)sha1_text, strlen (sha1_text) + 1);
    g_checksum_free (sha1);

    parse_xmlconfig (self, config_str);
  }

  protocol = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_PROTOCOL);
  if (protocol && openconnect_set_protocol (vpninfo, protocol))
    return -EINVAL;

  if (!g_strcmp0 (protocol, "pulse"))
    self->connect_urlpath = TRUE;

  cafile = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_CACERT);
  if (cafile)
    openconnect_set_cafile (vpninfo, cafile);

  csd = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_CSD_ENABLE);
  if (csd && !strcmp (csd, "yes")) {
    /* We're not running as root; we can't setuid(). */
    csd_wrapper = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_CSD_WRAPPER);
    if (csd_wrapper && !csd_wrapper[0])
      csd_wrapper = NULL;

    openconnect_setup_csd (vpninfo, getuid (), 1, csd_wrapper);
  }

  reported_os = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_REPORTED_OS);
  if (reported_os && reported_os[0])
    openconnect_set_reported_os (vpninfo, reported_os);

  proxy = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_PROXY);
  if (proxy && proxy[0] && openconnect_set_http_proxy (vpninfo, proxy))
    return -EINVAL;

  mcacert = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_MCACERT);
  mcakey = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_MCAKEY);
  openconnect_set_mca_cert (vpninfo, mcacert, mcakey);

  mca_key_pass = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_MCA_PASS);
  if (mca_key_pass)
    openconnect_set_mca_key_password (vpninfo, mca_key_pass);

  cert = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_USERCERT);
  sslkey = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_PRIVKEY);
  openconnect_set_client_cert (vpninfo, cert, sslkey);

  key_pass = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_KEY_PASS);
  if (key_pass)
    openconnect_set_key_password (vpninfo, key_pass);
  pem_passphrase_fsid = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID);
  if (pem_passphrase_fsid && cert && !strcmp (pem_passphrase_fsid, "yes"))
    openconnect_passphrase_from_fsid (vpninfo);

  token_mode = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_TOKEN_MODE);
  token_secret = g_hash_table_lookup (self->secrets, NM_OPENCONNECT_KEY_TOKEN_SECRET);
  if (!token_secret || !token_secret[0])
    token_secret = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_TOKEN_SECRET);
  if (token_mode) {
    int ret = 0;

    if (!strcmp (token_mode, "manual") && token_secret)
      ret = openconnect_set_token_mode (vpninfo, OC_TOKEN_MODE_STOKEN, token_secret);
    else if (!strcmp (token_mode, "stokenrc"))
      ret = openconnect_set_token_mode (vpninfo, OC_TOKEN_MODE_STOKEN, NULL);
    else if (!strcmp (token_mode, "totp") && token_secret)
      ret = openconnect_set_token_mode (vpninfo, OC_TOKEN_MODE_TOTP, token_secret);
    else if (!strcmp (token_mode, "hotp") && token_secret)
      ret = openconnect_set_token_mode (vpninfo, OC_TOKEN_MODE_HOTP, token_secret);
    else if (!strcmp (token_mode, "yubioath")) {
      /* This needs to be done from a thread because it can call back to
         ask for the PIN */
      self->token_mode = OC_TOKEN_MODE_YUBIOATH;
      if (token_secret && token_secret[0])
        self->token_secret = token_secret;
      else
        self->token_secret = NULL;
    }
    if (ret)
      g_warning ("Failed to initialize software token: %d", ret);
  }

  return 0;
}

/* OK */
static gboolean
hash_merge_one (gpointer key,
                gpointer value,
                gpointer new_hash)
{
  g_hash_table_insert (new_hash, key, value);
  return TRUE;
}

/* OK */
static void
hash_table_merge (GHashTable *old_hash,
                  GHashTable *new_hash)
{
  g_hash_table_foreach_steal (old_hash, &hash_merge_one, new_hash);
}

/* OK */
static char *
oc_server_url (AuthApp *self)
{
  return g_strdup (openconnect_get_connect_url (self->vpninfo));
}

/* OK */
static char *
oc_server_resolve (struct openconnect_info *vpninfo)
{
  /* Versions older than OpenConnect v7.07 (API 5.3) didn't
   * support the --resolve argument. Don't confuse them. */
  const char *ipaddr = openconnect_get_hostname (vpninfo);
  const char *dnsname = openconnect_get_dnsname (vpninfo);

  if (g_strcmp0 (ipaddr, dnsname)) {
    /* Strip the [] surrounding IPv6 literals. */
    int l = strlen (ipaddr);
    if (ipaddr[0] == '[' && ipaddr[l - 1] == ']') {
      ipaddr++;
      l -= 2;
    }
    return g_strdup_printf ("%s:%.*s", dnsname, l, ipaddr);
  }

  return NULL;
}

/* OK */
static void
keyring_store_passwords (gpointer key,
                         gpointer value,
                         gpointer user_data)
{
  KeyringPassword *kp = (KeyringPassword *)value;

  secret_password_store_sync (&openconnect_secret_schema, NULL,
                              kp->description, kp->password,
                              NULL, NULL,
                              "vpn_uuid", kp->vpn_uuid,
                              "auth_id", kp->auth_id,
                              "label", kp->label,
                              NULL);
}

static gboolean
cookie_obtained (AuthApp *self)
{
  LOG ("%s: ENTER\n", G_STRFUNC);

  self->getting_cookie = FALSE;

  /* auth_app_window_set_status_label (self->win, ""); */

  self->autosubmit = 0;

  if (self->cancelled) {
    /* user has chosen a new host, start from beginning */
    g_hash_table_remove_all (self->success_secrets);
    g_hash_table_remove_all (self->success_passwords);

    /* connect_host(self); */
    /* auth_app_connect_host (self); */
    LOG ("%s: EXIT 1\n", G_STRFUNC);
    return FALSE;
  }

  if (self->cookie_retval < 0) {
    /* error while getting cookie */
    /* if (self->last_notice_icon) { */
    /* gtk_image_set_from_icon_name(GTK_IMAGE (self->last_notice_icon), "dialog-error"); */
    /* gtk_image_set_icon_size (GTK_IMAGE (self->last_notice_icon), GTK_ICON_SIZE_LARGE); */
    /* gtk_widget_set_sensitive (self->cancel_button, FALSE); */
    /* } */
  } else if (!self->cookie_retval) {
    const void *cert;
    gchar *key, *value;

    /* got cookie */

    /* Merge in the secrets which we only wanted to remember if
       the connection was successful (lasthost, form entries) */
    hash_table_merge (self->success_secrets, self->secrets);

    /* Merge in the three *real* secrets that are actually used
       by nm-openconnect-service to make the connection */
    key = g_strdup (NM_OPENCONNECT_KEY_GATEWAY);
    value = oc_server_url (self);
    g_hash_table_insert (self->secrets, key, value);

    value = oc_server_resolve (self->vpninfo);
    if (value) {
      key = g_strdup (NM_OPENCONNECT_KEY_RESOLVE);
      g_hash_table_insert (self->secrets, key, value);
    }

    key = g_strdup (NM_OPENCONNECT_KEY_COOKIE);
    value = g_strdup (openconnect_get_cookie (self->vpninfo));
    g_hash_table_insert (self->secrets, key, value);
    openconnect_clear_cookie (self->vpninfo);

    cert = openconnect_get_peer_cert_hash (self->vpninfo);
    if (cert) {
      key = g_strdup (NM_OPENCONNECT_KEY_GWCERT);
      value = g_strdup (cert);
      g_hash_table_insert (self->secrets, key, value);
    }

    if (auth_get_save_passwords (self)) {
      g_hash_table_foreach (self->success_passwords, keyring_store_passwords, NULL);
    }

    LOG ("%s: Destroy window\n", G_STRFUNC);
    gtk_window_destroy (GTK_WINDOW (self->win));
  } else {
    /* no cookie; user cancellation */
    /* gtk_widget_show (self->no_form_label); */
  }

  g_hash_table_remove_all (self->success_secrets);
  g_hash_table_remove_all (self->success_passwords);

  LOG ("%s: EXIT 2\n", G_STRFUNC);
  return FALSE;
}

/* OK */
static gpointer
obtain_cookie (AuthApp *self)
{
  int ret;
  char cancelbuf;

  LOG ("%s: ENTER\n", G_STRFUNC);
  ret = openconnect_obtain_cookie (self->vpninfo);

  /* Suck out the poison */
  while (read (self->cmd_pipe, &cancelbuf, 1) == 1);

  self->cookie_retval = ret;
  g_idle_add ((GSourceFunc)cookie_obtained, self);
  LOG ("%s: EXIT\n", G_STRFUNC);

  return NULL;
}

/* OK */
static void
init_ui_data (AuthApp *self)
{
  char *vpn_useragent = g_hash_table_lookup (self->options, NM_OPENCONNECT_KEY_USERAGENT);

  self->form_entries = g_queue_new ();

  g_mutex_init (&self->form_mutex);
  g_cond_init (&self->form_retval_changed);
  g_cond_init (&self->form_shown_changed);
  g_cond_init (&self->cert_response_changed);

  self->success_secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  self->success_passwords = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, keyring_password_free);

  if (get_save_passwords (self))
    self->autosubmit = AUTOSUBMIT_LIMIT;

  /* If it's an empty string, forget it. */
  if (vpn_useragent && !*vpn_useragent)
    vpn_useragent = NULL;

  self->vpninfo = openconnect_vpninfo_new (vpn_useragent ?: "OpenConnect VPN Agent (NetworkManager)",
                                           validate_peer_cert,
                                           write_new_config,
                                           nm_process_auth_form,
                                           write_progress,
                                           self);

  /* The useragent provided to openconnect_vpninfo_new() gets the
   * OpenConnect version appended to it. But some servers need the
   * useragent to *precisely* match a known string; support for
   * that was added in OpenConnect 9.00 (API 5.8) with the
   * openconnect_set_useragent() function. */
  if (vpn_useragent)
    openconnect_set_useragent (self->vpninfo, vpn_useragent);

  openconnect_set_external_browser_callback (self->vpninfo, open_uri);
  openconnect_set_webview_callback (self->vpninfo, open_webview);
  self->cmd_pipe = openconnect_setup_cmd_pipe (self->vpninfo);
}

/* MAYBE */
static gpointer
init_connection (gpointer user_data)
{
  AuthApp *self = AUTH_APP (user_data);

  if (self->token_mode != OC_TOKEN_MODE_NONE)
    openconnect_set_token_mode (self->vpninfo, self->token_mode, self->token_secret);

  auth_app_window_set_mode (self->win, AUTH_APP_MODE_ENABLE_CONNECT);

  /* Start connecting now if there's only one host */
#if 0
  if (g_list_length (self->vpnhosts) == 1) {
    /* VPNHost *host = self->vpnhosts->data; */

    auth_app_window_set_mode (self->win, AUTH_APP_MODE_CONNECTING);
  } else
#endif
                                   {
    self->autosubmit = 0;
  }

  return NULL;
}

/* OK */
static gboolean
process_stdin (gpointer user_data)
{
  AuthApp *self = AUTH_APP (user_data);
  gsize count;
  GIOStatus status;
  char c;

  while (1) {
    status = g_io_channel_read_chars (self->stdin_channel, &c, 1, &count, NULL);
    if (status == G_IO_STATUS_AGAIN)
      return TRUE;

    g_return_val_if_fail (status == G_IO_STATUS_NORMAL, FALSE);

    /* Like nm_vpn_service_plugin_read_vpn_details(), treat \0 as \n */
    if (c == '\0' || c == '\n') {
      if (!strcmp (self->stdin_line->str, "QUIT")) {
        self->quit_seen = TRUE;
        if (self->win)
          gtk_window_destroy (GTK_WINDOW (self->win));
      }
      g_string_truncate (self->stdin_line, 0);
      continue;
    }

    if (self->stdin_line->len < 10)
      g_string_append_c (self->stdin_line, c);
  }

  return G_SOURCE_REMOVE;
}

/* OK */
static void
auth_app_activate (GApplication *app)
{
  AuthApp *self = AUTH_APP (app);

  LOG ("%s: ENTER\n", G_STRFUNC);

  /* Ensure we have all parameters we need */
  if (!vpn_uuid || !vpn_name || !vpn_service) {
    g_warning ("Have to supply UUID, name, and service");
    return;
  }

  /* We only handle OPENCONNECT service */
  if (g_strcmp0 (vpn_service, NM_VPN_SERVICE_TYPE_OPENCONNECT) != 0) {
    g_warning ("This dialog only works with the '%s' service", NM_VPN_SERVICE_TYPE_OPENCONNECT);
    return;
  }

  g_clear_pointer (&vpn_service, g_free);

  self->vpn_name = vpn_name;
  self->vpn_uuid = vpn_uuid;

  if (!nm_vpn_service_plugin_read_vpn_details (0, &self->options, &self->secrets)) {
    g_warning ("Failed to read '%s' (%s) data and secrets from stdin.", vpn_name, vpn_uuid);
    return;
  }

  init_ui_data (self);

  if (get_config (self)) {
    g_warning ("Failed to find VPN UUID %s\n", self->vpn_uuid);
    return;
  }

  g_unix_set_fd_nonblocking (0, TRUE, NULL);
  self->stdin_channel = g_io_channel_unix_new (0);
  self->stdin_source = g_io_create_watch (self->stdin_channel, G_IO_IN);
  self->stdin_line = g_string_new ("");

  /*
   * https://gitlab.gnome.org/GNOME/network-manager-applet/-/issues/179
   *
   * Some versions of nm-applet send the QUIT immediately along with the
   * DONE after the config+secrets. So check for it right now, before
   * displaying the dialog. If it's already been sent, ignore it (but
   * leave self->quit_seen TRUE so that we don't wait later).
   */
  process_stdin (self);

  if (!self->quit_seen) {
    g_source_set_callback (self->stdin_source, process_stdin, self, NULL);
    g_source_attach (self->stdin_source, NULL);
  }

  if (allow_interaction) {
    g_autoptr (GThread) init_thread = NULL;

    self->win = auth_app_window_new (AUTH_APP (app));
    auth_app_window_setup_window (AUTH_APP_WINDOW (self->win), self->vpn_name, self->vpnhosts);

    openconnect_init_ssl ();

    init_thread = g_thread_new ("init_connection", init_connection, self);

    gtk_window_present (GTK_WINDOW (self->win));
  }

  LOG ("%s: EXIT\n", G_STRFUNC);
}

/* OK */
static void
auth_app_shutdown (GApplication *app)
{
  AuthApp *self = AUTH_APP (app);
  GHashTableIter iter;
  char *key;
  char *value;

  LOG ("%s: ENTER\n", G_STRFUNC);

  /* Dump all secrets to stdout */
  if (g_hash_table_size (self->secrets) > 0) {
    g_hash_table_iter_init (&iter, self->secrets);
    while (g_hash_table_iter_next (&iter, (gpointer *)&key, (gpointer *)&value)) {
      fprintf (self->paramf, "%s\n%s\n", key, value);
    }
  }

  fprintf (self->paramf, "\n\n");
  fflush (self->paramf);

  LOG ("%s: quit seen %d\n", G_STRFUNC, self->quit_seen);

  G_APPLICATION_CLASS (auth_app_parent_class)->shutdown (app);
}

/* OK */
static void
auth_app_class_init (AuthAppClass *class)
{
  G_APPLICATION_CLASS (class)->activate = auth_app_activate;
  G_APPLICATION_CLASS (class)->shutdown = auth_app_shutdown;
}

/* OK */
AuthApp *
auth_app_new (void)
{
  GObject *obj = g_object_new (AUTH_APP_TYPE,
                               "application-id", "org.gnome.nm_auth_app",
                               "flags", G_APPLICATION_DEFAULT_FLAGS,
                               NULL);

  g_application_add_main_option_entries (G_APPLICATION (obj), entries);

  return AUTH_APP (obj);
}

void
auth_app_connect_host (AuthApp *self,
                       char    *hostname)
{
  g_autoptr (GThread) thread = NULL;
  VPNHost *host = NULL;
  char cancelbuf;
  GList *iter;

  LOG ("%s. ENTER\n", G_STRFUNC);

  if (self->getting_cookie)
    return;

  self->cancelled = FALSE;
  self->getting_cookie = TRUE;

  g_mutex_lock (&self->form_mutex);
  self->form_retval = NULL;
  g_mutex_unlock (&self->form_mutex);

  while (read (self->cmd_pipe, &cancelbuf, 1) == 1);

  /* reset ssl context.
   * TODO: this is probably not the way to go... */
  openconnect_reset_ssl (self->vpninfo);

  for (iter = self->vpnhosts; iter && iter->data; iter = g_list_next (iter)) {
    VPNHost *current_host = iter->data;

    if (g_strcmp0 (current_host->hostname, hostname) == 0) {
      host = current_host;
      break;
    }
  }

  if (!host)
    return;

  if (openconnect_parse_url (self->vpninfo, host->hostaddress)) {
    fprintf (stderr, "Failed to parse server URL '%s'\n", host->hostaddress);
    openconnect_set_hostname (self->vpninfo, host->hostaddress);
  }

  if (!openconnect_get_urlpath (self->vpninfo) && host->usergroup)
    openconnect_set_urlpath (self->vpninfo, host->usergroup);

  g_hash_table_insert (self->success_secrets, g_strdup ("lasthost"), g_strdup (host->hostname));
  thread = g_thread_new ("obtain_cookie", (GThreadFunc)obtain_cookie, self);
}

