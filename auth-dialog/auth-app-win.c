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

#include "auth-app-win.h"

struct _AuthAppWindow {
  AdwApplicationWindow parent;

  GtkWidget *toolbar_view;
  GtkWidget *title_widget;
  GtkWidget *view_stack;
  GtkWidget *bottom_stack;
  GtkWidget *group;
  GtkWidget *debug_window;
  GtkWidget *connect_button;
  GtkWidget *error_status_page;
  GtkWidget *text_view;
  GtkWidget *form_box;

  GtkTextBuffer *log;

  char *current_host_label;
};

G_DEFINE_TYPE (AuthAppWindow, auth_app_window, ADW_TYPE_APPLICATION_WINDOW);

static void
on_radio_button_toggled (GtkWidget *button,
                         gpointer   user_data)
{
  AuthAppWindow *self = AUTH_APP_WINDOW (user_data);

  if (gtk_check_button_get_active (GTK_CHECK_BUTTON (button))) {
    GtkWidget *row = gtk_widget_get_ancestor (GTK_WIDGET (button), ADW_TYPE_ACTION_ROW);
    const char *label = adw_preferences_row_get_title (ADW_PREFERENCES_ROW (row));

    g_clear_pointer (&self->current_host_label, g_free);
    self->current_host_label = g_strdup (label);
  }
}

static void
connect_state (AuthAppWindow *self)
{
  AuthApp *app = AUTH_APP (gtk_window_get_application (GTK_WINDOW (self)));

  g_print ("%s: ENTER\n", G_STRFUNC);
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->view_stack), "connecting");
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->bottom_stack), "connecting");
  adw_window_title_set_subtitle (ADW_WINDOW_TITLE (self->title_widget), "Contacting host…");

  auth_app_connect_host (app, self->current_host_label);
  g_print ("%s: EXIT\n", G_STRFUNC);
}

static void
on_connect_button_clicked (GtkWidget     *button,
                           AuthAppWindow *self)
{
  g_print ("%s: ENTER\n", G_STRFUNC);
  connect_state (self);
  g_print ("%s: EXIT\n", G_STRFUNC);
}

static void
scroll_log (GtkTextBuffer *log,
            GtkTextView   *view)
{
  GtkTextMark *mark;

  g_return_if_fail (GTK_IS_TEXT_VIEW (view));

  mark = gtk_text_buffer_get_insert (log);
  gtk_text_view_scroll_to_mark (view, mark, 0.0, FALSE, 0.0, 0.0);
}

static void
open_debug_view (GtkWidget *widget,
                 gpointer   user_data)
{
  AuthAppWindow *self = AUTH_APP_WINDOW (user_data);

  if (!self->debug_window) {
    GtkWidget *title_widget;
    GtkWidget *toolbar_view;
    GtkWidget *scrolled_window;
    GtkWidget *header_bar = adw_header_bar_new ();

    /* self->debug_window = adw_application_window_new (gtk_window_get_application (GTK_WINDOW (self))); */
    self->debug_window = adw_window_new ();
    gtk_window_set_default_size (GTK_WINDOW (self->debug_window), 1024, 768);

    toolbar_view = adw_toolbar_view_new ();

    title_widget = adw_window_title_new ("Debug Log", "");
    adw_header_bar_set_title_widget (ADW_HEADER_BAR (header_bar), title_widget);
    adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (toolbar_view), header_bar);

    scrolled_window = gtk_scrolled_window_new ();
    adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (toolbar_view), scrolled_window);

    gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scrolled_window), self->text_view);
    gtk_window_set_hide_on_close (GTK_WINDOW (self->debug_window), TRUE);

    /* adw_application_window_set_content (ADW_APPLICATION_WINDOW (self->debug_window), toolbar_view); */
    adw_window_set_content (ADW_WINDOW (self->debug_window), toolbar_view);
  }

  gtk_window_present (GTK_WINDOW (self->debug_window));
}

static void
on_cancel_button_clicked (GtkWidget *widget,
                          gpointer   user_data)
{
  AuthAppWindow *self = AUTH_APP_WINDOW (user_data);

  g_print ("%s: ENTER\n", G_STRFUNC);
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->view_stack), "start");
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->bottom_stack), "start");

  adw_window_title_set_subtitle (ADW_WINDOW_TITLE (self->title_widget), "Select host");
}

static void
on_login_button_clicked (GtkWidget *widget,
                         gpointer   user_data)
{
  AuthAppWindow *self = AUTH_APP_WINDOW (user_data);
  AuthApp *app = AUTH_APP (gtk_window_get_application (GTK_WINDOW (self)));

  g_print ("%s: ENTER\n", G_STRFUNC);

  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->view_stack), "connecting");
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->bottom_stack), "connecting");
  adw_window_title_set_subtitle (ADW_WINDOW_TITLE (self->title_widget), "Contacting host…");

  /* Clear form box */
  if (0) {
  GtkWidget *childs = gtk_widget_get_first_child(self->form_box);
  while (childs != NULL) {
    adw_preferences_group_remove(ADW_PREFERENCES_GROUP(self->form_box), childs);
    childs = gtk_widget_get_first_child(self->form_box);
  }
  }

  auth_app_login (app);
}

static void
on_retry_button_clicked (GtkWidget *widget,
                         gpointer   user_data)
{
  AuthAppWindow *self = AUTH_APP_WINDOW (user_data);

  g_print ("%s: ENTER\n", G_STRFUNC);
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->view_stack), "start");
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->bottom_stack), "start");

  adw_window_title_set_subtitle (ADW_WINDOW_TITLE (self->title_widget), "Select host");
}

static void
auth_app_window_init (AuthAppWindow *self)
{
  GtkWidget *header_bar;
  GtkWidget *menu;
  GtkWidget *page;
  GtkWidget *box;
  GtkWidget *spinner;
  GtkWidget *cancel_button;
  GtkWidget *retry_button;
  GtkWidget *login_button;

  gtk_window_set_default_size (GTK_WINDOW (self), 700, 400);

  self->toolbar_view = adw_toolbar_view_new ();
  menu = gtk_button_new_from_icon_name ("dialog-information-symbolic");
  g_signal_connect (G_OBJECT (menu), "clicked", G_CALLBACK (open_debug_view), self);

  header_bar = adw_header_bar_new ();
  adw_header_bar_pack_end (ADW_HEADER_BAR (header_bar), menu);
  self->title_widget = adw_window_title_new ("VPN", "Select host");
  adw_header_bar_set_title_widget (ADW_HEADER_BAR (header_bar), self->title_widget);
  adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (self->toolbar_view), header_bar);

  self->view_stack = adw_view_stack_new ();
  adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (self->toolbar_view), self->view_stack);

  self->bottom_stack = adw_view_stack_new ();
  adw_toolbar_view_add_bottom_bar (ADW_TOOLBAR_VIEW (self->toolbar_view), self->bottom_stack);

  page = adw_preferences_page_new ();
  self->group = adw_preferences_group_new ();
  gtk_widget_set_sensitive (self->group, FALSE);
  gtk_widget_set_margin_top (self->group, 12);
  gtk_widget_set_margin_bottom (self->group, 12);
  gtk_widget_set_margin_start (self->group, 12);
  gtk_widget_set_margin_end (self->group, 12);
  adw_preferences_page_add (ADW_PREFERENCES_PAGE (page), ADW_PREFERENCES_GROUP (self->group));

  self->connect_button = gtk_button_new_with_label ("Connect");
  g_signal_connect_object (self->connect_button, "clicked", G_CALLBACK (on_connect_button_clicked), self, 0);
  gtk_widget_set_sensitive (self->connect_button, FALSE);
  gtk_widget_set_margin_top (GTK_WIDGET (self->connect_button), 12);
  gtk_widget_set_margin_bottom (GTK_WIDGET (self->connect_button), 12);
  gtk_widget_set_halign (self->connect_button, GTK_ALIGN_CENTER);
  gtk_widget_add_css_class (self->connect_button, "suggested-action");
  gtk_widget_add_css_class (self->connect_button, "pill");
  adw_view_stack_add_named (ADW_VIEW_STACK (self->bottom_stack), self->connect_button, "start");

  adw_view_stack_add_named (ADW_VIEW_STACK (self->view_stack), page, "start");

  /* Connecting */
  box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);

  gtk_widget_set_valign (box, GTK_ALIGN_CENTER);
  spinner = adw_spinner_new ();
  gtk_widget_set_size_request (spinner, -1, 128);
  gtk_box_append (GTK_BOX (box), spinner);

  cancel_button = gtk_button_new_with_label ("Cancel");
  g_signal_connect_object (cancel_button, "clicked", G_CALLBACK (on_cancel_button_clicked), self, 0);
  gtk_widget_set_margin_top (GTK_WIDGET (cancel_button), 12);
  gtk_widget_set_margin_bottom (GTK_WIDGET (cancel_button), 12);
  gtk_widget_set_halign (cancel_button, GTK_ALIGN_CENTER);
  gtk_widget_add_css_class (cancel_button, "pill");
  adw_view_stack_add_named (ADW_VIEW_STACK (self->bottom_stack), cancel_button, "connecting");

  adw_view_stack_add_named (ADW_VIEW_STACK (self->view_stack), box, "connecting");

  /* Form */
  page = adw_preferences_page_new ();
  self->form_box = adw_preferences_group_new ();
  adw_preferences_page_add (ADW_PREFERENCES_PAGE (page), ADW_PREFERENCES_GROUP (self->form_box));

  login_button = gtk_button_new_with_label ("Login");
  g_signal_connect_object (login_button, "clicked", G_CALLBACK (on_login_button_clicked), self, 0);
  gtk_widget_set_margin_top (GTK_WIDGET (login_button), 12);
  gtk_widget_set_margin_bottom (GTK_WIDGET (login_button), 12);
  gtk_widget_set_halign (login_button, GTK_ALIGN_CENTER);
  gtk_widget_add_css_class (login_button, "pill");
  adw_view_stack_add_named (ADW_VIEW_STACK (self->bottom_stack), login_button, "form");

  adw_view_stack_add_named (ADW_VIEW_STACK (self->view_stack), page, "form");

  /* Error */
  self->error_status_page = adw_status_page_new ();
  gtk_widget_add_css_class (self->error_status_page, "compact");
  adw_status_page_set_icon_name (ADW_STATUS_PAGE (self->error_status_page), "network-error-symbolic");

  retry_button = gtk_button_new_with_label ("Retry");
  g_signal_connect_object (retry_button, "clicked", G_CALLBACK (on_retry_button_clicked), self, 0);
  gtk_widget_set_margin_top (GTK_WIDGET (retry_button), 12);
  gtk_widget_set_margin_bottom (GTK_WIDGET (retry_button), 12);
  gtk_widget_set_halign (retry_button, GTK_ALIGN_CENTER);
  gtk_widget_add_css_class (retry_button, "pill");
  adw_view_stack_add_named (ADW_VIEW_STACK (self->bottom_stack), retry_button, "failure");

  adw_view_stack_add_named (ADW_VIEW_STACK (self->view_stack), self->error_status_page, "failure");

  adw_application_window_set_content (ADW_APPLICATION_WINDOW (self), self->toolbar_view);

  self->text_view = gtk_text_view_new ();
  self->log = gtk_text_view_get_buffer (GTK_TEXT_VIEW (self->text_view));
  g_signal_connect (self->log, "changed", G_CALLBACK (scroll_log), self->text_view);
}

static void
auth_app_window_class_init (AuthAppWindowClass *class)
{
}

AuthAppWindow *
auth_app_window_new (AuthApp *app)
{
  return g_object_new (AUTH_APP_WINDOW_TYPE, "application", app, NULL);
}

void
auth_app_window_setup_window (AuthAppWindow *self,
                              const char    *vpn_name,
                              GList         *vpnhosts)
{
  GtkWidget *check_button_group = NULL;
  GList *iter;

  /* Set title */
  if (strlen (vpn_name) > 0) {
    g_autofree char *title = g_strdup_printf ("Connect to %s", vpn_name);
    adw_window_title_set_title (ADW_WINDOW_TITLE (self->title_widget), title);
  }

  /* Fill hosts */
  for (iter = vpnhosts; iter && iter->data; iter = g_list_next (iter)) {
    VPNHost *host = iter->data;
    GtkWidget *row = adw_action_row_new ();
    GtkWidget *check_button;

    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), host->hostname);
    adw_action_row_set_subtitle (ADW_ACTION_ROW (row), host->hostaddress);

    check_button = gtk_check_button_new ();
    gtk_widget_set_valign (check_button, GTK_ALIGN_CENTER);
    g_signal_connect (G_OBJECT (check_button), "toggled", G_CALLBACK (on_radio_button_toggled), self);
    adw_action_row_add_prefix (ADW_ACTION_ROW (row), GTK_WIDGET (check_button));
    adw_action_row_set_activatable_widget (ADW_ACTION_ROW (row), check_button);
    gtk_check_button_set_group (GTK_CHECK_BUTTON (check_button), GTK_CHECK_BUTTON (check_button_group));

    if (!check_button_group) {
      check_button_group = check_button;
      gtk_check_button_set_active (GTK_CHECK_BUTTON (check_button), TRUE);
    }

    adw_preferences_group_add (ADW_PREFERENCES_GROUP (self->group), row);
  }
}

void
auth_app_window_set_mode (AuthAppWindow *self,
                          AuthAppMode    mode)
{
  switch (mode) {
  case AUTH_APP_MODE_ENABLE_CONNECT:
    gtk_widget_set_sensitive (self->group, TRUE);
    gtk_widget_set_sensitive (self->connect_button, TRUE);
    break;
  case AUTH_APP_MODE_CONNECTING:
    connect_state (self);
    break;
  default:
    break;
  }
}

void
auth_app_window_log (AuthAppWindow *self,
                     gint           debug_level,
                     const char    *msg)
{
  GtkTextIter iter;

  if (!self || !self->log) {
    g_print ("[%d]: %s", debug_level, msg);
    return;
  }

  gtk_text_buffer_get_end_iter (self->log, &iter);

  switch (debug_level) {
  case 0:
    gtk_text_buffer_insert (self->log, &iter, "[ERROR] ", strlen ("[ERROR] "));
    break;
  case 1:
    gtk_text_buffer_insert (self->log, &iter, "[INFO] ", strlen ("[INFO] "));
    break;
  case 2:
    gtk_text_buffer_insert (self->log, &iter, "[DEBUG] ", strlen ("[DEBUG] "));
    break;
  default:
  case 3:
    gtk_text_buffer_insert (self->log, &iter, "[TRACE] ", strlen ("[TRACE] "));
    break;
  }

  gtk_text_buffer_insert (self->log, &iter, msg, -1);
}

void
auth_app_window_error (AuthAppWindow *self,
                       const char    *msg)
{
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->view_stack), "failure");
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->bottom_stack), "failure");

  adw_window_title_set_subtitle (ADW_WINDOW_TITLE (self->title_widget), "Connection Failure");

  adw_status_page_set_description (ADW_STATUS_PAGE (self->error_status_page), msg);
}

void
auth_app_window_show_form (AuthAppWindow *self)
{
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->view_stack), "form");
  adw_view_stack_set_visible_child_name (ADW_VIEW_STACK (self->bottom_stack), "form");

  adw_window_title_set_subtitle (ADW_WINDOW_TITLE (self->title_widget), "Form");
}

void
auth_app_window_add_form_info (AuthAppWindow *self,
                               gint           debug_level,
                               const char    *msg)
{
  GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

  gtk_box_append (GTK_BOX (box), gtk_image_new_from_icon_name ("info-outline-symbolic"));
  gtk_box_append (GTK_BOX (box), gtk_label_new (msg));
  gtk_widget_set_halign (box, GTK_ALIGN_CENTER);

  adw_preferences_group_add (ADW_PREFERENCES_GROUP (self->form_box), box);
}

GtkWidget *
auth_app_window_get_form_box (AuthAppWindow *self)
{
  return self->form_box;
}
