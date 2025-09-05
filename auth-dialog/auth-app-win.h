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

#pragma once

#include <adwaita.h>
#include "auth-app.h"

#define AUTH_APP_WINDOW_TYPE (auth_app_window_get_type ())
G_DECLARE_FINAL_TYPE (AuthAppWindow, auth_app_window, AUTH, APP_WINDOW, AdwApplicationWindow)

typedef enum {
  AUTH_APP_MODE_ENABLE_CONNECT,
  AUTH_APP_MODE_CONNECTING,
} AuthAppMode;

AuthAppWindow       *auth_app_window_new          (AuthApp    *app);

void   auth_app_window_setup_window (AuthAppWindow *self,
                                     const char    *vpn_name,
                                     GList         *vpnhosts);

void auth_app_window_log (AuthAppWindow *self,
                          gint           debug_level,
                          const char    *msg);

void auth_app_window_error (AuthAppWindow *self,
                            const char    *msg);

void   auth_app_window_set_mode     (AuthAppWindow *self,
                                     AuthAppMode    mode);

void   auth_app_window_show_notification (AuthAppWindow *self,
                                          const char    *text);

void   auth_app_window_show_form (AuthAppWindow *self);

void   auth_app_window_add_form_info (AuthAppWindow *self,
                                      gint           debug_level,
                                      const char    *msg);

GtkWidget *auth_app_window_get_form_box (AuthAppWindow *self);
