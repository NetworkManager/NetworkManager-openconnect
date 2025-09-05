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

#define AUTH_APP_TYPE (auth_app_get_type ())

G_DECLARE_FINAL_TYPE (AuthApp, auth_app, AUTH, APP, AdwApplication)

typedef struct {
  char *hostname;
  char *hostaddress;
  char *usergroup;
} VPNHost;

AuthApp *auth_app_new (void);

void auth_app_connect_host (AuthApp *self,
                            char    *hostname);

void auth_app_login (AuthApp *self);
