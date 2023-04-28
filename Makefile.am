AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = . po

EXTRA_DIST =

libexec_PROGRAMS =

plugin_LTLIBRARIES =

CLEANFILES = *.bak *~

dbusservicedir = $(datadir)/dbus-1/system.d
dbusservice_DATA = nm-openconnect-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-openconnect-service.name

###############################################################################

src_cppflags = \
	-I"$(top_srcdir)"/shared \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(NULL)

libexec_PROGRAMS += src/nm-openconnect-service

src_nm_openconnect_service_CPPFLAGS = \
	$(src_cppflags) \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DNM_OPENCONNECT_LOCALEDIR=\"$(datadir)/locale\" \
	$(NULL)

src_nm_openconnect_service_SOURCES = \
	$(top_srcdir)/shared/nm-utils/nm-shared-utils.c \
	$(top_srcdir)/shared/nm-utils/nm-shared-utils.h \
	src/nm-openconnect-service.c \
	src/nm-openconnect-service.h \
	$(NULL)

src_nm_openconnect_service_LDADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

libexec_PROGRAMS += src/nm-openconnect-service-openconnect-helper

src_nm_openconnect_service_openconnect_helper_CPPFLAGS = \
	$(src_cppflags) \
	$(NULL)

src_nm_openconnect_service_openconnect_helper_SOURCES = \
	$(top_srcdir)/shared/nm-utils/nm-shared-utils.c \
	$(top_srcdir)/shared/nm-utils/nm-shared-utils.h \
	src/nm-openconnect-service-openconnect-helper.c

src_nm_openconnect_service_openconnect_helper_LDADD = \
	$(GTHREAD_LIBS) \
	$(LIBNM_LIBS)

###############################################################################

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-openconnect.la
if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-openconnect-editor.la
endif
if WITH_GTK4
plugin_LTLIBRARIES += properties/libnm-gtk4-vpn-plugin-openconnect-editor.la
endif

properties/resources.h: properties/gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-header --internal

properties/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/properties --generate-dependencies $(srcdir)/properties/gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-source --internal

gtk4/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --generate-dependencies $(srcdir)/properties/gresource.xml |sed "s,^,$(builddir)/gtk4/,")
	@mkdir -p $(builddir)/gtk4
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/gtk4 --sourcedir=$(builddir)/gtk4 --generate-source --internal

gtk4/%.ui: properties/%.ui
	@mkdir -p $(builddir)/gtk4
	gtk4-builder-tool simplify --3to4 $< |grep -v can-default >$@

CLEANFILES += \
	gtk4/nm-openconnect-dialog.ui \
	gtk4/resources.c \
	properties/resources.c \
	properties/resources.h

EXTRA_DIST += \
	properties/gresource.xml

# Include a prebuilt file in tarball, to avoid hitting
# https://gitlab.gnome.org/GNOME/gtk/-/merge_requests/4415
EXTRA_DIST += \
	gtk4/nm-openconnect-dialog.ui

plugin_sources = \
	properties/nm-openconnect-editor-plugin.c \
	properties/nm-openconnect-editor-plugin.h \
	$(NULL)

editor_sources = \
	properties/auth-helpers.c \
	properties/auth-helpers.h \
	properties/nm-openconnect-editor.c \
	properties/nm-openconnect-editor.h
	$(NULL)

properties_cppflags = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(OPENCONNECT_CFLAGS) \
	-I$(top_srcdir)/shared \
	-DLOCALEDIR=\"$(datadir)/locale\"

###############################################################################

properties_libnm_vpn_plugin_openconnect_la_SOURCES = \
	$(top_srcdir)/shared/nm-utils/nm-vpn-editor-plugin-call.h \
	$(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.c \
	$(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.h \
	$(plugin_sources)

properties_libnm_vpn_plugin_openconnect_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	$(properties_cppflags) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_openconnect_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(LIBNM_LIBS) \
	$(OPENCONNECT_LIBS) \
	$(DL_LIBS) \
	$(NULL)

properties_libnm_vpn_plugin_openconnect_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-openconnect.ver"

###############################################################################

properties_libnm_vpn_plugin_openconnect_editor_la_SOURCES = \
	$(editor_sources)

nodist_properties_libnm_vpn_plugin_openconnect_editor_la_SOURCES = \
	properties/resources.h \
	properties/resources.c

properties_libnm_vpn_plugin_openconnect_editor_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_libnm_vpn_plugin_openconnect_editor_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(OPENCONNECT_LIBS)

properties_libnm_vpn_plugin_openconnect_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-openconnect-editor.ver"

###############################################################################

properties_libnm_gtk4_vpn_plugin_openconnect_editor_la_SOURCES = \
	$(editor_sources)

nodist_properties_libnm_gtk4_vpn_plugin_openconnect_editor_la_SOURCES = \
	properties/resources.h \
	gtk4/resources.c

properties_libnm_gtk4_vpn_plugin_openconnect_editor_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS)

properties_libnm_gtk4_vpn_plugin_openconnect_editor_la_LIBADD = \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_GTK4_LIBS) \
	$(OPENCONNECT_LIBS)

properties_libnm_gtk4_vpn_plugin_openconnect_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-openconnect-editor.ver"

###############################################################################

EXTRA_DIST += \
	properties/libnm-vpn-plugin-openconnect.ver \
	properties/libnm-vpn-plugin-openconnect-editor.ver \
	properties/nm-openconnect-dialog.ui

###############################################################################

if WITH_GNOME
if WITH_AUTHDLG
libexec_PROGRAMS += auth-dialog/nm-openconnect-auth-dialog
endif
endif

auth_dialog_nm_openconnect_auth_dialog_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(WEBKIT_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GCR_CFLAGS) \
	$(OPENCONNECT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
	-I"$(top_srcdir)/shared" \
	$(NULL)

auth_dialog_nm_openconnect_auth_dialog_SOURCES = \
	auth-dialog/main.c \
	$(NULL)

auth_dialog_nm_openconnect_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(WEBKIT_LIBS) \
	$(GCR_LIBS) \
	$(LIBNM_LIBS) \
	$(OPENCONNECT_LIBS) \
	$(LIBXML_LIBS) \
	$(LIBSECRET_LIBS)


appdatadir = $(datadir)/metainfo
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_in_files:.xml.in=.xml)
endif
appdata_in_files = appdata/network-manager-openconnect.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-openconnect-service.name: $(srcdir)/nm-openconnect-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $< >$@

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=yes \
	--with-gtk4

CLEANFILES +=				\
	$(nmvpnservice_DATA)		\
	$(desktop_DATA)			\
	$(appdata_files)

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST += \
	nm-openconnect-service.name.in \
	$(dbusservice_DATA) \
	$(desktop_in_files) \
	$(icon_DATA) \
	$(appdata_in_files) \
	$(appdata_files) \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	openconnect-strings.txt \
	\
	shared/README \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-utils/nm-vpn-editor-plugin-call.h \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-default.h \
	shared/nm-service-defines.h \
	$(NULL)
