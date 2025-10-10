%if 0%{?fedora} < 36 && 0%{?rhel} < 10
%bcond_with gtk4
%else
%bcond_without gtk4
%endif

%global nm_version          1.2.0
%global gtk3_version        3.4.0
%global openconnect_version 7.00

Summary:   NetworkManager VPN plugin for openconnect
Name:      network-manager-openconnect
Version:   1.2.9
Release:   1%{?dist}
License:   GPL-2.0-or-later and LGPL-2.0-only
Group:     Productivity/Networking/Other
URL:       http://www.gnome.org/projects/NetworkManager/
Source:    https://download.gnome.org/sources/NetworkManager-openconnect/1.2/network-manager-openconnect-%{version}.tar.gz

BuildRequires: make
BuildRequires: gcc
BuildRequires: pkgconfig(gtk+-3.0) >= %{gtk3_version}
BuildRequires: pkgconfig(libnm) >= %{nm_version}
BuildRequires: pkgconfig(libnma) >= %{nm_version}
BuildRequires: pkgconfig(libsecret-1)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: intltool gettext libtool
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(openconnect) >= %{openconnect_version}
BuildRequires: pkgconfig(gcr-3) >= 3.4
BuildRequires: (pkgconfig(webkit2gtk-4.1) or pkgconfig(webkit2gtk-4.0))
%if %with gtk4
BuildRequires: pkgconfig(gtk4) >= 4.0
BuildRequires: pkgconfig(libnma-gtk4) >= 1.8.33
%endif

Requires: NetworkManager   >= %{nm_version}
Requires: openconnect      >= %{openconnect_version}
Requires: dbus-common
Obsoletes: NetworkManager-openconnect < 1.2.3-0

Requires(pre): %{_sbindir}/useradd
Requires(pre): %{_sbindir}/groupadd

# Name used in Fedora
Provides: NetworkManager-openconnect = %{version}

%global __provides_exclude ^libnm-.*\\.so

%description
This package contains software for integrating the openconnect VPN software
with NetworkManager and the GNOME desktop

%package gnome
Summary: NetworkManager VPN plugin for OpenConnect - GNOME files

Requires: %{name}%{?_isa} = %{version}-%{release}
Provides: NetworkManager-openconnect-gnome = %{version}

%description gnome
This package contains software for integrating VPN capabilities with
the OpenConnect client with NetworkManager (GNOME files).

# Keep the package name the same as Fedora, but allow non-camel-case tarball/directory
%prep
%setup -q
if [ ! -x configure ]; then
    NOCONFIGURE=x ./autogen.sh
fi

%build
%configure \
        --enable-more-warnings=yes \
        --disable-static \
        --without-libnm-glib \
%if %with gtk4
        --with-gtk4 \
%endif
        --with-dist-version=%{version}-%{release}
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

rm -f %{buildroot}%{_libdir}/NetworkManager/lib*.la
rm -rf %{buildroot}%{_datadir}/locale

%pre
%{_sbindir}/groupadd -r nm-openconnect &>/dev/null || :
%{_sbindir}/useradd  -r -s /sbin/nologin -d / -M \
                     -c 'NetworkManager user for OpenConnect' \
                     -g nm-openconnect nm-openconnect &>/dev/null || :

%if 0%{?rhel} && 0%{?rhel} <= 7
%post
/usr/bin/update-desktop-database &> /dev/null || :
touch --no-create %{_datadir}/icons/hicolor
if [ -x %{_bindir}/gtk-update-icon-cache ]; then
      %{_bindir}/gtk-update-icon-cache --quiet %{_datadir}/icons/hicolor || :
fi

%postun
/usr/bin/update-desktop-database &> /dev/null || :
touch --no-create %{_datadir}/icons/hicolor
if [ -x %{_bindir}/gtk-update-icon-cache ]; then
      %{_bindir}/gtk-update-icon-cache --quiet %{_datadir}/icons/hicolor || :
fi
%endif

%files
%{_libdir}/NetworkManager/libnm-vpn-plugin-openconnect.so
%{_datadir}/dbus-1/system.d/nm-openconnect-service.conf
%{_prefix}/lib/NetworkManager/VPN
%{_libexecdir}/nm-openconnect-service
%{_libexecdir}/nm-openconnect-service-openconnect-helper
%doc AUTHORS ChangeLog NEWS
%license COPYING

%files gnome
%{_libexecdir}/nm-openconnect-auth-dialog
%{_libdir}/NetworkManager/libnm-vpn-plugin-openconnect-editor.so
%{_datadir}/metainfo/network-manager-openconnect.metainfo.xml

%if %with gtk4
%{_libdir}/NetworkManager/libnm-gtk4-vpn-plugin-openconnect-editor.so
%endif


%changelog
* Fri Mar 11 2022 Adam Williamson <awilliam@redhat.com> - 1.2.8-1
- Update to 1.2.8 release

* Wed Jan 19 2022 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.6-9
- Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild

* Wed Jul 21 2021 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.6-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild

* Mon Feb 15 2021 Lubomir Rintel <lkundrak@v3.sk> - 1.2.6-7
- Move dbus service file into /usr/share/dbus-1

* Mon Jan 25 2021 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.6-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Mon Jul 27 2020 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.6-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Thu Mar  5 2020 Dave Love <loveshack@fedoraproject.org> - 1.2.6-4
- Fix libnm_glib conditionals to build for el7

* Tue Jan 28 2020 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.6-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Wed Sep 25 2019 David Woodhouse <dwmw2@infradead.org> - 1.2.6-2
- Fix IPv6 nameserver support (#1753422)

* Wed Aug 07 2019 David Woodhouse <dwmw2@infradead.org> - 1.2.6-1
- Update to 1.2.6
- Support all protocols that OpenConnect does (#1714121)
- Persistent support (#1701157)

* Wed Jul 24 2019 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.4-12
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Thu Jan 31 2019 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.4-11
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Thu Jul 12 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.4-10
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.4-9
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Mon Jan 22 2018 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 1.2.4-8
- Remove obsolete scriptlets

* Thu Nov 30 2017 Lubomir Rintel <lkundrak@v3.sk> - 1.2.4-7
- Drop libnm-glib for Fedora 28

* Wed Aug 02 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.4-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.4-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.4-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Thu Dec 15 2016 Thomas Haller <thaller@redhat.com> - 1.2.4-3
- Belatedly obsolete main package for gnome package split (rh#1398425)

* Thu Dec 15 2016 David Woodhouse <dwmw2@infradead.org> - 1.2.4-2
- Improve certificate acceptance dialog and allow it to be disabled (bgo#770800)

* Mon Dec 05 2016 Lubomir Rintel <lkundrak@v3.sk> - 1.2.4-1
- Update to 1.2.4
- Fix IPv6-only operation
- Automatically submit forms with remembered values

* Fri Sep 23 2016 David Woodhouse <dwmw2@infradead.org> - 1.2.3-0.20160923gitac5cdf
- Update to a newer 1.2.3 prerelease
- Allow protocol selection through UI
- Add Yubikey OATH support

* Wed Jul 06 2016 David Woodhouse <dwmw2@infradead.org> - 1.2.3-0.20160606git5009f9
- Update to 1.2.3 prerelease
- Split GNOME support into separate package (#1088672)
- Add Juniper support (#1340495)

* Wed May 11 2016 Lubomir Rintel <lkundrak@v3.sk> - 1.2.2-1
- Update to 1.2.2 release

* Wed Apr 20 2016 Lubomir Rintel <lkundrak@v3.sk> - 1.2.0-1
- Update to 1.2.0 release

* Tue Apr  5 2016 Lubomir Rintel <lkundrak@v3.sk> - 1:1.2.0-0.3.rc1
- Update to NetworkManager-openconnect 1.2-rc1

* Tue Mar 29 2016 Lubomir Rintel <lkundrak@v3.sk> - 1:1.2.0-0.3.beta3
- Update to NetworkManager-openconnect 1.2-beta3

* Tue Mar  1 2016 Lubomir Rintel <lkundrak@v3.sk> - 1:1.2.0-0.3.beta2
- Update to NetworkManager-openconnect 1.2-beta2

* Wed Feb 03 2016 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.0-0.3.beta1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Tue Jan 19 2016 Lubomir Rintel <lkundrak@v3.sk> - 1:1.2.0-0.2.beta1
- Update to NetworkManager-openconnect 1.2-beta1

* Fri Oct 23 2015 Lubomir Rintel <lkundrak@v3.sk> - 1.2.0-0.1.20151023gitbf9b033
- Update to 1.2 git snapshot with multiple vpn connections support

* Mon Aug 31 2015 Lubomir Rintel <lkundrak@v3.sk> - 1.2.0-0.1.20150831git8e20043
- Update to 1.2 git snapshot with libnm-based properties plugin

* Tue Jun 16 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.0.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Tue May 5 2015 Lubomir Rintel <lkundrak@v3.sk> - 1.0.2-1
- Update to 1.0.2 release

* Mon Dec 22 2014 Dan Williams <dcbw@redhat.com> - 1.0.0-1
- Update to 1.0

* Tue Dec 02 2014 David Woodhouse <David.Woodhouse@intel.com> - 0.9.8.6-2
- Actually remember to add the patch

* Tue Dec 02 2014 David Woodhouse <David.Woodhouse@intel.com> - 0.9.8.6-1
- Update to 0.9.8.6 + later patches for libopenconnect5 support

* Fri Aug 15 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.8.4-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Fri Jun 06 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.8.4-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Fri Mar 07 2014 Adam Williamson <awilliam@redhat.com> - 0.9.8.4-2
- rebuilt for new openconnect

* Wed Mar 05 2014 David Woodouse <David.Woodhouse@intel.com> - 0.9.8.4-1
- Update to 0.9.8.4 + later patches for libopenconnect3 support

* Fri Aug 02 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.8.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Mon Jun 03 2013 David Woodouse <David.Woodhouse@intel.com> - 0.9.8.0-1
- Update to 0.9.8.0

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.7.0-2.git20120918
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Tue Sep 18 2012 Dan Winship <danw@redhat.com> - 0.9.7.0-1.git20120918
- Update to new snapshot to get IPv6 support (#829010)

* Wed Jul 18 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.4.0-8.git20120612
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Sun Jun 17 2012 David Woodhouse <David.Woodhouse@intel.com> - 0.9.4-7
- Add missing patch to git

* Sat Jun 16 2012 David Woodhouse <David.Woodhouse@intel.com> - 0.9.4-6
- Add gnome-keyring support for saving passwords (bgo #638861)

* Wed Jun 13 2012 David Woodhouse <David.Woodhouse@intel.com> - 0.9.4-5
- Update to work with new libopenconnect

* Wed Jun 13 2012 Ville Skyttä <ville.skytta@iki.fi> - 0.9.4.0-4
- Remove unnecessary ldconfig calls from scriptlets (#737330).

* Fri May 25 2012 David Woodhouse <David.Woodhouse@intel.com> - 0.9.4-3
- Fix cancel-after-failure-causes-next-attempt-to-immediately-abort bug.

* Thu May 17 2012 David Woodhouse <David.Woodhouse@intel.com> - 0.9.4-2
- BR an appropriate version of openconnect, to ensure cancellation support.

* Thu May 17 2012 David Woodhouse <David.Woodhouse@intel.com> - 0.9.4-1
- Update to 0.9.4.0 and some later patches:
- Properly cancel connect requests instead of waiting (perhaps forever).
- Wait for QUIT before exiting (bgo #674991).
- Create persistent tundev on demand for each connection.
- Check for success when dropping privileges.

* Mon Mar 19 2012 Dan Williams <dcbw@redhat.com> - 0.9.3.997-1
- Update to 0.9.3.997 (0.9.4-rc1)

* Fri Mar  2 2012 Dan Williams <dcbw@redhat.com> - 0.9.3.995-1
- Update to 0.9.3.995 (0.9.4-beta1)

* Sun Feb 26 2012 Peter Robinson <pbrobinson@fedoraproject.org> - 0.9.2.0-3
- Update for unannounced gnome-keyring devel changes

* Thu Jan 12 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.2.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Nov 10 2011 Adam Williamson <awilliam@redhat.com> - 0.9.2.0-1
- bump to 0.9.2.0
- pull david's patches properly from upstream

* Tue Nov 08 2011 David Woodhouse <David.Woodhouse@intel.com> - 0.9.0-5
- Deal with stupid premature glib API breakage.

* Tue Nov 08 2011 David Woodhouse <David.Woodhouse@intel.com> - 0.9.0-4
- Fix build failure due to including <glib/gtypes.h> directly.

* Tue Nov 08 2011 David Woodhouse <David.Woodhouse@intel.com> - 0.9.0-3
- Look for openconnect in /usr/sbin too

* Fri Aug 26 2011 Dan Williams <dcbw@redhat.com> - 0.9.0-1
- Update to 0.9.0
- ui: translation fixes

* Thu Aug 25 2011 David Woodhouse <David.Woodhouse@intel.com> - 0.8.999-3
- Rebuild again to really use shared library this time (#733431)

* Thu Jun 30 2011 David Woodhouse <David.Woodhouse@intel.com> - 0.8.999-2
- Link against shared libopenconnect.so instead of static library

* Tue May 03 2011 Dan Williams <dcbw@redhat.com> - 0.8.999-1
- Update to 0.8.999 (0.9-rc2)
- Updated translations
- Port to GTK+ 3.0

* Tue Apr 19 2011 David Woodhouse <dwmw2@infradead.org> - 0.8.1-9
- Fix handling of manually accepted certs and double-free of form answers

* Mon Apr 18 2011 David Woodhouse <dwmw2@infradead.org> - 0.8.1-8
- Update to *working* git snapshot

* Sat Mar 26 2011 Christopher Aillon <caillon@redhat.com> - 0.8.1-7
- Update to git snapshot

* Sat Mar 26 2011 Christopher Aillon <caillon@redhat.com> - 0.8.1-6
- Rebuild against NetworkManager 0.9

* Wed Mar 09 2011 David Woodhouse <dwmw2@infradead.org> 1:0.8.1-5
- BuildRequire openconnect-devel-static, although we don't. (rh #689043)

* Wed Mar 09 2011 David Woodhouse <dwmw2@infradead.org> 1:0.8.1-4
- BuildRequire libxml2-devel

* Wed Mar 09 2011 David Woodhouse <dwmw2@infradead.org> 1:0.8.1-3
- Rebuild with auth-dialog, no longer in openconnect package

* Mon Feb 07 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.8.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Jul 27 2010 Dan Williams <dcbw@redhat.com> - 1:0.8.1-1
- Update to 0.8.1 release
- Updated translations

* Sun Apr 11 2010 Dan Williams <dcbw@redhat.com> - 1:0.8.0-1
- Add support for proxy and "key from fsid" settings
- Add flag to enable Cisco Secure Desktop checker program
- Updated translations

* Mon Dec 14 2009 Dan Williams <dcbw@redhat.com> - 1:0.7.997-1
- Correctly handle PEM certificates without an ending newline (rh #507315)

* Mon Oct  5 2009 Dan Williams <dcbw@redhat.com> - 1:0.7.996-4.git20090921
- Rebuild for updated NetworkManager

* Mon Sep 21 2009 Dan Williams <dcbw@redhat.com> - 1:0.7.996-2
- Rebuild for updated NetworkManager

* Sun Aug 30 2009 Dan Williams <dcbw@redhat.com> - 0.7.996-1
- Rebuild for updated NetworkManager
- Drop upstreamed patches

* Mon Jul 27 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.7.0.99-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.7.0.99-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Mon Jun  1 2009 David Woodhouse <David.Woodhouse@intel.com> 1:0.7.0.99-5
- Accept 'pem_passphrase_fsid' key in gconf

* Wed May 27 2009 David Woodhouse <David.Woodhouse@intel.com> 1:0.7.0.99-4
- Handle 'gwcert' as a VPN secret, because openconnect might not be able
  to read the user's cacert file when it runs as an unprivileged user.

* Sat May  9 2009 David Woodhouse <David.Woodhouse@intel.com> 1:0.7.0.99-3
- Accept 'form:*' keys in gconf
- Allow setting of MTU option in gconf

* Wed Apr  1 2009 David Woodhouse <David.Woodhouse@intel.com> 1:0.7.0.99-2
- Update translations from SVN
- Accept 'lasthost' and 'autoconnect' keys in gconf

* Thu Mar  5 2009 Dan Williams <dcbw@redhat.com> 1:0.7.0.99-1
- Update to 0.7.1rc3

* Mon Feb 23 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.7.0.97-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Thu Feb 19 2009 Dan Williams <dcbw@redhat.com> 0.7.0.97-1
- Update to 0.7.1rc1

* Mon Jan  5 2009 David Woodhouse <David.woodhouse@intel.com> 0.7.0-4.svn14
- Rebuild for updated NetworkManager
- Update translations from GNOME SVN

* Sun Dec 21 2008 David Woodhouse <David.Woodhouse@intel.com> 0.7.0-3.svn9
- Update from GNOME SVN (translations, review feedback merged)

* Wed Dec 17 2008 David Woodhouse <David.Woodhouse@intel.com> 0.7.0-2.svn3
- Review feedback

* Tue Dec 16 2008 David Woodhouse <David.Woodhouse@intel.com> 0.7.0-1.svn3
- Change version numbering to match NetworkManager
