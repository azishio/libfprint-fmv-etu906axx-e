Name:           libfprint-etu906
Version:        0.1.1
Release:        1%{?dist}
Summary:        Private libfprint ETU906 fork for fprintd
License:        LGPL-2.1-or-later
URL:            https://github.com/azishio/libfprint-fmv-etu906axx-e
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  x86_64
Requires:       fprintd
BuildRequires:  meson >= 0.59.0
BuildRequires:  ninja-build
BuildRequires:  pkgconf-pkg-config
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  glib2-devel >= 2.68
BuildRequires:  libgusb-devel >= 0.2.0
BuildRequires:  openssl-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  systemd-devel
BuildRequires:  appstream
BuildRequires:  cairo-devel
BuildRequires:  gobject-introspection-devel
BuildRequires:  python3-gobject
BuildRequires:  python3-cairo
BuildRequires:  umockdev
BuildRequires:  umockdev-devel

%global _privatelibdir %{_libdir}/libfprint-etu906
%global __provides_exclude_from ^%{_privatelibdir}/.*$

%description
This package installs the upstream libfprint 1.94.9 code with the ETU906
driver in a private library directory and selects it for the existing fprintd
service.  The distribution libfprint library and fingerprint data remain
untouched.

%prep
%setup -q -n %{name}-%{version}

%build
meson setup redhat-linux-build \
    --wrap-mode=nodownload \
    --buildtype=plain \
    --prefix=%{_prefix} \
    --sysconfdir=%{_sysconfdir} \
    --localstatedir=%{_localstatedir} \
    -Dlibdir=%{_privatelibdir} \
    -Ddrivers=egismoc \
    -Dintrospection=true \
    -Ddoc=false \
    -Dgtk-examples=false \
    -Dinstalled-tests=false \
    -Dudev_rules=disabled \
    -Dudev_hwdb=disabled
meson compile -C redhat-linux-build

%install
DESTDIR=%{buildroot} meson install -C redhat-linux-build --no-rebuild
rm -rf %{buildroot}%{_includedir}/libfprint-2
rm -rf %{buildroot}%{_privatelibdir}/pkgconfig
rm -rf %{buildroot}%{_privatelibdir}/girepository-1.0
rm -rf %{buildroot}%{_datadir}/gir-1.0
rm -f %{buildroot}%{_datadir}/metainfo/org.freedesktop.libfprint.metainfo.xml
rmdir --ignore-fail-on-non-empty %{buildroot}%{_includedir} \
    %{buildroot}%{_datadir}/metainfo
install -Dpm 0644 packaging/systemd/fedora/fprintd.service.d/libfprint-etu906.conf \
    %{buildroot}%{_unitdir}/fprintd.service.d/libfprint-etu906.conf

%check
meson test -C redhat-linux-build --print-errorlogs

%posttrans
if [ -x /usr/bin/systemctl ] && /usr/bin/systemctl show --property=Version >/dev/null 2>&1; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
    if /usr/bin/systemctl --quiet is-active fprintd.service >/dev/null 2>&1; then
        /usr/bin/systemctl try-restart fprintd.service >/dev/null 2>&1 || :
    fi
fi

%postun
if [ "${1:-0}" -eq 0 ] && [ -x /usr/bin/systemctl ] && /usr/bin/systemctl show --property=Version >/dev/null 2>&1; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
    if /usr/bin/systemctl --quiet is-active fprintd.service >/dev/null 2>&1; then
        /usr/bin/systemctl try-restart fprintd.service >/dev/null 2>&1 || :
    fi
fi

%files
%license COPYING
%doc README.md NEWS ETU906.md AUTHORS
%{_privatelibdir}/libfprint-2.so.2*
%{_unitdir}/fprintd.service.d/libfprint-etu906.conf
%exclude %{_privatelibdir}/libfprint-2.so

%changelog
* Sat Sep 19 2026 libfprint ETU906 maintainers <noreply@example.invalid> - 0.1.1-1
- Report public certificate metadata on validation failure; retain strict verification.

* Sat Sep 19 2026 libfprint ETU906 maintainers <noreply@example.invalid> - 0.1.0-1
- Initial ETU906 private libfprint package.
