%define debug_package %{nil}
%bcond_with ndpi
%bcond_with ndpi_static
%define base_name redborder-flow-agent
%{!?ndpi_version: %define ndpi_version 6.0}

%if %{with ndpi_static}
Name:    redborder-flow-agent-ndpi-static
%elif %{with ndpi}
Name:    redborder-flow-agent-ndpi
%else
Name:    redborder-flow-agent
%endif

Version: %{__version}
Release: %{__release}%{?dist}

License: AGPL-3.0-or-later
URL: https://github.com/redborder/redborder-flow-agent
Source0: %{base_name}-%{version}.tar.gz
%{?with_ndpi_static:Source1: https://github.com/ntop/nDPI/archive/refs/tags/%{ndpi_version}.tar.gz#/nDPI-%{ndpi_version}.tar.gz}

BuildRequires: golang >= 1.22
BuildRequires: git
BuildRequires: systemd

%if %{with ndpi_static}
BuildRequires: autoconf, automake, libtool, make, gcc, pkgconfig, which
BuildRequires: libpcap-devel, json-c-devel
%define go_tags -tags ndpi
%elif %{with ndpi}
BuildRequires: (libndpi-dev or libndpi-devel)
Requires: libndpi
%define go_tags -tags ndpi
%else
%define go_tags %{nil}
%endif

Summary: High-performance multi-core flow exporter and traffic analysis probe
Group:   Applications/System
Requires: systemd

%description
redborder-flow-agent is a high-performance network probe and flow exporter written in Go.
It captures live traffic across multiple network interfaces using Linux raw AF_PACKET
sockets, performs stateful L4/L7 protocol analysis (open port tracking, TLS SNI,
HTTP Host/URI, DNS domain mapping, optional nDPI deep packet inspection), and exports
enriched flows as NetFlow v5, NetFlow v9, IPFIX (RFC 7011), sFlow v5, or directly as
JSON streams to Apache Kafka.

%prep
%setup -qn %{base_name}-%{version}
%if %{with ndpi_static}
mkdir -p _ndpi_build
tar -xzf %{SOURCE1} -C _ndpi_build --strip-components=1
%endif

%build
export GO111MODULE=on
export GOPROXY=off

%if %{with ndpi_static}
cd _ndpi_build
./autogen.sh
./configure --prefix=%{_builddir}/%{base_name}-%{version}/_ndpi_inst --enable-static --disable-shared --with-only-libndpi || ./configure --prefix=%{_builddir}/%{base_name}-%{version}/_ndpi_inst --enable-static --disable-shared
make -j$(nproc)
make install
# Remove shared libraries so the linker strictly embeds the static libndpi.a
rm -f %{_builddir}/%{base_name}-%{version}/_ndpi_inst/lib/*.so* %{_builddir}/%{base_name}-%{version}/_ndpi_inst/lib64/*.so*
cd ..

export CGO_ENABLED=1
export CGO_CFLAGS="-I%{_builddir}/%{base_name}-%{version}/_ndpi_inst/include"
export CGO_LDFLAGS="-L%{_builddir}/%{base_name}-%{version}/_ndpi_inst/lib -L%{_builddir}/%{base_name}-%{version}/_ndpi_inst/lib64 -lndpi -lm -lpthread -lresolv"
export CGO_LDFLAGS_ALLOW=".*"
%endif

go build -mod=vendor %{go_tags} -ldflags "-s -w -X main.version=%{version}" -o redborder-flow-agent ./cmd/rb-flow-agent

%install
install -d -m 0755 %{buildroot}/usr/bin
install -d -m 0755 %{buildroot}/etc/%{base_name}
install -d -m 0755 %{buildroot}/usr/lib/systemd/system
install -d -m 0750 %{buildroot}/var/log/%{base_name}

install -p -m 0755 redborder-flow-agent %{buildroot}/usr/bin/redborder-flow-agent
install -D -m 0644 configs/config.yaml %{buildroot}/etc/%{base_name}/config.yaml
install -D -m 0644 redborder-flow-agent.service %{buildroot}/usr/lib/systemd/system/%{base_name}.service
install -D -m 0644 redborder-flow-agent@.service %{buildroot}/usr/lib/systemd/system/%{base_name}@.service

%clean
rm -rf %{buildroot}

%post
%systemd_post %{base_name}.service

%preun
%systemd_preun %{base_name}.service

%postun
%systemd_postun_with_restart %{base_name}.service

%files
%defattr(-,root,root,-)
%license LICENSE
/usr/bin/redborder-flow-agent
/usr/lib/systemd/system/%{base_name}.service
/usr/lib/systemd/system/%{base_name}@.service
%dir /etc/%{base_name}
%config(noreplace) /etc/%{base_name}/config.yaml
%dir %attr(0750,root,root) /var/log/%{base_name}

%changelog
* Sat Sep 05 2026 David Vanhoucke <dvanhoucke@redborder.com> - 1.0.0-1
- Initial release of redborder-flow-agent
