#!/bin/bash
set -e

VERSION="${1:-$(cat VERSION 2>/dev/null || echo "0.1.0")}"
VERSION=$(echo "$VERSION" | tr -d "\r\n" | tr -d "v" | tr '-' '.')
FLAVOR="${2:-standard}" # standard, ndpi-shared, ndpi-static

BASE_NAME="redborder-flow-agent"
ARCH="amd64"
RPM_ARCH="x86_64"

# Set up build tags, binary names, and package names based on flavor
case "$FLAVOR" in
    standard)
        NAME="redborder-flow-agent"
        GO_TAGS=""
        GO_CGO=0
        GO_EXTLDFLAGS=""
        DEB_DEPENDS="systemd"
        RPM_REQUIRES="systemd"
        DESC_SUFFIX="(Pure Go standard build, no external nDPI dependency)"
        ;;
    ndpi-shared)
        NAME="redborder-flow-agent-ndpi"
        GO_TAGS="-tags ndpi"
        GO_CGO=1
        GO_EXTLDFLAGS=""
        DEB_DEPENDS="systemd, libndpi"
        RPM_REQUIRES="systemd, libndpi"
        DESC_SUFFIX="(Dynamic shared nDPI build, requires libndpi)"
        ;;
    ndpi-static)
        NAME="redborder-flow-agent-ndpi-static"
        GO_TAGS="-tags ndpi"
        GO_CGO=1
        GO_EXTLDFLAGS="-extldflags '-static -lndpi -lm -lpthread -lresolv'"
        DEB_DEPENDS="systemd"
        RPM_REQUIRES="systemd"
        DESC_SUFFIX="(Static embedded nDPI build, standalone runtime)"
        ;;
    *)
        echo "Error: Unknown flavor '$FLAVOR'. Valid flavors: standard, ndpi-shared, ndpi-static"
        exit 1
        ;;
esac

echo "========================================================"
echo " Packaging: $NAME (Version: $VERSION, Flavor: $FLAVOR)"
echo "========================================================"

# Clean previous build directories
rm -rf build
mkdir -p build bin

echo "=== Building $NAME binary ==="
if [ "$GO_CGO" -eq 1 ] && [ -n "$GO_EXTLDFLAGS" ]; then
    CGO_ENABLED=1 go build $GO_TAGS -ldflags="-s -w -X main.version=${VERSION} $GO_EXTLDFLAGS" -o build/$BASE_NAME ./cmd/rb-flow-agent
elif [ "$GO_CGO" -eq 1 ]; then
    CGO_ENABLED=1 go build $GO_TAGS -ldflags="-s -w -X main.version=${VERSION}" -o build/$BASE_NAME ./cmd/rb-flow-agent
else
    CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o build/$BASE_NAME ./cmd/rb-flow-agent
fi

# Save standalone binary in bin/ for direct release asset upload
cp build/$BASE_NAME "bin/$NAME"

# ---------------- RPM Package ----------------
if ! command -v rpmbuild &> /dev/null; then
    echo "rpmbuild not found, skipping RPM package generation."
    rm -rf build
    exit 0
fi

echo "=== Building RPM package ==="
RPM_DIR="$(pwd)/build/rpm"
mkdir -p "$RPM_DIR"/{SOURCES,SPECS,BUILD,RPMS,SRPMS,BUILDROOT}

# Install pre-built binary directly into buildroot
BR="$RPM_DIR/BUILDROOT/${NAME}-${VERSION}-1.x86_64"
mkdir -p "$BR/usr/bin"
mkdir -p "$BR/etc/redborder-flow-agent"
mkdir -p "$BR/usr/lib/systemd/system"

install -m 0755 build/$BASE_NAME "$BR/usr/bin/$BASE_NAME"
install -m 0644 configs/config.yaml "$BR/etc/redborder-flow-agent/config.yaml.default"
install -m 0644 configs/ja4_signatures.yaml "$BR/etc/redborder-flow-agent/ja4_signatures.yaml"
install -m 0644 packaging/systemd/redborder-flow-agent.service "$BR/usr/lib/systemd/system/redborder-flow-agent.service"
install -m 0644 packaging/systemd/redborder-flow-agent@.service "$BR/usr/lib/systemd/system/redborder-flow-agent@.service"

cat <<SPEC > "$RPM_DIR/SPECS/${NAME}.spec"
Name:           ${NAME}
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        High-Performance Network Flow Exporter & Probe ${DESC_SUFFIX}
License:        AGPLv3
URL:            https://github.com/redborder/redborder-flow-agent
Requires:       ${RPM_REQUIRES}

%define _build_id_links none
%define __strip /bin/true
%define debug_package %{nil}

%description
redborder-flow-agent captures network traffic across multiple interfaces,
performs L4/L7 stateful inspection (open port tracking, TLS SNI/version,
HTTP Host/URI/status, DNS snooping, JA4 TLS client fingerprinting, nDPI),
and exports enriched flows as NetFlow v5/v9, IPFIX, sFlow v5, and JSON streams.

%files
/usr/bin/$BASE_NAME
%config(noreplace) /etc/redborder-flow-agent/config.yaml.default
%config(noreplace) /etc/redborder-flow-agent/ja4_signatures.yaml
/usr/lib/systemd/system/redborder-flow-agent.service
/usr/lib/systemd/system/redborder-flow-agent@.service

%changelog
* Mon Sep 07 2026 redBorder Support <support@redborder.com> - ${VERSION}-1
- Release of ${NAME}
SPEC

rpmbuild --define "_topdir $RPM_DIR" --define "__os_install_post %{nil}" --define "debug_package %{nil}" -bb --buildroot "$BR" "$RPM_DIR/SPECS/${NAME}.spec"

cp "$RPM_DIR/RPMS/x86_64/${NAME}-${VERSION}-1."*.rpm ./${NAME}-${VERSION}-1.x86_64.rpm 2>/dev/null || cp "$RPM_DIR/RPMS/x86_64/"*.rpm ./
echo "RPM package created: ${NAME}-${VERSION}-1.x86_64.rpm"

rm -rf build
