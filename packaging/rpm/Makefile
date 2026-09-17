PACKAGE_NAME?=	redborder-flow-agent

VERSION?=	$(shell cat ../../VERSION 2>/dev/null || git describe --abbrev=6 --tags HEAD --always | sed 's/-/_/g')

BUILD_NUMBER?= 1

MOCK_CONFIG?=default

RESULT_DIR?=pkgs

WITH_NDPI?= 0
WITH_NDPI_STATIC?= 0
NDPI_VERSION?= 6.0

ifeq ($(WITH_NDPI_STATIC),1)
MOCK_NDPI_OPTS= --with ndpi_static --define "ndpi_version $(NDPI_VERSION)"
RPMBUILD_NDPI_OPTS= --with ndpi_static --define "ndpi_version $(NDPI_VERSION)"
else ifeq ($(WITH_NDPI),1)
MOCK_NDPI_OPTS= --with ndpi
RPMBUILD_NDPI_OPTS= --with ndpi
else
MOCK_NDPI_OPTS=
RPMBUILD_NDPI_OPTS=
endif

SOURCES:
	mkdir -p SOURCES

download_ndpi: SOURCES
ifeq ($(WITH_NDPI_STATIC),1)
	@if [ ! -f SOURCES/nDPI-$(NDPI_VERSION).tar.gz ]; then \
		echo "Downloading nDPI $(NDPI_VERSION) tarball..."; \
		curl -fsSL -o SOURCES/nDPI-$(NDPI_VERSION).tar.gz "https://github.com/ntop/nDPI/archive/refs/tags/$(NDPI_VERSION).tar.gz"; \
	fi
endif

archive: SOURCES download_ndpi
	cd ../../ && \
	tar --exclude-vcs \
		--exclude='./bin' \
		--exclude='./.cache' \
		--exclude='./packaging/rpm/SOURCES' \
		--exclude='./packaging/rpm/pkgs' \
		--exclude='*.json' \
		--exclude='*.pcap' \
		--exclude='*.rpm' \
		--transform 's/^\./$(PACKAGE_NAME)-$(VERSION)/' \
		-czf packaging/rpm/SOURCES/$(PACKAGE_NAME)-$(VERSION).tar.gz .

build_prepare: archive
	mkdir -p $(RESULT_DIR)
	rm -f $(RESULT_DIR)/$(PACKAGE_NAME)*.rpm

srpm: build_prepare
	/usr/bin/mock \
		-r $(MOCK_CONFIG) \
		$(MOCK_NDPI_OPTS) \
		--define "__version $(VERSION)" \
		--define "__release $(BUILD_NUMBER)" \
		--resultdir=$(RESULT_DIR) \
		--buildsrpm \
		--spec=redborder-flow-agent.spec \
		--sources=SOURCES
	@echo "======= Source RPM now available in $(RESULT_DIR) ======="

rpm: srpm
	/usr/bin/mock \
		-r $(MOCK_CONFIG) \
		$(MOCK_NDPI_OPTS) \
		--define "__version $(VERSION)" \
		--define "__release $(BUILD_NUMBER)" \
		--resultdir=$(RESULT_DIR) \
		--rebuild $(RESULT_DIR)/$(PACKAGE_NAME)*.src.rpm
	@echo "======= Binary RPMs now available in $(RESULT_DIR) ======="

rpm-local: build_prepare
	rpmbuild -ba \
		$(RPMBUILD_NDPI_OPTS) \
		--define "_topdir $(shell pwd)" \
		--define "_sourcedir $(shell pwd)/SOURCES" \
		--define "_rpmdir $(RESULT_DIR)" \
		--define "_srcrpmdir $(RESULT_DIR)" \
		--define "__version $(VERSION)" \
		--define "__release $(BUILD_NUMBER)" \
		redborder-flow-agent.spec
	@echo "======= Binary RPMs now available in $(RESULT_DIR) ======="

clean:
	rm -rf SOURCES pkgs BUILD BUILDROOT SRPMS RPMS *.rpm *.tar.gz
	rm -f *.log build.log root.log state.log available_pkgs installed_pkgs

distclean: clean
	rm -rf pkgs/*
