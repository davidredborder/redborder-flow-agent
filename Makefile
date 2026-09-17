BINARY_NAME=redborder-flow-agent
BUILD_DIR=bin

.PHONY: all build build-ndpi clean test test-ndpi run

all: build test

# Pure Go build (no CGO / libndpi dependency required)
build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/rb-flow-agent

# nDPI dynamic build (requires libndpi installed on target machine)
build-ndpi:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -tags ndpi -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/rb-flow-agent

# nDPI fully static build (zero runtime dependencies, runs on any Linux machine without libndpi installed)
build-ndpi-static:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -tags ndpi -ldflags="-s -w -extldflags '-static -lndpi -lm -lpthread -lresolv'" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/rb-flow-agent

test:
	go test -v ./...

test-ndpi:
	CGO_ENABLED=1 go test -tags ndpi -v ./...

lint:
	golangci-lint run ./...

package:
	./package.sh $$(cat VERSION 2>/dev/null || echo "0.1.0") standard

package-ndpi:
	./package.sh $$(cat VERSION 2>/dev/null || echo "0.1.0") ndpi-shared

package-ndpi-static:
	./package.sh $$(cat VERSION 2>/dev/null || echo "0.1.0") ndpi-static

clean:
	rm -rf $(BUILD_DIR) *.deb *.rpm build rpms release-rpms
	$(MAKE) -C packaging/rpm distclean

run: build
	./$(BUILD_DIR)/$(BINARY_NAME) --config configs/config.yaml

# RPM Packaging with Mock
rpm:
	$(MAKE) -C packaging/rpm rpm

rpm-ndpi:
	$(MAKE) -C packaging/rpm rpm WITH_NDPI=1 WITH_NDPI_STATIC=0

rpm-ndpi-static:
	$(MAKE) -C packaging/rpm rpm WITH_NDPI=0 WITH_NDPI_STATIC=1 NDPI_VERSION=6.0

rpm-all:
	@echo "=== Building Standard RPM ==="
	$(MAKE) -C packaging/rpm rpm WITH_NDPI=0 WITH_NDPI_STATIC=0
	@echo "=== Building Shared nDPI RPM ==="
	$(MAKE) -C packaging/rpm rpm WITH_NDPI=1 WITH_NDPI_STATIC=0
	@echo "=== Building Static nDPI 6.0 RPM ==="
	$(MAKE) -C packaging/rpm rpm WITH_NDPI=0 WITH_NDPI_STATIC=1 NDPI_VERSION=6.0

srpm:
	$(MAKE) -C packaging/rpm srpm

rpm-local:
	$(MAKE) -C packaging/rpm rpm-local
