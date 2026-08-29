GO ?= go
DIST := dist

.PHONY: generate test vet build-linux build-windows build clean

# Regenerate embedded BPF objects (amd64 + arm64 bytecode + Go bindings).
# Runs in a Linux container because clang needs a BPF backend target, which
# Apple's clang lacks. The generated files are committed, so this only needs
# to run when internal/monitors/ebpf/bpf/*.c changes.
generate:
	docker build -q -t elmer-bpfgen -f Dockerfile.bpfgen .
	docker run --rm -v "$(CURDIR):/src" -w /src elmer-bpfgen bash -c '\
	  go generate ./internal/monitors/ebpf/...'

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o $(DIST)/elmer-linux-amd64 ./cmd/elmer
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o $(DIST)/elmer-linux-arm64 ./cmd/elmer

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -o $(DIST)/elmer-windows-amd64.exe ./cmd/elmer
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GO) build -trimpath -o $(DIST)/elmer-windows-arm64.exe ./cmd/elmer

build: build-linux build-windows

clean:
	rm -rf $(DIST)
