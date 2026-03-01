VERSION := 0.1.0
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X github.com/hamalizer/gpg_go/internal/config.AppVersion=$(VERSION)-$(COMMIT)"

GO      := go
GOFLAGS := -trimpath

PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin
MANDIR  := $(PREFIX)/share/man/man1

.PHONY: all build cli gui install uninstall clean test lint man

all: build

build: cli gui

cli:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/gpg-go ./cmd/gpg-go

gui:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/gpg-go-gui ./cmd/gpg-go-gui

install: build man
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 bin/gpg-go $(DESTDIR)$(BINDIR)/gpg-go
	install -m 755 bin/gpg-go-gui $(DESTDIR)$(BINDIR)/gpg-go-gui
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 man/gpg-go.1 $(DESTDIR)$(MANDIR)/gpg-go.1
	install -m 644 man/gpg-go-gui.1 $(DESTDIR)$(MANDIR)/gpg-go-gui.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/gpg-go
	rm -f $(DESTDIR)$(BINDIR)/gpg-go-gui
	rm -f $(DESTDIR)$(MANDIR)/gpg-go.1
	rm -f $(DESTDIR)$(MANDIR)/gpg-go-gui.1

test:
	$(GO) test -v -race ./...

lint:
	$(GO) vet ./...

clean:
	rm -rf bin/

man:
	@echo "Man pages ready in man/"

# Cross-compilation targets
.PHONY: build-linux build-darwin build-windows build-all

build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/gpg-go-linux-amd64 ./cmd/gpg-go
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/gpg-go-linux-arm64 ./cmd/gpg-go

build-darwin:
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/gpg-go-darwin-amd64 ./cmd/gpg-go
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/gpg-go-darwin-arm64 ./cmd/gpg-go

build-windows:
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/gpg-go-windows-amd64.exe ./cmd/gpg-go

build-all: build-linux build-darwin build-windows
