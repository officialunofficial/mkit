# Makefile — one-shot install helper for mkit-sign-se.
#
# Common targets:
#
#   make build     # swift build -c release
#   make test      # swift test + tests/e2e.sh
#   make install   # cp the release binary into $(PREFIX)/bin
#   make uninstall # remove the installed binary
#
# Override PREFIX to install somewhere other than /usr/local, e.g.
#   make install PREFIX=$HOME/.local

PREFIX ?= /usr/local
BIN    := mkit-sign-se
BUILD  := .build/release/$(BIN)
DEST   := $(PREFIX)/bin/$(BIN)

.PHONY: all build test unit-test e2e-test install uninstall clean

all: build

build:
	swift build -c release

unit-test:
	swift test

e2e-test:
	./Tests/e2e.sh

test: unit-test e2e-test

install: build
	@mkdir -p $(PREFIX)/bin
	cp $(BUILD) $(DEST)
	@echo "installed $(DEST)"

uninstall:
	@rm -f $(DEST) && echo "removed $(DEST)"

clean:
	swift package clean
	rm -rf .build
