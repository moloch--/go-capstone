GO ?= go
CURL ?= curl
GOENV = GOCACHE=$(CURDIR)/.gocache GOPATH=$(CURDIR)/.gopath GOMODCACHE=$(CURDIR)/.gopath/pkg/mod

CAPSTONE_WASM_VERSION ?= v6.0.0-Alpha7
CAPSTONE_WASM_NAME := libcapstone.wasm
CAPSTONE_WASM_DIR := internal/assets
CAPSTONE_WASM_PATH := $(CAPSTONE_WASM_DIR)/$(CAPSTONE_WASM_NAME)
CAPSTONE_WASM_URL := https://github.com/moloch--/capstone/releases/download/$(CAPSTONE_WASM_VERSION)/$(CAPSTONE_WASM_NAME)
CLI_BIN := bin/go-capstone

.PHONY: all wasm deps build cli test fmt clean

all: build

$(CAPSTONE_WASM_PATH):
	mkdir -p $(CAPSTONE_WASM_DIR)
	$(CURL) -L --fail --output $(CAPSTONE_WASM_PATH) $(CAPSTONE_WASM_URL)

wasm: $(CAPSTONE_WASM_PATH)

deps: wasm
	$(GOENV) $(GO) mod download

build: deps
	$(GOENV) $(GO) build .
	$(MAKE) cli

cli: deps
	mkdir -p bin
	$(GOENV) $(GO) build -o $(CLI_BIN) ./cli

test: deps
	$(GOENV) $(GO) test . ./cli

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin
