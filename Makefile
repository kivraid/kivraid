TAILWIND_VERSION := v4.3.3
SQLC_VERSION     := v1.31.1
AIR_VERSION      := v1.67.4

OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)

ifeq ($(OS),darwin)
  TW_OS := macos
else
  TW_OS := linux
endif
ifeq ($(ARCH),x86_64)
  TW_ARCH := x64
else
  TW_ARCH := arm64
endif

TAILWIND := .tools/tailwindcss-$(TAILWIND_VERSION)
CSS_IN   := internal/web/static/src/app.css
CSS_OUT  := internal/web/static/app.css

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build css css-watch sqlc test vet run dev clean docker screenshots

build: css sqlc
	go build -ldflags "$(LDFLAGS)" -o kivraid ./cmd/kivraid

docker:
	docker build --build-arg VERSION=$(VERSION) -t kivraid:$(VERSION) -t kivraid:latest .

css: $(CSS_OUT)

$(CSS_OUT): $(CSS_IN) $(TAILWIND) $(shell find internal/web/templates -name '*.html' 2>/dev/null)
	$(TAILWIND) -i $(CSS_IN) -o $(CSS_OUT) --minify

css-watch: $(TAILWIND)
	$(TAILWIND) -i $(CSS_IN) -o $(CSS_OUT) --watch

$(TAILWIND):
	mkdir -p .tools
	curl -fsSL -o $(TAILWIND) \
		https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$(TW_OS)-$(TW_ARCH)
	chmod +x $(TAILWIND)

sqlc:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate

# Regenerate the README captures (docs/img/*.png) from a seeded demo
# instance. Requires Google Chrome or Chromium installed locally.
screenshots: build
	cd tools/screenshots && go run . --binary ../../kivraid --out ../../docs/img

test:
	go test ./...

vet:
	go vet ./...

run: build
	./kivraid serve --config kivraid.yaml

# Rebuild and restart on every change to Go, templates, CSS, JS or SQL
# (see .air.toml). Needs a kivraid.yaml, like `make run`.
dev: $(TAILWIND)
	go run github.com/air-verse/air@$(AIR_VERSION)

clean:
	rm -f kivraid $(CSS_OUT)
