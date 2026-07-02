TAILWIND_VERSION := v4.1.11
SQLC_VERSION     := v1.30.0

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

.PHONY: build css css-watch sqlc test vet run clean

build: css sqlc
	go build -o kivraid ./cmd/kivraid

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

test:
	go test ./...

vet:
	go vet ./...

run: build
	./kivraid serve --config kivraid.yaml

clean:
	rm -f kivraid $(CSS_OUT)
