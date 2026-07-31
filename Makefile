# reaper - Makefile
#
# Common workflows:
#   make              typecheck + compile TypeScript to dist/
#   make help         list every available target with a short description
#   make sandbox      build the hardened docker analysis image
#   make demo         deobfuscate the bundled EtherHiding fixture end-to-end
#   make ci           the checks CI should run (typecheck + verify-examples)

# ── Config (override on the command line, e.g. `make IMAGE_TAG=v2 sandbox`) ──
IMAGE_NAME ?= reaper-sandbox
IMAGE_TAG  ?= latest
NPM        ?= npm
NODE       ?= node
NPX        ?= npx
DOCKER     ?= docker

# Where 'demo' drops its output. Kept inside the workspace (gitignored) so
# everything related to a run lives in one place.
BUILD_DIR  := build

# Marker file so `build` only re-installs deps when package.json moves.
NODE_STAMP := node_modules/.install-stamp

.DEFAULT_GOAL := all
.PHONY: all help install build typecheck test clean distclean \
        sandbox sandbox-rebuild sandbox-clean \
        demo verify-examples ci fmt-check

## ── User-facing targets ─────────────────────────────────────────────────────

all: typecheck build  ## (default) typecheck + compile to dist/

help:  ## Show this help
	@printf "\nUsage: make [target]\n\nTargets:\n"
	@awk 'BEGIN {FS = ":.*##"} \
	     /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)
	@printf "\nOverridable variables: IMAGE_NAME=$(IMAGE_NAME) IMAGE_TAG=$(IMAGE_TAG)\n\n"

install: $(NODE_STAMP)  ## Install npm dependencies

build: $(NODE_STAMP)  ## Compile TypeScript to dist/
	$(NPX) tsc
	@chmod +x dist/cli.js
	@# Copy non-TS runtime files (e.g. the evalscope worker) into dist/.
	@mkdir -p dist/analyzers
	@cp src/analyzers/*.cjs dist/analyzers/

typecheck: $(NODE_STAMP)  ## Type-check without emitting (CI-friendly)
	$(NPX) tsc --noEmit

test: $(NODE_STAMP)  ## Run the node:test suite (tsx loader)
	$(NODE) --import tsx --test test/*.test.ts

clean:  ## Remove dist/ and build/ (keep node_modules)
	rm -rf dist $(BUILD_DIR)

distclean: clean  ## Also remove node_modules (full reset)
	rm -rf node_modules

## ── Docker sandbox ──────────────────────────────────────────────────────────

sandbox:  ## Build the hardened docker sandbox image
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) docker/

sandbox-rebuild:  ## Force-rebuild the sandbox image with no layer cache
	$(DOCKER) build --no-cache -t $(IMAGE_NAME):$(IMAGE_TAG) docker/

sandbox-clean:  ## Remove the sandbox image
	-$(DOCKER) rmi $(IMAGE_NAME):$(IMAGE_TAG)

## ── Example / demo ──────────────────────────────────────────────────────────

demo: $(NODE_STAMP)  ## End-to-end deobfuscate the EtherHiding fixture
	@mkdir -p $(BUILD_DIR)/demo
	$(NPX) tsx src/cli.ts examples/etherhiding/sample.html --rewrite $(BUILD_DIR)/demo
	@echo ""
	@echo "Deobfuscated stage-1 loader (first 30 lines):"
	@echo "─────────────────────────────────────────────"
	@head -30 $(BUILD_DIR)/demo/*.deobf.js

verify-examples:  ## Verify every committed artifact still hashes correctly
	@for sums in examples/*/SHA256SUMS; do \
		dir=$$(dirname "$$sums"); \
		echo "== $$dir =="; \
		( cd "$$dir" && sha256sum -c SHA256SUMS ) || exit 1; \
	done

## ── CI / quality gates ──────────────────────────────────────────────────────

ci: typecheck test verify-examples  ## Run the checks CI should run

## ── Internal ────────────────────────────────────────────────────────────────

# Install when package.json or package-lock.json is newer than the stamp.
# Touching the stamp on success means re-runs are idempotent fast no-ops.
$(NODE_STAMP): package.json package-lock.json
	$(NPM) install
	@mkdir -p $(@D) && touch $@
