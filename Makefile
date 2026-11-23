# ZK Access Gate: root task runner (owner: devops). Every target is a thin wrapper over an existing
# npm script or p3/Makefile target; CI (.github/workflows/ci.yml) calls the same targets.
#
# Package layout (what `make install` installs):
#   .              npm ci  (circuits toolchain: snarkjs, circomlib(js), mocha, circom_tester)
#   issuer/        npm ci  (fastify, mocha, c8)
#   p3/            npm ci  (npm workspaces: gateway, services, ui, ...)
#   client/, client/attacks/, tests/safety/
#                  no dependencies and no lockfile: they use node: built-ins and resolve
#                  snarkjs / circomlibjs from the root node_modules (and fastify from issuer/).
# circom 2.2.3 is native (cargo install) and is not installed by make; see `make check-env`.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# circom is installed by `cargo install` into ~/.cargo/bin (same lookup as circuits/test/setup.js).
export PATH := $(HOME)/.cargo/bin:$(PATH)

NPM_CI := npm ci --no-audit --no-fund

.PHONY: help install install-root install-issuer install-p3 check-env check-env-demo \
        test test-all test-circuits test-identity test-safety test-p3 \
        artifacts-check vectors-check lint types fmt build-p3 ci demo demo-down

help: ## List targets
	@grep -E '^[a-z0-9-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n",$$1,$$2}'

# --- install ------------------------------------------------------------------------------------
install: install-root install-issuer install-p3 ## npm ci at the root, issuer/ and p3/ (client/, client/attacks/, tests/safety/ have no deps)

install-root: ## npm ci at the repo root
	$(NPM_CI)

install-issuer: ## npm ci in issuer/
	cd issuer && $(NPM_CI)

install-p3: ## npm ci in p3/
	cd p3 && $(NPM_CI)

# --- environment --------------------------------------------------------------------------------
check-env: ## Require node >= 20 and circom == 2.2.3; report docker
	scripts/check-env.sh

check-env-demo: ## Require node >= 20 and docker + compose (circom optional)
	scripts/check-env.sh --demo

# --- tests --------------------------------------------------------------------------------------
test: test-all test-p3 ## Everything: npm run test:all (circuits, issuer, client, attacks, safety) + p3 checks

test-all: ## npm run test:all at the root (needs circom 2.2.3)
	npm run test:all

test-circuits: ## Circuit suite: root npm test (mocha, needs circom 2.2.3)
	npm test

test-identity: ## issuer, client and client/attacks suites (issuer cross-check needs circom 2.2.3)
	npm test --prefix issuer
	npm test --prefix client
	npm test --prefix client/attacks

test-safety: ## Floor tier: tests/safety (F8.05 runs the issuer cross-check, needs circom 2.2.3)
	npm run test:safety

test-p3: ## p3: typecheck, lint, format:check, test
	cd p3 && npm run typecheck && npm run lint && npm run format:check && npm test

artifacts-check: ## Committed proving artefacts match their manifests (npm run artifacts:check)
	npm run artifacts:check

vectors-check: ## Committed test vectors are up to date (gen-vectors.js --check)
	node circuits/scripts/gen-vectors.js --check

# --- quality ------------------------------------------------------------------------------------
# Only p3/ has a linter, formatter and type checker; the root JS trees have none configured.
lint: ## p3 ESLint + Prettier check
	cd p3 && npm run lint && npm run format:check

types: ## p3 TypeScript strict type check
	cd p3 && npm run typecheck

fmt: ## Format p3/ with prettier (scripts/fmt)
	scripts/fmt

build-p3: ## p3 production builds (TypeScript + Vite)
	cd p3 && npm run build

ci: check-env test artifacts-check vectors-check build-p3 ## What CI runs, in one go

# --- demo ---------------------------------------------------------------------------------------
# p3/Makefile `demo` needs ./p3/artifacts from `p1-build` (circom2 WASM build, installed on demand
# into p3/tools/circom; no native circom needed) and the persona fixtures from `fixtures`.
p3/node_modules/.package-lock.json: p3/package-lock.json
	cd p3 && $(NPM_CI)

demo: check-env-demo p3/node_modules/.package-lock.json ## Docker demo (p3: p1-build, fixtures, docker compose up --build) -> http://localhost:8088
	$(MAKE) -C p3 p1-build fixtures demo

demo-down: ## Stop the Docker demo
	$(MAKE) -C p3 demo-down
