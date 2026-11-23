# ZK Access Gate — root task runner (P3 devops lane; closes risk R-007).
# Every target maps to a real command; any failing suite makes `make` exit non-zero.
#
# Requirements: Node >= 20, npm, circom 2.2.3 on PATH (circuit suite and the floor-8 cross-checks),
# Docker (demo and live Keycloak). Install circom 2.2.3:
#   cargo install --locked --git https://github.com/iden3/circom.git --tag v2.2.3 circom

CIRCOM_VERSION := 2.2.3
P3 := p3
COMPOSE := docker compose --project-directory $(P3) -f $(P3)/docker-compose.yml

.PHONY: help install check-circom build test test-circuits test-issuer test-client test-attacks \
	test-safety test-p3 artifacts-check lint types test-keycloak e2e demo demo-local demo-reset demo-down

help: ## List targets
	@grep -E '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  %-16s %s\n",$$1,$$2}'

install: ## Install all dependencies (root, issuer, p3)
	npm ci
	npm ci --prefix issuer
	npm ci --prefix $(P3)

check-circom: ## Fail unless circom $(CIRCOM_VERSION) is on PATH
	@v="$$(circom --version 2>/dev/null)"; \
	if [ "$$v" = "circom compiler $(CIRCOM_VERSION)" ]; then echo "circom $(CIRCOM_VERSION): ok"; \
	else echo "ERROR: circom $(CIRCOM_VERSION) required, found: $${v:-none}"; \
	echo "  cargo install --locked --git https://github.com/iden3/circom.git --tag v$(CIRCOM_VERSION) circom"; exit 1; fi

build: ## Build the P3 workspaces (the safety tier runs the gateway from p3/gateway/dist)
	npm run build --prefix $(P3)

test: check-circom build test-circuits test-issuer test-client test-attacks test-safety test-p3 ## ALL suites (non-zero on any failure)
	@echo "make test: all suites passed"

test-circuits: check-circom ## Circuit suite (mocha + circom_tester)
	npm test

test-issuer: check-circom ## Issuer + registry (includes the floor-8 circom cross-check)
	npm test --prefix issuer

test-client: ## Client prover / wallet
	npm test --prefix client

test-attacks: ## Attack Lab library
	npm test --prefix client/attacks

test-safety: build ## Safety floors, incl. the gateway tests F3.09 F4.06 F5.07 F7.05
	npm test --prefix tests/safety

test-p3: ## P3: lint, format, typecheck, unit/integration/security tests (incl. team issuer + attack suite)
	npm run lint --prefix $(P3)
	npm run format:check --prefix $(P3)
	npm run typecheck --prefix $(P3)
	npm test --prefix $(P3)

artifacts-check: ## Committed circuit artefacts match their manifests
	npm run artifacts:check

lint: ## ESLint + Prettier check (p3; the only tree with a linter configured)
	npm run lint --prefix $(P3)
	npm run format:check --prefix $(P3)

types: ## TypeScript strict type checks (p3)
	npm run typecheck --prefix $(P3)

test-keycloak: ## Live Keycloak in Docker: real PKCE login, JWKS validation, policies
	$(COMPOSE) up -d keycloak
	@for i in $$(seq 1 60); do curl -sf -o /dev/null http://localhost:8080/realms/zkag/.well-known/openid-configuration && exit 0; sleep 3; done; echo "Keycloak did not become ready"; exit 1
	KEYCLOAK_LIVE_URL=http://localhost:8080 npm test --prefix $(P3) -w baseline/sso-gateway

e2e: ## Playwright against a running demo (E2E_BASE_URL, default http://localhost:8088; use localhost, Keycloak redirects there)
	cd $(P3)/ui && E2E_BASE_URL=$${E2E_BASE_URL:-http://localhost:8088} npx playwright test

demo: ## Full demo in Docker: UI http://localhost:8088, Keycloak http://localhost:8080
	$(COMPOSE) up --build -d
	@echo "UI http://localhost:8088 (operator token: OPERATOR_TOKEN in p3/env.example) · Keycloak http://localhost:8080"

demo-local: ## Demo without Docker images (run `docker compose up -d keycloak` in p3 for SSO): UI :5173
	npm run v4:setup --prefix $(P3)
	npm run dev --prefix $(P3)

demo-reset: ## Fresh demo state: drop the demo volumes (issuer registry, wallets) and restart
	$(COMPOSE) down -v
	$(COMPOSE) up --build -d

demo-down: ## Stop the Docker demo
	$(COMPOSE) down
