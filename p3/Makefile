# ZK Access Gate — task runner. Every target maps to a real script.
.PHONY: help install p1-build p1-audit fixtures dev build typecheck lint format-check test e2e bench demo demo-down reset check

help:
	@grep -E '^[a-z0-9-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

install: ## Install all workspace dependencies
	npm install
p1-build: ## Compile the unmodified P1 circuit + DEV-ONLY Groth16 setup into ./artifacts
	npm run p1:build
p1-audit: ## Execute the P1 security audit against real proofs (evidence/p1-audit-report.json)
	npm run p1:audit
fixtures: ## Generate diagnostic persona fixtures for the P2 stand-in
	npm run p1:fixtures
dev: ## Run gateway, services, SSO baseline, P2 stand-in and UI locally (http://localhost:5173)
	npm run dev
build: ## Production builds (TypeScript + Vite)
	npm run build
typecheck: ## TypeScript strict type checks
	npm run typecheck
lint: ## ESLint
	npm run lint
format-check: ## Prettier check
	npm run format:check
test: ## Unit + integration + security tests (Vitest)
	npm test
e2e: ## Playwright browser tests (requires `make dev` running)
	npm run test:e2e
bench: ## Benchmarks (100 iterations) → bench/results/latest.{json,csv}
	npm run bench
demo: ## Full Docker demo (requires Docker and `make p1-build` first) → http://localhost:8088
	docker compose up --build
demo-down: ## Stop the Docker demo
	docker compose down
reset: ## Reset demo state through the gateway admin API (local dev stack)
	node scripts/reset-demo.mjs
check: typecheck lint test build ## All quality gates
