# Developer entry points. Everything runs through `uv`, so no manual venv
# activation and no dependence on which branch you last built.
#
#   make setup     once per checkout (or after switching branches)
#   make check     what CI runs — do this before every commit
#
# Targets that touch the Vectra API are marked; the rest need no credentials.

.DEFAULT_GOAL := help
.PHONY: help setup test test-v tools tools-mt check compile serve clean reset

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Install the project with dev extras (run after a branch switch)
	uv sync --extra dev

test: ## Run the test suite
	uv run pytest tests/ -q

test-v: ## Run the test suite, verbose, stop on first failure
	uv run pytest tests/ -vx

tools: ## Print the tool inventory with side-effect annotations (no creds)
	uv run python scripts/list_tools.py

tools-mt: ## Same, but via the multi-tenant registration path (no creds)
	uv run python scripts/list_tools.py --prefix prod

compile: ## Byte-compile the package to catch syntax errors fast
	uv run python -m compileall -q src scripts

check: compile ## Everything CI runs: compile, annotation check, tests
	uv run python scripts/list_tools.py --check
	uv run pytest tests/ -q
	@echo "\nall checks passed"

probe: ## Verify the SQL reference against the live API (NEEDS credentials)
	uv run python scripts/probe_sql_capabilities.py

probe-tables: ## Same, plus an existence check on every documented table
	uv run python scripts/probe_sql_capabilities.py --tables

serve: ## Run the server on stdio for manual poking (NEEDS credentials)
	uv run vectra-ai-mcp-server --transport stdio --debug

clean: ## Remove caches and build artifacts
	find . -type d -name __pycache__ -not -path './.venv/*' -prune -exec rm -rf {} +
	rm -rf .pytest_cache build dist *.egg-info

reset: clean ## Rebuild the venv from scratch (fixes a stale/moved venv)
	rm -rf .venv
	uv sync --extra dev
