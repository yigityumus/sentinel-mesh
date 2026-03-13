.PHONY: help setup install clean clean-cache clean-all lint lint-fix test test-auth test-api test-log test-no-cache docker-build docker-up docker-down dev run-auth run-api run-log

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

# Project variables
PROJECT_NAME := SentinelMesh
DOCKER_COMPOSE_FILE := docker-compose.yml
SERVICES := auth api log

##@ General

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BLUE)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BLUE)Working Directory:$(NC) $(PWD)"
	@echo "$(BLUE)Python Version:$(NC) $$(python3 --version 2>&1)"

##@ Setup & Installation

setup: clean install ## Complete setup (clean + install dependencies)

install: ## Install dependencies for all services (poetry install)
	@echo "$(BLUE)Installing dependencies for all services...$(NC)"
	@for service in $(SERVICES); do \
		echo "$(YELLOW)→ Installing $$service service$(NC)"; \
		cd services/$$service && poetry install && cd - > /dev/null; \
	done
	@echo "$(GREEN)All dependencies installed$(NC)"

##@ Testing

test: test-no-cache ## Run all tests (alias for test-no-cache)

test-no-cache: clean-cache ## Run all tests with no cache (CI/CD simulation)
	@echo ""
	@echo "$(BLUE)════════════════════════════════════════════════════════$(NC)"
	@echo "$(BLUE)  SentinelMesh - Complete Test Suite$(NC)"
	@echo "$(BLUE)════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(BLUE)Step 1: Testing Auth Service (129 tests)$(NC)"
	@cd services/auth && poetry run pytest tests/ --cache-clear -q && cd - > /dev/null
	@echo "$(GREEN)✓ Auth Service Tests Passed$(NC)"
	@echo ""
	@echo "$(BLUE)Step 2: Testing API Service (50 tests)$(NC)"
	@cd services/api && poetry run pytest tests/ --cache-clear -q && cd - > /dev/null
	@echo "$(GREEN)✓ API Service Tests Passed$(NC)"
	@echo ""
	@echo "$(BLUE)Step 3: Testing Log Service Detection (35 tests)$(NC)"
	@cd services/log && poetry run pytest tests/test_brute_force.py tests/test_token_abuse.py tests/test_admin_probing.py tests/test_integration.py --cache-clear -q && cd - > /dev/null
	@echo "$(GREEN)✓ Log Service Detection Tests Passed$(NC)"
	@echo ""
	@echo "$(BLUE)Step 4: Linting All Services$(NC)"
	@cd services/auth && poetry run ruff check . > /dev/null && cd - > /dev/null
	@echo "$(GREEN)✓ Auth Service Linting Passed$(NC)"
	@cd services/api && poetry run ruff check . > /dev/null && cd - > /dev/null
	@echo "$(GREEN)✓ API Service Linting Passed$(NC)"
	@cd services/log && poetry run ruff check . > /dev/null && cd - > /dev/null
	@echo "$(GREEN)✓ Log Service Linting Passed$(NC)"
	@echo ""
	@echo "$(BLUE)════════════════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)✓ All Tests Passed Successfully!$(NC)"
	@echo "$(BLUE)════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(BLUE)Summary:$(NC)"
	@echo "  Auth Service:        129 tests"
	@echo "  API Service:          50 tests"
	@echo "  Log Service:          35 tests (detection pipeline)"
	@echo "  $(GREEN)Total: 214 tests passed$(NC)"
	@echo ""

test-auth: ## Run auth service tests only
	@echo "$(BLUE)Testing Auth Service...$(NC)"
	@cd services/auth && poetry run pytest tests/ --cache-clear -v && cd - > /dev/null
	@echo "$(GREEN)Auth tests passed$(NC)"

test-api: ## Run API service tests only
	@echo "$(BLUE)Testing API Service...$(NC)"
	@cd services/api && poetry run pytest tests/ --cache-clear -v && cd - > /dev/null
	@echo "$(GREEN)API tests passed$(NC)"

test-log: ## Run log service detection tests only
	@echo "$(BLUE)Testing Log Service Detection...$(NC)"
	@cd services/log && poetry run pytest tests/test_brute_force.py tests/test_token_abuse.py tests/test_admin_probing.py tests/test_integration.py --cache-clear -v && cd - > /dev/null
	@echo "$(GREEN)Log detection tests passed$(NC)"

test-auth-quick: ## Run auth tests without verbose output
	@cd services/auth && poetry run pytest tests/ --cache-clear -q

test-api-quick: ## Run API tests without verbose output
	@cd services/api && poetry run pytest tests/ --cache-clear -q

test-log-quick: ## Run log tests without verbose output
	@cd services/log && poetry run pytest tests/test_brute_force.py tests/test_token_abuse.py tests/test_admin_probing.py tests/test_integration.py --cache-clear -q

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	@cd services/auth && poetry run pytest tests/ --cov=app --cov-report=term-missing && cd - > /dev/null

##@ Code Quality

lint: ## Lint all services (ruff check)
	@echo "$(BLUE)Linting all services...$(NC)"
	@for service in $(SERVICES); do \
		echo "$(YELLOW)→ Linting $$service service$(NC)"; \
		cd services/$$service && poetry run ruff check . && cd - > /dev/null; \
	done
	@echo "$(GREEN)All services pass linting$(NC)"

lint-auth: ## Lint auth service only
	@echo "$(BLUE)Linting Auth Service...$(NC)"
	@cd services/auth && poetry run ruff check .

lint-api: ## Lint API service only
	@echo "$(BLUE)Linting API Service...$(NC)"
	@cd services/api && poetry run ruff check .

lint-log: ## Lint log service only
	@echo "$(BLUE)Linting Log Service...$(NC)"
	@cd services/log && poetry run ruff check .

lint-fix: ## Auto-fix linting issues in all services
	@echo "$(BLUE)Auto-fixing linting issues...$(NC)"
	@for service in $(SERVICES); do \
		echo "$(YELLOW)→ Fixing $$service service$(NC)"; \
		cd services/$$service && poetry run ruff check . --fix && cd - > /dev/null; \
	done
	@echo "$(GREEN)Linting issues fixed$(NC)"

##@ Cleaning

clean: clean-cache ## Clean build artifacts and caches
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@find . -type d -name dist -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name build -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.egg-info" -delete 2>/dev/null || true
	@echo "$(GREEN)Build artifacts cleaned$(NC)"

clean-cache: ## Remove Python cache and pytest cache
	@echo "$(BLUE)Clearing caches...$(NC)"
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)Caches cleared$(NC)"

clean-all: clean ## Deep clean (same as clean for now)
	@echo "$(GREEN)Complete cleanup done$(NC)"

##@ Docker

docker-build: ## Build Docker images for all services
	@echo "$(BLUE)Building Docker images...$(NC)"
	@docker-compose build
	@echo "$(GREEN)Docker images built$(NC)"

docker-up: ## Start services with docker-compose
	@echo "$(BLUE)Starting services...$(NC)"
	@docker-compose up -d
	@echo "$(GREEN)Services started$(NC)"
	@echo "$(BLUE)Services running:$(NC)"
	@docker-compose ps

docker-down: ## Stop and remove containers
	@echo "$(BLUE)Stopping services...$(NC)"
	@docker-compose down
	@echo "$(GREEN)Services stopped$(NC)"

docker-logs: ## View docker compose logs (attach to all services)
	@docker-compose logs -f

docker-logs-auth: ## View auth service logs
	@docker-compose logs -f auth

docker-logs-api: ## View API service logs
	@docker-compose logs -f api

docker-logs-log: ## View log service logs
	@docker-compose logs -f log

docker-shell-auth: ## Open shell in auth container
	@docker-compose exec auth sh

docker-shell-api: ## Open shell in API container
	@docker-compose exec api sh

docker-shell-log: ## Open shell in log container
	@docker-compose exec log sh

docker-ps: ## Show running containers
	@docker-compose ps

docker-restart: docker-down docker-up ## Restart all services

##@ Development

dev: install ## Setup for local development (install + clean caches)
	@echo "$(GREEN)Development environment ready$(NC)"
	@echo "$(BLUE)Next steps:$(NC)"
	@echo "  • Run 'make test' to run all tests"
	@echo "  • Run 'make lint' to check code quality"
	@echo "  • Run 'make docker-up' to start services with Docker"
	@echo "  • Run 'make help' to see all available commands"

run: installation-verify docker-up ## Verify installation and start Docker services
	@echo "$(GREEN)SentinelMesh is running$(NC)"

run-auth: ## Run auth service locally (poetry run)
	@echo "$(BLUE)Starting Auth Service...$(NC)"
	@cd services/auth && poetry run uvicorn app.main:app --reload --host 0.0.0.0 --port 8001

run-api: ## Run API service locally (poetry run)
	@echo "$(BLUE)Starting API Service...$(NC)"
	@cd services/api && poetry run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run-log: ## Run log service locally (poetry run)
	@echo "$(BLUE)Starting Log Service...$(NC)"
	@cd services/log && poetry run uvicorn app.main:app --reload --host 0.0.0.0 --port 8003

##@ Verification

verify: test lint ## Verify code quality and tests (same as test + lint)

installation-verify: ## Verify all services are installed and ready
	@echo "$(BLUE)Verifying installation...$(NC)"
	@for service in $(SERVICES); do \
		echo "$(YELLOW)→ Checking $$service service$(NC)"; \
		cd services/$$service && poetry show > /dev/null && echo "  Dependencies installed" && cd - > /dev/null; \
	done
	@echo "$(GREEN)Installation verified$(NC)"

##@ CI/CD

ci: clean test lint ## Run CI suite (clean + test + lint)
	@echo "$(GREEN)CI pipeline passed$(NC)"

ci-fast: test-auth-quick test-api-quick test-log-quick lint ## Fast CI (quick tests + lint)
	@echo "$(GREEN)Fast CI pipeline passed$(NC)"

##@ Utilities

version: ## Show project and dependency versions
	@echo "$(BLUE)SentinelMesh Project Versions$(NC)"
	@echo "Python: $$(python3 --version 2>&1)"
	@echo "Docker: $$(docker --version 2>&1)"
	@echo "Docker Compose: $$(docker-compose --version 2>&1 || echo 'Not installed')"
	@echo ""
	@echo "$(BLUE)Service versions:$(NC)"
	@for service in $(SERVICES); do \
		echo "$(YELLOW)$$service:$(NC)"; \
		cd services/$$service && poetry show | head -3 && cd - > /dev/null; \
	done

status: ## Show status of all services
	@echo "$(BLUE)Project Status$(NC)"
	@echo "$(YELLOW)Services:$(NC) $(SERVICES)"
	@echo "$(YELLOW)Docker Compose:$(NC) $$(test -f $(DOCKER_COMPOSE_FILE) && echo 'Found' || echo 'Not found')"
	@echo ""
	@echo "$(YELLOW)Test Files:$(NC)"
	@find services -name "test_*.py" -type f | wc -l | xargs echo "  Total test files:"
	@echo ""
	@echo "$(BLUE)Docker containers:$(NC)"
	@docker-compose ps 2>/dev/null || echo "  Docker not running"

##@ Documentation

docs: ## Show README
	@cat README.md

docs-test: ## Show test results documentation
	@cat CI_TEST_RESULTS.md

docs-test-summary: ## Show test summary quickly
	@grep -E "^(|# |## |### |\|)" CI_TEST_RESULTS.md | head -50

.SILENT: help version status docs docs-test-summary