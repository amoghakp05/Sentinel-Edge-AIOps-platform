# ============================================================
# Makefile — aiops-platform (CICADA 2026)
# Requires: Python 3.11+, Docker, make (Git Bash / WSL on Windows)
# Every target prints what it does so the judge can follow along.
# ============================================================

PYTHON   := .venv/bin/python
PIP      := .venv/bin/pip
PYTEST   := .venv/bin/pytest
UVICORN  := .venv/bin/uvicorn

# ── Windows compatibility: use Scripts\ instead of bin/ ──────────────────────
ifeq ($(OS),Windows_NT)
  PYTHON  := .venv/Scripts/python
  PIP     := .venv/Scripts/pip
  PYTEST  := .venv/Scripts/pytest
  UVICORN := .venv/Scripts/uvicorn
endif

.PHONY: help venv install dev-install test test-phase1 lint format \
        sim collector-tail collector-run saas-eu saas-in aiopsctl \
        docker-up docker-down docker-logs clean proof

# ── Default target ────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  aiops-platform — CICADA 2026"
	@echo "  ─────────────────────────────────────────────────────"
	@echo "  make venv          Create virtual environment"
	@echo "  make install       Install all dependencies"
	@echo "  make test          Run all tests"
	@echo "  make test-phase1   Run Phase 1 tests only"
	@echo "  make proof         Run Phase 11 acceptance gate proof suite"
	@echo "  make sim           Start the telemetry simulator (port 9000)"
	@echo "  make saas-eu       Start SaaS for EU region   (port 8001)"
	@echo "  make saas-in       Start SaaS for IN region   (port 8002)"
	@echo "  make collector-tail  Show latest raw events (local DB)"
	@echo "  make docker-up     Start entire stack via Docker Compose"
	@echo "  make docker-down   Tear down Docker stack"
	@echo "  make docker-logs   Follow all container logs"
	@echo "  make lint          Run ruff linter"
	@echo "  make format        Run ruff formatter"
	@echo "  make clean         Remove build artefacts and databases"
	@echo ""

# ── Environment ───────────────────────────────────────────────────────────────
venv:
	python -m venv .venv
	@echo "[OK] Virtual environment created in .venv/"

install: venv
	$(PIP) install -e ".[dev]" --quiet
	@echo "[OK] Dependencies installed"

dev-install: install

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	$(PYTEST) tests/ -v --tb=short

test-phase0:
	$(PYTEST) tests/test_redact.py tests/test_policy.py -v --tb=short

test-phase1:
	$(PYTEST) tests/test_phase1.py -v --tb=short

test-all:
	$(PYTEST) tests/ -v --tb=short --cov=collector --cov=saas --cov-report=term-missing

proof:
	$(PYTHON) tools/run_proof.py

# ── Linting / formatting ──────────────────────────────────────────────────────
lint:
	$(PYTHON) -m ruff check collector/ saas/ tools/ tests/

format:
	$(PYTHON) -m ruff format collector/ saas/ tools/ tests/

# ── Running services ──────────────────────────────────────────────────────────
sim:
	@echo "[SIM] Starting telemetry simulator on http://localhost:9000"
	$(UVICORN) tools.sim_stream_server:app --host 0.0.0.0 --port 9000 --reload

saas-eu:
	@echo "[SAAS-EU] Starting SaaS (eu-central-1) on http://localhost:8001"
	SAAS_REGION=eu-central-1 $(UVICORN) saas.main:app --host 0.0.0.0 --port 8001 --no-access-log --reload

saas-in:
	@echo "[SAAS-IN] Starting SaaS (ap-south-1) on http://localhost:8002"
	SAAS_REGION=ap-south-1 $(UVICORN) saas.main:app --host 0.0.0.0 --port 8002 --no-access-log --reload

collector-tail:
	$(PYTHON) -m collector.cli raw tail --n 20

collector-run:
	$(PYTHON) -m collector.cli run

# ── aiopsctl ─────────────────────────────────────────────────────────────────
aiopsctl:
	$(PYTHON) -m saas.cli_aiopsctl --help

# ── Docker ───────────────────────────────────────────────────────────────────
docker-up:
	@echo "[DOCKER] Starting full stack..."
	docker compose up -d --build
	@echo "[DOCKER] Stack running. Dashboard: http://localhost:3000"

docker-down:
	docker compose down -v

docker-logs:
	docker compose logs -f

docker-status:
	docker compose ps

# ── Utilities ─────────────────────────────────────────────────────────────────
demo-phase1:
	$(PYTHON) tools/demo_phase1.py

inject-cpu:
	$(PYTHON) tools/scenario_injector.py cpu-spike --collector col-acme-eu-1

inject-latency:
	$(PYTHON) tools/scenario_injector.py latency-rise --collector col-acme-eu-2

inject-brute:
	$(PYTHON) tools/scenario_injector.py failed-login-burst --collector col-globex-in-1

clean:
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -f collector_local*.db test_*.db
	rm -rf .pytest_cache htmlcov .coverage
	@echo "[OK] Clean complete"
