.PHONY: install lint format typecheck test cov live check docs serve docker

VENV ?= .venv
BIN := $(VENV)/bin

install:
	python3 -m venv $(VENV)
	$(BIN)/pip install -e ".[dev]"

lint:
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests

format:
	$(BIN)/ruff format src tests
	$(BIN)/ruff check --fix src tests

typecheck:
	$(BIN)/mypy

test:
	$(BIN)/pytest

cov:
	$(BIN)/pytest --cov --cov-report=term-missing

live:
	TXRAY_LIVE_RPC=$${TXRAY_LIVE_RPC:-https://ethereum-rpc.publicnode.com} $(BIN)/pytest -m live

check: lint typecheck test

docs:
	$(BIN)/txray rules --markdown > docs/RULES.md

serve:
	$(BIN)/txray serve --allow-anonymous

docker:
	docker build -t txray:local .
