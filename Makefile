.PHONY: help install test coverage lint format run docker-build docker-up docker-down migrate seed clean

help:
	@echo "Auth-as-a-Service (AaaS) Makefile"
	@echo "-----------------------------------"
	@echo "make install       Install dependencies"
	@echo "make test          Run pytest suite"
	@echo "make coverage      Run tests with coverage threshold"
	@echo "make lint          Run ruff, black, and mypy"
	@echo "make format        Format code with black and ruff"
	@echo "make run           Run local development server"
	@echo "make docker-build  Build Docker image"
	@echo "make docker-up     Start full docker-compose stack"
	@echo "make docker-down   Stop docker-compose stack"
	@echo "make migrate       Run Alembic database migrations"
	@echo "make clean         Remove cache files and artifacts"

install:
	pip install -r requirements-dev.txt

test:
	pytest -v tests/

coverage:
	pytest --cov=auth_service --cov-report=term-missing --cov-fail-under=65 tests/

lint:
	ruff check auth_service/ tests/
	black --check auth_service/ tests/
	mypy auth_service/ --ignore-missing-imports

format:
	black auth_service/ tests/
	ruff check --fix auth_service/ tests/

run:
	uvicorn auth_service.main:app --host 0.0.0.0 --port 8000 --reload

docker-build:
	docker build -t auth-as-a-service:latest .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down -v

migrate:
	alembic upgrade head

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov .mypy_cache .ruff_cache

