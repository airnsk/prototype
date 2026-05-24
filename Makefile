.PHONY: build up down logs test unit integration security e2e experiment clean

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down -v

logs:
	docker compose logs -f

# --- Tests ---
test: unit integration security e2e

unit:
	pytest tests/unit -v

integration:
	pytest tests/integration -v

security:
	pytest tests/security -v

e2e:
	pytest tests/integration/test_e2e.py -v

# --- Experiment ---
experiment:
	python -m experiments.runner

# --- Cleanup ---
clean:
	docker compose down -v
	docker system prune -f

# --- Helpers ---
shell-controller:
	docker compose exec controller /bin/sh

shell-client:
	docker compose exec client-agent /bin/sh

shell-server:
	docker compose exec server-agent /bin/sh
