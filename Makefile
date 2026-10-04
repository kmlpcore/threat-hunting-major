COMPOSE ?= docker compose
CLI = $(COMPOSE) run --rm --no-deps cli
RUN_ID ?= demo
DAYS ?= 7
USERS ?= 40

.PHONY: env up down clean ping seed generate ingest check status test local-demo schemas

env:            ## create .env from the example (edit the secrets afterwards)
	@test -f .env || cp .env.example .env

up: env         ## start the stack and wait for health
	$(COMPOSE) up -d --build --wait

down:
	$(COMPOSE) down

clean:          ## stop and delete all volumes (raw Object Lock is GOVERNANCE in dev, so this works)
	$(COMPOSE) down -v

ping:           ## M0 exit check
	$(CLI) ping

generate:
	$(CLI) generate --run-id $(RUN_ID) --days $(DAYS) --users $(USERS)

ingest:
	$(CLI) ingest --run-id $(RUN_ID)

seed: generate ingest

check:          ## M1 exit checks
	$(CLI) ecs-check
	$(COMPOSE) run --rm --no-deps --entrypoint python cli -m benchmarks.ground_truth_check --run-id $(RUN_ID)

status:
	curl -s localhost:8001/partitions/summary

test:
	$(COMPOSE) run --rm --no-deps --entrypoint python cli -m pytest -q tests

local-demo:     ## whole pipeline in-process, no Docker (SQLite + in-memory bus + ./.local)
	python -m engine.cli --local demo --run-id $(RUN_ID) --days $(DAYS) --users $(USERS)

schemas:        ## export event contracts to schemas/events/
	python -m engine.common.events export
