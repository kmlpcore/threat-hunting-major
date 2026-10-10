COMPOSE ?= docker compose
CLI = $(COMPOSE) run --rm --no-deps cli
RUN_ID ?= demo
DAYS ?= 7
USERS ?= 40

.PHONY: env up down clean ping seed generate ingest check status test local-demo schemas         hunt feeds history retention drill fidelity report attack-bundle

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

hunt:           ## M5: plan + run the benchmark Sigma corpus (RULE=path to override)
	$(CLI) hunt $(or $(RULE),rules/sigma)

feeds:          ## M7: pull every enabled TI feed now (offline samples unless TI_FEEDS_OFFLINE=0)
	$(CLI) feeds

history:        ## M8: add one generated day per past year (15-year layout)
	$(CLI) history --years 15

retention:      ## M8: apply retention to every layer (raw is a dry run)
	$(CLI) retention apply

drill:          ## M8: readability drill over every retained year
	$(CLI) retention drill

fidelity:       ## M9: recall / precision per rule vs full rehydration
	$(COMPOSE) run --rm --no-deps --entrypoint python cli -m benchmarks.fidelity --run-id $(RUN_ID)

report:         ## M9: full evaluation -> docs/evaluation.md
	$(COMPOSE) run --rm --no-deps --entrypoint python cli -m benchmarks.report --run-id $(RUN_ID) --feeds

attack-bundle:  ## download the full MITRE ATT&CK Enterprise bundle (validator prefers it over the subset)
	curl -fsSL -o data/attack/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

local-demo:     ## whole pipeline in-process, no Docker (SQLite + in-memory bus + ./.local)
	python -m engine.cli --local demo --run-id $(RUN_ID) --days $(DAYS) --users $(USERS)

schemas:        ## export event contracts to schemas/events/
	python -m engine.common.events export
