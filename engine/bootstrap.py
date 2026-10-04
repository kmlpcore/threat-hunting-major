"""One-shot initialisation (the `engine-init` compose service).

Creates the Postgres schemas/tables, then bootstraps Lakekeeper (warehouse on
MinIO + Iceberg namespaces). Safe to run repeatedly.
"""
from __future__ import annotations

import json
import logging
import time

from sqlalchemy.exc import OperationalError

from engine.common.config import Settings
from engine.common.db import create_all, make_engine

log = logging.getLogger("engine.bootstrap")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings.from_env()
    engine = make_engine(settings.database_url)
    for attempt in range(30):
        try:
            create_all(engine)
            break
        except OperationalError:
            log.info("waiting for database (attempt %d)", attempt + 1)
            time.sleep(2)
    else:
        raise SystemExit("database not reachable")
    log.info("database schemas ready")

    result = {"database": "ok"}
    if settings.lakekeeper_url:
        from engine.common.catalog import bootstrap_lakekeeper
        result["catalog"] = bootstrap_lakekeeper(settings)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
