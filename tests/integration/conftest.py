"""One generated + fully processed dataset shared by the M2-M9 integration tests.

Local mode (SQLite catalog + local files). PyIceberg's local file IO needs POSIX paths, so
these tests run in the engine container (Linux); they are skipped on Windows.
"""
import argparse
import sys
from datetime import date

import pytest

from engine.common import catalog as catalog_mod


@pytest.fixture(scope="session")
def pl_settings(tmp_path_factory):
    from engine.common.config import Settings
    tmp = tmp_path_factory.mktemp("pipeline")
    return Settings.from_env().with_overrides(
        database_url=f"sqlite:///{(tmp / 'engine.db').as_posix()}", bus_url="memory://", storage_backend="local",
        local_storage_root=tmp / "objects", ground_truth_dir=tmp / "gt", lakekeeper_url=None)


@pytest.fixture(scope="session")
def pl_runtime(pl_settings):
    from engine.cqrs.runtime import Runtime
    return Runtime.from_settings(pl_settings, create_tables=True)


@pytest.fixture(scope="session")
def pipeline(pl_settings, pl_runtime):
    if sys.platform == "win32":
        pytest.skip("PyIceberg local IO needs POSIX paths")
    from engine.cli import LocalClient, cmd_ingest
    from engine.generator.run import generate
    catalog_mod.reset_catalog()
    generate(pl_settings, pl_runtime.store, run_id="p", start=date(2026, 9, 7), days=6, users=10, seed=3)
    client = LocalClient.__new__(LocalClient)
    client.rt = pl_runtime
    cmd_ingest(argparse.Namespace(run_id="p", local=True), pl_settings, client)
    pl_runtime.drain(pipeline=True)
    yield pl_runtime
    catalog_mod.reset_catalog()
