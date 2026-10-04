from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from engine.common.config import Settings
from engine.cqrs.runtime import Runtime


@pytest.fixture
def settings(tmp_path) -> Settings:
    # Hive-style partition keys make deep paths; on Windows (260-char MAX_PATH) set
    # ENGINE_TEST_TMP to a short directory if the default temp dir is too deep.
    short = os.environ.get("ENGINE_TEST_TMP")
    objects = Path(tempfile.mkdtemp(dir=short)) if short else tmp_path / "objects"
    return Settings.from_env().with_overrides(
        database_url=f"sqlite:///{(tmp_path / 'engine.db').as_posix()}",
        bus_url="memory://",
        storage_backend="local",
        local_storage_root=objects,
        ground_truth_dir=tmp_path / "ground_truth",
        lakekeeper_url=None,
    )


@pytest.fixture
def runtime(settings) -> Runtime:
    return Runtime.from_settings(settings, create_tables=True)
