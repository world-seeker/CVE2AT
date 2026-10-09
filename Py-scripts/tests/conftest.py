import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))          # so `import sample_data` works
sys.path.insert(0, str(Path(__file__).parent.parent))   # so `import cve2at` works without installing

import pytest
import requests

import sample_data as sd


@pytest.fixture(autouse=True)
def no_real_sleep(monkeypatch):
    """The fetcher waits between NVD requests; tests must not."""
    monkeypatch.setattr("cve2at.fetch.time.sleep", lambda s: None)


@pytest.fixture
def datasets(tmp_path):
    d = tmp_path / "datasets"
    sd.write_reference_datasets(d)
    return d


@pytest.fixture
def fake_nvd(monkeypatch):
    """Route every NVD request to the synthetic 8-CVE universe; returns the list of calls made."""
    calls = []
    monkeypatch.setattr(requests.Session, "get", sd.make_fake_get(sd.fake_vulnerabilities(), calls))
    return calls
