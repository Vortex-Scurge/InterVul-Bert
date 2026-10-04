"""Tests for data models, adapters, schemas, and loader."""

import pandas as pd

from src.data.adapters import CVEfixesAdapter, DiverseVulAdapter
from src.data.dataset_loader import DatasetInspector
from src.data.schemas import VulnerabilitySample


def test_vulnerability_sample_schema():
    s = VulnerabilitySample(
        sample_id="test_001",
        code="int main() { return 0; }",
        target=0,
        project="test_proj",
    )
    d = s.to_dict()
    assert d["sample_id"] == "test_001"
    assert d["target"] == 0

    reconstructed = VulnerabilitySample.from_dict(d)
    assert reconstructed.sample_id == s.sample_id
    assert reconstructed.code == s.code


def test_diversevul_adapter():
    func_data = {"func": "void bad() { strcpy(a, b); }", "target": 1}
    meta_data = {"project": "linux", "CWE": "CWE-120", "CVE": "CVE-2021-0001"}
    sample = DiverseVulAdapter.adapt(func_data, meta_data, index=42)

    assert sample.target == 1
    assert sample.project == "linux"
    assert sample.cwe == "CWE-120"
    assert sample.cve == "CVE-2021-0001"


def test_cvefixes_adapter():
    row = pd.Series(
        {
            "source": "void vuln_func() { system(arg); }",
            "cwe_id": "CWE-78",
            "cve_id": "CVE-2020-1234",
            "project_and_commit_id": "curl@curl/abcdef123456",
            "label": 1,
        }
    )
    sample = CVEfixesAdapter.adapt_row(row, index=10)
    assert sample.target == 1
    assert sample.cwe == "CWE-78"
    assert sample.cve == "CVE-2020-1234"
    assert sample.project == "curl"


def test_dataset_inspector():
    samples = [
        VulnerabilitySample("s1", "void f1() { int a; }", 0, project="p1"),
        VulnerabilitySample("s2", "void f2() { strcpy(a, b); }", 1, project="p2", cwe="CWE-120"),
        VulnerabilitySample("s3", "void f3() { system(x); }", 1, project="p3", cwe="CWE-78"),
    ]
    stats = DatasetInspector.inspect(samples, dataset_name="UnitTestDataset")
    assert stats["total_samples"] == 3
    assert stats["vulnerable_samples"] == 2
    assert stats["safe_samples"] == 1
    assert stats["unique_projects"] == 3
