"""Dataset loader, inspection, and checksum utilities."""

import hashlib
import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from ..utils.logger import get_logger
from .adapters import CVEfixesAdapter, DevignAdapter, DiverseVulAdapter
from .schemas import VulnerabilitySample

logger = get_logger("InterVul-Graph.data")


def compute_file_checksum(filepath: Path, algorithm: str = "sha256") -> str:
    """Calculate cryptographic hash of a file."""
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


class DatasetLoader:
    """Unified loader for vulnerability datasets."""

    @staticmethod
    def load_jsonl(filepath: Path, max_samples: int | None = None) -> list[VulnerabilitySample]:
        """Load samples from a JSONL file."""
        samples: list[VulnerabilitySample] = []
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"JSONL file not found: {path.resolve()}")

        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if max_samples and i >= max_samples:
                    break
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                samples.append(VulnerabilitySample.from_dict(data))
        return samples

    @staticmethod
    def save_jsonl(samples: list[VulnerabilitySample], filepath: Path) -> None:
        """Save samples to a JSONL file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(s.to_dict()) + "\n" for s in samples)

    @staticmethod
    def stream_diversevul(
        func_path: Path,
        meta_path: Path | None = None,
        max_samples: int | None = None,
    ) -> Generator[VulnerabilitySample, None, None]:
        """Stream samples from DiverseVul JSON files line-by-line."""
        meta_file = (
            open(meta_path, "r", encoding="utf-8")
            if meta_path and Path(meta_path).is_file()
            else None
        )
        try:
            with open(func_path, "r", encoding="utf-8") as func_file:
                for idx, func_line in enumerate(func_file):
                    if max_samples and idx >= max_samples:
                        break
                    func_line = func_line.strip()
                    if not func_line:
                        continue
                    func_data = json.loads(func_line)
                    meta_data = None
                    if meta_file:
                        meta_line = meta_file.readline().strip()
                        if meta_line:
                            try:
                                meta_data = json.loads(meta_line)
                            except Exception:
                                meta_data = None
                    yield DiverseVulAdapter.adapt(func_data, meta_data, index=idx)
        finally:
            if meta_file:
                meta_file.close()

    @staticmethod
    def load_cvefixes(csv_path: Path, max_samples: int | None = None) -> list[VulnerabilitySample]:
        """Load CVEfixes dataset from CSV."""
        path = Path(csv_path)
        if not path.is_file():
            raise FileNotFoundError(f"CVEfixes file not found: {path.resolve()}")
        df = pd.read_csv(path, nrows=max_samples)
        samples = [CVEfixesAdapter.adapt_row(row, idx) for idx, row in df.iterrows()]
        return samples

    @staticmethod
    def load_devign(csv_path: Path, max_samples: int | None = None) -> list[VulnerabilitySample]:
        """Load Devign dataset from CSV."""
        path = Path(csv_path)
        if not path.is_file():
            raise FileNotFoundError(f"Devign file not found: {path.resolve()}")
        df = pd.read_csv(path, nrows=max_samples)
        samples = [DevignAdapter.adapt_row(row, idx) for idx, row in df.iterrows()]
        return samples


class DatasetInspector:
    """Detailed statistical inspector for vulnerability datasets."""

    @staticmethod
    def inspect(
        samples: list[VulnerabilitySample], dataset_name: str = "DiverseVul"
    ) -> dict[str, Any]:
        """Compute exhaustive statistics and metadata on a sample collection."""
        total = len(samples)
        if total == 0:
            return {"error": "Empty sample list"}

        vuln_count = sum(1 for s in samples if s.target == 1)
        safe_count = total - vuln_count
        ratio = vuln_count / safe_count if safe_count > 0 else float("inf")

        projects = set(s.project for s in samples if s.project)
        cwes = set(s.cwe for s in samples if s.cwe)
        cves = set(s.cve for s in samples if s.cve)
        languages = set(s.language for s in samples if s.language)

        lengths = [len(s.code.splitlines()) for s in samples]
        char_lengths = [len(s.code) for s in samples]

        # Check for exact duplicates
        code_hashes = {}
        exact_duplicates = 0
        normalized_hashes = {}
        near_duplicates = 0

        for s in samples:
            h_exact = hashlib.md5(s.code.encode("utf-8")).hexdigest()
            if h_exact in code_hashes:
                exact_duplicates += 1
            else:
                code_hashes[h_exact] = s.sample_id

            # Near duplicate check: collapse whitespace
            norm_code = "".join(s.code.split())
            h_norm = hashlib.md5(norm_code.encode("utf-8")).hexdigest()
            if h_norm in normalized_hashes:
                near_duplicates += 1
            else:
                normalized_hashes[h_norm] = s.sample_id

        stats = {
            "dataset_name": dataset_name,
            "total_samples": total,
            "vulnerable_samples": vuln_count,
            "safe_samples": safe_count,
            "class_ratio_vuln_to_safe": round(ratio, 4),
            "vuln_percentage": round((vuln_count / total) * 100, 2),
            "unique_projects": len(projects),
            "unique_cwes": len(cwes),
            "unique_cves": len(cves),
            "languages": list(languages),
            "avg_lines_per_function": round(float(np.mean(lengths)), 2),
            "median_lines_per_function": float(np.median(lengths)),
            "max_lines_per_function": int(np.max(lengths)),
            "min_lines_per_function": int(np.min(lengths)),
            "avg_chars_per_function": round(float(np.mean(char_lengths)), 2),
            "exact_duplicates": exact_duplicates,
            "near_duplicates": near_duplicates,
            "missing_code_count": sum(1 for s in samples if not s.code.strip()),
        }
        return stats
