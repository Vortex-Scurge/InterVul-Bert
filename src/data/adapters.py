"""Dataset schema adapters to canonical VulnerabilitySample format."""

from typing import Any

import pandas as pd

from .schemas import VulnerabilitySample


class DiverseVulAdapter:
    """Adapter for the DiverseVul vulnerability dataset format."""

    @staticmethod
    def adapt(
        func_dict: dict[str, Any],
        meta_dict: dict[str, Any] | None = None,
        index: int = 0,
    ) -> VulnerabilitySample:
        """Convert DiverseVul record to VulnerabilitySample."""
        code = func_dict.get("func", "")
        target = int(func_dict.get("target", 0))

        project = "unknown"
        commit_id = None
        cwe = None
        cve = None

        if meta_dict:
            project = meta_dict.get("project", "unknown")
            commit_id = meta_dict.get("commit_id")
            cwe = meta_dict.get("CWE")
            cve = meta_dict.get("CVE")

        sample_id = f"diversevul_{index:06d}"
        if commit_id:
            sample_id = f"diversevul_{project}_{commit_id[:8]}_{index}"

        return VulnerabilitySample(
            sample_id=sample_id,
            code=code,
            target=target,
            project=project,
            commit_id=commit_id,
            cwe=cwe,
            cve=cve,
            language="c",
            metadata={
                "source_dataset": "DiverseVul",
                "bug_info": meta_dict.get("bug_info") if meta_dict else None,
            },
        )


class CVEfixesAdapter:
    """Adapter for CVEfixes dataset formats (CSV or Parquet)."""

    @staticmethod
    def adapt_row(row: pd.Series, index: int = 0) -> VulnerabilitySample:
        """Convert a CVEfixes DataFrame row to VulnerabilitySample."""
        # Check source/code column
        code = ""
        for col in ["source", "raw_lines", "code", "func", "function"]:
            if col in row and pd.notna(row[col]):
                val = row[col]
                if isinstance(val, (list, tuple)):
                    code = "".join(val)
                else:
                    code = str(val)
                break

        # Check label/target column
        target = 1  # In CVEfixes test.csv, samples are typically vulnerable functions with CVE/CWE
        if "label" in row and pd.notna(row["label"]):
            try:
                target = int(row["label"])
            except (ValueError, TypeError):
                target = 1
        elif "target" in row and pd.notna(row["target"]):
            try:
                target = int(row["target"])
            except (ValueError, TypeError):
                target = 1

        project = str(row.get("project_and_commit_id", "unknown")).split("@")[0]
        commit_id = (
            str(row.get("project_and_commit_id", "")).split("/")[-1]
            if "/" in str(row.get("project_and_commit_id", ""))
            else None
        )
        cwe = str(row.get("cwe_id", "CWE-Unknown")) if pd.notna(row.get("cwe_id")) else None
        cve = str(row.get("cve_id", "CVE-Unknown")) if pd.notna(row.get("cve_id")) else None

        sample_id = f"cvefixes_{index:06d}"
        if cve and cve != "CVE-Unknown":
            sample_id = f"cvefixes_{cve}_{index}"

        return VulnerabilitySample(
            sample_id=sample_id,
            code=code,
            target=target,
            project=project,
            commit_id=commit_id,
            cwe=cwe,
            cve=cve,
            language="c",
            metadata={
                "source_dataset": "CVEfixes",
                "time": str(row.get("time", "")),
                "original_address": str(row.get("original_address", "")),
            },
        )


class DevignAdapter:
    """Adapter for Devign dataset CSV/JSON format."""

    @staticmethod
    def adapt_row(row: pd.Series, index: int = 0) -> VulnerabilitySample:
        """Convert Devign row to VulnerabilitySample."""
        code = str(row.get("func", row.get("code", "")))
        target = int(row.get("target", row.get("label", 0)))
        project = str(row.get("project", "devign_project"))
        commit_id = str(row.get("commit_id", None))

        return VulnerabilitySample(
            sample_id=f"devign_{project}_{index:05d}",
            code=code,
            target=target,
            project=project,
            commit_id=commit_id,
            cwe=row.get("cwe", None),
            language="c",
            metadata={"source_dataset": "Devign"},
        )
