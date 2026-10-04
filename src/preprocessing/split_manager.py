"""Data leakage prevention, deduplication, and project/CVE-aware splitting."""

import hashlib
import random
from collections import defaultdict
from typing import Any

from ..data.schemas import VulnerabilitySample
from ..utils.logger import get_logger

logger = get_logger("InterVul-Graph.preprocessing.split")


class SplitManager:
    """Manages project-aware and CVE-aware dataset partitioning with strict leakage checks."""

    @staticmethod
    def compute_exact_hash(code: str) -> str:
        """MD5 hash of stripped code."""
        return hashlib.md5(code.strip().encode("utf-8")).hexdigest()

    @staticmethod
    def compute_normalized_hash(code: str) -> str:
        """MD5 hash with collapsed whitespace and comments removed."""
        from .cleaner import CodeCleaner

        cleaned = CodeCleaner.clean(code, remove_comments=True)
        collapsed = "".join(cleaned.split())
        return hashlib.md5(collapsed.encode("utf-8")).hexdigest()

    @classmethod
    def deduplicate(
        cls, samples: list[VulnerabilitySample]
    ) -> tuple[list[VulnerabilitySample], int, int]:
        """Remove exact duplicates and audit near-duplicates."""
        seen_exact: set[str] = set()
        seen_norm: set[str] = set()
        unique_samples: list[VulnerabilitySample] = []
        exact_dupes = 0
        near_dupes = 0

        for s in samples:
            h_exact = cls.compute_exact_hash(s.code)
            if h_exact in seen_exact:
                exact_dupes += 1
                continue
            seen_exact.add(h_exact)

            h_norm = cls.compute_normalized_hash(s.code)
            if h_norm in seen_norm:
                near_dupes += 1
                # Drop near-duplicates to ensure strict data separation
                continue
            seen_norm.add(h_norm)

            unique_samples.append(s)

        return unique_samples, exact_dupes, near_dupes

    @classmethod
    def project_aware_split(
        cls,
        samples: list[VulnerabilitySample],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        seed: int = 42,
    ) -> tuple[
        list[VulnerabilitySample],
        list[VulnerabilitySample],
        list[VulnerabilitySample],
        dict[str, Any],
    ]:
        """Split dataset strictly by project so no project appears in multiple splits."""
        unique_samples, exact_dupes, near_dupes = cls.deduplicate(samples)

        # Group samples by connected components of (Project, CVE)
        import networkx as nx

        cluster_graph = nx.Graph()

        for s in unique_samples:
            proj_key = f"proj_{s.project}"
            cluster_graph.add_node(proj_key)
            valid_cve = s.cve and str(s.cve).strip().lower() not in ["none", "null", "unknown", ""]
            if valid_cve:
                cve_key = f"cve_{s.cve.strip()}"
                cluster_graph.add_edge(proj_key, cve_key)

        # Map each sample to its connected component ID
        sample_to_cluster = {}
        components = list(nx.connected_components(cluster_graph))
        for cluster_id, comp in enumerate(components):
            for item in comp:
                sample_to_cluster[item] = cluster_id

        cluster_to_samples: dict[int, list[VulnerabilitySample]] = defaultdict(list)
        for s in unique_samples:
            proj_key = f"proj_{s.project}"
            cid = sample_to_cluster.get(proj_key, 0)
            cluster_to_samples[cid].append(s)

        sorted_clusters = sorted(
            cluster_to_samples.keys(),
            key=lambda cid: len(cluster_to_samples[cid]),
            reverse=True,
        )
        rng = random.Random(seed)
        rng.shuffle(sorted_clusters)

        train_samples: list[VulnerabilitySample] = []
        val_samples: list[VulnerabilitySample] = []
        test_samples: list[VulnerabilitySample] = []

        total_target = len(unique_samples)
        train_target = int(total_target * train_ratio)
        val_target = int(total_target * val_ratio)

        for cid in sorted_clusters:
            c_samples = cluster_to_samples[cid]
            if len(train_samples) + len(c_samples) <= train_target or (
                not train_samples and len(c_samples) > train_target
            ):
                train_samples.extend(c_samples)
            elif len(val_samples) + len(c_samples) <= val_target or not val_samples:
                val_samples.extend(c_samples)
            else:
                test_samples.extend(c_samples)

        # If any split is empty due to small project counts, redistribute gracefully
        if not test_samples and len(val_samples) > 2:
            test_samples = val_samples[len(val_samples) // 2 :]
            val_samples = val_samples[: len(val_samples) // 2]

        leakage_report = cls.verify_no_leakage(train_samples, val_samples, test_samples)
        leakage_report["deduplication"] = {
            "exact_duplicates_removed": exact_dupes,
            "near_duplicates_removed": near_dupes,
            "retained_unique_samples": len(unique_samples),
        }

        return train_samples, val_samples, test_samples, leakage_report

    @classmethod
    def verify_no_leakage(
        cls,
        train_samples: list[VulnerabilitySample],
        val_samples: list[VulnerabilitySample],
        test_samples: list[VulnerabilitySample],
    ) -> dict[str, Any]:
        """Verify strict independence across train, val, and test splits."""
        train_exact = {cls.compute_exact_hash(s.code) for s in train_samples}
        val_exact = {cls.compute_exact_hash(s.code) for s in val_samples}
        test_exact = {cls.compute_exact_hash(s.code) for s in test_samples}

        train_norm = {cls.compute_normalized_hash(s.code) for s in train_samples}
        val_norm = {cls.compute_normalized_hash(s.code) for s in val_samples}
        test_norm = {cls.compute_normalized_hash(s.code) for s in test_samples}

        train_projects = {s.project for s in train_samples if s.project != "unknown"}
        val_projects = {s.project for s in val_samples if s.project != "unknown"}
        test_projects = {s.project for s in test_samples if s.project != "unknown"}

        def is_valid_cve(c: Any) -> bool:
            return bool(c and str(c).strip().lower() not in ["none", "null", "unknown", ""])

        train_cves = {str(s.cve).strip() for s in train_samples if is_valid_cve(s.cve)}
        val_cves = {str(s.cve).strip() for s in val_samples if is_valid_cve(s.cve)}
        test_cves = {str(s.cve).strip() for s in test_samples if is_valid_cve(s.cve)}

        exact_leak_train_val = len(train_exact.intersection(val_exact))
        exact_leak_train_test = len(train_exact.intersection(test_exact))
        near_leak_train_val = len(train_norm.intersection(val_norm))
        near_leak_train_test = len(train_norm.intersection(test_norm))

        proj_leak_train_val = len(train_projects.intersection(val_projects))
        proj_leak_train_test = len(train_projects.intersection(test_projects))
        cve_leak_train_val = len(train_cves.intersection(val_cves))
        cve_leak_train_test = len(train_cves.intersection(test_cves))

        is_leak_free = (
            exact_leak_train_val == 0
            and exact_leak_train_test == 0
            and near_leak_train_val == 0
            and near_leak_train_test == 0
            and proj_leak_train_test == 0
            and cve_leak_train_val == 0
            and cve_leak_train_test == 0
        )

        return {
            "is_leak_free": is_leak_free,
            "train_samples_count": len(train_samples),
            "val_samples_count": len(val_samples),
            "test_samples_count": len(test_samples),
            "exact_duplicate_leakage": {
                "train_val_overlap": exact_leak_train_val,
                "train_test_overlap": exact_leak_train_test,
            },
            "near_duplicate_leakage": {
                "train_val_overlap": near_leak_train_val,
                "train_test_overlap": near_leak_train_test,
            },
            "project_leakage": {
                "train_projects_count": len(train_projects),
                "val_projects_count": len(val_projects),
                "test_projects_count": len(test_projects),
                "train_val_project_overlap": proj_leak_train_val,
                "train_test_project_overlap": proj_leak_train_test,
                "overlapping_projects": list(train_projects.intersection(test_projects)),
            },
            "cve_leakage": {
                "train_test_cve_overlap": cve_leak_train_test,
                "overlapping_cves": list(train_cves.intersection(test_cves)),
            },
        }
