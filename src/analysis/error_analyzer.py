"""Error analysis engine for false positives, false negatives, and failure mode taxonomy."""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from ..data.schemas import PredictionOutput, VulnerabilitySample


class ErrorAnalyzer:
    """Dissects classification failures by CWE, project, length, and confidence."""

    @classmethod
    def analyze_predictions(
        cls,
        samples: list[VulnerabilitySample],
        predictions: list[PredictionOutput],
        output_dir: str | Path = "results/error_analysis",
    ) -> dict[str, Any]:
        """Run comprehensive error analysis and save outputs."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        sample_map = {s.sample_id: s for s in samples}

        fps = []
        fns = []
        tps = []
        tns = []

        for p in predictions:
            sample = sample_map.get(p.sample_id)
            code_len = len(sample.code.splitlines()) if sample else 0
            cwe_raw = sample.cwe if sample else "Unknown"
            if isinstance(cwe_raw, list):
                cwe = ", ".join(str(c) for c in cwe_raw) if cwe_raw else "Unknown"
            else:
                cwe = str(cwe_raw) if cwe_raw else "Unknown"
            project = sample.project if sample else "Unknown"

            item = {
                "sample_id": p.sample_id,
                "ground_truth": p.ground_truth,
                "prediction": p.prediction,
                "probability": p.probability,
                "confidence": (p.probability if p.prediction == 1 else (1.0 - p.probability)),
                "cwe": cwe,
                "project": project,
                "line_count": code_len,
                "length_bin": (
                    "<20"
                    if code_len < 20
                    else ("20-50" if code_len <= 50 else ("50-100" if code_len <= 100 else ">100"))
                ),
                "code_snippet": sample.code[:200] if sample else "",
            }

            if p.ground_truth == 0 and p.prediction == 1:
                fps.append(item)
            elif p.ground_truth == 1 and p.prediction == 0:
                fns.append(item)
            elif p.ground_truth == 1 and p.prediction == 1:
                tps.append(item)
            else:
                tns.append(item)

        # Sort FPs and FNs by model confidence descending (most egregious errors first)
        fps = sorted(fps, key=lambda x: x["confidence"], reverse=True)
        fns = sorted(fns, key=lambda x: x["confidence"], reverse=True)

        # Analysis by CWE
        cwe_fp_counts = defaultdict(int)
        cwe_fn_counts = defaultdict(int)
        for fp in fps:
            cwe_fp_counts[fp["cwe"]] += 1
        for fn in fns:
            cwe_fn_counts[fn["cwe"]] += 1

        # Analysis by Project
        proj_fp_counts = defaultdict(int)
        proj_fn_counts = defaultdict(int)
        for fp in fps:
            proj_fp_counts[fp["project"]] += 1
        for fn in fns:
            proj_fn_counts[fn["project"]] += 1

        # Analysis by Length
        len_fp_counts = defaultdict(int)
        len_fn_counts = defaultdict(int)
        for fp in fps:
            len_fp_counts[fp["length_bin"]] += 1
        for fn in fns:
            len_fn_counts[fn["length_bin"]] += 1

        summary = {
            "total_samples": len(predictions),
            "true_positives": len(tps),
            "true_negatives": len(tns),
            "false_positives": len(fps),
            "false_negatives": len(fns),
            "top_false_positive": fps[0] if fps else None,
            "top_false_negative": fns[0] if fns else None,
            "cwe_fp_distribution": dict(
                sorted(cwe_fp_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "cwe_fn_distribution": dict(
                sorted(cwe_fn_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "project_fp_distribution": dict(
                sorted(proj_fp_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "project_fn_distribution": dict(
                sorted(proj_fn_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "length_fp_distribution": dict(len_fp_counts),
            "length_fn_distribution": dict(len_fn_counts),
        }

        # Save structured outputs
        with open(out_path / "error_analysis_summary.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        pd.DataFrame(fps).to_csv(out_path / "false_positives.csv", index=False)
        pd.DataFrame(fns).to_csv(out_path / "false_negatives.csv", index=False)

        # Generate markdown report
        md_content = cls._generate_markdown_report(summary, fps[:5], fns[:5])
        with open(out_path / "error_analysis_report.md", "w", encoding="utf-8") as f:
            f.write(md_content)

        return summary

    @staticmethod
    def _generate_markdown_report(
        summary: dict[str, Any],
        top_fps: list[dict[str, Any]],
        top_fns: list[dict[str, Any]],
    ) -> str:
        """Render readable markdown error report."""
        lines = [
            "# Empirical Error Analysis Report",
            "",
            "## Summary Metrics",
            f"- **Evaluated Samples:** {summary['total_samples']}",
            f"- **True Positives (TP):** {summary['true_positives']}",
            f"- **True Negatives (TN):** {summary['true_negatives']}",
            f"- **False Positives (FP):** {summary['false_positives']}",
            f"- **False Negatives (FN):** {summary['false_negatives']}",
            "",
            "## High-Confidence False Positives (Actual: SAFE, Model: VULNERABLE)",
            "",
        ]

        if top_fps:
            for i, fp in enumerate(top_fps):
                lines.extend(
                    [
                        f"### False Positive #{i+1}",
                        f"- **Sample ID:** `{fp['sample_id']}`",
                        f"- **Project:** `{fp['project']}` | **CWE:** `{fp['cwe']}`",
                        f"- **Model Confidence:** `{fp['confidence']:.4f}` (Probability: `{fp['probability']:.4f}`)",
                        f"- **Code Length:** `{fp['line_count']}` lines (`{fp['length_bin']}`)",
                        "```c",
                        fp["code_snippet"].strip(),
                        "```",
                        "",
                    ]
                )
        else:
            lines.append("No False Positives observed.")

        lines.extend(
            [
                "## High-Confidence False Negatives (Actual: VULNERABLE, Model: SAFE)",
                "",
            ]
        )

        if top_fns:
            for i, fn in enumerate(top_fns):
                lines.extend(
                    [
                        f"### False Negative #{i+1}",
                        f"- **Sample ID:** `{fn['sample_id']}`",
                        f"- **Project:** `{fn['project']}` | **CWE:** `{fn['cwe']}`",
                        f"- **Model Confidence:** `{fn['confidence']:.4f}` (Probability: `{fn['probability']:.4f}`)",
                        f"- **Code Length:** `{fn['line_count']}` lines (`{fn['length_bin']}`)",
                        "```c",
                        fn["code_snippet"].strip(),
                        "```",
                        "",
                    ]
                )
        else:
            lines.append("No False Negatives observed.")

        lines.extend(
            [
                "## Error Distribution by CWE",
                "### Top CWEs in False Positives:",
                *(f"- `{k}`: {v}" for k, v in summary["cwe_fp_distribution"].items()),
                "",
                "### Top CWEs in False Negatives:",
                *(f"- `{k}`: {v}" for k, v in summary["cwe_fn_distribution"].items()),
                "",
                "## Error Distribution by Function Length",
                "| Length Bin | False Positives | False Negatives |",
                "|---|---|---|",
            ]
        )
        all_bins = set(summary["length_fp_distribution"].keys()).union(
            set(summary["length_fn_distribution"].keys())
        )
        for b in sorted(all_bins):
            fp_c = summary["length_fp_distribution"].get(b, 0)
            fn_c = summary["length_fn_distribution"].get(b, 0)
            lines.append(f"| {b} | {fp_c} | {fn_c} |")

        return "\n".join(lines)
