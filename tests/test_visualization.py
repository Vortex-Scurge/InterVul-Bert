"""Tests for ASCII, HTML, and SVG visual output generation."""

import tempfile
from pathlib import Path

import pytest

from src.data.schemas import VulnerabilityChain
from src.visualization.html_report import HTMLReportGenerator
from src.visualization.svg_graph import SVGGraphGenerator
from src.visualization.terminal_view import TerminalVisualizer


@pytest.fixture
def sample_chain():
    return VulnerabilityChain(
        chain_id="CHAIN_TEST",
        nodes=[
            {"function": "process_request", "score": 0.82, "role": "SOURCE"},
            {"function": "validate_input", "score": 0.67, "role": "INTERMEDIATE"},
            {"function": "execute_query", "score": 0.94, "role": "TARGET"},
        ],
        edges=[
            ["process_request", "validate_input"],
            ["validate_input", "execute_query"],
        ],
        source_func="process_request",
        sink_func="execute_query",
        target_func="execute_query",
        max_risk_score=0.94,
        avg_risk_score=0.81,
        heuristic_chain_score=0.88,
        status="HIGH-RISK CHAIN",
    )


def test_terminal_visualizer(sample_chain):
    rendered = TerminalVisualizer.render_chain(sample_chain)
    assert "INTERPROCEDURAL VULNERABILITY CHAIN" in rendered
    assert "process_request" in rendered
    assert "execute_query" in rendered
    assert "HIGH-RISK CHAIN" in rendered


def test_html_report_generator(sample_chain):
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_path = Path(tmp_dir) / "test_report.html"
        html = HTMLReportGenerator.generate_report(sample_chain, output_path=report_path)

        assert report_path.is_file()
        assert "<!DOCTYPE html>" in html
        assert "CHAIN_TEST" in html
        assert "execute_query" in html


def test_svg_graph_generator(sample_chain):
    with tempfile.TemporaryDirectory() as tmp_dir:
        svg_path = Path(tmp_dir) / "test_graph.svg"
        svg = SVGGraphGenerator.generate_chain_svg(sample_chain, output_path=svg_path)

        assert svg_path.is_file()
        assert "<svg" in svg
        assert "CHAIN_TEST" in svg
