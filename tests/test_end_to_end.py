"""End-to-end integration test validating the entire analysis pipeline."""

import tempfile
from pathlib import Path

from src.callgraph.graph_builder import CallGraph
from src.interprocedural.chain_detector import ChainDetector
from src.interprocedural.scoring import FunctionScorer
from src.models.model_factory import ModelFactory
from src.visualization.html_report import HTMLReportGenerator
from src.visualization.svg_graph import SVGGraphGenerator
from src.visualization.terminal_view import TerminalVisualizer

SAMPLE_CODE = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void db_native_execute(const char *sql) {
    system(sql);
}

void execute_query(char *query) {
    db_native_execute(query);
}

void validate_input(char *buf) {
    execute_query(buf);
}

void process_request(void) {
    char input[256];
    fgets(input, sizeof(input), stdin);
    validate_input(input);
}
"""


def test_complete_end_to_end_pipeline():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        reports_dir = tmp_path / "reports"
        chains_dir = tmp_path / "chains"

        # 1. Device and Model
        device = ModelFactory.get_device()
        model, tokenizer = ModelFactory.load_codebert("microsoft/codebert-base", device=device)
        scorer = FunctionScorer(model=model, tokenizer=tokenizer, device=device)
        detector = ChainDetector(scorer=scorer)

        # 2. Call Graph
        cg = CallGraph().build_from_code(SAMPLE_CODE)
        assert len(cg.graph.nodes) >= 4

        # 3. Chain Detection
        chains = detector.detect_chains(cg, target_function_name="execute_query")
        assert len(chains) > 0
        primary = chains[0]

        # 4. Comparison
        comparison = detector.compare_local_vs_interprocedural(cg, target_name="execute_query")
        assert "local_analysis" in comparison
        assert "interprocedural_analysis" in comparison
        assert "context_aware_chain_score" in comparison["interprocedural_analysis"]
        assert "explanation" in comparison["interprocedural_analysis"]

        # 5. Visual Rendering
        term_text = TerminalVisualizer.render_chain(primary)
        assert "execute_query" in term_text
        assert "Chain Evidence Strength" in term_text
        assert "CHAIN ASSESSMENT" in term_text
        assert "Path traversal:            CONFIRMED" in term_text

        html_file = reports_dir / f"{primary.chain_id}.html"
        html_out = HTMLReportGenerator.generate_report(
            chain=primary,
            comparison=comparison,
            output_path=html_file,
        )
        assert html_file.is_file()
        assert "<!DOCTYPE html>" in html_out
        assert "Context-Aware Chain Score" in html_out
        assert "Chain Evidence Strength" in html_out

        svg_file = chains_dir / f"{primary.chain_id}.svg"
        svg_out = SVGGraphGenerator.generate_chain_svg(primary, output_path=svg_file)
        assert svg_file.is_file()
        assert "<svg" in svg_out
        assert "Chain Evidence Strength" in svg_out
