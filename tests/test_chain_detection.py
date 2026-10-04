"""Tests for vulnerability chain detection and scoring."""

from src.callgraph.graph_builder import CallGraph
from src.interprocedural.chain_detector import ChainDetector
from src.interprocedural.scoring import FunctionScorer, HeuristicChainScorer
from src.models.model_factory import ModelFactory

SAMPLE_CHAIN_CODE = """
void execute_query(char *query) {
    system(query);
}

void validate_input(char *buf) {
    execute_query(buf);
}

void process_request(void) {
    char user_input[256];
    fgets(user_input, sizeof(user_input), stdin);
    validate_input(user_input);
}
"""


def test_heuristic_chain_scorer():
    score = HeuristicChainScorer.calculate_chain_risk([0.8, 0.9], has_source=True, has_sink=True)
    assert 0.70 <= score <= 1.0

    strength = HeuristicChainScorer.calculate_chain_evidence_strength(
        0.91, source_detected=True, sink_detected=True, has_path=True
    )
    # (0.91 + 1.0 + 1.0 + 1.0) / 4 = 3.91 / 4 = 0.9775 ~ 0.98
    assert 0.97 <= strength <= 0.98


def test_chain_detector_execution():
    device = ModelFactory.get_device()
    model, tokenizer = ModelFactory.load_codebert("microsoft/codebert-base", device=device)
    scorer = FunctionScorer(model=model, tokenizer=tokenizer, device=device)
    detector = ChainDetector(scorer=scorer)

    cg = CallGraph().build_from_code(SAMPLE_CHAIN_CODE)

    # 1. Targeted execution: explicitly sets TARGET
    chains = detector.detect_chains(cg, target_function_name="validate_input")
    assert len(chains) > 0
    c = chains[0]
    assert c.chain_id == "CHAIN_001"
    assert c.target_func == "validate_input"
    target_nodes = [n for n in c.nodes if n["role"] == "TARGET"]
    assert len(target_nodes) == 1
    assert target_nodes[0]["function"] == "validate_input"

    # 2. Automatic discovery: NO node labeled as TARGET
    auto_chains = detector.detect_chains(cg, target_function_name=None)
    assert len(auto_chains) > 0
    c_auto = auto_chains[0]
    assert c_auto.target_func == ""
    assert not any(n["role"] == "TARGET" for n in c_auto.nodes)

    # In automatic chain: process_request -> validate_input -> execute_query -> system
    roles = {n["function"]: n["role"] for n in c_auto.nodes}
    assert roles.get("process_request") == "SOURCE"
    assert roles.get("validate_input") == "INTERMEDIATE"
    # execute_query directly calls system() sink
    assert roles.get("execute_query") == "HIGH-RISK INTERMEDIATE"
    assert roles.get("system") == "SINK"

    assert c_auto.chain_evidence_strength > 0.0
    assert c_auto.path_traversal == "CONFIRMED"
