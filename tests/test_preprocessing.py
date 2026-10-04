"""Tests for code cleaning, tokenization, and leakage-aware partitioning."""

from src.data.schemas import VulnerabilitySample
from src.preprocessing.cleaner import CodeCleaner
from src.preprocessing.split_manager import SplitManager
from src.preprocessing.tokenizer_wrapper import CodeTokenizerWrapper


def test_code_cleaner_comments():
    raw_code = """
    // Single line comment
    int main() {
        /* Multi-line
           comment block */
        return 0;
    }
    """
    cleaned = CodeCleaner.clean(raw_code, remove_comments=True)
    assert "// Single line comment" not in cleaned
    assert "/* Multi-line" not in cleaned
    assert "return 0;" in cleaned


def test_split_manager_leakage_prevention():
    samples = [
        VulnerabilitySample("s1", "void f1() { return 1; }", 0, project="proj_alpha", cve="CVE-1"),
        VulnerabilitySample("s2", "void f2() { return 2; }", 1, project="proj_alpha", cve="CVE-1"),
        VulnerabilitySample("s3", "void f3() { return 3; }", 0, project="proj_beta", cve="CVE-2"),
        VulnerabilitySample("s4", "void f4() { return 4; }", 1, project="proj_gamma", cve="CVE-3"),
        VulnerabilitySample("s5", "void f5() { return 5; }", 0, project="proj_delta", cve="CVE-4"),
    ]

    _train, _val, _test, report = SplitManager.project_aware_split(
        samples, train_ratio=0.5, val_ratio=0.25, test_ratio=0.25
    )
    assert report["is_leak_free"] is True
    assert report["project_leakage"]["train_test_project_overlap"] == 0
    assert report["cve_leakage"]["train_test_cve_overlap"] == 0


def test_tokenizer_wrapper():
    tok = CodeTokenizerWrapper(pretrained_model_name="microsoft/codebert-base", max_length=64)
    out = tok.tokenize_code("int main() { return 0; }")
    assert "input_ids" in out
    assert "attention_mask" in out
    assert out["input_ids"].shape == (1, 64)
