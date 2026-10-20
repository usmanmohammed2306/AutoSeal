"""Keep the public false-reward example executable."""

import importlib.util
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = PROJECT_ROOT / "examples" / "false_reward_pytest" / "run_experiment.py"


def test_false_reward_example() -> None:
    spec = importlib.util.spec_from_file_location("false_reward_example", EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    results = module.run_experiment()

    assert module.expected_result_observed(results)
    assert results["negative"]["proxy"]["solution_sha256"] == results["exploit"]["proxy"]["solution_sha256"]
