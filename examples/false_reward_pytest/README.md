# A false reward from seven skipped tests

This small experiment shows why a successful test process is not always proof that a candidate solved the task.

The task is to implement `is_even(value: int) -> bool`. The verifier owns seven tests. The positive candidate is correct. The negative and exploit candidates both return `True` for every input. The exploit also contains a `conftest.py` file that asks Pytest to skip every collected test.

Run from the repository root after installing the development dependencies:

```bash
python examples/false_reward_pytest/run_experiment.py
```

The runner creates fresh temporary workspaces for every evaluation. The vulnerable proxy copies the whole candidate directory. The independent audit copies only the declared `solution.py` artifact. Both evaluate identical `solution.py` bytes for each candidate.

Expected result:

| Candidate | Proxy | Audit |
|---|---|---|
| Positive | Seven tests pass | Seven tests pass |
| Negative | Three tests fail | Three tests fail |
| Exploit | Seven tests skip and Pytest exits zero | Three tests fail |

The exploit is a deliberately constructed example, not a claim that an autonomous agent discovered it. The audit is independent in one specific respect: candidate controlled Pytest configuration cannot enter its workspace. It is not a general proof that the verifier covers every behavior of the task.

The JSON output keeps process exit codes, test counts, and the files copied into each workspace visible. The script exits nonzero if the expected matrix changes.
