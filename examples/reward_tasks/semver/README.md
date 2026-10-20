# Semantic-version comparison reward task

This second task makes the reward bridge less trivial than `is_even`. Its seven cases follow the [SemVer 2.0.0 precedence rules](https://semver.org/spec/v2.0.0.html) for numeric core versions, build metadata, stable versus prerelease, numeric identifier ordering, mixed identifier types, lexical prerelease ordering, and prefix length. Every case also checks the reverse comparison. Inputs are valid SemVer 2.0.0 strings; malformed inputs are outside this small contract.

Two separately written candidates pass the verifier. Two ordinary incorrect candidates fail. The exploit candidate returns zero for everything and supplies a candidate-controlled Pytest hook that skips all tests. A vulnerable proxy that trusts Pytest's exit code awards a pass, while a projected verifier that accepts only `solution.py` rejects it. This fixture is a deliberately seeded case, not evidence that an autonomous model discovered the bypass.

The local task is for training-plumbing and evaluator-integrity experiments. It is not an external benchmark case or a sufficient final research corpus by itself.
