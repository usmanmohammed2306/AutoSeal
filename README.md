<div align="center">

# AutoSeal

### When a coding agent passes the test without solving the task, AutoSeal investigates why.

An ML and full-stack research platform for detecting evaluator reward hacking,
preserving execution evidence, repairing vulnerable verifiers,
and independently validating the repair.

**Current status:** Early research prototype — execution foundation under development

</div>

---

## The experiment that started AutoSeal

I began with a deliberately small programming task: implement a function that
determines whether an integer is even.

A correct solution passed all seven tests. An ordinary incorrect solution failed.
But the same incorrect solution, accompanied by a candidate-controlled Pytest
configuration, skipped every test and still caused Pytest to exit successfully.

The vulnerable evaluator awarded a pass. An independent audit rejected the same
solution.

```text
Incorrect candidate
        │
        ├── Vulnerable proxy ──► 7 skipped, exit 0 ──► PASS
        │
        └── Independent audit ─► 3 failed, exit 1 ──► REJECT
