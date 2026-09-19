<div align="center">

# AutoSeal

### When a coding agent passes the test without solving the task, AutoSeal investigates why.

I am building AutoSeal as an ML and full-stack research platform. Its goal is to
detect evaluator reward hacking, preserve execution evidence, repair vulnerable
verifiers, and validate each repair through an independent audit.

**Built so far:** A reproducible false-reward experiment and a typed process runner.

**Working on next:** Timeouts and safe process termination.

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
        |
        +--> Vulnerable proxy: 7 skipped, exit 0, PASS
        |
        +--> Independent audit: 3 failed, exit 1, REJECT
```

That disagreement is the problem AutoSeal is being built to investigate.

## What the project is trying to answer

AutoSeal starts with a simple question: how can we tell whether a coding agent
actually solved a task or only found a weakness in the evaluator?

The long-term system will compare a proxy evaluator with an independent audit.
When their verdicts disagree, it will preserve the evidence, investigate the
cause, propose a safer verifier, and test the repair against both exploits and
legitimate solutions.

This complete pipeline is not built yet. I am developing it one tested layer at
a time, beginning with reproducible experiments and reliable process execution.

## How I am building it

Every project day has its own record under `research/`. Each record explains
what I built, why I built it, how it works, what the tests prove, what they do
not prove, and what I still need to improve.

Reusable code lives in `src/`, automated tests live in `tests/`, and runnable
examples live in `examples/`.

I want the repository to show the complete engineering journey, including the
mistakes, limitations, evidence, and decisions that shape the final system.
