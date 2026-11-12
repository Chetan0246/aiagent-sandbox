# Contributing to Aegis-Sandbox

Thank you for your interest in contributing to **Aegis-Sandbox**! This project welcomes contributions in AI agent boundary testing, hypervisor isolation, and Linux systems hardening.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Chetan0246/aiagent-sandbox.git
   cd aiagent-sandbox
   ```

2. Install in editable mode:
   ```bash
   pip install -e .
   ```

3. Run the unit test suite:
   ```bash
   python -m unittest discover -s tests
   ```

## Code of Conduct & Contribution Guidelines
* **Safety First**: Do not submit weaponized zero-day exploit payloads or destructive scripts. All probes should be self-reaping and designed for defensive boundary evaluation.
* **Empirical Integrity**: Submissions adding new benchmark data or probes must include reproduction steps, exit codes, and hardware specifications.
* **Testing**: Ensure all new probes have corresponding test cases in `tests/`.
