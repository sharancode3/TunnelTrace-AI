# Root Integration & End-to-End Test Suite — TunnelTrace AI

This directory is reserved for cross-subsystem integration, regression, and End-to-End (E2E) verification tests.

## Test Scope
- Subsystem-specific unit and integration tests are co-located within `backend/tests/`.
- Full-system integration, golden PCAP replays, and closed-loop testbed remediation verification suites reside here.

## Execution Rules
- All tests adhere strictly to the verification principles defined in `docs/requirements/TESTING_VALIDATION_PLAN.md`.
- No mock or test fixture may fake success without real assertion logic.
