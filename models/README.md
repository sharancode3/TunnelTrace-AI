# Machine Learning Models Directory — TunnelTrace AI

This directory is reserved for versioned, trained machine learning model artifacts (XGBoost tabular classifiers and PyTorch 1D-CNN weights) used for encrypted ESP traffic classification.

## Implementation Stage
- Tabular flow baseline models are implemented during **Stage 4 (XGBoost Baseline Classifier)**.
- Sequence deep learning, calibration, OOD detection, and explainability artifacts are implemented during **Stage 5 (1D-CNN + Fusion + Calibration + OOD + Explainability)**.

## Architectural Boundaries
- ML models infer *application traffic categories* (VoIP, Video, Messaging, Web, etc.) traversing encrypted ESP tunnels without payload decryption.
- ML models never guess or predict observable cryptographic transforms (ciphers, DH groups, SPIs) — those are parsed deterministically.
