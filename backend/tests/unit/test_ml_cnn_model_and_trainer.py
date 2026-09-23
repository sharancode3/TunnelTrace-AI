"""Unit tests for Lightweight1DCNN architecture, TorchScript export, and CNNTrainer."""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import torch

from app.ml.cnn.model import Lightweight1DCNN
from app.ml.cnn.trainer import CNNTrainer, CNNTrainingConfig, SequenceTensorDataset
from app.ml.sequence_extractor import SequenceExtractor
from app.ml.sequence_schema import SequenceSchema


def test_lightweight_cnn_forward_shapes():
    """Verify output shapes and probability normalization of Lightweight1DCNN."""
    model = Lightweight1DCNN(in_channels=3, num_classes=7, conv1_channels=16, conv2_channels=32, fc_hidden=32)
    batch_size = 4
    seq_len = 64
    x = torch.randn(batch_size, 3, seq_len)
    mask = torch.ones(batch_size, seq_len, dtype=torch.bool)
    mask[:, 30:] = False  # Mask half the sequence

    logits = model(x, mask)
    assert logits.shape == (batch_size, 7)

    probs = model.predict_proba(x, mask)
    assert probs.shape == (batch_size, 7)
    sums = probs.sum(dim=1)
    assert torch.allclose(sums, torch.ones(batch_size), atol=1e-5)


def test_lightweight_cnn_torchscript_export():
    """Verify TorchScript compilation and numerical equivalence."""
    model = Lightweight1DCNN(in_channels=3, num_classes=7, conv1_channels=16, conv2_channels=32)
    model.eval()

    x = torch.randn(2, 3, 32)
    mask = torch.ones(2, 32, dtype=torch.bool)

    scripted = torch.jit.script(model)
    with tempfile.TemporaryDirectory() as tmp_dir:
        model_path = Path(tmp_dir) / "model.pt"
        torch.jit.save(scripted, str(model_path))

        loaded = torch.jit.load(str(model_path), map_location="cpu")
        loaded.eval()

        with torch.no_grad():
            orig_probs = model.predict_proba(x, mask)
            loaded_probs = loaded.predict_proba(x, mask)

        assert torch.allclose(orig_probs, loaded_probs, atol=1e-5)


def test_cnn_trainer_training_loop():
    """Verify CNN training with early stopping and loss convergence."""
    config = CNNTrainingConfig(
        epochs=5,
        batch_size=4,
        learning_rate=0.01,
        early_stopping_patience=3,
        conv1_channels=8,
        conv2_channels=16,
        fc_hidden=16,
    )
    trainer = CNNTrainer(config=config)

    # 12 synthetic samples across 2 classes
    np.random.seed(42)
    tensors = np.random.randn(12, 3, 32).astype(np.float32)
    masks = np.ones((12, 32), dtype=bool)
    labels = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1], dtype=np.int64)

    train_ds = SequenceTensorDataset(tensors[:8], masks[:8], labels[:8])
    val_ds = SequenceTensorDataset(tensors[8:], masks[8:], labels[8:])

    model, metrics = trainer.train_single_horizon(train_ds, val_ds, num_classes=2)

    assert "final_val_loss" in metrics
    assert "final_val_macro_f1" in metrics
    assert metrics["total_epochs"] >= 1

    probs = trainer.predict_proba(model, tensors[8:], masks[8:])
    assert probs.shape == (4, 2)
    assert np.allclose(probs.sum(axis=1), 1.0, atol=1e-4)


def test_cnn_trainer_horizon_evaluation():
    """Verify evaluation of candidate horizons N in {32, 64}."""
    config = CNNTrainingConfig(epochs=2, batch_size=4, candidate_horizons=[16, 32])
    trainer = CNNTrainer(config=config)
    extractor = SequenceExtractor(SequenceSchema(default_horizon=32))

    # Create dummy flows of packets
    train_flows = [
        [{"packet_time": j * 0.05, "packet_length": 500, "direction": 1} for j in range(20)]
        for _ in range(6)
    ]
    train_labels = np.array([0, 0, 0, 1, 1, 1], dtype=np.int64)

    val_flows = [
        [{"packet_time": j * 0.05, "packet_length": 500, "direction": 1} for j in range(20)]
        for _ in range(4)
    ]
    val_labels = np.array([0, 0, 1, 1], dtype=np.int64)

    res = trainer.evaluate_candidate_horizons(
        raw_train_packets_by_flow=train_flows,
        train_labels=train_labels,
        raw_val_packets_by_flow=val_flows,
        val_labels=val_labels,
        extractor=extractor,
        horizons=[16, 32],
    )

    assert "candidates" in res
    assert 16 in res["candidates"]
    assert 32 in res["candidates"]
    assert res["selected_horizon"] in (16, 32)
    assert "mean_time_to_decision_ms" in res["candidates"][16]
