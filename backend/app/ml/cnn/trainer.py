"""PyTorch 1D-CNN Sequence Classifier Training & Horizon Selection Pipeline."""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import f1_score
from torch.utils.data import DataLoader, Dataset

from app.ml.cnn.model import Lightweight1DCNN
from app.ml.sequence_schema import SequenceSchema


class SequenceTensorDataset(Dataset):
    """PyTorch Dataset wrapping 3D sequence arrays, masks, and class labels."""

    def __init__(
        self,
        tensors: np.ndarray,  # (N_samples, 3, Horizon)
        masks: np.ndarray,  # (N_samples, Horizon)
        labels: np.ndarray,  # (N_samples,)
        weights: np.ndarray | None = None,  # (N_samples,)
    ) -> None:
        self.tensors = torch.tensor(tensors, dtype=torch.float32)
        self.masks = torch.tensor(masks, dtype=torch.bool)
        self.labels = torch.tensor(labels, dtype=torch.long)
        self.weights = torch.tensor(weights, dtype=torch.float32) if weights is not None else None

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        item = {
            "tensor": self.tensors[idx],
            "mask": self.masks[idx],
            "label": self.labels[idx],
        }
        if self.weights is not None:
            item["weight"] = self.weights[idx]
        return item


@dataclass
class CNNTrainingConfig:
    """Hyperparameters for 1D-CNN sequence model training."""

    epochs: int = 35
    batch_size: int = 16
    learning_rate: float = 0.002
    weight_decay: float = 1e-4
    early_stopping_patience: int = 8
    device: str = "cpu"
    random_seed: int = 42
    candidate_horizons: list[int] = field(default_factory=lambda: [32, 64, 128])
    conv1_channels: int = 32
    conv2_channels: int = 64
    fc_hidden: int = 64
    dropout_rate: float = 0.3


class CNNTrainer:
    """Trains 1D-CNN sequence classifiers, evaluates candidate horizons, and exports TorchScript models."""

    def __init__(
        self,
        schema: SequenceSchema | None = None,
        config: CNNTrainingConfig | None = None,
    ) -> None:
        self.schema = schema or SequenceSchema()
        self.config = config or CNNTrainingConfig()

    def set_seed(self, seed: int) -> None:
        """Seed random number generators for reproducible training."""
        np.random.seed(seed)
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)

    def train_single_horizon(
        self,
        train_dataset: SequenceTensorDataset,
        val_dataset: SequenceTensorDataset,
        num_classes: int = 7,
    ) -> tuple[Lightweight1DCNN, dict[str, Any]]:
        """Train a Lightweight1DCNN for a single horizon N with validation early stopping.

        Returns:
            tuple of (best_model, training_metrics_dict)
        """
        self.set_seed(self.config.random_seed)
        device = torch.device(self.config.device)

        model = Lightweight1DCNN(
            in_channels=3,
            num_classes=num_classes,
            conv1_channels=self.config.conv1_channels,
            conv2_channels=self.config.conv2_channels,
            fc_hidden=self.config.fc_hidden,
            dropout_rate=self.config.dropout_rate,
        ).to(device)

        # Compute train-only class weights if imbalance exists
        labels_train = train_dataset.labels.numpy()
        unique_classes, counts = np.unique(labels_train, return_counts=True)
        class_weights = torch.ones(num_classes, dtype=torch.float32, device=device)
        total_samples = len(labels_train)
        for c, cnt in zip(unique_classes, counts, strict=False):
            if c < num_classes:
                class_weights[c] = total_samples / (len(unique_classes) * float(cnt))

        criterion = nn.CrossEntropyLoss(weight=class_weights)
        optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )

        train_loader = DataLoader(
            train_dataset,
            batch_size=self.config.batch_size,
            shuffle=True,
            drop_last=False,
        )

        best_val_f1 = -1.0
        best_val_loss = float("inf")
        best_state = copy.deepcopy(model.state_dict())
        epochs_no_improve = 0
        history: list[dict[str, float]] = []

        start_time = time.perf_counter()

        for epoch in range(1, self.config.epochs + 1):
            model.train()
            total_train_loss = 0.0
            train_batches = 0

            for batch in train_loader:
                x = batch["tensor"].to(device)
                m = batch["mask"].to(device)
                y = batch["label"].to(device)

                optimizer.zero_grad()
                logits = model(x, m)
                loss = criterion(logits, y)
                loss.backward()
                optimizer.step()

                total_train_loss += float(loss.item())
                train_batches += 1

            avg_train_loss = total_train_loss / max(1, train_batches)

            # Evaluate on validation
            val_loss, val_f1, _ = self.evaluate(model, val_dataset, criterion, device)

            history.append({
                "epoch": epoch,
                "train_loss": avg_train_loss,
                "val_loss": val_loss,
                "val_macro_f1": val_f1,
            })

            # Early stopping check (Macro-F1 primary, val loss tie-breaker)
            if val_f1 > best_val_f1 or (abs(val_f1 - best_val_f1) < 1e-4 and val_loss < best_val_loss):
                best_val_f1 = val_f1
                best_val_loss = val_loss
                best_state = copy.deepcopy(model.state_dict())
                epochs_no_improve = 0
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= self.config.early_stopping_patience:
                    break

        training_duration = time.perf_counter() - start_time

        # Load best state
        model.load_state_dict(best_state)
        model.eval()

        # Final evaluation with best state
        final_val_loss, final_val_f1, val_preds = self.evaluate(model, val_dataset, criterion, device)

        metrics = {
            "best_epoch": len(history) - epochs_no_improve,
            "total_epochs": len(history),
            "final_val_loss": final_val_loss,
            "final_val_macro_f1": final_val_f1,
            "training_duration_sec": training_duration,
            "history": history,
        }

        return model, metrics

    def evaluate(
        self,
        model: Lightweight1DCNN,
        dataset: SequenceTensorDataset,
        criterion: nn.Module | None = None,
        device: torch.device | None = None,
    ) -> tuple[float, float, np.ndarray]:
        """Evaluate model on a dataset, returning (loss, macro_f1, predictions)."""
        dev = device or torch.device(self.config.device)
        model.eval()

        loader = DataLoader(dataset, batch_size=self.config.batch_size, shuffle=False)
        all_preds = []
        all_targets = []
        total_loss = 0.0
        batches = 0

        with torch.no_grad():
            for batch in loader:
                x = batch["tensor"].to(dev)
                m = batch["mask"].to(dev)
                y = batch["label"].to(dev)

                logits = model(x, m)
                if criterion is not None:
                    loss = criterion(logits, y)
                    total_loss += float(loss.item())
                    batches += 1

                preds = torch.argmax(logits, dim=1).cpu().numpy()
                all_preds.extend(preds)
                all_targets.extend(y.cpu().numpy())

        avg_loss = (total_loss / max(1, batches)) if batches > 0 else 0.0
        macro_f1 = float(f1_score(all_targets, all_preds, average="macro", zero_division=0))
        return avg_loss, macro_f1, np.array(all_preds)

    def predict_proba(
        self,
        model: Lightweight1DCNN,
        tensors: np.ndarray,
        masks: np.ndarray,
    ) -> np.ndarray:
        """Compute softmax probability matrix of shape (N_samples, 7)."""
        device = torch.device(self.config.device)
        model.eval()
        t_tensors = torch.tensor(tensors, dtype=torch.float32, device=device)
        t_masks = torch.tensor(masks, dtype=torch.bool, device=device)

        with torch.no_grad():
            probs = model.predict_proba(t_tensors, t_masks)
            return probs.cpu().numpy()

    def evaluate_candidate_horizons(
        self,
        raw_train_packets_by_flow: list[list[dict[str, Any]]],
        train_labels: np.ndarray,
        raw_val_packets_by_flow: list[list[dict[str, Any]]],
        val_labels: np.ndarray,
        extractor: Any,
        horizons: list[int] | None = None,
    ) -> dict[str, Any]:
        """Train and evaluate 1D-CNN candidates across N in {32, 64, 128} on validation evidence."""
        target_horizons = horizons or self.config.candidate_horizons
        results: dict[int, dict[str, Any]] = {}
        models: dict[int, Lightweight1DCNN] = {}

        best_horizon = target_horizons[0]
        best_f1 = -1.0

        for N in target_horizons:
            # Extract train tensors for horizon N
            train_tensors = []
            train_masks = []
            for pkts in raw_train_packets_by_flow:
                t, m, _ = extractor.extract_sequence(pkts, N=N)
                train_tensors.append(t)
                train_masks.append(m)

            # Extract val tensors for horizon N
            val_tensors = []
            val_masks = []
            val_durations = []
            val_actual_lens = []
            for pkts in raw_val_packets_by_flow:
                t, m, meta = extractor.extract_sequence(pkts, N=N)
                val_tensors.append(t)
                val_masks.append(m)
                val_durations.append(meta["duration_ms"])
                val_actual_lens.append(meta["actual_length"])

            train_ds = SequenceTensorDataset(np.array(train_tensors), np.array(train_masks), train_labels)
            val_ds = SequenceTensorDataset(np.array(val_tensors), np.array(val_masks), val_labels)

            model, metrics = self.train_single_horizon(train_ds, val_ds)
            models[N] = model

            # Calculate empirical time-to-decision metrics
            mean_decision_packets = float(np.mean(val_actual_lens)) if val_actual_lens else 0.0
            mean_decision_ms = float(np.mean(val_durations)) if val_durations else 0.0

            cand_result = {
                "horizon_N": N,
                "val_macro_f1": metrics["final_val_macro_f1"],
                "val_loss": metrics["final_val_loss"],
                "mean_packets_needed": mean_decision_packets,
                "mean_time_to_decision_ms": mean_decision_ms,
                "training_duration_sec": metrics["training_duration_sec"],
            }
            results[N] = cand_result

            if cand_result["val_macro_f1"] > best_f1:
                best_f1 = cand_result["val_macro_f1"]
                best_horizon = N

        return {
            "candidates": results,
            "selected_horizon": best_horizon,
            "selected_model": models[best_horizon],
            "selection_rationale": f"Selected N={best_horizon} based on validation Macro-F1={best_f1:.4f}",
        }

    def export_torchscript(
        self,
        model: Lightweight1DCNN,
        output_path: Path,
    ) -> Path:
        """Export Lightweight1DCNN model as a TorchScript artifact (.pt)."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        model.eval()
        scripted_model = torch.jit.script(model)
        torch.jit.save(scripted_model, str(output_path))
        return output_path

    @staticmethod
    def load_torchscript(model_path: Path) -> torch.jit.ScriptModule:
        """Load a TorchScript model artifact without using arbitrary pickle."""
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        return torch.jit.load(str(model_path), map_location=torch.device("cpu"))
