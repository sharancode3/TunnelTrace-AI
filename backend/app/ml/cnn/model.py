"""Lightweight 1D-CNN Sequence Classifier for Encrypted ESP Traffic."""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class Lightweight1DCNN(nn.Module):
    """Lightweight 1D-CNN with masked global average pooling for sequence traffic classification.

    Input shape: (Batch, 3, Sequence_Length)
        Channel 0: Direction (+1.0 fwd, -1.0 rev, 0.0 pad)
        Channel 1: Normalized packet length
        Channel 2: Delta time

    Mask shape: (Batch, Sequence_Length) boolean/float mask where True/1.0 indicates a valid packet.
    """

    def __init__(
        self,
        in_channels: int = 3,
        num_classes: int = 7,
        conv1_channels: int = 32,
        conv2_channels: int = 64,
        fc_hidden: int = 64,
        dropout_rate: float = 0.3,
    ) -> None:
        super().__init__()
        self.in_channels = in_channels
        self.num_classes = num_classes

        # Conv Block 1
        self.conv1 = nn.Conv1d(in_channels, conv1_channels, kernel_size=5, padding=2)
        self.bn1 = nn.BatchNorm1d(conv1_channels)

        # Conv Block 2
        self.conv2 = nn.Conv1d(conv1_channels, conv2_channels, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(conv2_channels)

        # Classifier Head
        self.fc1 = nn.Linear(conv2_channels, fc_hidden)
        self.dropout = nn.Dropout(p=dropout_rate)
        self.fc2 = nn.Linear(fc_hidden, num_classes)

    def forward(
        self,
        x: torch.Tensor,
        mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Forward pass computing raw class logits.

        Args:
            x: Tensor of shape (Batch, 3, N)
            mask: Optional Tensor of shape (Batch, N) indicating unpadded elements.

        Returns:
            Logits tensor of shape (Batch, num_classes)
        """
        # Conv Block 1
        out = F.relu(self.bn1(self.conv1(x)))

        # Conv Block 2
        out = F.relu(self.bn2(self.conv2(out)))

        # Masked Global Average Pooling
        if mask is not None:
            # mask shape: (B, N) -> (B, 1, N)
            m = mask.unsqueeze(1).float()
            out = out * m
            sum_pooled = out.sum(dim=2)  # (B, C)
            valid_lengths = m.sum(dim=2).clamp(min=1.0)  # (B, 1)
            pooled = sum_pooled / valid_lengths
        else:
            pooled = out.mean(dim=2)

        # Classifier Head
        feat = F.relu(self.fc1(pooled))
        feat = self.dropout(feat)
        logits = self.fc2(feat)
        return logits

    @torch.jit.export
    def predict_proba(
        self,
        x: torch.Tensor,
        mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Compute softmax probabilities across classes."""
        logits = self.forward(x, mask)
        return F.softmax(logits, dim=1)
