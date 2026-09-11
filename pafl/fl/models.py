"""Detectors. Small on purpose.

The paper's claim is about admission control, not about squeezing the last
point of F1 out of an architecture. Small models also make the federated sweep
cheap and let many runs share one GPU, which is the main cost lever on both
Colab and AWS.
"""
from __future__ import annotations
import numpy as np
import torch
import torch.nn as nn


class WindowAE(nn.Module):
    """Dense autoencoder over a flattened window of process telemetry."""

    def __init__(self, n_channels: int, window: int, hidden: int = 128, latent: int = 24):
        super().__init__()
        self.n_channels, self.window = n_channels, window
        d = n_channels * window
        self.encoder = nn.Sequential(
            nn.Linear(d, hidden), nn.ReLU(),
            nn.Linear(hidden, latent), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent, hidden), nn.ReLU(),
            nn.Linear(hidden, d),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    @torch.no_grad()
    def score(self, x: torch.Tensor) -> torch.Tensor:
        """Reconstruction error per sample: the anomaly score."""
        return ((self.forward(x) - x) ** 2).mean(dim=1)


class GRUAE(nn.Module):
    """Sequence autoencoder. Slower, and closer to what the ICS literature uses."""

    def __init__(self, n_channels: int, window: int, hidden: int = 64, layers: int = 1):
        super().__init__()
        self.n_channels, self.window = n_channels, window
        self.enc = nn.GRU(n_channels, hidden, layers, batch_first=True)
        self.dec = nn.GRU(hidden, hidden, layers, batch_first=True)
        self.out = nn.Linear(hidden, n_channels)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        b = x.shape[0]
        seq = x.view(b, self.window, self.n_channels)
        _, h = self.enc(seq)
        rep = h[-1].unsqueeze(1).repeat(1, self.window, 1)
        y, _ = self.dec(rep)
        return self.out(y).reshape(b, -1)

    @torch.no_grad()
    def score(self, x: torch.Tensor) -> torch.Tensor:
        return ((self.forward(x) - x) ** 2).mean(dim=1)


MODELS = {"window_ae": WindowAE, "gru_ae": GRUAE}


def build_model(name: str, n_channels: int, window: int, **kw) -> nn.Module:
    if name not in MODELS:
        raise KeyError(f"unknown model {name!r}; choose from {sorted(MODELS)}")
    return MODELS[name](n_channels=n_channels, window=window, **kw)


def get_flat_params(model: nn.Module) -> torch.Tensor:
    return torch.cat([p.detach().reshape(-1) for p in model.parameters()])


def set_flat_params(model: nn.Module, flat: torch.Tensor) -> None:
    i = 0
    for p in model.parameters():
        n = p.numel()
        p.data.copy_(flat[i:i + n].view_as(p))
        i += n


def n_params(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters())
