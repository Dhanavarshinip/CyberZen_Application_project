"""
Deep Autoencoder Anomaly Detector for CyberThreat AI System.

Implements PyTorch-based Deep Learning Autoencoder for non-linear telemetry reconstruction:
Architecture:
- Input Dimension D (Telemetry Feature Vector)
- Dense Encoder: Linear(D -> 16) -> LeakyReLU(0.2) -> Linear(16 -> 8) (Latent Bottleneck)
- Dense Decoder: Linear(8 -> 16) -> LeakyReLU(0.2) -> Linear(16 -> D)
- Loss: Mean Squared Error (MSE) Reconstruction Loss:
  L(x, x_hat) = (1/D) * sum((x_j - x_hat_j)^2)

Anomalies exhibit higher reconstruction error due to rare feature correlations
unseen during baseline training.
"""

import os
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import Dict, Any, List, Optional


class AutoencoderNet(nn.Module):
    """Deep Autoencoder neural network with bottleneck representation."""

    def __init__(self, input_dim: int = 10, latent_dim: int = 8):
        super(AutoencoderNet, self).__init__()
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.LeakyReLU(0.2),
            nn.Linear(16, latent_dim),
            nn.LeakyReLU(0.2)
        )
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 16),
            nn.LeakyReLU(0.2),
            nn.Linear(16, input_dim)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed


class DeepAutoencoderAnomalyDetector:
    """
    Deep Learning Anomaly Detector using PyTorch Autoencoder reconstruction loss.
    """

    def __init__(self, input_dim: int = 10, threshold_percentile: float = 95.0, lr: float = 0.005):
        self.input_dim = input_dim
        self.threshold_percentile = threshold_percentile
        self.lr = lr
        self.model = AutoencoderNet(input_dim=input_dim, latent_dim=8)
        self.criterion = nn.MSELoss()
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.lr, weight_decay=1e-5)
        self.is_trained = False
        self.reconstruction_threshold = 0.15  # Default baseline threshold
        self.feature_means = None
        self.feature_stds = None

    def _normalize(self, X: np.ndarray) -> np.ndarray:
        """Z-score normalization based on learned baseline parameters."""
        if self.feature_means is None:
            self.feature_means = np.mean(X, axis=0)
            self.feature_stds = np.std(X, axis=0)
            self.feature_stds[self.feature_stds == 0.0] = 1.0  # Prevent div by zero
        return (X - self.feature_means) / self.feature_stds

    def train(self, features_list: List[List[float]], epochs: int = 40, batch_size: int = 32):
        """
        Trains the Autoencoder on normal baseline feature vectors.
        """
        if not features_list or len(features_list) < 5:
            return

        X_raw = np.array(features_list, dtype=np.float32)
        self.input_dim = X_raw.shape[1]
        self.model = AutoencoderNet(input_dim=self.input_dim, latent_dim=max(4, self.input_dim // 2))
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.lr)

        X_norm = self._normalize(X_raw)
        dataset = torch.tensor(X_norm, dtype=torch.float32)

        self.model.train()
        for epoch in range(epochs):
            permutation = torch.randperm(dataset.size(0))
            for i in range(0, dataset.size(0), batch_size):
                indices = permutation[i:i + batch_size]
                batch = dataset[indices]

                self.optimizer.zero_grad()
                reconstructed = self.model(batch)
                loss = self.criterion(reconstructed, batch)
                loss.backward()
                self.optimizer.step()

        # Compute empirical threshold on training set
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(dataset)
            errors = torch.mean((dataset - reconstructed) ** 2, dim=1).numpy()
            self.reconstruction_threshold = float(np.percentile(errors, self.threshold_percentile))

        self.is_trained = True

    def predict_anomaly(self, feature_vector: List[float]) -> Dict[str, Any]:
        """
        Evaluates reconstruction loss for a single feature vector.
        Returns: normalized anomaly score (0-100), raw loss, is_anomaly boolean.
        """
        x_raw = np.array([feature_vector], dtype=np.float32)

        if not self.is_trained:
            # Fallback heuristic if not yet trained
            heuristic = min(1.0, max(0.0, float(np.mean(feature_vector)) / 100.0))
            return {
                "raw_reconstruction_loss": heuristic,
                "reconstruction_threshold": 0.5,
                "anomaly_score": round(heuristic * 100.0, 2),
                "is_anomaly": heuristic >= 0.5,
                "model_type": "deep_autoencoder_untrained"
            }

        x_norm = (x_raw - self.feature_means) / self.feature_stds
        x_tensor = torch.tensor(x_norm, dtype=torch.float32)

        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(x_tensor)
            mse_loss = float(torch.mean((x_tensor - reconstructed) ** 2).item())

        # Scale anomaly score: 0-100 where 50 is threshold
        ratio = mse_loss / max(0.001, self.reconstruction_threshold)
        if ratio <= 1.0:
            score = ratio * 50.0  # 0 to 50 for normal
        else:
            score = min(100.0, 50.0 + (ratio - 1.0) * 25.0)  # 50 to 100 for anomaly

        return {
            "raw_reconstruction_loss": round(mse_loss, 5),
            "reconstruction_threshold": round(self.reconstruction_threshold, 5),
            "anomaly_score": round(score, 2),
            "is_anomaly": mse_loss >= self.reconstruction_threshold,
            "model_type": "deep_autoencoder_pytorch"
        }

    def save(self, filepath: str):
        """Save PyTorch Deep Autoencoder weights and normalization parameters."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        torch.save({
            "model_state": self.model.state_dict(),
            "input_dim": self.input_dim,
            "threshold": self.reconstruction_threshold,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "is_trained": self.is_trained
        }, filepath)

    def load(self, filepath: str) -> bool:
        """Load PyTorch Deep Autoencoder weights from disk."""
        if os.path.exists(filepath):
            try:
                checkpoint = torch.load(filepath, weights_only=False)
                self.input_dim = checkpoint["input_dim"]
                self.model = AutoencoderNet(input_dim=self.input_dim, latent_dim=max(4, self.input_dim // 2))
                self.model.load_state_dict(checkpoint["model_state"])
                self.reconstruction_threshold = checkpoint["threshold"]
                self.feature_means = checkpoint["feature_means"]
                self.feature_stds = checkpoint["feature_stds"]
                self.is_trained = checkpoint["is_trained"]
                return True
            except Exception:
                return False
        return False
