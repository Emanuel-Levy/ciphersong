"""
Estimador de Tonalidade Musical / Escala (`senior-architect`).
Acumula as notas cantadas pelo usuário e utiliza os perfis cognitivos de
Krumhansl-Schmuckler para identificar em qual Tom (Maior ou Menor) o cantor está cantando.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np

from ciphersong.core.music_theory import (
    NOTE_NAMES_EN,
    NOTE_NAMES_PT,
    PitchNote,
    relative_minor_or_major,
)

# Perfis de Krumhansl-Kessler para tonalidades Maiores e Menores (C até B)
MAJOR_PROFILE = np.array(
    [6.35, 2.23, 3.48, 2.33, 4.38, 4.09, 2.52, 5.19, 2.39, 3.66, 2.29, 2.88],
    dtype=np.float64,
)
MINOR_PROFILE = np.array(
    [6.33, 2.68, 3.52, 5.38, 2.60, 3.53, 2.54, 4.75, 3.98, 2.69, 3.34, 3.17],
    dtype=np.float64,
)


@dataclass(frozen=True)
class KeyEstimation:
    """Representa a tonalidade musical estimada a partir do canto."""
    tonic_pitch_class: int
    is_major: bool
    key_en: str             # ex: "G Major" ou "Em"
    key_pt: str             # ex: "Sol Maior" ou "Mi Menor"
    relative_key_en: str    # ex: "Em"
    relative_key_pt: str    # ex: "Mi Menor"
    confidence: float       # 0.0 a 1.0 (percentual de certeza)
    samples_collected: int  # Quantidade de frames vocais analisados


class MusicalKeyEstimator:
    """
    Acumula um histograma cromático (12 classes de notas) com decaimento suave
    e estima o Tom Musical predominante da performance vocal.
    """

    def __init__(self, min_samples_for_estimation: int = 8, decay: float = 0.985) -> None:
        self.min_samples_for_estimation = min_samples_for_estimation
        self.decay = decay
        self._chroma_weights = np.zeros(12, dtype=np.float64)
        self._samples_count = 0

    @property
    def samples_count(self) -> int:
        return self._samples_count

    def reset(self) -> None:
        """Limpa o histórico de notas da sessão atual."""
        self._chroma_weights.fill(0.0)
        self._samples_count = 0

    def add_note(self, note: PitchNote) -> Optional[KeyEstimation]:
        """
        Registra uma nota cantada no histograma cromático.
        Notas mais afinadas (menor desvio em cents) recebem peso ligeiramente maior.
        """
        self._chroma_weights *= self.decay
        tuning_weight = max(0.4, 1.0 - (abs(note.cents_offset) / 60.0))
        self._chroma_weights[note.pitch_class] += tuning_weight
        self._samples_count += 1

        if self._samples_count < self.min_samples_for_estimation:
            return None

        return self.estimate_current_key()

    def estimate_current_key(self) -> Optional[KeyEstimation]:
        """Calcula a correlação de Pearson com as 24 escalas (12 Maiores e 12 Menores)."""
        if self._samples_count == 0 or np.sum(self._chroma_weights) <= 1e-6:
            return None

        best_score = -2.0
        second_best_score = -2.0
        best_tonic = 0
        best_is_major = True

        chroma_norm = self._chroma_weights - np.mean(self._chroma_weights)
        chroma_std = float(np.linalg.norm(chroma_norm))
        if chroma_std <= 1e-9:
            # Se apenas uma nota foi cantada repetidamente, assume o tom maior daquela tônica
            best_tonic = int(np.argmax(self._chroma_weights))
            rel_en, rel_pt = relative_minor_or_major(best_tonic, True)
            return KeyEstimation(
                tonic_pitch_class=best_tonic,
                is_major=True,
                key_en=f"{NOTE_NAMES_EN[best_tonic]}",
                key_pt=f"{NOTE_NAMES_PT[best_tonic]} Maior",
                relative_key_en=rel_en,
                relative_key_pt=rel_pt,
                confidence=0.65,
                samples_collected=self._samples_count,
            )

        for tonic in range(12):
            # Rotaciona o perfil para alinhar com a tônica testada
            maj_rot = np.roll(MAJOR_PROFILE, tonic)
            min_rot = np.roll(MINOR_PROFILE, tonic)

            maj_corr = float(
                np.dot(chroma_norm, maj_rot - np.mean(maj_rot))
                / (chroma_std * np.linalg.norm(maj_rot - np.mean(maj_rot)))
            )
            min_corr = float(
                np.dot(chroma_norm, min_rot - np.mean(min_rot))
                / (chroma_std * np.linalg.norm(min_rot - np.mean(min_rot)))
            )

            for corr, is_maj in ((maj_corr, True), (min_corr, False)):
                if corr > best_score:
                    second_best_score = best_score
                    best_score = corr
                    best_tonic = tonic
                    best_is_major = is_maj
                elif corr > second_best_score:
                    second_best_score = corr

        if best_is_major:
            key_en = f"{NOTE_NAMES_EN[best_tonic]}"
            key_pt = f"{NOTE_NAMES_PT[best_tonic]} Maior"
        else:
            key_en = f"{NOTE_NAMES_EN[best_tonic]}m"
            key_pt = f"{NOTE_NAMES_PT[best_tonic]} Menor"

        rel_en, rel_pt = relative_minor_or_major(best_tonic, best_is_major)

        # Normaliza confiança entre 0.50 e 0.99 com base na correlação e margem
        raw_conf = max(0.0, min(1.0, (best_score + 0.2) / 1.1))
        margin_boost = max(0.0, min(0.15, (best_score - second_best_score) * 0.5))
        confidence = round(min(0.99, max(0.45, raw_conf + margin_boost)), 2)

        return KeyEstimation(
            tonic_pitch_class=best_tonic,
            is_major=best_is_major,
            key_en=key_en,
            key_pt=key_pt,
            relative_key_en=rel_en,
            relative_key_pt=rel_pt,
            confidence=confidence,
            samples_collected=self._samples_count,
        )
