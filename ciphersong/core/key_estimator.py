"""
Estimador Avançado de Tonalidade Musical / Escala (`senior-architect`).

Recursos Implementados:
1. Perfis Cognitivos de Tonalidade Otimizados (Krumhansl-Schmuckler + Temperley).
2. Ponderação por Estabilidade Vocal (afinação firme ganha maior peso).
3. Histerese de Tonalidade (Key Locking).
4. Estimativa do 2º e 3º Tons Mais Prováveis (Runner-up Keys) para exibição em círculos auxiliares.
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

# Perfis Otimizados de Krumhansl-Temperley com calibração harmônica e modal
# [I, bII, II, bIII, III, IV, bV, V, bVI, VI, bVII, VII]
MAJOR_PROFILE = np.array(
    [6.50, 1.60, 3.50, 1.60, 4.80, 3.60, 1.60, 4.80, 1.60, 3.60, 1.60, 3.20],
    dtype=np.float64,
)
# Perfil Menor com 3ª menor marcante (5.40), sensível harmônica (3.60) e 5ª atenuada (4.30)
# para evitar que a dominante (ex: Mi em Am) seja confundida com a tônica
MINOR_PROFILE = np.array(
    [6.60, 1.60, 3.50, 5.40, 1.60, 3.60, 1.60, 4.30, 3.80, 1.60, 3.40, 3.60],
    dtype=np.float64,
)


def _build_unit_profile_matrix(base_profile: np.ndarray) -> np.ndarray:
    """Pré-calcula as 12 rotações centradas e normalizadas (norma L2 = 1) para correlação rápida."""
    centered = base_profile - np.mean(base_profile)
    unit = centered / float(np.linalg.norm(centered))
    return np.array([np.roll(unit, tonic) for tonic in range(12)], dtype=np.float64)


_MAJOR_UNIT_PROFILES = _build_unit_profile_matrix(MAJOR_PROFILE)
_MINOR_UNIT_PROFILES = _build_unit_profile_matrix(MINOR_PROFILE)


@dataclass(frozen=True)
class KeyEstimation:
    """Representa a tonalidade musical estimada a partir do canto e os tons alternativos mais prováveis."""
    tonic_pitch_class: int
    is_major: bool
    key_en: str             # ex: "G" ou "Em"
    key_pt: str             # ex: "Sol Maior" ou "Mi Menor"
    relative_key_en: str    # ex: "Em"
    relative_key_pt: str    # ex: "Mi Menor"
    confidence: float       # 0.0 a 1.0 (percentual de certeza do 1º tom)
    samples_collected: int  # Quantidade de frames vocais analisados
    # 2º Tom mais provável
    second_key_en: str = ""
    second_key_pt: str = ""
    second_confidence: float = 0.0
    # 3º Tom mais provável
    third_key_en: str = ""
    third_key_pt: str = ""
    third_confidence: float = 0.0


class MusicalKeyEstimator:
    """
    Acumula um histograma cromático (12 classes de notas) com decaimento suave
    e estima o 1º, 2º e 3º Tons Musicais mais prováveis da melodia.
    """

    def __init__(self, min_samples_for_estimation: int = 5, decay: float = 0.988) -> None:
        self.min_samples_for_estimation = min_samples_for_estimation
        self.decay = decay
        self._chroma_weights = np.zeros(12, dtype=np.float64)
        self._samples_count = 0
        self._locked_key: Optional[KeyEstimation] = None
        self._locked_score: float = -1.0

    @property
    def samples_count(self) -> int:
        return self._samples_count

    def reset(self) -> None:
        """Limpa o histórico de notas e o tom travado da sessão atual."""
        self._chroma_weights.fill(0.0)
        self._samples_count = 0
        self._locked_key = None
        self._locked_score = -1.0

    def add_note(self, note: PitchNote) -> Optional[KeyEstimation]:
        """
        Registra uma nota cantada no histograma cromático.
        Notas mais afinadas (menor desvio em cents) recebem peso significativamente maior.
        """
        self._chroma_weights *= self.decay

        abs_cents = abs(note.cents_offset)
        if abs_cents <= 18.0:
            tuning_weight = 1.4
        elif abs_cents <= 35.0:
            tuning_weight = 1.0
        else:
            tuning_weight = 0.45

        self._chroma_weights[note.pitch_class] += tuning_weight
        self._samples_count += 1

        if self._samples_count < self.min_samples_for_estimation:
            return None

        return self.estimate_current_key()

    def estimate_current_key(self) -> Optional[KeyEstimation]:
        """Calcula a correlação de Pearson com as 24 escalas e ranqueia as 3 mais prováveis."""
        if self._samples_count == 0 or np.sum(self._chroma_weights) <= 1e-6:
            return None

        # 1. Compressão perceptiva logarítmica:
        # Suaviza a saturação de notas longas sustentadas (evita que segurar uma 5ª, como Mi em Am,
        # sufoque as demais notas da melodia).
        effective_chroma = np.log1p(self._chroma_weights * 2.5)

        chroma_norm = effective_chroma - np.mean(effective_chroma)
        chroma_std = float(np.linalg.norm(chroma_norm))
        if chroma_std <= 1e-9:
            best_tonic = int(np.argmax(self._chroma_weights))
            rel_en, rel_pt = relative_minor_or_major(best_tonic, True)
            return KeyEstimation(
                tonic_pitch_class=best_tonic,
                is_major=True,
                key_en=f"{NOTE_NAMES_EN[best_tonic]}",
                key_pt=f"{NOTE_NAMES_PT[best_tonic]} Maior",
                relative_key_en=rel_en,
                relative_key_pt=rel_pt,
                confidence=0.70,
                samples_collected=self._samples_count,
            )

        # 2. Avalia correlação vetorizada com todos os 24 tons possíveis (12 Maiores e 12 Menores)
        chroma_unit = chroma_norm / chroma_std
        maj_corrs = _MAJOR_UNIT_PROFILES @ chroma_unit
        min_corrs = _MINOR_UNIT_PROFILES @ chroma_unit

        scores: dict[tuple[int, bool], float] = {}
        for tonic in range(12):
            scores[(tonic, True)] = float(maj_corrs[tonic])
            scores[(tonic, False)] = float(min_corrs[tonic])

        # Ordena todos os 24 tons por pontuação decrescente
        sorted_pairs = sorted(scores.items(), key=lambda item: item[1], reverse=True)

        (best_tonic, best_is_major), best_score = sorted_pairs[0]
        second_best_score = sorted_pairs[1][1] if len(sorted_pairs) > 1 else best_score

        # 3. Verificação de diversidade melódica (mínimo de notas distintas cantadas)
        distinct_notes = int(np.sum(self._chroma_weights >= 0.7))

        # Histerese dinâmica: se já temos um tom detectado e validado por melodia,
        # exige confirmação da transição para um novo tom
        if self._locked_key is not None and distinct_notes >= 3:
            current_pair = (self._locked_key.tonic_pitch_class, self._locked_key.is_major)
            curr_score = scores.get(current_pair, -1.0)
            if best_score < curr_score + 0.06:
                best_tonic = self._locked_key.tonic_pitch_class
                best_is_major = self._locked_key.is_major
                best_score = max(curr_score, best_score)

        if best_is_major:
            key_en = f"{NOTE_NAMES_EN[best_tonic]}"
            key_pt = f"{NOTE_NAMES_PT[best_tonic]} Maior"
        else:
            key_en = f"{NOTE_NAMES_EN[best_tonic]}m"
            key_pt = f"{NOTE_NAMES_PT[best_tonic]} Menor"

        rel_en, rel_pt = relative_minor_or_major(best_tonic, best_is_major)

        # Confiança do 1º tom ajustada pela diversidade de notas
        raw_conf = max(0.0, min(1.0, (best_score + 0.25) / 1.15))
        margin = max(0.0, best_score - second_best_score)
        calculated_conf = round(min(0.99, max(0.50, raw_conf + (margin * 0.4))), 2)

        # Se houver poucas notas distintas (ex: apenas a nota inicial 'Eu...' segurada),
        # a confiança não trava falso positivo até a melodia desenvolver
        if distinct_notes < 3:
            confidence = min(0.60, calculated_conf)
        else:
            confidence = calculated_conf

        # Identifica o 2º e o 3º tom mais prováveis (diferentes do 1º tom)
        runner_ups: list[tuple[str, str, float]] = []
        for (cand_tonic, cand_is_maj), cand_score in sorted_pairs:
            if (cand_tonic, cand_is_maj) == (best_tonic, best_is_major):
                continue
            cand_en = f"{NOTE_NAMES_EN[cand_tonic]}" if cand_is_maj else f"{NOTE_NAMES_EN[cand_tonic]}m"
            cand_pt = f"{NOTE_NAMES_PT[cand_tonic]} Maior" if cand_is_maj else f"{NOTE_NAMES_PT[cand_tonic]} Menor"
            cand_conf = round(max(0.15, min(0.92, (cand_score + 0.22) / 1.18)), 2)
            runner_ups.append((cand_en, cand_pt, cand_conf))
            if len(runner_ups) == 2:
                break

        sec_en, sec_pt, sec_conf = runner_ups[0] if len(runner_ups) > 0 else ("", "", 0.0)
        thi_en, thi_pt, thi_conf = runner_ups[1] if len(runner_ups) > 1 else ("", "", 0.0)

        estimation = KeyEstimation(
            tonic_pitch_class=best_tonic,
            is_major=best_is_major,
            key_en=key_en,
            key_pt=key_pt,
            relative_key_en=rel_en,
            relative_key_pt=rel_pt,
            confidence=confidence,
            samples_collected=self._samples_count,
            second_key_en=sec_en,
            second_key_pt=sec_pt,
            second_confidence=sec_conf,
            third_key_en=thi_en,
            third_key_pt=thi_pt,
            third_confidence=thi_conf,
        )

        if distinct_notes >= 3 and confidence >= 0.70:
            self._locked_key = estimation
            self._locked_score = best_score
        else:
            self._locked_key = None
            self._locked_score = -1.0

        return estimation
