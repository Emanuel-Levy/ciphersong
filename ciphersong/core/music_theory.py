"""
Módulo de Teoria Musical e Conversão de Frequências (`fast-helper`).
Converte frequências fundamentais (Hz) em notas musicais, oitavas e desvios (cents).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

NOTE_NAMES_EN: tuple[str, ...] = (
    "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"
)

NOTE_NAMES_PT: tuple[str, ...] = (
    "Dó", "Dó#", "Ré", "Ré#", "Mi", "Fá", "Fá#", "Sol", "Sol#", "Lá", "Lá#", "Si"
)


@dataclass(frozen=True)
class PitchNote:
    """Representa uma nota musical extraída de uma frequência em Hz."""
    frequency_hz: float
    midi_number: int
    pitch_class: int  # 0 (C) a 11 (B)
    note_en: str      # ex: "G"
    note_pt: str      # ex: "Sol"
    octave: int       # ex: 3
    cents_offset: float  # Desvio entre -50.0 e +50.0 cents
    nominal_frequency_hz: float = 0.0  # Frequência padrão exata da nota (ex: 440.0 para A4)

    @property
    def full_name_en(self) -> str:
        return f"{self.note_en}{self.octave}"

    @property
    def full_name_pt(self) -> str:
        return f"{self.note_pt}{self.octave}"


def frequency_to_note(frequency_hz: float, a4_hz: float = 440.0) -> PitchNote:
    """
    Converte uma frequência em Hz para a nota musical mais próxima (padrão A4 = 440 Hz).
    Lança ValueError se a frequência for <= 0.
    """
    if frequency_hz <= 0 or math.isnan(frequency_hz) or math.isinf(frequency_hz):
        raise ValueError("A frequência deve ser um número positivo maior que zero.")

    # Número MIDI exato (contínuo) onde A4 (440 Hz) = 69
    exact_midi = 69.0 + 12.0 * math.log2(frequency_hz / a4_hz)
    nearest_midi = int(round(exact_midi))

    # Frequência nominal exata da nota temperada (sem desvio de afinação)
    nominal_hz = a4_hz * (2.0 ** ((nearest_midi - 69.0) / 12.0))

    # Desvio em cents (-50 a +50)
    cents = (exact_midi - nearest_midi) * 100.0

    pitch_class = nearest_midi % 12
    octave = (nearest_midi // 12) - 1

    return PitchNote(
        frequency_hz=round(frequency_hz, 2),
        midi_number=nearest_midi,
        pitch_class=pitch_class,
        note_en=NOTE_NAMES_EN[pitch_class],
        note_pt=NOTE_NAMES_PT[pitch_class],
        octave=octave,
        cents_offset=round(cents, 1),
        nominal_frequency_hz=round(nominal_hz, 2),
    )


def relative_minor_or_major(pitch_class: int, is_major: bool) -> tuple[str, str]:
    """
    Retorna a tonalidade relativa (Menor se a atual for Maior, ou Maior se for Menor)
    nos formatos (Inglês, Português).
    """
    if is_major:
        # Relativa menor fica 3 semitons abaixo (ou +9 mod 12)
        rel_idx = (pitch_class - 3) % 12
        return f"{NOTE_NAMES_EN[rel_idx]}m", f"{NOTE_NAMES_PT[rel_idx]} Menor"
    else:
        # Relativa maior fica 3 semitons acima
        rel_idx = (pitch_class + 3) % 12
        return f"{NOTE_NAMES_EN[rel_idx]}", f"{NOTE_NAMES_PT[rel_idx]} Maior"
