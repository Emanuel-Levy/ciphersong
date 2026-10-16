"""
Detector de Frequência Fundamental (Pitch Detection) em Tempo Real (`senior-architect`).
Processa buffers de áudio na memória RAM (sem gravar em disco) usando autocorrelação
parabólica otimizada com NumPy para a faixa vocal humana (75 Hz - 900 Hz).
Inclui Auto-Gain (AGC) e Noise Gate sensível para microfones USB/Headset/Celular.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np

from ciphersong.core.music_theory import PitchNote, frequency_to_note


@dataclass(frozen=True)
class VoiceFrameResult:
    """Resultado da análise instantânea de um bloco (frame) de áudio."""
    is_singing: bool
    rms_volume: float
    note: Optional[PitchNote] = None


class VocalPitchDetector:
    """
    Extrai a frequência fundamental (f0) de um sinal de voz mono.
    Inclui Noise Gate (RMS) ajustável e normalização automática de ganho.
    """

    def __init__(
        self,
        sample_rate: int = 44100,
        min_freq_hz: float = 75.0,
        max_freq_hz: float = 900.0,
        rms_threshold: float = 0.002,
    ) -> None:
        self.sample_rate = sample_rate
        self.min_freq_hz = min_freq_hz
        self.max_freq_hz = max_freq_hz
        self.rms_threshold = rms_threshold

    def analyze_frame(self, audio_buffer: np.ndarray) -> VoiceFrameResult:
        """
        Analisa um array 1D de amostras de áudio (float32 entre -1.0 e 1.0)
        exclusivamente em memória RAM.
        """
        if audio_buffer.size == 0:
            return VoiceFrameResult(is_singing=False, rms_volume=0.0, note=None)

        samples = np.asarray(audio_buffer, dtype=np.float64).ravel()

        # Remove componente DC antes de calcular o RMS
        samples = samples - np.mean(samples)

        # Calcula volume RMS para filtrar silêncio/ruído de fundo
        rms = float(np.sqrt(np.mean(samples ** 2)))
        if rms < self.rms_threshold:
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        # Auto-Gain (Normalização suave em RAM para microfones com volume baixo)
        peak = float(np.max(np.abs(samples)))
        if peak > 1e-6:
            samples = samples / peak

        windowed = samples * np.hanning(samples.size)

        # Autocorrelação rápida via FFT (Wiener-Khinchin)
        n = windowed.size
        fft_size = 1 << (2 * n - 1).bit_length()
        spectrum = np.fft.rfft(windowed, n=fft_size)
        autocorr = np.fft.irfft(spectrum * np.conj(spectrum), n=fft_size)[:n]

        if autocorr[0] <= 1e-9:
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        autocorr = autocorr / autocorr[0]

        min_lag = max(1, int(self.sample_rate / self.max_freq_hz))
        max_lag = min(n - 2, int(self.sample_rate / self.min_freq_hz))
        if max_lag <= min_lag:
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        # Encontra o primeiro vale negativo/zero antes de buscar o pico fundamental
        d = np.diff(autocorr)
        positive_slopes = np.where(d > 0)[0]
        start_idx = max(min_lag, int(positive_slopes[0])) if positive_slopes.size > 0 else min_lag
        if start_idx >= max_lag:
            start_idx = min_lag

        search_region = autocorr[start_idx : max_lag + 1]
        peak_offset = int(np.argmax(search_region))
        peak_lag = start_idx + peak_offset
        peak_clarity = float(autocorr[peak_lag])

        # Exige periodicidade mínima para confirmar que é voz/nota cantada e não ruído branco
        if peak_clarity < 0.28:
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        # Interpolação parabólica para precisão sub-amostra (melhor precisão em cents)
        refined_lag = float(peak_lag)
        if 1 <= peak_lag < n - 1:
            y0, y1, y2 = autocorr[peak_lag - 1], autocorr[peak_lag], autocorr[peak_lag + 1]
            denom = 2.0 * (2.0 * y1 - y2 - y0)
            if abs(denom) > 1e-9:
                refined_lag += (y2 - y0) / denom

        freq_hz = float(self.sample_rate / refined_lag)
        if not (self.min_freq_hz <= freq_hz <= self.max_freq_hz):
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        pitch_note = frequency_to_note(freq_hz)
        return VoiceFrameResult(is_singing=True, rms_volume=rms, note=pitch_note)
