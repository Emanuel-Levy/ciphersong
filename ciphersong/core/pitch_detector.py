"""
Detector Avançado de Frequência Fundamental (Pitch Detection) em Tempo Real (`senior-architect`).

Recursos Implementados:
1. Filtragem Espectral na Faixa Vocal (65 Hz - 1100 Hz): Remove ruídos de baixa frequência (rumble/vento)
   e sibilâncias/chiados de alta frequência antes da autocorrelação.
2. Auto-Gain Control (AGC) e Noise Gate Adaptativo para microfones USB, celulares e notebooks.
3. Prevenção de Salto de Oitava (Octave Error Correction).
4. Estabilizador de Frequência e Trava de Nota (Pitch Hysteresis & Anti-Jitter):
   - Elimina a oscilação rápida de decimais aplicando filtro de mediana e EMA.
   - Fornece a frequência mais aproximada da nota musical nominal sem oscilações bruscas.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional

import numpy as np

from ciphersong.core.music_theory import PitchNote, frequency_to_note
from ciphersong.core.key_estimator import KeyEstimation


@dataclass(frozen=True)
class VoiceFrameResult:
    """Resultado da análise instantânea de um bloco (frame) de áudio."""
    is_singing: bool
    rms_volume: float
    note: Optional[PitchNote] = None


class VocalPitchDetector:
    """
    Extrai a frequência fundamental (f0) de um sinal de voz mono na memória RAM.
    Inclui filtragem passa-faixa vocal, Auto-Gain e Estabilizador de Tom/Frequência.
    """

    def __init__(
        self,
        sample_rate: int = 44100,
        min_freq_hz: float = 80.0,
        max_freq_hz: float = 1000.0,
        rms_threshold: float = 0.0050,
        smooth: bool = True,
    ) -> None:
        self.sample_rate = sample_rate
        self.min_freq_hz = min_freq_hz
        self.max_freq_hz = max_freq_hz
        self.rms_threshold = rms_threshold
        self.smooth = smooth

        # Buffer para estabilização de frequência (anti-jitter)
        self._recent_freqs: Deque[float] = deque(maxlen=5)
        self._locked_note: Optional[PitchNote] = None
        self._candidate_midi: Optional[int] = None
        self._candidate_count: int = 0
        self._silent_frames_count: int = 0
        self._smoothed_cents: float = 0.0

        # Cache de janelamento e máscara espectral para evitar realocação por frame
        self._cached_dsp_key: Optional[tuple[int, int]] = None
        self._hanning_window: Optional[np.ndarray] = None
        self._fft_size: int = 0
        self._vocal_mask: Optional[np.ndarray] = None

    def reset_state(self) -> None:
        """Limpa o buffer de estabilização."""
        self._recent_freqs.clear()
        self._locked_note = None
        self._candidate_midi = None
        self._candidate_count = 0
        self._silent_frames_count = 0
        self._smoothed_cents = 0.0

    def _get_dsp_buffers(self, n: int) -> tuple[np.ndarray, int, np.ndarray]:
        """Retorna (hanning_window, fft_size, vocal_mask) cacheados para o tamanho de bloco e sample_rate atuais."""
        key = (n, self.sample_rate)
        if (
            self._cached_dsp_key != key
            or self._hanning_window is None
            or self._vocal_mask is None
        ):
            fft_size = 1 << (2 * n - 1).bit_length()
            freq_bins = np.fft.rfftfreq(fft_size, d=1.0 / self.sample_rate)
            vocal_mask = np.ones_like(freq_bins, dtype=np.float64)
            vocal_mask[freq_bins < 65.0] = 0.05
            vocal_mask[freq_bins > 1150.0] = 0.05

            self._cached_dsp_key = key
            self._hanning_window = np.hanning(n)
            self._fft_size = fft_size
            self._vocal_mask = vocal_mask

        return self._hanning_window, self._fft_size, self._vocal_mask

    def analyze_frame(self, audio_buffer: np.ndarray) -> VoiceFrameResult:
        """
        Analisa um array 1D de amostras de áudio (float32 entre -1.0 e 1.0)
        exclusivamente em memória RAM.
        """
        if audio_buffer.size == 0:
            self._handle_silence()
            return VoiceFrameResult(is_singing=False, rms_volume=0.0, note=None)

        samples = np.asarray(audio_buffer, dtype=np.float64).ravel()

        # 1. Remove componente DC (offset contínuo)
        samples = samples - np.mean(samples)

        # 2. Calcula volume RMS para o Noise Gate
        rms = float(np.sqrt(np.mean(samples * samples)))
        if rms < self.rms_threshold:
            self._handle_silence()
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        # 3. Auto-Gain Control (Normalização suave sem amplificar ruído de fundo da sala)
        peak = float(np.max(np.abs(samples)))
        if peak > 0.02:
            samples = samples / peak
        elif peak > 1e-4:
            # Limita o ganho máximo a 3x para nunca amplificar ruídos residuais
            samples = samples * min(3.0, 1.0 / peak)

        n = samples.size
        hanning_win, fft_size, vocal_mask = self._get_dsp_buffers(n)
        windowed = samples * hanning_win

        # 4. Filtragem Espectral Passa-Faixa Vocal (Wiener-Khinchin filtrado)
        # Atenua ruídos mecânicos (<65 Hz) e sibilâncias agudas (>1150 Hz)
        spectrum = np.fft.rfft(windowed, n=fft_size)
        filtered_spectrum = spectrum * vocal_mask
        power_spectrum = filtered_spectrum * np.conj(filtered_spectrum)
        autocorr = np.fft.irfft(power_spectrum, n=fft_size)[:n]

        if autocorr[0] <= 1e-9:
            self._handle_silence()
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        autocorr = autocorr / autocorr[0]

        min_lag = max(1, int(self.sample_rate / self.max_freq_hz))
        max_lag = min(n - 2, int(self.sample_rate / self.min_freq_hz))
        if max_lag <= min_lag:
            self._handle_silence()
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        # 5. Encontra o primeiro vale positivo antes do pico fundamental
        d = np.diff(autocorr)
        positive_slopes = np.where(d > 0)[0]
        start_idx = max(min_lag, int(positive_slopes[0])) if positive_slopes.size > 0 else min_lag
        if start_idx >= max_lag:
            start_idx = min_lag

        search_region = autocorr[start_idx : max_lag + 1]
        peak_offset = int(np.argmax(search_region))
        peak_lag = start_idx + peak_offset
        peak_clarity = float(autocorr[peak_lag])

        # Exige periodicidade e clareza harmônica (rejeita ruído ambiente, respiração e sons de fundo)
        if peak_clarity < 0.50:
            self._handle_silence()
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        # 6. Correção de erro de oitava (Octave Error Correction)
        # Se houver um pico quase tão forte na metade do lag, a verdadeira nota é a fundamental
        half_lag = int(round(peak_lag / 2.0))
        if min_lag <= half_lag <= max_lag and autocorr[half_lag] > 0.82 * peak_clarity:
            peak_lag = half_lag

        # 7. Interpolação parabólica sub-amostra
        refined_lag = float(peak_lag)
        if 1 <= peak_lag < n - 1:
            y0, y1, y2 = autocorr[peak_lag - 1], autocorr[peak_lag], autocorr[peak_lag + 1]
            denom = 2.0 * (2.0 * y1 - y2 - y0)
            if abs(denom) > 1e-9:
                refined_lag += (y2 - y0) / denom

        raw_freq_hz = float(self.sample_rate / refined_lag)
        if not (self.min_freq_hz <= raw_freq_hz <= self.max_freq_hz):
            self._handle_silence()
            return VoiceFrameResult(is_singing=False, rms_volume=rms, note=None)

        # 8. Estabilizador de Frequência e Trava de Nota (Histerese)
        self._silent_frames_count = 0
        if not self.smooth:
            raw_note = frequency_to_note(raw_freq_hz)
            return VoiceFrameResult(is_singing=True, rms_volume=rms, note=raw_note)

        stabilized_note = self._stabilize_pitch(raw_freq_hz)
        return VoiceFrameResult(is_singing=True, rms_volume=rms, note=stabilized_note)

    def _handle_silence(self) -> None:
        """Gerencia o decaimento após pausas vocais."""
        self._silent_frames_count += 1
        if self._silent_frames_count > 3:
            self._recent_freqs.clear()
            self._candidate_midi = None
            self._candidate_count = 0
            self._locked_note = None

    def _stabilize_pitch(self, raw_freq_hz: float) -> PitchNote:
        """
        Aplica filtro de mediana temporal e histerese para travar na nota mais aproximada
        e evitar o salto frenético de casas decimais na tela.
        """
        self._recent_freqs.append(raw_freq_hz)
        median_hz = float(np.median(self._recent_freqs))
        cand_note = frequency_to_note(median_hz)

        # Se não há nota travada, trava imediatamente
        if self._locked_note is None:
            self._locked_note = cand_note
            self._smoothed_cents = cand_note.cents_offset
            self._candidate_midi = None
            self._candidate_count = 0
            return cand_note

        # Se a nota cantada é a mesma que está travada:
        if cand_note.midi_number == self._locked_note.midi_number:
            # Suaviza o desvio em cents com filtro exponencial (EMA)
            self._smoothed_cents = 0.65 * self._smoothed_cents + 0.35 * cand_note.cents_offset
            self._candidate_count = 0
            self._candidate_midi = None
            # Mantém a frequência nominal exata da nota para estabilidade visual perfeita
            return PitchNote(
                frequency_hz=cand_note.nominal_frequency_hz,
                midi_number=cand_note.midi_number,
                pitch_class=cand_note.pitch_class,
                note_en=cand_note.note_en,
                note_pt=cand_note.note_pt,
                octave=cand_note.octave,
                cents_offset=round(self._smoothed_cents, 1),
                nominal_frequency_hz=cand_note.nominal_frequency_hz,
            )

        # Se a voz tentou mudar para outra nota (histerese de 2 frames para confirmar):
        if self._candidate_midi == cand_note.midi_number:
            self._candidate_count += 1
            if self._candidate_count >= 2:
                # Transição confirmada para a nova nota!
                self._locked_note = cand_note
                self._smoothed_cents = cand_note.cents_offset
                self._candidate_count = 0
                self._candidate_midi = None
                return cand_note
        else:
            self._candidate_midi = cand_note.midi_number
            self._candidate_count = 1

        # Enquanto a nova nota não for confirmada, continua exibindo a nota travada estável
        return PitchNote(
            frequency_hz=self._locked_note.nominal_frequency_hz,
            midi_number=self._locked_note.midi_number,
            pitch_class=self._locked_note.pitch_class,
            note_en=self._locked_note.note_en,
            note_pt=self._locked_note.note_pt,
            octave=self._locked_note.octave,
            cents_offset=round(self._smoothed_cents, 1),
            nominal_frequency_hz=self._locked_note.nominal_frequency_hz,
        )
