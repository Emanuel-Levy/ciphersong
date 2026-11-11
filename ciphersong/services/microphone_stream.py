"""
Serviço Híbrido de Microfone em Tempo Real para Android, iOS e Desktop (`senior-architect` + `security-specialist`).

Arquitetura Multiplataforma:
1. Mobile (Android / iOS) & Flet Native:
   - Usa `flet_audio_recorder.AudioRecorder` em modo streaming (`AudioEncoder.PCM16BITS`),
     que recebe blocos de áudio (`chunk: bytes`) diretamente em memória RAM via `on_stream`
     sem nunca gravar arquivo de áudio no armazenamento do celular!
2. Desktop (Windows / macOS / Linux):
   - Usa `sounddevice` (PortAudio) para baixa latência nas placas de som USB/PC, com fallback
     automático para o `AudioRecorder` do Flet ou simulador de voz.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

import numpy as np

from ciphersong.core.key_estimator import KeyEstimation, MusicalKeyEstimator
from ciphersong.core.pitch_detector import VocalPitchDetector, VoiceFrameResult


@dataclass(frozen=True)
class AudioInputDevice:
    """Representa um dispositivo físico/virtual de entrada de microfone."""
    index: int
    name: str
    default_samplerate: int
    channels: int


class LiveMicrophoneService:
    """
    Gerencia a captura de áudio em tempo real pelo microfone (Android PCM16 Stream,
    Desktop PortAudio ou Simulador Vocal Sintético) e notifica a UI via callback.
    """

    def __init__(
        self,
        sample_rate: int = 44100,
        block_size: int = 4096,
        on_update: Optional[Callable[[VoiceFrameResult, Optional[KeyEstimation]], None]] = None,
    ) -> None:
        self.sample_rate = sample_rate
        self.block_size = block_size
        self.on_update = on_update

        self.pitch_detector = VocalPitchDetector(sample_rate=sample_rate)
        self.key_estimator = MusicalKeyEstimator(min_samples_for_estimation=5)

        self._is_running = False
        self._stream: Optional[Any] = None
        self._flet_recorder: Optional[Any] = None
        self._pcm_ring_buffer = np.zeros(0, dtype=np.float32)
        self._sim_thread: Optional[threading.Thread] = None
        self.last_frame: Optional[VoiceFrameResult] = None
        self.last_key: Optional[KeyEstimation] = None

    @property
    def is_running(self) -> bool:
        return self._is_running

    @staticmethod
    def list_input_devices() -> list[AudioInputDevice]:
        """Lista microfones disponíveis no Desktop ou retorna o microfone nativo do Android."""
        devices: list[AudioInputDevice] = []
        try:
            import sounddevice as sd
            raw_list = sd.query_devices()
            seen_names: set[str] = set()
            for idx, dev in enumerate(raw_list):
                max_in = int(dev.get("max_input_channels", 0))
                name = str(dev.get("name", f"Microfone {idx}")).strip()
                if max_in > 0 and name not in seen_names:
                    seen_names.add(name)
                    sr = int(float(dev.get("default_samplerate", 44100)))
                    devices.append(
                        AudioInputDevice(
                            index=idx,
                            name=name,
                            default_samplerate=sr,
                            channels=max_in,
                        )
                    )
        except Exception:
            pass

        if not devices:
            devices.append(
                AudioInputDevice(
                    index=0,
                    name="Microfone Interno (Android / Mobile)",
                    default_samplerate=44100,
                    channels=1,
                )
            )
        return devices

    def reset_session(self) -> None:
        """Zera a contagem de notas e estimativa de tom da sessão atual."""
        self.key_estimator.reset()
        if hasattr(self.pitch_detector, "reset_state"):
            self.pitch_detector.reset_state()
        self._pcm_ring_buffer = np.zeros(0, dtype=np.float32)
        self.last_frame = None
        self.last_key = None

    def process_audio_chunk(self, audio_chunk: np.ndarray) -> tuple[VoiceFrameResult, Optional[KeyEstimation]]:
        """
        Analisa um bloco de áudio exclusivamente em RAM e atualiza a estimativa de Tom.
        """
        frame_result = self.pitch_detector.analyze_frame(audio_chunk)
        self.last_frame = frame_result

        if frame_result.is_singing and frame_result.note is not None:
            self.last_key = self.key_estimator.add_note(frame_result.note)

        if self.on_update is not None:
            self.on_update(frame_result, self.last_key)

        return frame_result, self.last_key

    def handle_pcm16_bytes(self, raw_bytes: bytes, sample_rate: int = 44100) -> Optional[tuple[VoiceFrameResult, Optional[KeyEstimation]]]:
        """
        Recebe bytes brutos `PCM16BITS` vindos do `flet_audio_recorder` no Android/iOS,
        converte para float32 (-1.0 a 1.0) em memória RAM e analisa blocos de `block_size`.
        """
        if not raw_bytes:
            return None

        if self.sample_rate != sample_rate:
            self.sample_rate = sample_rate
            self.pitch_detector.sample_rate = sample_rate

        # Garante alinhamento de 2 bytes (int16 little-endian)
        even_len = (len(raw_bytes) // 2) * 2
        if even_len == 0:
            return None

        int16_samples = np.frombuffer(raw_bytes[:even_len], dtype=np.int16)
        float_samples = int16_samples.astype(np.float32) / 32768.0

        self._pcm_ring_buffer = np.concatenate((self._pcm_ring_buffer, float_samples))
        result: Optional[tuple[VoiceFrameResult, Optional[KeyEstimation]]] = None

        while self._pcm_ring_buffer.size >= self.block_size:
            frame = self._pcm_ring_buffer[: self.block_size].copy()
            self._pcm_ring_buffer = self._pcm_ring_buffer[self.block_size // 2 :]
            result = self.process_audio_chunk(frame)
            frame.fill(0.0)

        return result

    async def start_mobile_flet_recorder(self, recorder_service: Any) -> tuple[bool, str]:
        """
        Inicia a captura via `flet_audio_recorder.AudioRecorder` (ideal para APK Android / iOS).
        Opera em modo streaming PCM16 100% em RAM (sem gravar arquivo no celular).
        """
        try:
            import flet_audio_recorder as far

            has_perm = await recorder_service.has_permission()
            if not has_perm:
                return False, "Permissão de microfone negada no Android. Autorize nas configurações."

            self.reset_session()
            self._flet_recorder = recorder_service
            self._is_running = True

            config = far.AudioRecorderConfiguration(
                encoder=far.AudioEncoder.PCM16BITS,
                sample_rate=44100,
                channels=1,
                suppress_noise=False,
                auto_gain=True,
            )
            started = await recorder_service.start_recording(output_path=None, configuration=config)
            if started:
                return True, "Ouvindo Microfone Android (Streaming PCM16 em RAM)..."
            self._is_running = False
            return False, "Não foi possível iniciar o gravador PCM16 no dispositivo."
        except Exception as exc:
            self._is_running = False
            return False, f"Erro no microfone mobile: {exc}"

    def start_microphone(self, device_index: Optional[int] = None) -> tuple[bool, str]:
        """
        Inicia a captura real do microfone no Desktop usando `sounddevice`.
        """
        if self._is_running:
            self.stop()

        try:
            import sounddevice as sd

            self.reset_session()
            dev_info = sd.query_devices(device=device_index, kind="input")
            native_sr = int(float(dev_info.get("default_samplerate", 44100)))
            dev_name = str(dev_info.get("name", "Microfone Padrão"))

            self.sample_rate = native_sr
            self.pitch_detector.sample_rate = native_sr
            self._is_running = True

            def _audio_callback(indata: np.ndarray, frames: int, time_info: object, status: object) -> None:
                if not self._is_running:
                    return
                if indata.ndim > 1 and indata.shape[1] > 1:
                    mono = np.mean(indata, axis=1).copy()
                else:
                    mono = indata.ravel().copy()

                self.process_audio_chunk(mono)
                mono.fill(0.0)

            self._stream = sd.InputStream(
                device=device_index,
                samplerate=self.sample_rate,
                blocksize=self.block_size,
                channels=1,
                dtype="float32",
                callback=_audio_callback,
            )
            self._stream.start()
            return True, f"Ouvindo: {dev_name} ({self.sample_rate} Hz)"
        except Exception as exc:
            self._is_running = False
            self._stream = None
            return False, f"Driver Desktop indisponível ({exc}). No Android, o stream nativo PCM16 será acionado."

    def start_voice_simulation(self, scale_name: str = "Sol Maior") -> None:
        """
        Simula um cantor vocalizando notas de uma tonalidade conhecida (ex: Sol Maior).
        """
        self.stop()
        self.reset_session()
        self.sample_rate = 44100
        self.pitch_detector.sample_rate = 44100
        self._is_running = True

        scales_hz: dict[str, list[float]] = {
            "Sol Maior": [196.00, 220.00, 246.94, 261.63, 293.66, 329.63, 369.99, 392.00],
            "Dó Maior": [261.63, 293.66, 329.63, 349.23, 392.00, 440.00, 493.88, 523.25],
            "Lá Menor": [220.00, 246.94, 261.63, 293.66, 329.63, 349.23, 392.00, 440.00],
        }
        freqs = scales_hz.get(scale_name, scales_hz["Sol Maior"])

        def _sim_loop() -> None:
            t = np.arange(self.block_size, dtype=np.float64) / self.sample_rate
            idx = 0
            while self._is_running:
                f0 = freqs[idx % len(freqs)]
                vibrato = math.sin(time.time() * 5.0) * 1.1
                freq = f0 + vibrato
                wave = (
                    0.55 * np.sin(2.0 * np.pi * freq * t)
                    + 0.20 * np.sin(2.0 * np.pi * (2.0 * freq) * t)
                    + 0.10 * np.sin(2.0 * np.pi * (3.0 * freq) * t)
                ).astype(np.float32)

                self.process_audio_chunk(wave)
                idx += 1
                time.sleep(0.22)

        self._sim_thread = threading.Thread(target=_sim_loop, daemon=True)
        self._sim_thread.start()

    def stop(self) -> None:
        """Interrompe a captura do microfone Desktop, Mobile ou simulação."""
        self._is_running = False
        if self._stream is not None:
            try:
                self._stream.stop()
                self._stream.close()
            except Exception:
                pass
            self._stream = None
        self.reset_session()
