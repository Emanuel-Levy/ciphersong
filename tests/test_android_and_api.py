"""
Testes automatizados (`senior-architect` + `security-specialist`) para:
1. Streaming de microfone Android PCM16 em memória RAM (`handle_pcm16_bytes`).
2. Endpoints REST do Backend FastAPI (`backend_api.py`).
3. Cliente HTTP Resiliente (`SongsApiClient`) usado no APK Android.
"""

from __future__ import annotations

import math
import numpy as np
from fastapi.testclient import TestClient

from backend_api import app
from ciphersong.services.api_client import SongsApiClient
from ciphersong.services.microphone_stream import LiveMicrophoneService


def test_android_pcm16_bytes_streaming_detects_pitch() -> None:
    """
    Simula o envio de blocos de bytes `PCM16BITS` (int16 little-endian) gerados
    pelo `flet_audio_recorder` no Android (ex: Lá 4 = 440 Hz) e verifica se a nota
    é detectada em RAM sem gravar em disco.
    """
    sample_rate = 44100
    block_size = 4096
    mic = LiveMicrophoneService(sample_rate=sample_rate, block_size=block_size)

    # Gera uma senoide de 440 Hz (Lá 4) em int16 PCM (2 blocos de 4096 amostras)
    total_samples = block_size * 2
    t = np.arange(total_samples, dtype=np.float64) / sample_rate
    wave_float = 0.6 * np.sin(2.0 * math.pi * 440.0 * t)
    wave_int16 = (wave_float * 32767.0).astype(np.int16)
    raw_pcm_bytes = wave_int16.tobytes()

    result = mic.handle_pcm16_bytes(raw_pcm_bytes, sample_rate=sample_rate)
    assert result is not None
    frame_res, _ = result
    assert frame_res.is_singing is True
    assert frame_res.note is not None
    assert frame_res.note.note_en == "A"
    assert frame_res.note.octave == 4
    assert abs(frame_res.note.frequency_hz - 440.0) < 3.0


def test_backend_api_health_endpoint() -> None:
    """Testa o endpoint de saúde (/health) da API intermediária FastAPI."""
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "ciphersong-api"


def test_songs_api_client_normalization() -> None:
    """Garante que o SongsApiClient configura a URL base sem barra duplicada."""
    api = SongsApiClient(api_base_url="https://api.ciphersong.app/")
    assert api.api_base_url == "https://api.ciphersong.app"
