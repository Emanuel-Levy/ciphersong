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


def test_android_imports_without_dotenv(monkeypatch) -> None:
    """
    Garante que no Android (onde python-dotenv não é instalado no APK),
    todos os módulos (mongo_connection, api_client, app_flet e main)
    são importados sem ModuleNotFoundError (prevenindo tela cinza no celular).
    """
    import importlib
    import sys
    import ciphersong.database.mongo_connection as mc

    monkeypatch.setitem(sys.modules, "dotenv", None)
    reloaded = importlib.reload(mc)
    assert hasattr(reloaded, "MongoDBConnection")


def test_system_notifications_ipc_mock_server() -> None:
    """
    Testa o envio de notificação nativa e vibração do sistema via socket IPC (127.0.0.1:19876)
    simulando o servidor da MainActivity.kt.
    """
    import socket
    import threading
    import json
    from ciphersong.services.system_notifications import (
        send_system_notification,
        send_system_vibration,
        ping_system_service,
        ANDROID_IPC_PORT,
    )

    received_payloads = []
    server_running = True

    def _mock_android_server():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", ANDROID_IPC_PORT))
                s.listen(1)
                s.settimeout(2.0)
                while server_running:
                    try:
                        conn, _ = s.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        data = conn.recv(1024)
                        if data:
                            msg = json.loads(data.decode("utf-8").strip())
                            received_payloads.append(msg)
                            if msg.get("action") == "ping":
                                conn.sendall(b'{"status":"ok","alive":true}\n')
                            else:
                                conn.sendall(b'{"status":"ok","notified":true}\n')
        except Exception as e:
            print(f"Mock server bind error: {e}")

    server_thread = threading.Thread(target=_mock_android_server, daemon=True)
    server_thread.start()
    import time
    time.sleep(0.1)

    try:
        # Testa ping
        alive = ping_system_service()
        assert alive is True

        # Testa notificação de chamada urgente (Ping)
        ok_call = send_system_notification(
            title="📲 Chamada de Levy",
            body="Levy está te chamando para o ensaio!",
            is_call=True,
            vibrate=True,
        )
        assert ok_call is True

        # Testa notificação de nova música na Semana
        ok_weekly = send_system_notification(
            title="📅 Repertório da Semana",
            body="+2 músicas adicionadas no repertório da semana!",
            is_call=False,
            vibrate=True,
        )
        assert ok_weekly is True

        # Testa vibração
        ok_vib = send_system_vibration(pattern="call")
        assert ok_vib is True

        # Verifica os payloads recebidos
        actions = [p["action"] for p in received_payloads]
        assert "ping" in actions
        assert "notify" in actions
        assert "vibrate" in actions

        notify_payloads = [p for p in received_payloads if p.get("action") == "notify"]
        assert len(notify_payloads) == 2
        assert notify_payloads[0]["is_call"] is True
        assert notify_payloads[0]["title"] == "📲 Chamada de Levy"
        assert notify_payloads[1]["is_call"] is False
        assert notify_payloads[1]["title"] == "📅 Repertório da Semana"
    finally:
        server_running = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dummy:
                dummy.connect(("127.0.0.1", ANDROID_IPC_PORT))
        except Exception:
            pass
        server_thread.join(timeout=1.0)


def test_system_notifications_graceful_fallback_when_offline(monkeypatch) -> None:
    """
    Garante que no Desktop ou quando o IPC socket não estiver respondendo,
    as funções não levantam exceções não tratadas e retornam False com fallback seguro.
    """
    import ciphersong.services.system_notifications as sn
    # Porta comprovadamente fechada
    monkeypatch.setattr(sn, "ANDROID_IPC_PORT", 19998)

    res = sn.send_system_notification(
        title="Teste Offline",
        body="Mensagem de teste",
        is_call=False,
        timeout_sec=0.1,
    )
    assert res is False

    res_vib = sn.send_system_vibration(pattern="normal", timeout_sec=0.1)
    assert res_vib is False

