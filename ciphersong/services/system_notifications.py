"""
Módulo de Notificações Nativas e Vibração do Sistema - CipherSong
Comunicação de Baixa Latência via Loopback IPC com MainActivity Android.
Funciona mesmo com o app em segundo plano, minimizado ou tela bloqueada.
Em ambientes Desktop, opera com fallback seguro e gracioso.
"""
import json
import logging
import os
import socket
import sys
import threading
from typing import Optional

logger = logging.getLogger("ciphersong.notifications")

ANDROID_IPC_PORT = 19876
ANDROID_IPC_HOST = "127.0.0.1"


def is_running_on_android() -> bool:
    """Verifica se a aplicação está em execução no ambiente Android (Serious Python / Flet Mobile)."""
    return (
        os.environ.get("FLET_PLATFORM") == "android"
        or "ANDROID_ARGUMENT" in os.environ
        or "ANDROID_ROOT" in os.environ
        or "com.ciphersong" in sys.executable.lower()
    )


def send_system_notification(
    title: str,
    body: str,
    is_call: bool = False,
    vibrate: bool = True,
    notification_id: Optional[int] = None,
    timeout_sec: float = 1.5,
) -> bool:
    """
    Envia notificação nativa para a barra de status / gaveta do sistema operacional.
    No Android, despacha para o MainActivity.kt através de socket TCP loopback (127.0.0.1:19876).
    Exibe alerta sonoro, heads-up banner e vibração do dispositivo.
    """
    payload = {
        "action": "notify",
        "title": title,
        "body": body,
        "is_call": is_call,
        "vibrate": vibrate,
    }
    if notification_id is not None:
        payload["id"] = int(notification_id)

    raw_data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")

    # 1. Tenta envio direto ao IPC nativo do Android (com 1 retentativa se waking up)
    for attempt in range(2):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_sec)
                s.connect((ANDROID_IPC_HOST, ANDROID_IPC_PORT))
                s.sendall(raw_data)
                resp = s.recv(512)
                if resp:
                    logger.info(f"[SystemNotification] Entregue com sucesso ao Android: {title}")
                    return True
        except (ConnectionRefusedError, socket.timeout, OSError) as ipc_err:
            if attempt == 0 and is_running_on_android():
                import time
                time.sleep(0.15)
                continue
            logger.debug(f"[SystemNotification] IPC nativo não conectado ({ipc_err}). Fallback de plataforma ativo.")

    # 2. Fallback para Desktop (Windows / macOS / Linux)
    if is_call and sys.platform.startswith("win"):
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass

    return False


def send_system_vibration(pattern: str = "normal", timeout_sec: float = 1.0) -> bool:
    """
    Dispara vibração física nativa no dispositivo Android via IPC.
    Padrões: 'call' (3 pulsos intensos) ou 'normal' (2 pulsos moderados).
    """
    payload = {
        "action": "vibrate",
        "pattern": pattern,
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_sec)
            s.connect((ANDROID_IPC_HOST, ANDROID_IPC_PORT))
            raw_data = (json.dumps(payload) + "\n").encode("utf-8")
            s.sendall(raw_data)
            try:
                s.recv(256)
            except Exception:
                pass
            return True
    except Exception:
        return False


def ping_system_service(timeout_sec: float = 0.8) -> bool:
    """Verifica se o serviço de notificações do sistema Android está pronto e respondendo."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_sec)
            s.connect((ANDROID_IPC_HOST, ANDROID_IPC_PORT))
            s.sendall(b'{"action":"ping"}\n')
            resp = s.recv(256)
            return b'"alive":true' in resp
    except Exception:
        return False


def request_system_notification_permission(timeout_sec: float = 0.8) -> bool:
    """Solicita a exibição do diálogo de permissão de notificações em tempo de execução no Android."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_sec)
            s.connect((ANDROID_IPC_HOST, ANDROID_IPC_PORT))
            s.sendall(b'{"action":"request_permission"}\n')
            resp = s.recv(256)
            return b'"ok"' in resp
    except Exception:
        return False


def open_system_notification_settings(timeout_sec: float = 0.8) -> bool:
    """Abre as configurações de notificação do CipherSong no sistema operacional do dispositivo."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_sec)
            s.connect((ANDROID_IPC_HOST, ANDROID_IPC_PORT))
            s.sendall(b'{"action":"open_settings"}\n')
            resp = s.recv(256)
            return b'"ok"' in resp
    except Exception:
        return False
