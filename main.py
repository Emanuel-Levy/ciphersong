"""
Ponto de entrada multiplataforma (Android APK / iOS / Desktop) do CipherSong.
"""

from __future__ import annotations

import os
import sys
import traceback

import flet as ft

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _is_mobile_runtime() -> bool:
    """Detecta se o código está rodando empacotado dentro do APK Android ou iOS."""
    return (
        sys.platform in ("android", "ios")
        or "ANDROID_ARGUMENT" in os.environ
        or "ANDROID_BOOTLOGO" in os.environ
        or os.getenv("FLET_PLATFORM", "").lower() in ("android", "ios")
    )


import re

def sanitize_traceback(tb_str: str) -> str:
    r"""
    Higieniza tracebacks removendo qualquer diretório da máquina de desenvolvimento (ex: C:\Users\Dev\...).
    Substitui por caminhos genéricos e relativos (/ciphersong/... ou /site-packages/...).
    """
    if not tb_str:
        return tb_str
    # Normaliza barras invertidas dentro de aspas File "..."
    def _norm_path(match):
        p = match.group(1).replace("\\", "/")
        return f'File "{p}"'
    tb_str = re.sub(r'File "([^"]+)"', _norm_path, tb_str)
    # Remove pastas temporarias do serious_python
    tb_str = re.sub(r'[A-Za-z]:/[^"\'\n\r]*?/serious_python_temp[0-9a-fA-F]*/', '/ciphersong/', tb_str)
    tb_str = re.sub(r'[A-Za-z]:\\[^"\'\n\r]*?[\\/]serious_python_temp[0-9a-fA-F]*[\\/]', '/ciphersong/', tb_str)
    # Remove caminhos locais de site-packages (incluindo arquiteturas)
    tb_str = re.sub(r'[A-Za-z]:/[^"\'\n\r]*?/site-packages/(?:arm64-v8a|armeabi-v7a|x86_64)/', '/site-packages/', tb_str, flags=re.IGNORECASE)
    tb_str = re.sub(r'[A-Za-z]:/[^"\'\n\r]*?/site-packages/', '/site-packages/', tb_str, flags=re.IGNORECASE)
    tb_str = re.sub(r'[A-Za-z]:\\[^"\'\n\r]*?[\\/]site-packages[\\/](?:arm64-v8a|armeabi-v7a|x86_64)[\\/]', '/site-packages/', tb_str, flags=re.IGNORECASE)
    tb_str = re.sub(r'[A-Za-z]:\\[^"\'\n\r]*?[\\/]site-packages[\\/]', '/site-packages/', tb_str, flags=re.IGNORECASE)
    # Remove caminhos locais do projeto ciphersong
    tb_str = re.sub(r'[A-Za-z]:/[^"\'\n\r]*?/(ciphersong/[^"\'\n\r]*)', r'/\1', tb_str, flags=re.IGNORECASE)
    tb_str = re.sub(r'[A-Za-z]:\\[^"\'\n\r]*?[\\/](ciphersong[\\/][^"\'\n\r]*)', r'/\1', tb_str, flags=re.IGNORECASE)
    # Normaliza qualquer path duplo como /ciphersong/ciphersong
    tb_str = tb_str.replace('/ciphersong/ciphersong/', '/ciphersong/')
    # Substitui qualquer outro caminho absoluto Windows remanescente
    tb_str = re.sub(r'[A-Za-z]:[/\\][^"\'\n\r]+', '/app', tb_str)
    return tb_str


def _sanitized_excepthook(exc_type, exc_val, exc_tb):
    raw_tb = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
    sys.stderr.write(sanitize_traceback(raw_tb))

sys.excepthook = _sanitized_excepthook


def safe_app_entrypoint(page: ft.Page) -> None:
    """
    Inicializa a interface do CipherSong após estabelecer o canal Flet,
    garantindo que qualquer falha de ambiente seja exibida de forma clara na tela
    em vez de deixar a tela cinza no Android.
    """
    try:
        from ciphersong.ui.app_flet import build_ciphersong_app
        build_ciphersong_app(page)
    except Exception as exc:
        page.bgcolor = "#18181B"
        page.padding = 24
        clean_tb = sanitize_traceback(traceback.format_exc())
        page.add(
            ft.Column(
                spacing=10,
                controls=[
                    ft.Text("Erro ao iniciar CipherSong", size=18, weight=ft.FontWeight.BOLD, color="#EF4444"),
                    ft.Text(str(exc), size=13, color="#F4F4F5"),
                    ft.Text(clean_tb, size=10, color="#A1A1AA"),
                ],
            )
        )
        page.update()


def main() -> None:
    runner = getattr(ft, "run", getattr(ft, "app", None))
    if runner is None:
        try:
            from flet.app import run as runner
        except ImportError:
            try:
                from flet import app as runner
            except ImportError:
                raise RuntimeError("Não foi possível encontrar a função 'run' ou 'app' no módulo flet.")

    if _is_mobile_runtime():
        runner(safe_app_entrypoint)
    else:
        app_view = getattr(getattr(ft, "AppView", object()), "WEB_BROWSER", "web_browser")
        runner(
            safe_app_entrypoint,
            view=app_view,
            port=8550,
        )


if __name__ == "__main__":
    main()
