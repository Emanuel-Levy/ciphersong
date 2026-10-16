"""
Ponto de entrada multiplataforma (Android APK / iOS / Desktop) do CipherSong.
"""

from __future__ import annotations

import os
import sys

import flet as ft

from ciphersong.ui.app_flet import build_ciphersong_app

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


def main() -> None:
    if _is_mobile_runtime():
        ft.run(build_ciphersong_app)
    else:
        ft.run(
            build_ciphersong_app,
            view=ft.AppView.WEB_BROWSER,
            port=8550,
        )


if __name__ == "__main__":
    main()

