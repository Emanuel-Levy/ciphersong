"""
Gerenciador de Notificações In-App e Sistema (Barra de Notificação Flutuante e Vibração).
"""

from __future__ import annotations

import threading
import time
from typing import Any

import flet as ft

from ciphersong.services.system_notifications import (
    send_system_notification,
    send_system_vibration,
)
from ciphersong.ui.theme import C_ACCENT


class InAppNotificationManager:
    """Controla o banner flutuante superior de notificações in-app e despachos de SO."""

    def __init__(self, page: ft.Page, haptic: Any | None = None) -> None:
        self.page = page
        self.haptic = haptic

        self.icon = ft.Icon(ft.Icons.NOTIFICATIONS_ACTIVE_ROUNDED, color="#18181B", size=22)
        self.text = ft.Text("", size=13, weight=ft.FontWeight.BOLD, color="#18181B")

        self.card = ft.Container(
            content=ft.Row(
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    self.icon,
                    ft.Column(
                        spacing=1,
                        expand=True,
                        controls=[self.text],
                    ),
                    ft.IconButton(
                        icon=ft.Icons.CLOSE_ROUNDED,
                        icon_color="#18181B",
                        icon_size=18,
                        on_click=self.hide,
                    ),
                ],
            ),
            bgcolor=C_ACCENT,
            border_radius=12,
            padding=ft.Padding.symmetric(horizontal=12, vertical=8),
            shadow=ft.BoxShadow(spread_radius=1, blur_radius=14, color="#000000"),
        )

        self.overlay = ft.Container(
            top=12,
            left=12,
            right=12,
            alignment=ft.Alignment.TOP_CENTER,
            visible=False,
            content=self.card,
        )

    def hide(self, e: ft.ControlEvent | None = None) -> None:
        self.overlay.visible = False
        try:
            self.page.update()
        except Exception:
            pass

    def trigger_phone_vibration(self, pattern: str = "normal") -> None:
        """Aciona a vibração física do celular (3x pulsos para chamadas de equipe vs 1x para notificações)."""
        def _vib():
            try:
                # 1. Vibração via IPC nativo do Android
                send_system_vibration(pattern=pattern)
                # 2. Vibração Flet haptic (para UI em 1º plano)
                if self.haptic is not None:
                    if pattern == "call":
                        for _ in range(3):
                            try:
                                self.page.run_task(self.haptic.vibrate)
                            except Exception:
                                pass
                            time.sleep(0.35)
                    else:
                        try:
                            self.page.run_task(self.haptic.vibrate)
                        except Exception:
                            pass
            except Exception as v_err:
                print(f"[Vibration Warning]: {v_err}")

        threading.Thread(target=_vib, daemon=True).start()

    def show(
        self,
        message: str,
        duration_sec: float = 6.0,
        is_call: bool = False,
        vibrate: bool = True,
        title: str | None = None,
    ) -> None:
        self.text.value = message
        if is_call:
            self.card.bgcolor = "#F59E0B"  # Destaque âmbar/dourado para chamada urgente
            self.icon.icon = ft.Icons.RING_VOLUME_ROUNDED
            self.icon.color = "#18181B"
            if vibrate:
                self.trigger_phone_vibration(pattern="call")
            try:
                if hasattr(self.page, "window") and hasattr(self.page.window, "to_front"):
                    self.page.window.to_front()
            except Exception:
                pass
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass
        else:
            self.card.bgcolor = C_ACCENT
            self.icon.icon = ft.Icons.NOTIFICATIONS_ACTIVE_ROUNDED
            self.icon.color = "#18181B"
            if vibrate:
                self.trigger_phone_vibration(pattern="normal")

        # Notificação nativa para a barra do sistema operacional (Android Status Bar)
        def _dispatch_system():
            try:
                header = title or ("📲 Chamada de Equipe" if is_call else "CipherSong")
                send_system_notification(
                    title=header,
                    body=message,
                    is_call=is_call,
                    vibrate=vibrate,
                )
            except Exception as s_err:
                print(f"[SystemNotification Warning]: {s_err}")

        threading.Thread(target=_dispatch_system, daemon=True).start()

        self.overlay.visible = True
        try:
            self.page.update()
        except Exception:
            pass

        def _auto_hide():
            time.sleep(duration_sec)
            self.overlay.visible = False
            try:
                self.page.update()
            except Exception:
                pass

        threading.Thread(target=_auto_hide, daemon=True).start()
