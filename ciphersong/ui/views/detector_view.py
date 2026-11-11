"""
Aba 1: Detector Vocal & Afinador em Tempo Real (UI/UX Flet 1.0).
Gerencia microfone, medidor de sinal, afinador circular, detecção de tom e histórico de registros salvos.
"""

from __future__ import annotations

import time
from typing import Any

import flet as ft
from ciphersong.security.local_vault import EncryptedSessionVault
from ciphersong.services.microphone_stream import LiveMicrophoneService

from ciphersong.core.key_estimator import KeyEstimation
from ciphersong.core.pitch_detector import VoiceFrameResult
from ciphersong.ui.theme import (
    C_ACCENT,
    C_BG,
    C_BORDER,
    C_DANGER,
    C_IN_TUNE,
    C_MUTED,
    C_OFF_TUNE,
    C_SURFACE,
    C_TEXT,
)


class DetectorView:
    """Componente visual e controlador da Aba 1 (Detector & Afinador)."""

    def __init__(
        self,
        page: ft.Page,
        vault: EncryptedSessionVault,
        mic_service: LiveMicrophoneService,
        mobile_recorder: Any | None = None,
    ) -> None:
        self.page = page
        self.vault = vault
        self.mic_service = mic_service
        self.mobile_recorder = mobile_recorder
        self.last_ui_render_ts = 0.0

        # Dispositivos de Entrada de Áudio
        input_devices = self.mic_service.list_input_devices()
        default_dev_key = str(input_devices[0].index) if input_devices else "default"

        self.mic_dropdown = ft.Dropdown(
            label="Microfone de Entrada",
            value=default_dev_key,
            bgcolor=C_SURFACE,
            border_color=C_BORDER,
            color=C_TEXT,
            options=[
                ft.DropdownOption(key=str(d.index), text=f"{d.name} ({d.default_samplerate} Hz)")
                for d in input_devices
            ]
            or [ft.DropdownOption(key="default", text="Microfone Padrão do Sistema")],
        )

        self.status_badge = ft.Text(
            "Selecione o microfone e clique em 'Ouvir Microfone'",
            size=12,
            color=C_MUTED,
            text_align=ft.TextAlign.CENTER,
        )

        self.mic_level_bar = ft.ProgressBar(
            value=0.0,
            width=320,
            height=6,
            color=C_ACCENT,
            bgcolor=C_SURFACE,
            border_radius=3,
        )
        self.mic_level_label = ft.Text(
            "Sinal do Microfone: Silêncio",
            size=11,
            color=C_MUTED,
        )

        self.note_title = ft.Text(
            "--",
            size=52,
            weight=ft.FontWeight.BOLD,
            color=C_ACCENT,
            text_align=ft.TextAlign.CENTER,
        )
        self.note_subtitle = ft.Text(
            "Cante no microfone",
            size=15,
            color=C_TEXT,
            text_align=ft.TextAlign.CENTER,
        )
        self.freq_label = ft.Text(
            "0.0 Hz  |  0 cents",
            size=13,
            color=C_MUTED,
            text_align=ft.TextAlign.CENTER,
        )

        self.cents_bar = ft.ProgressBar(
            value=0.5,
            width=220,
            height=8,
            color=C_IN_TUNE,
            bgcolor=C_BG,
            border_radius=4,
        )

        self.tuner_gauge = ft.Container(
            width=240,
            height=240,
            border_radius=120,
            bgcolor=C_SURFACE,
            border=ft.Border.all(4, C_BORDER),
            alignment=ft.Alignment.CENTER,
            content=ft.Column(
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=5,
                controls=[
                    self.note_title,
                    self.note_subtitle,
                    self.freq_label,
                    ft.Container(height=4),
                    self.cents_bar,
                    ft.Text("♭ (-50c)        Afinado        ♯ (+50c)", size=10, color=C_MUTED),
                ],
            ),
        )

        self.key_main_text = ft.Text(
            "Aguardando voz...",
            size=22,
            weight=ft.FontWeight.BOLD,
            color=C_TEXT,
        )
        self.key_relative_text = ft.Text(
            "Cante por alguns segundos para identificar o Tom",
            size=13,
            color=C_MUTED,
        )
        self.confidence_chip = ft.Text(
            "Confiança: --%",
            size=12,
            weight=ft.FontWeight.W_600,
            color=C_ACCENT,
        )

        self.key_card = ft.Container(
            padding=14,
            border_radius=14,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1, C_BORDER),
            content=ft.Column(
                spacing=5,
                horizontal_alignment=ft.CrossAxisAlignment.START,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("TOM DA MÚSICA (ESCALA)", size=11, weight=ft.FontWeight.BOLD, color=C_ACCENT),
                            self.confidence_chip,
                        ],
                    ),
                    self.key_main_text,
                    self.key_relative_text,
                ],
            ),
        )

        # 2 Círculos Menores com o 2º e 3º tons mais prováveis
        self.alt_key_2_title = ft.Text("--", size=17, weight=ft.FontWeight.BOLD, color=C_TEXT)
        self.alt_key_2_label = ft.Text("2º Mais Provável", size=9, color=C_MUTED, text_align=ft.TextAlign.CENTER)
        self.alt_key_2_conf = ft.Text("--%", size=10, weight=ft.FontWeight.W_600, color=C_ACCENT)

        self.circle_key_2 = ft.Container(
            width=120,
            height=100,
            border_radius=16,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1, C_BORDER),
            alignment=ft.Alignment.CENTER,
            padding=6,
            content=ft.Column(
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=2,
                controls=[
                    self.alt_key_2_label,
                    self.alt_key_2_title,
                    self.alt_key_2_conf,
                ],
            ),
        )

        self.alt_key_3_title = ft.Text("--", size=17, weight=ft.FontWeight.BOLD, color=C_TEXT)
        self.alt_key_3_label = ft.Text("3º Mais Provável", size=9, color=C_MUTED, text_align=ft.TextAlign.CENTER)
        self.alt_key_3_conf = ft.Text("--%", size=10, weight=ft.FontWeight.W_600, color=C_ACCENT)

        self.circle_key_3 = ft.Container(
            width=120,
            height=100,
            border_radius=16,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1, C_BORDER),
            alignment=ft.Alignment.CENTER,
            padding=6,
            content=ft.Column(
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=2,
                controls=[
                    self.alt_key_3_label,
                    self.alt_key_3_title,
                    self.alt_key_3_conf,
                ],
            ),
        )

        self.alt_keys_row = ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                ft.Text("Outros tons possíveis:", size=11, color=C_MUTED, weight=ft.FontWeight.W_600),
                ft.Row(spacing=8, controls=[self.circle_key_2, self.circle_key_3]),
            ],
        )

        self.history_column = ft.Column(spacing=8)

        self.btn_mic = ft.FilledButton(
            content="Ouvir Microfone",
            icon=ft.Icons.MIC,
            bgcolor=C_IN_TUNE,
            color="#18181B",
            expand=True,
            on_click=self.toggle_mic,
        )

        self.btn_sim = ft.OutlinedButton(
            content="Simular Voz",
            icon=ft.Icons.GRAPHIC_EQ,
            style=ft.ButtonStyle(
                color=C_TEXT,
                side=ft.BorderSide(1, C_BORDER),
            ),
            expand=True,
            on_click=self.trigger_simulation,
        )

        self.btn_save_tuner = ft.FilledButton(
            content="Salvar Tom Detectado no Histórico",
            icon=ft.Icons.LOCK_OUTLINE,
            bgcolor=C_ACCENT,
            color="#18181B",
            on_click=self.save_current_key,
        )

        self.mic_dropdown.on_select = self.on_mic_device_change
        self.mic_service.on_update = self.on_audio_update

        # Coluna visual da Aba 1
        self.view = ft.Column(
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            controls=[
                self.mic_dropdown,
                ft.Column(
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=4,
                    controls=[self.mic_level_label, self.mic_level_bar],
                ),
                self.status_badge,
                self.tuner_gauge,
                self.key_card,
                self.alt_keys_row,
                ft.Row(spacing=10, controls=[self.btn_mic, self.btn_sim]),
                self.btn_save_tuner,
                ft.Divider(color=C_BORDER),
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Text("Últimos Tons Capturados", size=14, weight=ft.FontWeight.BOLD, color=C_TEXT),
                    ],
                ),
                ft.Container(content=self.history_column),
            ],
        )

    def refresh_history_ui(self) -> None:
        records = self.vault.load_records()
        self.history_column.controls.clear()
        if not records:
            self.history_column.controls.append(
                ft.Text("Nenhum tom salvo ainda no cofre local.", size=12, color=C_MUTED)
            )
        else:
            for rec in records[:5]:
                self.history_column.controls.append(
                    ft.Container(
                        padding=10,
                        border_radius=10,
                        bgcolor=C_SURFACE,
                        border=ft.Border.all(1, C_BORDER),
                        content=ft.Row(
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            controls=[
                                ft.Column(
                                    spacing=2,
                                    controls=[
                                        ft.Text(
                                            f"{rec.detected_key_pt} ({rec.detected_key_en})",
                                            size=14,
                                            weight=ft.FontWeight.BOLD,
                                            color=C_TEXT,
                                        ),
                                        ft.Text(
                                            f"Relativa: {rec.relative_key_pt} • Nota: {rec.last_note} ({rec.last_freq_hz} Hz)",
                                            size=11,
                                            color=C_MUTED,
                                        ),
                                    ],
                                ),
                                ft.Column(
                                    horizontal_alignment=ft.CrossAxisAlignment.END,
                                    spacing=2,
                                    controls=[
                                        ft.Text(f"{rec.confidence_pct}%", size=12, weight=ft.FontWeight.BOLD, color=C_IN_TUNE),
                                        ft.Text(rec.timestamp, size=10, color=C_MUTED),
                                    ],
                                ),
                            ],
                        ),
                    )
                )
        try:
            self.page.update()
        except Exception:
            pass

    def on_audio_update(self, frame: VoiceFrameResult, key_est: KeyEstimation | None) -> None:
        now_ts = time.monotonic()
        if (now_ts - self.last_ui_render_ts) < 0.050 and not frame.is_singing:
            return
        self.last_ui_render_ts = now_ts

        norm_vol = min(1.0, frame.rms_volume * 35.0)
        self.mic_level_bar.value = norm_vol
        if frame.rms_volume >= 0.0018:
            self.mic_level_label.value = f"Sinal do Microfone: Ativo (RMS {frame.rms_volume:.4f})"
            self.mic_level_bar.color = C_IN_TUNE if frame.is_singing else C_ACCENT
        else:
            self.mic_level_label.value = "Sinal do Microfone: Silêncio (cante próximo ao microfone)"
            self.mic_level_bar.color = C_MUTED

        if frame.is_singing and frame.note is not None:
            n = frame.note
            self.note_title.value = f"{n.note_pt}{n.octave}"
            self.note_subtitle.value = f"Cifra: {n.full_name_en}"
            target_hz = n.nominal_frequency_hz if n.nominal_frequency_hz > 0 else n.frequency_hz
            self.freq_label.value = f"{target_hz:.1f} Hz  |  {n.cents_offset:+.0f} cents"

            norm_cents = max(0.0, min(1.0, (n.cents_offset + 50.0) / 100.0))
            self.cents_bar.value = norm_cents

            if abs(n.cents_offset) <= 15.0:
                self.tuner_gauge.border = ft.Border.all(4, C_IN_TUNE)
                self.cents_bar.color = C_IN_TUNE
            else:
                self.tuner_gauge.border = ft.Border.all(4, C_OFF_TUNE)
                self.cents_bar.color = C_OFF_TUNE
        else:
            self.cents_bar.value = 0.5
            self.cents_bar.color = C_MUTED
            self.tuner_gauge.border = ft.Border.all(4, C_BORDER)
            if self.note_title.value != "--":
                self.note_subtitle.value = "Aguardando canto..."

        if key_est is not None:
            self.key_main_text.value = f"{key_est.key_pt} ({key_est.key_en})"
            self.key_relative_text.value = f"Escala Relativa: {key_est.relative_key_pt} ({key_est.relative_key_en})"
            self.confidence_chip.value = f"Confiança: {int(key_est.confidence * 100)}%"

            self.alt_key_2_title.value = key_est.second_key_en or "--"
            self.alt_key_2_conf.value = f"{int(key_est.second_confidence * 100)}%" if key_est.second_confidence > 0 else "--%"
            self.alt_key_3_title.value = key_est.third_key_en or "--"
            self.alt_key_3_conf.value = f"{int(key_est.third_confidence * 100)}%" if key_est.third_confidence > 0 else "--%"

        try:
            self.page.update()
        except Exception:
            pass

    def _selected_device_index(self) -> int | None:
        val = self.mic_dropdown.value
        if val and val.isdigit():
            return int(val)
        return None

    def reset_audio_and_key_ui(self) -> None:
        self.mic_service.reset_session()
        self.key_main_text.value = "Aguardando voz..."
        self.key_relative_text.value = "Cante por alguns segundos para identificar o Tom"
        self.confidence_chip.value = "Confiança: --%"
        self.note_title.value = "--"
        self.note_subtitle.value = "Cante no microfone"
        self.freq_label.value = "0.0 Hz  |  0 cents"
        self.cents_bar.value = 0.5
        self.cents_bar.color = C_IN_TUNE
        self.tuner_gauge.border = ft.Border.all(4, C_BORDER)
        self.mic_level_bar.value = 0.0
        self.mic_level_label.value = "Sinal do Microfone: Silêncio"
        self.alt_key_2_title.value = "--"
        self.alt_key_2_conf.value = "--%"
        self.alt_key_3_title.value = "--"
        self.alt_key_3_conf.value = "--%"

    async def toggle_mic(self, e: ft.ControlEvent) -> None:
        if self.mic_service.is_running:
            if self.mic_service._flet_recorder is not None:
                try:
                    await self.mic_service._flet_recorder.stop_recording()
                except Exception:
                    pass
                self.mic_service._flet_recorder = None
            self.mic_service.stop()

            self.note_title.value = "--"
            self.note_subtitle.value = "Microfone em pausa • Tom mantido"
            self.freq_label.value = "0.0 Hz  |  0 cents"
            self.cents_bar.value = 0.5
            self.cents_bar.color = C_IN_TUNE
            self.tuner_gauge.border = ft.Border.all(4, C_BORDER)
            self.mic_level_bar.value = 0.0
            self.mic_level_label.value = "Sinal do Microfone: Silêncio"

            self.btn_mic.content = "Ouvir Microfone"
            self.btn_mic.bgcolor = C_IN_TUNE
            self.btn_mic.color = "#18181B"
            self.status_badge.value = "Microfone pausado • Tom detectado preservado"
        else:
            self.reset_audio_and_key_ui()

            is_mobile = getattr(self.page, "platform", None) in (
                ft.PagePlatform.ANDROID,
                ft.PagePlatform.IOS,
            )
            if is_mobile and self.mobile_recorder is not None:
                ok, msg = await self.mic_service.start_mobile_flet_recorder(self.mobile_recorder)
            else:
                ok, msg = self.mic_service.start_microphone(device_index=self._selected_device_index())
                if not ok and self.mobile_recorder is not None:
                    ok_mob, msg_mob = await self.mic_service.start_mobile_flet_recorder(self.mobile_recorder)
                    if ok_mob:
                        ok, msg = ok_mob, msg_mob
            self.status_badge.value = msg
            if ok:
                self.btn_mic.content = "Parar Microfone"
                self.btn_mic.bgcolor = C_DANGER
                self.btn_mic.color = "#FFFFFF"
        self.page.update()

    def on_mic_device_change(self, e: ft.ControlEvent) -> None:
        sel_val = getattr(e, "data", None) or getattr(getattr(e, "control", None), "value", None) or self.mic_dropdown.value
        if sel_val is not None:
            self.mic_dropdown.value = str(sel_val)
        if self.mic_service.is_running and self.mic_service._flet_recorder is None:
            ok, msg = self.mic_service.start_microphone(device_index=self._selected_device_index())
            self.status_badge.value = msg
            self.page.update()

    def trigger_simulation(self, e: ft.ControlEvent) -> None:
        if self.mic_service.is_running:
            self.mic_service.stop()
            self.note_title.value = "--"
            self.note_subtitle.value = "Simulação em pausa • Tom mantido"
            self.freq_label.value = "0.0 Hz  |  0 cents"
            self.btn_mic.content = "Ouvir Microfone"
            self.btn_mic.bgcolor = C_IN_TUNE
            self.btn_mic.color = "#18181B"
            self.status_badge.value = "Simulação pausada • Tom preservado"
        else:
            self.reset_audio_and_key_ui()
            self.mic_service.start_voice_simulation("Sol Maior")
            self.btn_mic.content = "Parar Simulação"
            self.btn_mic.bgcolor = C_DANGER
            self.btn_mic.color = "#FFFFFF"
            self.status_badge.value = "Simulando voz cantando em Sol Maior (G)..."
        self.page.update()

    def save_current_key(self, e: ft.ControlEvent) -> None:
        if self.mic_service.last_key is None:
            self.status_badge.value = "Cante ou simule por alguns segundos antes de salvar o Tom!"
            self.page.update()
            return

        k = self.mic_service.last_key
        last_n = self.mic_service.last_frame.note if (self.mic_service.last_frame and self.mic_service.last_frame.note) else None
        rec = self.vault.create_record(
            key_pt=k.key_pt,
            key_en=k.key_en,
            relative_pt=k.relative_key_pt,
            confidence=k.confidence,
            last_note=last_n.full_name_pt if last_n else k.key_pt,
            last_freq_hz=last_n.frequency_hz if last_n else 0.0,
        )
        self.vault.save_record(rec)
        self.status_badge.value = f"Tom {k.key_pt} salvo no cofre criptografado (AES-256-GCM)!"
        self.refresh_history_ui()
