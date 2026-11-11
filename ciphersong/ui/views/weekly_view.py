"""
Aba 3: Repertório da Semana, 7 Sub-abas de dias da semana, Agendamento e Exclusão (UI/UX Flet 1.0).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
import logging
import threading
from typing import Any

import flet as ft
from ciphersong.security.local_vault import EncryptedSessionVault

from ciphersong.services.api_client import SongsApiClient
from ciphersong.ui.theme import (
    C_ACCENT,
    C_BG,
    C_BORDER,
    C_CARD_BG,
    C_DANGER,
    C_IN_TUNE,
    C_INPUT_BG,
    C_MUTED,
    C_SURFACE,
    C_TEXT,
    C_WHITE,
)

logger = logging.getLogger(__name__)


class WeeklyView:
    """Gerencia o repertório da semana, sub-abas diárias e modais de agendamento/exclusão."""

    WEEK_DAYS_NAMES: list[str] = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]

    def __init__(
        self,
        page: ft.Page,
        vault: EncryptedSessionVault,
        api_client: SongsApiClient,
        show_notification: Callable[..., Any],
        nav_manager: Any | None = None,
        get_logged_user_name: Callable[[], str | None] | None = None,
    ) -> None:
        self.page = page
        self.vault = vault
        self.api_client = api_client
        self.show_notification = show_notification
        self.nav_manager = nav_manager
        self.get_logged_user_name = get_logged_user_name

        self.week_offset = 0
        self.today_date = datetime.now().date()
        self.today_weekday = self.today_date.weekday()
        self.selected_date_str: str = self.today_date.strftime("%Y-%m-%d")
        self.selected_day_name: str = self.WEEK_DAYS_NAMES[self.today_weekday]
        self.selected_date_display: str = self.today_date.strftime("%d/%m")

        self.pending_delete_weekly_id: str | None = None
        self.pending_delete_weekly_item: dict | None = None
        self.cached_db_songs: list[dict] = []

        self.week_range_text = ft.Text("Semana Atual", size=13, weight=ft.FontWeight.W_600, color=C_TEXT)
        self.subtabs_row = ft.Row(scroll=ft.ScrollMode.ADAPTIVE, spacing=6)

        self.weekly_header_title = ft.Text(
            f"📅 Escala de {self.selected_day_name} ({self.selected_date_display})",
            size=15,
            weight=ft.FontWeight.BOLD,
            color=C_TEXT,
        )
        self.weekly_header_count = ft.Text("0 músicas agendadas", size=11, color=C_MUTED)
        self.weekly_songs_column = ft.Column(spacing=8)

        # Modal de Confirmação para Excluir da Escala
        self.del_weekly_title = ft.Text("", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT, text_align=ft.TextAlign.CENTER)
        self.del_weekly_info = ft.Text("", size=12, color=C_MUTED, text_align=ft.TextAlign.CENTER)

        self.delete_weekly_card = ft.Container(
            width=360,
            padding=22,
            border_radius=20,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1.5, C_BORDER),
            shadow=ft.BoxShadow(
                spread_radius=2,
                blur_radius=24,
                color=ft.Colors.with_opacity(0.6, "#000000"),
                offset=ft.Offset(0, 10),
            ),
            content=ft.Column(
                tight=True,
                spacing=14,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Container(
                        width=58,
                        height=58,
                        shape=ft.BoxShape.CIRCLE,
                        bgcolor=ft.Colors.with_opacity(0.15, C_DANGER),
                        alignment=ft.Alignment.CENTER,
                        content=ft.Icon(
                            ft.Icons.DELETE_FOREVER_ROUNDED,
                            color=C_DANGER,
                            size=32,
                        ),
                    ),
                    self.del_weekly_title,
                    self.del_weekly_info,
                    ft.Container(height=4),
                    ft.Row(
                        spacing=12,
                        alignment=ft.MainAxisAlignment.CENTER,
                        controls=[
                            ft.OutlinedButton(
                                content="Cancelar",
                                style=ft.ButtonStyle(
                                    color=C_TEXT,
                                    side=ft.BorderSide(1, C_BORDER),
                                    padding=ft.Padding.symmetric(horizontal=18, vertical=12),
                                ),
                                expand=True,
                                on_click=self.close_delete_weekly_modal,
                            ),
                            ft.FilledButton(
                                content="Remover",
                                icon=ft.Icons.DELETE_OUTLINE,
                                bgcolor=C_DANGER,
                                color=C_WHITE,
                                style=ft.ButtonStyle(
                                    padding=ft.Padding.symmetric(horizontal=18, vertical=12),
                                ),
                                expand=True,
                                on_click=self.confirm_delete_weekly_song,
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.delete_weekly_confirm_overlay = ft.Container(
            left=0,
            top=0,
            right=0,
            bottom=0,
            alignment=ft.Alignment.CENTER,
            bgcolor=ft.Colors.with_opacity(0.70, C_INPUT_BG),
            blur=ft.Blur(14, 14, tile_mode=ft.BlurTileMode.CLAMP),
            visible=False,
            content=ft.Column(
                scroll=ft.ScrollMode.AUTO,
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[self.delete_weekly_card],
            ),
        )

        # Modal para Agendar Música na Escala
        self.weekly_song_dropdown = ft.Dropdown(
            label="Escolha a Música da Equipe",
            hint_text="Selecione uma das músicas ensaiadas",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
            options=[],
            on_select=self.on_weekly_song_selected,
        )

        self.weekly_song_key_display_text = ft.Text(
            "Selecione uma música do acervo",
            size=12,
            weight=ft.FontWeight.BOLD,
            color=C_CARD_BG,
        )

        self.weekly_song_key_badge = ft.Container(
            content=self.weekly_song_key_display_text,
            bgcolor=C_ACCENT,
            border_radius=8,
            padding=ft.Padding.symmetric(horizontal=10, vertical=6),
            alignment=ft.Alignment.CENTER,
        )

        self.weekly_song_details_text = ft.Text(
            "Música selecionada no banco de dados.",
            size=11,
            color=C_MUTED,
        )

        self.weekly_day_checkboxes: list[ft.Checkbox] = []
        self.weekly_days_selection_column = ft.Column(spacing=2)
        self.weekly_add_feedback = ft.Text("", size=11, color=C_DANGER, text_align=ft.TextAlign.CENTER)
        self.weekly_modal_title = ft.Text("📅 Agendar no Repertório", size=17, weight=ft.FontWeight.BOLD, color=C_TEXT)

        self.add_weekly_card = ft.Container(
            width=360,
            padding=20,
            border_radius=20,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1.5, C_BORDER),
            shadow=ft.BoxShadow(
                spread_radius=2,
                blur_radius=24,
                color=ft.Colors.with_opacity(0.6, "#000000"),
                offset=ft.Offset(0, 10),
            ),
            content=ft.Column(
                tight=True,
                spacing=10,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            self.weekly_modal_title,
                            ft.IconButton(
                                icon=ft.Icons.CLOSE,
                                icon_color=C_MUTED,
                                tooltip="Fechar",
                                on_click=self.close_add_weekly_modal,
                            ),
                        ],
                    ),
                    ft.Text(
                        "Marque as músicas que estão no banco de dados para os respectivos dias da semana.",
                        size=11,
                        color=C_MUTED,
                    ),
                    self.weekly_song_dropdown,
                    self.weekly_song_key_badge,
                    self.weekly_song_details_text,
                    ft.Divider(color=C_BORDER),
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("Selecione os dias da escala:", size=12, weight=ft.FontWeight.BOLD, color=C_TEXT),
                        ],
                    ),
                    ft.Container(
                        padding=8,
                        border_radius=10,
                        bgcolor=C_BG,
                        border=ft.Border.all(1, C_BORDER),
                        content=self.weekly_days_selection_column,
                    ),
                    self.weekly_add_feedback,
                    ft.Row(
                        spacing=10,
                        alignment=ft.MainAxisAlignment.CENTER,
                        controls=[
                            ft.OutlinedButton(
                                content="Cancelar",
                                style=ft.ButtonStyle(
                                    color=C_TEXT,
                                    side=ft.BorderSide(1, C_BORDER),
                                    padding=ft.Padding.symmetric(horizontal=16, vertical=12),
                                ),
                                expand=True,
                                on_click=self.close_add_weekly_modal,
                            ),
                            ft.FilledButton(
                                content="Agendar",
                                icon=ft.Icons.EVENT_AVAILABLE,
                                bgcolor=C_ACCENT,
                                color=C_CARD_BG,
                                style=ft.ButtonStyle(
                                    padding=ft.Padding.symmetric(horizontal=16, vertical=12),
                                ),
                                expand=True,
                                on_click=self.confirm_add_weekly_song,
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.add_weekly_overlay = ft.Container(
            left=0,
            top=0,
            right=0,
            bottom=0,
            alignment=ft.Alignment.CENTER,
            bgcolor=ft.Colors.with_opacity(0.70, C_INPUT_BG),
            blur=ft.Blur(14, 14, tile_mode=ft.BlurTileMode.CLAMP),
            visible=False,
            content=ft.Column(
                scroll=ft.ScrollMode.AUTO,
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[self.add_weekly_card],
            ),
        )

        self.fab_add_weekly_song = ft.FloatingActionButton(
            icon=ft.Icons.ADD,
            bgcolor=C_ACCENT,
            foreground_color=C_CARD_BG,
            tooltip="Agendar música para esta semana",
            on_click=self.open_add_weekly_modal,
            shape=ft.CircleBorder(),
        )

        self.view = ft.Column(
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            visible=False,
            controls=[
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.IconButton(ft.Icons.CHEVRON_LEFT, icon_color=C_TEXT, tooltip="Semana anterior", on_click=self.prev_week),
                        ft.Row(
                            spacing=6,
                            controls=[
                                self.week_range_text,
                                ft.TextButton(
                                    content="Hoje",
                                    style=ft.ButtonStyle(color=C_ACCENT),
                                    tooltip="Voltar para a data atual",
                                    on_click=self.reset_to_today,
                                ),
                            ],
                        ),
                        ft.IconButton(ft.Icons.CHEVRON_RIGHT, icon_color=C_TEXT, tooltip="Próxima semana", on_click=self.next_week),
                    ],
                ),
                ft.Container(
                    content=self.subtabs_row,
                ),
                ft.Divider(color=C_BORDER),
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Column(
                            spacing=2,
                            controls=[
                                self.weekly_header_title,
                                self.weekly_header_count,
                            ],
                        ),
                        ft.IconButton(
                            icon=ft.Icons.SYNC,
                            icon_color=C_ACCENT,
                            tooltip="Atualizar da nuvem (tempo real)",
                            on_click=lambda e: self.refresh_weekly_schedule(),
                        ),
                    ],
                ),
                ft.Container(content=self.weekly_songs_column),
            ],
        )

    def get_week_info(self, offset: int):
        target_ref = self.today_date + timedelta(weeks=offset)
        monday = target_ref - timedelta(days=target_ref.weekday())
        sunday = monday + timedelta(days=6)
        days = []
        for i in range(7):
            d = monday + timedelta(days=i)
            days.append({
                "date": d,
                "date_str": d.strftime("%Y-%m-%d"),
                "date_display": d.strftime("%d/%m"),
                "name": self.WEEK_DAYS_NAMES[i],
                "is_today": (d == self.today_date),
            })
        return days, monday, sunday

    def close_delete_weekly_modal(self, e: ft.ControlEvent) -> None:
        self.pending_delete_weekly_id = None
        self.pending_delete_weekly_item = None
        self.delete_weekly_confirm_overlay.visible = False
        self.page.update()

    def confirm_delete_weekly_song(self, e: ft.ControlEvent) -> None:
        if self.pending_delete_weekly_id:
            target_id = self.pending_delete_weekly_id
            item = getattr(self, "pending_delete_weekly_item", {}) or {}
            titulo = item.get("titulo", "Música")
            data_ensaio = item.get("data_ensaio")

            self.pending_delete_weekly_id = None
            self.pending_delete_weekly_item = None
            self.delete_weekly_confirm_overlay.visible = False
            self.page.update()

            # 1. Deleta imediatamente do cofre local seguro para resposta visual instantânea
            self.vault.delete_weekly_item(target_id, titulo=titulo, data_ensaio=data_ensaio)
            self.refresh_weekly_schedule(sync_cloud=False)

            # 2. Deleta no MongoDB Atlas em background e re-sincroniza
            def _bg_delete():
                try:
                    deleted = self.api_client.remover_repertorio_semana(
                        target_id,
                        titulo=titulo,
                        data_ensaio=data_ensaio,
                    )
                    if deleted:
                        if self.show_notification:
                            self.show_notification(f"'{titulo}' removida da escala!", True)
                    else:
                        if self.show_notification:
                            self.show_notification(f"'{titulo}' removida localmente.", True)
                except Exception as exc:
                    print(f"[Delete Weekly API Warning]: {exc}")
                    if self.show_notification:
                        self.show_notification("Removida localmente (offline).", False)

                self.vault.delete_weekly_item(target_id, titulo=titulo, data_ensaio=data_ensaio)
                self.refresh_weekly_schedule(sync_cloud=True)

            threading.Thread(target=_bg_delete, daemon=True).start()

    def prompt_delete_weekly_song(self, item: dict) -> None:
        self.pending_delete_weekly_id = str(item.get("_id") or item.get("id") or "")
        self.pending_delete_weekly_item = item
        self.del_weekly_title.value = item.get("titulo", "Música")
        sol = item.get("cantor_principal", "Não informado")
        tom = item.get("tom_selecionado") or item.get("tom") or item.get("key") or "Tom não definido"
        dt = item.get("data_ensaio", "")
        self.del_weekly_info.value = f"🎤 Solista: {sol} • Tom: {tom}\n📅 Data: {dt}"
        self.delete_weekly_confirm_overlay.visible = True
        self.page.update()

    def extract_song_keys(self, song_dict: dict) -> list[str]:
        raw = song_dict.get("tons") or song_dict.get("keys") or song_dict.get("tom") or []
        if isinstance(raw, str):
            raw = raw.strip()
            if raw.startswith("[") and raw.endswith("]"):
                try:
                    import json
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        raw = parsed
                except Exception:
                    pass
            if isinstance(raw, str):
                if "," in raw:
                    raw = [x.strip() for x in raw.split(",") if x.strip()]
                elif "/" in raw:
                    raw = [x.strip() for x in raw.split("/") if x.strip()]
                elif raw:
                    raw = [raw]
                else:
                    raw = []
        if isinstance(raw, list):
            cleaned: list[str] = []
            for item in raw:
                s_item = str(item).strip()
                if s_item and s_item not in cleaned:
                    cleaned.append(s_item)
            return cleaned
        return []

    def on_weekly_song_selected(self, e: ft.ControlEvent | None = None) -> None:
        selected_song_id = None
        if e is not None and getattr(e, "data", None):
            selected_song_id = str(e.data).strip()
        elif hasattr(self.weekly_song_dropdown, "value") and self.weekly_song_dropdown.value:
            selected_song_id = str(self.weekly_song_dropdown.value).strip()

        if selected_song_id:
            self.weekly_song_dropdown.value = selected_song_id

        matched = next(
            (s for s in self.cached_db_songs if str(s.get("_id") or s.get("id")) == str(selected_song_id)),
            None
        )

        if matched:
            song_keys = self.extract_song_keys(matched)
            if song_keys:
                recorded_tones_str = ", ".join(song_keys)
            elif matched.get("tons") or matched.get("keys") or matched.get("tom"):
                raw_t = matched.get("tons") or matched.get("keys") or matched.get("tom")
                recorded_tones_str = str(raw_t[0] if isinstance(raw_t, list) and raw_t else raw_t)
            else:
                recorded_tones_str = "Tom padrão (G)"

            self.weekly_song_key_display_text.value = f"🎼 {recorded_tones_str}"
            singer = matched.get("cantor_principal") or matched.get("soloist") or "Não informado"
            versao = matched.get("versao", "Original")
            self.weekly_song_details_text.value = f"🎤 Solista: {singer} • 🎸 Versão: {versao}"
            self.weekly_song_details_text.color = C_ACCENT
        else:
            self.weekly_song_key_display_text.value = "Selecione uma música do acervo"
            self.weekly_song_details_text.value = "Música não encontrada no acervo."
            self.weekly_song_details_text.color = C_MUTED

        try:
            self.weekly_song_key_display_text.update()
        except Exception:
            pass
        try:
            self.weekly_song_details_text.update()
        except Exception:
            pass
        try:
            self.page.update()
        except Exception:
            pass

    def close_add_weekly_modal(self, e: ft.ControlEvent) -> None:
        self.add_weekly_overlay.visible = False
        self.page.update()

    def confirm_add_weekly_song(self, e: ft.ControlEvent) -> None:
        song_id = self.weekly_song_dropdown.value
        if not song_id:
            self.weekly_add_feedback.value = "⚠️ Por favor, selecione uma música do acervo!"
            self.page.update()
            return

        selected_days = [cb.data for cb in self.weekly_day_checkboxes if cb.value]
        if not selected_days:
            self.weekly_add_feedback.value = "⚠️ Selecione pelo menos 1 dia da semana para agendar!"
            self.page.update()
            return

        matched = next((s for s in self.cached_db_songs if str(s.get("_id") or s.get("id")) == str(song_id)), None)
        title = matched.get("titulo") or matched.get("title") or "Música" if matched else "Música"
        singer = matched.get("cantor_principal") or matched.get("soloist") or "Não informado" if matched else "Não informado"
        versao = matched.get("versao", "Original") if matched else "Original"

        song_keys = self.extract_song_keys(matched) if matched else []
        if song_keys:
            tom = str(song_keys[0])
        elif matched and (matched.get("tons") or matched.get("keys") or matched.get("tom")):
            raw_t = matched.get("tons") or matched.get("keys") or matched.get("tom")
            tom = str(raw_t[0] if isinstance(raw_t, list) and raw_t else raw_t)
        else:
            tom = "Tom não informado"

        user_name = (self.get_logged_user_name() if self.get_logged_user_name else None) or "Equipe"

        days_info, _, _ = self.get_week_info(self.week_offset)
        items_to_sync: list[dict] = []
        for d_str in selected_days:
            d_info = next((d for d in days_info if d["date_str"] == d_str), None)
            d_name = d_info["name"] if d_info else "Ensaio"

            saved_w = self.vault.save_weekly_item(
                musica_id=str(song_id),
                titulo=title,
                cantor_principal=singer,
                tom_selecionado=tom,
                data_ensaio=d_str,
                dia_semana=d_name,
                versao=versao,
                adicionado_por=user_name,
                synced=False,
                equipe_id=self.api_client.active_equipe_id or "",
            )
            items_to_sync.append({
                "local_id": saved_w.id,
                "musica_id": str(song_id),
                "titulo": title,
                "cantor_principal": singer,
                "tom_selecionado": tom,
                "data_ensaio": d_str,
                "dia_semana": d_name,
                "versao": versao,
                "adicionado_por": user_name,
            })

        self.add_weekly_overlay.visible = False
        self.refresh_weekly_schedule(sync_cloud=False)
        dias_nomes = [d_info["name"] for d_str in selected_days for d_info in days_info if d_info["date_str"] == d_str]
        dias_str = ", ".join(dias_nomes) if dias_nomes else "dias selecionados"
        self.show_notification(f"'{title}' marcada para {dias_str} no Repertório da Semana!", vibrate=True, title="📅 Agendado na Semana")
        if self.nav_manager and self.nav_manager.current_tab != "weekly":
            self.nav_manager.unseen_weekly_count += len(selected_days)
            try:
                self.nav_manager.update_badges_and_glow()
            except Exception:
                pass
        try:
            self.page.update()
        except Exception:
            pass

        def _bg_sync_weekly_add():
            for it in items_to_sync:
                try:
                    self.api_client.adicionar_repertorio_semana(
                        musica_id=it["musica_id"],
                        titulo=it["titulo"],
                        cantor_principal=it["cantor_principal"],
                        tom_selecionado=it["tom_selecionado"],
                        data_ensaio=it["data_ensaio"],
                        dia_semana=it["dia_semana"],
                        versao=it["versao"],
                        adicionado_por=it["adicionado_por"],
                        equipe_id=self.api_client.active_equipe_id,
                    )
                    self.vault.mark_weekly_as_synced(it["local_id"])
                except Exception:
                    pass
            self.refresh_weekly_schedule(sync_cloud=False)

        threading.Thread(target=_bg_sync_weekly_add, daemon=True).start()

    def open_add_weekly_modal(self, e: ft.ControlEvent | None = None, preselected_song: dict | None = None) -> None:
        self.weekly_add_feedback.value = ""

        loaded_songs: list[dict] = []
        seen_norm_keys: set[tuple[str, str, str]] = set()

        if preselected_song:
            p_id = str(preselected_song.get("id") or preselected_song.get("_id") or "")
            p_title = preselected_song.get("title") or preselected_song.get("titulo") or "Música"
            p_sol = preselected_song.get("soloist") or preselected_song.get("cantor_principal") or ""
            p_ver = preselected_song.get("versao") or "Original"
            norm_key = (p_title.strip().lower(), p_sol.strip().lower(), p_ver.strip().lower())
            seen_norm_keys.add(norm_key)
            loaded_songs.append({
                "_id": p_id,
                "id": p_id,
                "titulo": p_title,
                "title": p_title,
                "cantor_principal": p_sol,
                "soloist": p_sol,
                "tons": preselected_song.get("keys") or preselected_song.get("tons") or [],
                "versao": p_ver,
            })
            self.weekly_modal_title.value = f"📅 Marcar: {p_title}"
        else:
            self.weekly_modal_title.value = "📅 Agendar no Repertório"

        try:
            local_songs = self.vault.load_songs(equipe_id=self.api_client.active_equipe_id)
            for s in local_songs:
                norm_key = (
                    str(s.title).strip().lower(),
                    str(s.soloist).strip().lower(),
                    str(s.versao).strip().lower(),
                )
                if norm_key[0] and norm_key not in seen_norm_keys:
                    seen_norm_keys.add(norm_key)
                    loaded_songs.append({
                        "_id": s.id,
                        "id": s.id,
                        "titulo": s.title,
                        "title": s.title,
                        "cantor_principal": s.soloist,
                        "soloist": s.soloist,
                        "tons": s.keys,
                        "versao": s.versao,
                    })
        except Exception:
            pass

        self.cached_db_songs = loaded_songs

        def _format_option_text(s_item: dict) -> str:
            t = s_item.get("titulo") or s_item.get("title") or "Música"
            sol = s_item.get("cantor_principal") or s_item.get("soloist") or ""
            k_list = self.extract_song_keys(s_item)
            k_badge = f" [{k_list[0]}]" if k_list else ""
            if sol and sol.lower() != "não informado":
                return f"{t} — {sol}{k_badge}"
            return f"{t}{k_badge}"

        opts = [
            ft.DropdownOption(
                key=str(s.get("_id") or s.get("id")),
                text=_format_option_text(s),
            )
            for s in self.cached_db_songs
        ]
        self.weekly_song_dropdown.options = opts

        if preselected_song and self.cached_db_songs or self.cached_db_songs:
            self.weekly_song_dropdown.value = str(self.cached_db_songs[0].get("_id") or self.cached_db_songs[0].get("id"))
            self.on_weekly_song_selected(None)
        else:
            self.weekly_song_dropdown.value = None
            self.weekly_song_key_display_text.value = "Nenhuma música no acervo"
            self.weekly_song_details_text.value = "Cadastre músicas na Aba 'Músicas' antes de agendar."

        days_info, _, _ = self.get_week_info(self.week_offset)
        self.weekly_day_checkboxes = []
        self.weekly_days_selection_column.controls.clear()

        for d in days_info:
            is_def_checked = (d["date_str"] == self.selected_date_str)
            cb = ft.Checkbox(
                label=f"{d['name']} ({d['date_display']})",
                value=is_def_checked,
                data=d["date_str"],
                fill_color=C_ACCENT,
                check_color=C_CARD_BG,
            )
            self.weekly_day_checkboxes.append(cb)
            self.weekly_days_selection_column.controls.append(cb)

        self.add_weekly_overlay.visible = True
        self.page.update()

        def _bg_fetch_db() -> None:
            try:
                cloud_db, _ = self.api_client.listar_ou_buscar("", equipe_id=self.api_client.active_equipe_id)
                if cloud_db:
                    updated = list(self.cached_db_songs)
                    seen_ids = {str(s.get("_id") or s.get("id")) for s in updated}
                    for doc in cloud_db:
                        doc_id = str(doc.get("_id", ""))
                        if doc_id and doc_id not in seen_ids:
                            seen_ids.add(doc_id)
                            updated.append(doc)
                    self.cached_db_songs = updated
                    new_opts = [
                        ft.DropdownOption(
                            key=str(s.get("_id") or s.get("id")),
                            text=_format_option_text(s),
                        )
                        for s in self.cached_db_songs
                    ]
                    self.weekly_song_dropdown.options = new_opts
                    if not self.weekly_song_dropdown.value and self.cached_db_songs:
                        self.weekly_song_dropdown.value = str(self.cached_db_songs[0].get("_id") or self.cached_db_songs[0].get("id"))
                        self.on_weekly_song_selected(None)
                    self.page.update()
            except Exception as exc:
                logger.debug("Erro ao buscar músicas da nuvem no modal semanal: %s", exc)

        threading.Thread(target=_bg_fetch_db, daemon=True).start()

    def render_subtabs(self) -> None:
        self.subtabs_row.controls.clear()
        days_info, monday, sunday = self.get_week_info(self.week_offset)
        self.week_range_text.value = f"Semana: {monday.strftime('%d/%m')} a {sunday.strftime('%d/%m')}"

        for d in days_info:
            is_sel = (d["date_str"] == self.selected_date_str)
            is_tod = d["is_today"]

            if is_sel:
                bg = C_ACCENT
                txt_col = "#18181B"
                date_col = "#09090B"
                border_style = ft.Border.all(1.5, C_ACCENT)
            elif is_tod:
                bg = C_SURFACE
                txt_col = C_TEXT
                date_col = C_IN_TUNE
                border_style = ft.Border.all(1.5, C_IN_TUNE)
            else:
                bg = C_SURFACE
                txt_col = C_TEXT
                date_col = C_MUTED
                border_style = ft.Border.all(1, C_BORDER)

            def _make_select(day_data: dict):
                def _on_subtab_click(e: ft.ControlEvent) -> None:
                    self.selected_date_str = day_data["date_str"]
                    self.selected_day_name = day_data["name"]
                    self.selected_date_display = day_data["date_display"]
                    self.weekly_header_title.value = f"📅 Escala de {self.selected_day_name} ({self.selected_date_display})"
                    self.render_subtabs()
                    self.refresh_weekly_schedule(sync_cloud=True)
                return _on_subtab_click

            subtab_btn = ft.Container(
                content=ft.Column(
                    spacing=2,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.Text(d["name"], size=11, weight=ft.FontWeight.BOLD, color=txt_col),
                        ft.Text(d["date_display"], size=10, weight=ft.FontWeight.W_600, color=date_col),
                    ],
                ),
                padding=ft.Padding.symmetric(horizontal=10, vertical=7),
                border_radius=10,
                bgcolor=bg,
                border=border_style,
                alignment=ft.Alignment.CENTER,
                on_click=_make_select(d),
            )
            self.subtabs_row.controls.append(subtab_btn)
        self.page.update()

    def prev_week(self, e: ft.ControlEvent) -> None:
        self.week_offset -= 1
        days_info, _, _ = self.get_week_info(self.week_offset)
        self.selected_date_str = days_info[0]["date_str"]
        self.selected_day_name = days_info[0]["name"]
        self.selected_date_display = days_info[0]["date_display"]
        self.weekly_header_title.value = f"📅 Escala de {self.selected_day_name} ({self.selected_date_display})"
        self.render_subtabs()
        self.refresh_weekly_schedule(sync_cloud=True)

    def next_week(self, e: ft.ControlEvent) -> None:
        self.week_offset += 1
        days_info, _, _ = self.get_week_info(self.week_offset)
        self.selected_date_str = days_info[0]["date_str"]
        self.selected_day_name = days_info[0]["name"]
        self.selected_date_display = days_info[0]["date_display"]
        self.weekly_header_title.value = f"📅 Escala de {self.selected_day_name} ({self.selected_date_display})"
        self.render_subtabs()
        self.refresh_weekly_schedule(sync_cloud=True)

    def reset_to_today(self, e: ft.ControlEvent) -> None:
        self.week_offset = 0
        self.selected_date_str = self.today_date.strftime("%Y-%m-%d")
        self.selected_day_name = self.WEEK_DAYS_NAMES[self.today_weekday]
        self.selected_date_display = self.today_date.strftime("%d/%m")
        self.weekly_header_title.value = f"📅 Escala de {self.selected_day_name} ({self.selected_date_display})"
        self.render_subtabs()
        self.refresh_weekly_schedule(sync_cloud=True)

    def _render_weekly_to_ui(self, items: list[dict], source_badge: str) -> None:
        self.weekly_songs_column.controls.clear()
        self.weekly_header_count.value = f"{len(items)} {'música' if len(items) == 1 else 'músicas'} agendada{'s' if len(items) != 1 else ''} • {source_badge}"

        if not items:
            self.weekly_songs_column.controls.append(
                ft.Container(
                    padding=28,
                    border_radius=14,
                    bgcolor=C_SURFACE,
                    border=ft.Border.all(1, C_BORDER),
                    alignment=ft.Alignment.CENTER,
                    content=ft.Column(
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=8,
                        controls=[
                            ft.Icon(ft.Icons.EVENT_NOTE_ROUNDED, size=42, color=C_MUTED),
                            ft.Text(
                                f"Nenhuma música agendada para {self.selected_day_name} ({self.selected_date_display})",
                                size=14,
                                weight=ft.FontWeight.BOLD,
                                color=C_TEXT,
                                text_align=ft.TextAlign.CENTER,
                            ),
                            ft.Text(
                                "Toque no botão '+' flutuante no canto inferior direito para adicionar músicas da equipe para este ensaio.",
                                size=11,
                                color=C_MUTED,
                                text_align=ft.TextAlign.CENTER,
                            ),
                        ],
                    ),
                )
            )
        else:
            for item in items:
                def _make_delete_weekly(it: dict):
                    return lambda e: self.prompt_delete_weekly_song(it)

                self.weekly_songs_column.controls.append(
                    ft.Container(
                        padding=12,
                        border_radius=12,
                        bgcolor=C_SURFACE,
                        border=ft.Border.all(1, C_BORDER),
                        content=ft.Column(
                            spacing=6,
                            controls=[
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    vertical_alignment=ft.CrossAxisAlignment.START,
                                    controls=[
                                        ft.Column(
                                            spacing=4,
                                            expand=True,
                                            controls=[
                                                ft.Text(
                                                    item["titulo"],
                                                    size=15,
                                                    weight=ft.FontWeight.BOLD,
                                                    color=C_TEXT,
                                                ),
                                                ft.Row(
                                                    wrap=True,
                                                    spacing=6,
                                                    run_spacing=4,
                                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                                    controls=[
                                                        ft.Container(
                                                            padding=ft.Padding.symmetric(horizontal=8, vertical=2),
                                                            border_radius=6,
                                                            bgcolor=C_ACCENT,
                                                            content=ft.Text(
                                                                f"Tom: {item.get('tom_selecionado') or item.get('tom') or item.get('key') or 'Tom não definido'}",
                                                                size=11,
                                                                weight=ft.FontWeight.BOLD,
                                                                color="#18181B",
                                                            ),
                                                        ),
                                                        ft.Container(
                                                            padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                                                            border_radius=6,
                                                            bgcolor=C_BG,
                                                            border=ft.Border.all(1, C_BORDER),
                                                            content=ft.Text(
                                                                f"🎸 {item.get('versao', 'Original')}",
                                                                size=10,
                                                                color=C_ACCENT,
                                                            ),
                                                        ),
                                                    ],
                                                ),
                                                ft.Text(f"🎤 Solista: {item.get('cantor_principal', 'Não informado')}", size=12, color=C_MUTED),
                                            ],
                                        ),
                                        ft.IconButton(
                                            icon=ft.Icons.DELETE_OUTLINE,
                                            icon_color=C_DANGER,
                                            tooltip="Remover da escala",
                                            on_click=_make_delete_weekly(item),
                                        ),
                                    ],
                                ),
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    controls=[
                                        ft.Text(f"👤 Agendado por: {item.get('adicionado_por', 'Equipe')}", size=11, color=C_MUTED),
                                        ft.Text(f"📅 {item.get('data_ensaio', '')}", size=10, color=C_MUTED),
                                    ],
                                ),
                            ],
                        ),
                    )
                )
        self.page.update()

    def refresh_weekly_schedule(self, sync_cloud: bool = True) -> None:
        local_items = self.vault.load_weekly_schedule(self.selected_date_str, equipe_id=self.api_client.active_equipe_id)
        initial_items = [
            {
                "_id": r.id,
                "id": r.id,
                "musica_id": r.musica_id,
                "titulo": r.titulo,
                "cantor_principal": r.cantor_principal,
                "tom_selecionado": r.tom_selecionado,
                "data_ensaio": r.data_ensaio,
                "dia_semana": r.dia_semana,
                "versao": r.versao,
                "adicionado_por": r.adicionado_por,
            }
            for r in local_items
        ]
        self._render_weekly_to_ui(initial_items, "🔒 Cache Local Seguro")

        if sync_cloud:
            def _bg_weekly_sync() -> None:
                try:
                    unsynced_w = self.vault.get_unsynced_weekly_items()
                    for uw in unsynced_w:
                        try:
                            self.api_client.adicionar_repertorio_semana(
                                musica_id=uw.musica_id,
                                titulo=uw.titulo,
                                cantor_principal=uw.cantor_principal,
                                tom_selecionado=uw.tom_selecionado,
                                data_ensaio=uw.data_ensaio,
                                dia_semana=uw.dia_semana,
                                versao=uw.versao,
                                adicionado_por=uw.adicionado_por,
                                equipe_id=self.api_client.active_equipe_id,
                            )
                            self.vault.mark_weekly_as_synced(uw.id)
                        except Exception as exc:
                            logger.debug("Falha ao sincronizar item offline da semana (%s): %s", uw.titulo, exc)
                            break

                    cloud_items, _ = self.api_client.listar_repertorio_semana(
                        data_ensaio=self.selected_date_str,
                        equipe_id=self.api_client.active_equipe_id,
                    )
                    if cloud_items is not None:
                        deduped_cloud = []
                        seen_w: set[tuple[str, str, str]] = set()
                        for ci in cloud_items:
                            w_tit = str(ci.get("titulo", "")).strip()
                            w_cp = str(ci.get("cantor_principal", "")).strip()
                            w_dt = str(ci.get("data_ensaio", "")).strip()
                            w_key = (w_tit.lower(), w_cp.lower(), w_dt)
                            if not w_tit or w_key in seen_w:
                                continue
                            seen_w.add(w_key)
                            deduped_cloud.append(ci)
                            self.vault.save_weekly_item(
                                musica_id=str(ci.get("musica_id") or ci.get("_id") or ""),
                                titulo=w_tit,
                                cantor_principal=w_cp,
                                tom_selecionado=str(ci.get("tom_selecionado", "")),
                                data_ensaio=w_dt,
                                dia_semana=str(ci.get("dia_semana", "Ensaio")),
                                versao=str(ci.get("versao", "Original")),
                                adicionado_por=str(ci.get("adicionado_por", "Equipe")),
                                synced=True,
                                equipe_id=self.api_client.active_equipe_id or "",
                                item_id=str(ci.get("_id") or ci.get("id") or ""),
                            )
                        self.vault.reconcile_weekly_items(deduped_cloud, data_ensaio=self.selected_date_str, equipe_id=self.api_client.active_equipe_id)
                        self._render_weekly_to_ui(deduped_cloud, "☁️ Nuvem (Todos os usuários)")
                except Exception as exc:
                    logger.debug("Erro na sincronização em segundo plano do repertório da semana: %s", exc)

            threading.Thread(target=_bg_weekly_sync, daemon=True).start()
