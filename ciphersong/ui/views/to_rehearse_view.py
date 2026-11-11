"""
Aba 4: Músicas a Ensaiar, Sugestões com Link do YouTube e Graduação para Repertório Ensaiado (UI/UX Flet 1.0).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

import flet as ft
from ciphersong.security.local_vault import EncryptedSessionVault, sanitize_youtube_url
from ciphersong.services.microphone_stream import LiveMicrophoneService

from ciphersong.services.api_client import SongsApiClient
from ciphersong.ui.theme import (
    ALL_MUSICAL_KEYS,
    C_ACCENT,
    C_BG,
    C_BORDER,
    C_CARD_BG,
    C_DANGER,
    C_IN_TUNE,
    C_INPUT_BG,
    C_MUTED,
    C_OFF_TUNE,
    C_SURFACE,
    C_TEXT,
    C_WHITE,
)

logger = logging.getLogger("ciphersong.ui.to_rehearse")


class ToRehearseView:
    """Gerencia a fila de músicas sugeridas a ensaiar e o fluxo de graduação."""

    def __init__(
        self,
        page: ft.Page,
        vault: EncryptedSessionVault,
        api_client: SongsApiClient,
        mic_service: LiveMicrophoneService,
        on_song_graduated: Callable[[], None] | None = None,
        get_logged_user_name: Callable[[], str | None] | None = None,
    ) -> None:
        self.page = page
        self.vault = vault
        self.api_client = api_client
        self.mic_service = mic_service
        self.on_song_graduated = on_song_graduated
        self.get_logged_user_name = get_logged_user_name

        self.pending_delete_tr_id: str | None = None
        self.pending_delete_item: dict | None = None
        self.current_graduating_item: dict | None = None
        self.grad_selected_keys: set[str] = set()

        self.to_rehearse_header_count = ft.Text("0 músicas na fila", size=11, color=C_MUTED)
        self.to_rehearse_list_column = ft.Column(spacing=8)

        # Modal de Confirmação para Excluir de "A Ensaiar"
        self.del_tr_title = ft.Text("", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT, text_align=ft.TextAlign.CENTER)
        self.del_tr_info = ft.Text("", size=12, color=C_MUTED, text_align=ft.TextAlign.CENTER)

        self.delete_tr_card = ft.Container(
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
                    self.del_tr_title,
                    self.del_tr_info,
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
                                on_click=self.close_delete_tr_modal,
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
                                on_click=self.confirm_delete_tr_song,
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.delete_tr_confirm_overlay = ft.Container(
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
                controls=[self.delete_tr_card],
            ),
        )

        # Modal para Adicionar Música em "A Ensaiar"
        self.tr_title_input = ft.TextField(
            label="Nome da Música *",
            hint_text="Ex: Bondade de Deus / Ruja o Leão",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )
        self.tr_singer_version_input = ft.TextField(
            label="Cantor / Versão de Referência *",
            hint_text="Ex: Isaías Saad / Gabriel Guedes",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )
        self.tr_youtube_input = ft.TextField(
            label="Link do YouTube (Opcional)",
            hint_text="Ex: https://www.youtube.com/watch?v=...",
            prefix_icon=ft.Icons.VIDEO_LIBRARY_ROUNDED,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )
        self.tr_add_feedback = ft.Text("", size=11, color=C_DANGER, text_align=ft.TextAlign.CENTER)

        self.add_to_rehearse_card = ft.Container(
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
                            ft.Text("⏳ Adicionar a Ensaiar", size=17, weight=ft.FontWeight.BOLD, color=C_TEXT),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE,
                                icon_color=C_MUTED,
                                tooltip="Fechar",
                                on_click=self.close_add_to_rehearse_modal,
                            ),
                        ],
                    ),
                    ft.Text(
                        "Músicos e cantores podem sugerir músicas para o próximo ensaio com link de referência.",
                        size=11,
                        color=C_MUTED,
                    ),
                    self.tr_title_input,
                    self.tr_singer_version_input,
                    self.tr_youtube_input,
                    self.tr_add_feedback,
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
                                on_click=self.close_add_to_rehearse_modal,
                            ),
                            ft.FilledButton(
                                content="Adicionar à Fila",
                                icon=ft.Icons.ADD_TASK,
                                bgcolor=C_ACCENT,
                                color=C_CARD_BG,
                                style=ft.ButtonStyle(
                                    padding=ft.Padding.symmetric(horizontal=16, vertical=12),
                                ),
                                expand=True,
                                on_click=self.confirm_add_to_rehearse,
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.add_to_rehearse_overlay = ft.Container(
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
                controls=[self.add_to_rehearse_card],
            ),
        )

        # Modal com Fundo Borrado "Ensaiado" (Graduação)
        self.grad_title_input = ft.TextField(
            label="Nome da Música *",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )
        self.grad_soloist_input = ft.TextField(
            label="Solista / Cantor Principal *",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )
        self.grad_version_input = ft.TextField(
            label="Versão da Cifra / Arranjo",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )
        self.grad_keys_display = ft.Text(
            "Tons selecionados: Nenhum (toque nos botões abaixo)",
            size=11,
            color=C_ACCENT,
            weight=ft.FontWeight.W_600,
        )
        self.grad_keys_grid = ft.Row(
            wrap=True,
            spacing=4,
            run_spacing=4,
        )
        self.grad_feedback_text = ft.Text("", size=11, color=C_DANGER, text_align=ft.TextAlign.CENTER)

        self.graduate_card = ft.Container(
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
                            ft.Row(
                                spacing=6,
                                controls=[
                                    ft.Icon(ft.Icons.CHECK_CIRCLE, color=C_IN_TUNE, size=22),
                                    ft.Text("Marcar como Ensaiada", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                ],
                            ),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE,
                                icon_color=C_MUTED,
                                tooltip="Fechar",
                                on_click=self.close_graduate_modal,
                            ),
                        ],
                    ),
                    ft.Text(
                        "Confirme ou ajuste o nome, solista e selecione o(s) tom(ns) do ensaio.",
                        size=11,
                        color=C_MUTED,
                    ),
                    self.grad_title_input,
                    self.grad_soloist_input,
                    self.grad_version_input,
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("Tons Ensaiados:", size=12, weight=ft.FontWeight.BOLD, color=C_TEXT),
                            ft.TextButton(
                                content="+ Usar Tom Detectado",
                                style=ft.ButtonStyle(color=C_ACCENT),
                                on_click=self.use_detected_key_in_grad,
                            ),
                        ],
                    ),
                    self.grad_keys_display,
                    self.grad_keys_grid,
                    self.grad_feedback_text,
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
                                on_click=self.close_graduate_modal,
                            ),
                            ft.FilledButton(
                                content="Confirmar e Salvar",
                                icon=ft.Icons.CHECK,
                                bgcolor=C_IN_TUNE,
                                color=C_WHITE,
                                style=ft.ButtonStyle(
                                    padding=ft.Padding.symmetric(horizontal=16, vertical=12),
                                ),
                                expand=True,
                                on_click=self.confirm_graduate_song,
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.graduate_song_overlay = ft.Container(
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
                controls=[self.graduate_card],
            ),
        )

        self.fab_add_to_rehearse = ft.FloatingActionButton(
            icon=ft.Icons.ADD,
            bgcolor=C_ACCENT,
            foreground_color=C_CARD_BG,
            tooltip="Sugerir música para o próximo ensaio",
            on_click=self.open_add_to_rehearse_modal,
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
                        ft.Column(
                            spacing=2,
                            controls=[
                                ft.Text("⏳ Músicas a Ensaiar", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                self.to_rehearse_header_count,
                            ],
                        ),
                        ft.IconButton(
                            icon=ft.Icons.SYNC,
                            icon_color=C_ACCENT,
                            tooltip="Atualizar da nuvem (tempo real)",
                            on_click=lambda e: self.refresh_to_rehearse_list(sync_cloud=True),
                        ),
                    ],
                ),
                ft.Text(
                    "Fila de músicas a serem ensaiadas no próximo ensaio. Clique em 'Ensaiado' para cadastrar o tom definitivo.",
                    size=11,
                    color=C_MUTED,
                ),
                ft.Container(content=self.to_rehearse_list_column),
            ],
        )

        self.rebuild_grad_key_buttons()

    def close_delete_tr_modal(self, e: ft.ControlEvent) -> None:
        self.pending_delete_tr_id = None
        self.pending_delete_item = None
        self.delete_tr_confirm_overlay.visible = False
        self.page.update()

    def confirm_delete_tr_song(self, e: ft.ControlEvent) -> None:
        item = self.pending_delete_item or {}
        target_id = self.pending_delete_tr_id or str(item.get("id") or item.get("_id") or "")
        item_tit = item.get("titulo")
        item_cv = item.get("cantor_versao")

        self.pending_delete_tr_id = None
        self.pending_delete_item = None
        self.delete_tr_confirm_overlay.visible = False
        self.page.update()

        if target_id or item_tit:
            # 1. Remove do cofre local instantaneamente por ID e fallback de título/versão
            self.vault.delete_a_ensaiar(target_id, titulo=item_tit, cantor_versao=item_cv)
            # Atualiza UI local sem aguardar rede (zero delay e sem reaparecimento como fantasma)
            self.refresh_to_rehearse_list(sync_cloud=False)

            # 2. Exclui da nuvem (MongoDB Atlas / API HTTP) em background com ID e fallback
            active_eq = self.api_client.active_equipe_id

            def _bg_delete_tr():
                try:
                    self.api_client.remover_a_ensaiar(
                        target_id,
                        titulo=item_tit,
                        cantor_versao=item_cv,
                        equipe_id=active_eq,
                    )
                except Exception as exc:
                    logger.warning("Delete ToRehearse API Warning: %s", exc)

            threading.Thread(target=_bg_delete_tr, daemon=True).start()

    def prompt_delete_tr_song(self, item: dict) -> None:
        self.pending_delete_item = item
        self.pending_delete_tr_id = str(item.get("id") or item.get("_id") or "")
        self.del_tr_title.value = item.get("titulo", "Música")
        cv = item.get("cantor_versao", "")
        self.del_tr_info.value = f"🎤 Cantor / Versão: {cv}"
        self.delete_tr_confirm_overlay.visible = True
        self.page.update()

    def close_add_to_rehearse_modal(self, e: ft.ControlEvent) -> None:
        self.add_to_rehearse_overlay.visible = False
        self.page.update()

    def confirm_add_to_rehearse(self, e: ft.ControlEvent) -> None:
        title = (self.tr_title_input.value or "").strip()
        cantor_versao = (self.tr_singer_version_input.value or "").strip()
        raw_yt_url = (self.tr_youtube_input.value or "").strip()

        if not title:
            self.tr_add_feedback.value = "⚠️ Por favor, informe o Nome da Música!"
            self.page.update()
            return

        if not cantor_versao:
            self.tr_add_feedback.value = "⚠️ Por favor, informe o Cantor / Versão!"
            self.page.update()
            return

        try:
            yt_url = sanitize_youtube_url(raw_yt_url)
        except ValueError as val_exc:
            self.tr_add_feedback.value = f"⚠️ {val_exc}"
            self.page.update()
            return

        user_name = (self.get_logged_user_name() if self.get_logged_user_name else None) or "Equipe"

        saved_tr = self.vault.save_a_ensaiar(
            titulo=title,
            cantor_versao=cantor_versao,
            youtube_url=yt_url,
            status="Próximo Ensaio",
            adicionado_por=user_name,
            synced=False,
            equipe_id=self.api_client.active_equipe_id or "",
        )

        self.tr_title_input.value = ""
        self.tr_singer_version_input.value = ""
        self.tr_youtube_input.value = ""
        self.tr_add_feedback.value = ""
        self.add_to_rehearse_overlay.visible = False
        self.refresh_to_rehearse_list(sync_cloud=False)

        def _bg_sync_add_tr():
            try:
                res_cloud, _ = self.api_client.adicionar_a_ensaiar(
                    titulo=title,
                    cantor_versao=cantor_versao,
                    youtube_url=yt_url,
                    adicionado_por=user_name,
                    equipe_id=self.api_client.active_equipe_id,
                )
                cloud_id = str(res_cloud.get("_id") or res_cloud.get("id") or "") if isinstance(res_cloud, dict) else ""
                if cloud_id:
                    self.vault.save_a_ensaiar(
                        titulo=title,
                        cantor_versao=cantor_versao,
                        youtube_url=yt_url,
                        status="Próximo Ensaio",
                        adicionado_por=user_name,
                        synced=True,
                        equipe_id=self.api_client.active_equipe_id or "",
                        item_id=cloud_id,
                    )
                self.vault.mark_a_ensaiar_as_synced(saved_tr.id)
                self.refresh_to_rehearse_list(sync_cloud=False)
            except Exception as exc:
                logger.debug("Falha ao sincronizar nova sugestão A Ensaiar: %s", exc)

        threading.Thread(target=_bg_sync_add_tr, daemon=True).start()

    def open_add_to_rehearse_modal(self, e: ft.ControlEvent) -> None:
        self.tr_add_feedback.value = ""
        self.add_to_rehearse_overlay.visible = True
        self.page.update()

    def rebuild_grad_key_buttons(self) -> None:
        self.grad_keys_grid.controls.clear()
        for k_label in ALL_MUSICAL_KEYS:
            is_sel = k_label in self.grad_selected_keys

            def _make_grad_toggle(key_str: str):
                def _on_click(e: ft.ControlEvent) -> None:
                    if key_str in self.grad_selected_keys:
                        self.grad_selected_keys.remove(key_str)
                    else:
                        self.grad_selected_keys.add(key_str)
                    if self.grad_selected_keys:
                        ordered = [k for k in ALL_MUSICAL_KEYS if k in self.grad_selected_keys]
                        self.grad_keys_display.value = f"Tons ensaiados ({len(ordered)}): " + ", ".join(ordered)
                    else:
                        self.grad_keys_display.value = "Tons selecionados: Nenhum (toque nos botões abaixo)"
                    self.rebuild_grad_key_buttons()
                    self.page.update()
                return _on_click

            btn = ft.FilledButton(
                content=k_label.split(" ")[0],
                tooltip=k_label,
                bgcolor=C_ACCENT if is_sel else C_BG,
                color=C_CARD_BG if is_sel else C_MUTED,
                height=32,
                style=ft.ButtonStyle(padding=ft.Padding.symmetric(horizontal=8, vertical=4)),
                on_click=_make_grad_toggle(k_label),
            )
            self.grad_keys_grid.controls.append(btn)

    def use_detected_key_in_grad(self, e: ft.ControlEvent) -> None:
        if self.mic_service.last_key is not None:
            k_en = self.mic_service.last_key.key_en
            for full_k in ALL_MUSICAL_KEYS:
                if full_k.startswith(f"{k_en} "):
                    self.grad_selected_keys.add(full_k)
            ordered = [k for k in ALL_MUSICAL_KEYS if k in self.grad_selected_keys]
            self.grad_keys_display.value = f"Tons ensaiados ({len(ordered)}): " + ", ".join(ordered)
            self.rebuild_grad_key_buttons()
            self.grad_feedback_text.color = C_ACCENT
            self.grad_feedback_text.value = f"Tom detectado ({k_en}) adicionado!"
        else:
            self.grad_feedback_text.color = C_OFF_TUNE
            self.grad_feedback_text.value = "Nenhum tom detectado recentemente no afinador."
        self.page.update()

    def close_graduate_modal(self, e: ft.ControlEvent) -> None:
        self.graduate_song_overlay.visible = False
        self.page.update()

    def confirm_graduate_song(self, e: ft.ControlEvent) -> None:
        title = (self.grad_title_input.value or "").strip()
        soloist = (self.grad_soloist_input.value or "").strip() or "Não informado"
        versao = (self.grad_version_input.value or "").strip() or "Original"
        ordered_keys = [k for k in ALL_MUSICAL_KEYS if k in self.grad_selected_keys]

        if not title:
            self.grad_feedback_text.color = C_DANGER
            self.grad_feedback_text.value = "⚠️ Informe o Nome da Música!"
            self.page.update()
            return

        if not ordered_keys:
            self.grad_feedback_text.color = C_DANGER
            self.grad_feedback_text.value = "⚠️ Selecione pelo menos 1 Tom em que a música foi ensaiada!"
            self.page.update()
            return

        active_eq = self.api_client.active_equipe_id or ""
        graduating_item = self.current_graduating_item
        self.current_graduating_item = None

        # 1. Persistência otimista imediata no cofre local (zero bloqueio da UI)
        saved_song = self.vault.save_song(
            title=title,
            keys=ordered_keys,
            soloist=soloist,
            versao=versao,
            synced=False,
            equipe_id=active_eq,
        )

        target_id = ""
        grad_tit = None
        grad_cv = None
        if graduating_item:
            target_id = str(graduating_item.get("_id") or graduating_item.get("id") or "")
            grad_tit = graduating_item.get("titulo")
            grad_cv = graduating_item.get("cantor_versao")
            if target_id or grad_tit:
                self.vault.delete_a_ensaiar(target_id, titulo=grad_tit, cantor_versao=grad_cv)

        self.graduate_song_overlay.visible = False
        self.refresh_to_rehearse_list(sync_cloud=False)
        if self.on_song_graduated:
            self.on_song_graduated()

        # 2. Sincronização na nuvem em background
        def _bg_graduate_sync():
            try:
                self.api_client.salvar_musica(
                    titulo=title,
                    cantor_principal=soloist,
                    tons=ordered_keys,
                    versao=versao,
                    equipe_id=active_eq or None,
                )
                self.vault.mark_song_as_synced(saved_song.id)
                if self.on_song_graduated:
                    self.on_song_graduated()
            except Exception as exc:
                logger.warning("Graduate Save Cloud Warning: %s", exc)

            if target_id or grad_tit:
                try:
                    self.api_client.remover_a_ensaiar(
                        target_id,
                        titulo=grad_tit,
                        cantor_versao=grad_cv,
                        equipe_id=active_eq or None,
                    )
                except Exception as exc:
                    logger.warning("Graduate Remove A-Ensaiar Warning: %s", exc)

        threading.Thread(target=_bg_graduate_sync, daemon=True).start()

    def prompt_graduate_song(self, item: dict) -> None:
        self.current_graduating_item = item
        self.grad_feedback_text.value = ""
        self.grad_selected_keys.clear()

        self.grad_title_input.value = item.get("titulo", "")
        raw_cv = item.get("cantor_versao", "").strip()
        if "/" in raw_cv:
            parts = [p.strip() for p in raw_cv.split("/") if p.strip()]
            self.grad_soloist_input.value = parts[0] if parts else "Não informado"
            self.grad_version_input.value = parts[1] if len(parts) > 1 else "Original"
        else:
            self.grad_soloist_input.value = raw_cv or "Não informado"
            self.grad_version_input.value = "Original"

        self.grad_keys_display.value = "Tons selecionados: Nenhum (toque nos botões abaixo)"
        self.rebuild_grad_key_buttons()
        self.graduate_song_overlay.visible = True
        self.page.update()

    def _render_to_rehearse_to_ui(self, items: list[dict], source_badge: str) -> None:
        self.to_rehearse_list_column.controls.clear()
        self.to_rehearse_header_count.value = f"{len(items)} {'música' if len(items) == 1 else 'músicas'} na fila • {source_badge}"

        if not items:
            self.to_rehearse_list_column.controls.append(
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
                            ft.Icon(ft.Icons.MUSIC_NOTE_ROUNDED, size=42, color=C_MUTED),
                            ft.Text(
                                "Nenhuma música na fila a ensaiar",
                                size=14,
                                weight=ft.FontWeight.BOLD,
                                color=C_TEXT,
                                text_align=ft.TextAlign.CENTER,
                            ),
                            ft.Text(
                                "Toque no botão '+' flutuante para sugerir músicas para o próximo ensaio da equipe com link do YouTube.",
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
                def _make_delete_tr(it: dict):
                    return lambda e: self.prompt_delete_tr_song(it)

                def _make_graduate(it: dict):
                    return lambda e: self.prompt_graduate_song(it)

                yt_link = (item.get("youtube_url") or "").strip()

                actions_row_controls = []

                if yt_link:
                    actions_row_controls.append(
                        ft.FilledButton(
                            content="Ver no YouTube",
                            icon=ft.Icons.PLAY_ARROW_ROUNDED,
                            url=yt_link,
                            bgcolor=C_DANGER,
                            color=C_WHITE,
                            style=ft.ButtonStyle(
                                padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                            ),
                            tooltip="Abrir vídeo de referência no YouTube",
                        )
                    )

                actions_row_controls.append(
                    ft.FilledButton(
                        content="Ensaiado",
                        icon=ft.Icons.CHECK_CIRCLE_OUTLINE,
                        bgcolor=C_IN_TUNE,
                        color=C_WHITE,
                        style=ft.ButtonStyle(
                            padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                        ),
                        tooltip="Marcar como ensaiada e cadastrar tom no repertório",
                        on_click=_make_graduate(item),
                    )
                )

                self.to_rehearse_list_column.controls.append(
                    ft.Container(
                        padding=14,
                        border_radius=14,
                        bgcolor=C_SURFACE,
                        border=ft.Border.all(1, C_BORDER),
                        content=ft.Column(
                            spacing=8,
                            controls=[
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    vertical_alignment=ft.CrossAxisAlignment.START,
                                    controls=[
                                        ft.Column(
                                            spacing=2,
                                            expand=True,
                                            controls=[
                                                ft.Text(item["titulo"], size=15, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                                ft.Text(f"🎤 {item.get('cantor_versao', '')}", size=12, color=C_MUTED),
                                            ],
                                        ),
                                        ft.Row(
                                            spacing=4,
                                            controls=[
                                                ft.Container(
                                                    padding=ft.Padding.symmetric(horizontal=8, vertical=3),
                                                    border_radius=6,
                                                    bgcolor=ft.Colors.with_opacity(0.15, C_OFF_TUNE),
                                                    border=ft.Border.all(1, C_OFF_TUNE),
                                                    content=ft.Text(
                                                        "⏳ Próximo Ensaio",
                                                        size=10,
                                                        weight=ft.FontWeight.BOLD,
                                                        color=C_OFF_TUNE,
                                                    ),
                                                ),
                                                ft.IconButton(
                                                    icon=ft.Icons.DELETE_OUTLINE,
                                                    icon_color=C_DANGER,
                                                    tooltip="Remover sugestão",
                                                    on_click=_make_delete_tr(item),
                                                ),
                                            ],
                                        ),
                                    ],
                                ),
                                ft.Row(
                                    spacing=8,
                                    alignment=ft.MainAxisAlignment.START,
                                    controls=actions_row_controls,
                                ),
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    controls=[
                                        ft.Text(f"👤 Sugerido por: {item.get('adicionado_por', 'Equipe')}", size=10, color=C_MUTED),
                                        ft.Text(f"Status: {item.get('status', 'Próximo Ensaio')}", size=10, color=C_MUTED),
                                    ],
                                ),
                            ],
                        ),
                    )
                )
        self.page.update()

    def refresh_to_rehearse_list(self, sync_cloud: bool = True) -> None:
        local_items = self.vault.load_a_ensaiar(equipe_id=self.api_client.active_equipe_id)
        initial_items = [
            {
                "_id": r.id,
                "id": r.id,
                "titulo": r.titulo,
                "cantor_versao": r.cantor_versao,
                "youtube_url": r.youtube_url,
                "status": r.status,
                "adicionado_por": r.adicionado_por,
            }
            for r in local_items
        ]
        self._render_to_rehearse_to_ui(initial_items, "🔒 Cache Local Seguro")

        if sync_cloud:
            def _bg_tr_sync():
                try:
                    unsynced_tr = self.vault.get_unsynced_a_ensaiar_items()
                    for utr in unsynced_tr:
                        try:
                            self.api_client.adicionar_a_ensaiar(
                                titulo=utr.titulo,
                                cantor_versao=utr.cantor_versao,
                                youtube_url=utr.youtube_url,
                                adicionado_por=utr.adicionado_por,
                                equipe_id=self.api_client.active_equipe_id,
                            )
                            self.vault.mark_a_ensaiar_as_synced(utr.id)
                        except Exception:
                            break

                    cloud_items, _ = self.api_client.listar_a_ensaiar(equipe_id=self.api_client.active_equipe_id)
                    if cloud_items is not None:
                        deduped_tr = []
                        seen_tr: set[tuple[str, str]] = set()
                        for ci in cloud_items:
                            tr_tit = str(ci.get("titulo", "")).strip()
                            tr_cv = str(ci.get("cantor_versao", "")).strip()
                            tr_key = (tr_tit.lower(), tr_cv.lower())
                            if not tr_tit or tr_key in seen_tr:
                                continue
                            seen_tr.add(tr_key)
                            deduped_tr.append(ci)
                            self.vault.save_a_ensaiar(
                                titulo=tr_tit,
                                cantor_versao=tr_cv,
                                youtube_url=str(ci.get("youtube_url", "")),
                                status=str(ci.get("status", "Próximo Ensaio")),
                                adicionado_por=str(ci.get("adicionado_por", "Equipe")),
                                synced=True,
                                equipe_id=self.api_client.active_equipe_id or "",
                                item_id=str(ci.get("_id") or ci.get("id") or ""),
                            )
                        self.vault.reconcile_a_ensaiar(deduped_tr, equipe_id=self.api_client.active_equipe_id)
                        self._render_to_rehearse_to_ui(deduped_tr, "☁️ Nuvem (Todos os usuários)")
                except Exception as exc:
                    logger.debug("Falha no sync background A Ensaiar: %s", exc)

            threading.Thread(target=_bg_tr_sync, daemon=True).start()
