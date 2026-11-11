"""
Aba 2: Músicas Cadastradas, Pesquisa, Filtro de Cantores, Cadastro e Exclusão (UI/UX Flet 1.0).
"""

from __future__ import annotations

from collections.abc import Callable
import logging
import threading
from typing import Any

import flet as ft
from ciphersong.security.local_vault import EncryptedSessionVault, RehearsedSongRecord
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
    create_skeleton_loader,
)

logger = logging.getLogger(__name__)


class RepertoireView:
    """Gerencia a visualização do repertório ensaiado, formulário de cadastro e modal de exclusão."""

    def __init__(
        self,
        page: ft.Page,
        vault: EncryptedSessionVault,
        api_client: SongsApiClient,
        mic_service: LiveMicrophoneService,
        on_schedule_song: Callable[[dict], None] | None = None,
    ) -> None:
        self.page = page
        self.vault = vault
        self.api_client = api_client
        self.mic_service = mic_service
        self.on_schedule_song = on_schedule_song

        self.selected_keys_set: set[str] = set()
        self.all_repertoire_songs: list[dict] = []
        self.pending_delete_song_id: str | None = None

        # Componentes do Topo da Lista
        self.search_input = ft.TextField(
            label="Pesquisar música, tom ou versão...",
            prefix_icon=ft.Icons.SEARCH,
            bgcolor=C_SURFACE,
            border_color=C_BORDER,
            color=C_TEXT,
            on_change=self.on_search_change,
        )

        self.singer_filter_dropdown = ft.Dropdown(
            label="Filtrar por Cantor Cadastrado",
            value="todos",
            bgcolor=C_SURFACE,
            border_color=C_BORDER,
            color=C_TEXT,
            options=[ft.DropdownOption(key="todos", text="👥 Todos os Cantores")],
            on_select=self.on_singer_filter_change,
        )

        self.repertoire_header_count = ft.Text("0 músicas cadastradas", size=11, color=C_MUTED)
        self.songs_list_column = ft.Column(spacing=8)

        # Campos do Formulário de Adicionar Música
        self.song_title_input = ft.TextField(
            label="Nome da Música *",
            hint_text="Ex: Bondade de Deus / Oceanos",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )

        self.soloist_input = ft.TextField(
            label="Solista / Cantor Principal *",
            hint_text="Ex: Solista / Ministério / Grupo",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )

        self.version_input = ft.TextField(
            label="Versão / Cifra de Quem? (Opcional)",
            hint_text="Ex: Gabriel Guedes / Original / Morada / Isaias Saad",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )

        self.selected_keys_display = ft.Text(
            "Tons selecionados: Nenhum (toque nos botões abaixo)",
            size=12,
            color=C_ACCENT,
            weight=ft.FontWeight.W_600,
        )

        self.song_feedback_text = ft.Text("", size=12, color=C_IN_TUNE)

        self.key_buttons_grid = ft.Row(
            wrap=True,
            spacing=6,
            run_spacing=6,
        )

        self.btn_refresh_songs = ft.IconButton(
            icon=ft.Icons.REFRESH_ROUNDED,
            icon_color=C_ACCENT,
            icon_size=24,
            tooltip="Atualizar lista de músicas (sincronizar nuvem)",
            on_click=self.handle_refresh_songs,
        )

        self.btn_toggle_add = ft.Container(
            content=ft.Icon(ft.Icons.ADD, color=C_CARD_BG, size=26),
            bgcolor=C_ACCENT,
            shape=ft.BoxShape.CIRCLE,
            width=44,
            height=44,
            alignment=ft.Alignment.CENTER,
            tooltip="Cadastrar nova música ensaiada",
            on_click=self.toggle_add_form,
        )

        self.fab_add_song = ft.FloatingActionButton(
            icon=ft.Icons.ADD,
            bgcolor=C_ACCENT,
            foreground_color=C_CARD_BG,
            tooltip="Cadastrar nova música",
            on_click=self.toggle_add_form,
            shape=ft.CircleBorder(),
        )

        self.add_song_form_container = ft.Container(
            padding=14,
            border_radius=14,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1, C_BORDER),
            visible=False,
            content=ft.Column(
                spacing=10,
                horizontal_alignment=ft.CrossAxisAlignment.START,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("Cadastrar Nova Música Ensaiada", size=15, weight=ft.FontWeight.BOLD, color=C_TEXT),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE,
                                icon_color=C_MUTED,
                                tooltip="Fechar formulário",
                                on_click=self.close_add_form,
                            ),
                        ],
                    ),
                    self.song_title_input,
                    self.soloist_input,
                    self.version_input,
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("Selecione um ou mais Tons:", size=12, weight=ft.FontWeight.BOLD, color=C_TEXT),
                            ft.TextButton(
                                content="+ Usar Tom Detectado",
                                style=ft.ButtonStyle(color=C_ACCENT),
                                on_click=self.use_detected_key_in_form,
                            ),
                        ],
                    ),
                    self.selected_keys_display,
                    self.key_buttons_grid,
                    self.song_feedback_text,
                    ft.FilledButton(
                        content="Cadastrar Música Ensaiada",
                        icon=ft.Icons.ADD_TASK,
                        bgcolor=C_ACCENT,
                        color=C_CARD_BG,
                        on_click=self.handle_save_song,
                    ),
                ],
            ),
        )

        # Modal de Confirmação de Exclusão
        self.del_modal_title = ft.Text(
            "",
            size=16,
            weight=ft.FontWeight.BOLD,
            color=C_TEXT,
            text_align=ft.TextAlign.CENTER,
        )
        self.del_modal_info = ft.Text(
            "",
            size=12,
            color=C_MUTED,
            text_align=ft.TextAlign.CENTER,
        )
        self.del_modal_keys_row = ft.Row(
            wrap=True,
            spacing=6,
            alignment=ft.MainAxisAlignment.CENTER,
        )

        self.delete_card = ft.Container(
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
                    self.del_modal_title,
                    self.del_modal_info,
                    self.del_modal_keys_row,
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
                                on_click=self.close_delete_modal,
                            ),
                            ft.FilledButton(
                                content="Excluir",
                                icon=ft.Icons.DELETE_OUTLINE,
                                bgcolor=C_DANGER,
                                color=C_WHITE,
                                style=ft.ButtonStyle(
                                    padding=ft.Padding.symmetric(horizontal=18, vertical=12),
                                ),
                                expand=True,
                                on_click=self.confirm_delete_song,
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.delete_confirm_overlay = ft.Container(
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
                controls=[self.delete_card],
            ),
        )

        self.view = ft.Column(
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            visible=True,
            controls=[
                self.singer_filter_dropdown,
                self.search_input,
                self.add_song_form_container,
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.Column(
                            spacing=2,
                            controls=[
                                ft.Text("Músicas Ensaiadas", size=15, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                self.repertoire_header_count,
                            ],
                        ),
                        ft.Row(
                            spacing=4,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            controls=[
                                self.btn_refresh_songs,
                                self.btn_toggle_add,
                            ],
                        ),
                    ],
                ),
                ft.Container(content=self.songs_list_column),
            ],
        )

        self.rebuild_key_selector_buttons()

    @staticmethod
    def _records_to_dicts(records: list[RehearsedSongRecord]) -> list[dict[str, Any]]:
        """Converte registros do cofre em dicionários padronizados para a camada de UI (DRY)."""
        return [
            {
                "id": s.id,
                "title": s.title,
                "soloist": s.soloist,
                "versao": s.versao,
                "keys": s.keys,
                "created_at": s.created_at,
                "source_icon": "☁️" if s.synced else "🔒",
            }
            for s in records
        ]

    @staticmethod
    def _apply_filters(songs: list[dict[str, Any]], query: str = "", selected_singer: str = "todos") -> list[dict[str, Any]]:
        """Filtra lista de músicas em memória por cantor e termo de busca (DRY)."""
        filtered = list(songs)
        if selected_singer and selected_singer != "todos":
            singer_norm = selected_singer.strip().lower()
            filtered = [
                s for s in filtered
                if (s.get("soloist") or "").strip().lower() == singer_norm
            ]
        if query:
            q = query.strip().lower()
            filtered = [
                s for s in filtered
                if q in s.get("title", "").lower()
                or q in (s.get("soloist") or "").lower()
                or q in (s.get("versao") or "").lower()
                or any(q in k.lower() for k in s.get("keys", []))
            ]
        return filtered

    def rebuild_key_selector_buttons(self) -> None:
        self.key_buttons_grid.controls.clear()
        for k_label in ALL_MUSICAL_KEYS:
            is_sel = k_label in self.selected_keys_set

            def _make_toggle(key_str: str):
                def _on_click(e: ft.ControlEvent) -> None:
                    if key_str in self.selected_keys_set:
                        self.selected_keys_set.remove(key_str)
                    else:
                        self.selected_keys_set.add(key_str)
                    if self.selected_keys_set:
                        ordered = [k for k in ALL_MUSICAL_KEYS if k in self.selected_keys_set]
                        self.selected_keys_display.value = f"Tons selecionados ({len(ordered)}): " + ", ".join(ordered)
                    else:
                        self.selected_keys_display.value = "Tons selecionados: Nenhum (toque nos botões abaixo)"
                    self.rebuild_key_selector_buttons()
                    self.page.update()
                return _on_click

            btn = ft.FilledButton(
                content=k_label.split(" ")[0],
                tooltip=k_label,
                bgcolor=C_ACCENT if is_sel else C_BG,
                color=C_CARD_BG if is_sel else C_MUTED,
                height=34,
                on_click=_make_toggle(k_label),
            )
            self.key_buttons_grid.controls.append(btn)

    def use_detected_key_in_form(self, e: ft.ControlEvent) -> None:
        if self.mic_service.last_key is not None:
            k_en = self.mic_service.last_key.key_en
            for full_k in ALL_MUSICAL_KEYS:
                if full_k.startswith(f"{k_en} "):
                    self.selected_keys_set.add(full_k)
            ordered = [k for k in ALL_MUSICAL_KEYS if k in self.selected_keys_set]
            self.selected_keys_display.value = f"Tons selecionados ({len(ordered)}): " + ", ".join(ordered)
            self.rebuild_key_selector_buttons()
            self.song_feedback_text.color = C_ACCENT
            self.song_feedback_text.value = f"Tom detectado ({k_en}) adicionado à seleção!"
        else:
            self.song_feedback_text.color = C_OFF_TUNE
            self.song_feedback_text.value = "Nenhum tom detectado ainda no microfone."
        self.page.update()

    def toggle_add_form(self, e: ft.ControlEvent) -> None:
        self.add_song_form_container.visible = not self.add_song_form_container.visible
        if self.add_song_form_container.visible:
            self.btn_toggle_add.content = ft.Icon(ft.Icons.CLOSE, color=C_CARD_BG, size=24)
            self.btn_toggle_add.bgcolor = C_DANGER
            self.fab_add_song.icon = ft.Icons.CLOSE
            self.fab_add_song.bgcolor = C_DANGER
        else:
            self.btn_toggle_add.content = ft.Icon(ft.Icons.ADD, color=C_CARD_BG, size=26)
            self.btn_toggle_add.bgcolor = C_ACCENT
            self.fab_add_song.icon = ft.Icons.ADD
            self.fab_add_song.bgcolor = C_ACCENT
        self.page.update()

    def close_add_form(self, e: ft.ControlEvent) -> None:
        self.add_song_form_container.visible = False
        self.btn_toggle_add.content = ft.Icon(ft.Icons.ADD, color=C_CARD_BG, size=26)
        self.btn_toggle_add.bgcolor = C_ACCENT
        self.fab_add_song.icon = ft.Icons.ADD
        self.fab_add_song.bgcolor = C_ACCENT
        self.page.update()

    def close_delete_modal(self, e: ft.ControlEvent | None = None) -> None:
        self.pending_delete_song_id = None
        self.delete_confirm_overlay.visible = False
        self.page.update()

    def confirm_delete_song(self, e: ft.ControlEvent) -> None:
        if self.pending_delete_song_id:
            target_id = self.pending_delete_song_id
            self.pending_delete_song_id = None
            self.delete_confirm_overlay.visible = False
            # Remoção otimista imediata no cofre local sem bloquear a thread principal da UI
            self.vault.delete_song(target_id)
            self.refresh_songs_list(sync_cloud=False)

            def _bg_del_cloud() -> None:
                try:
                    self.api_client.deletar_musica(target_id)
                except Exception as exc:
                    logger.warning("Falha ao excluir música na nuvem (%s): %s", target_id, exc)

            threading.Thread(target=_bg_del_cloud, daemon=True).start()

    def prompt_delete_song(self, song_item: dict) -> None:
        self.pending_delete_song_id = song_item["id"]
        self.del_modal_title.value = song_item["title"]
        self.del_modal_info.value = f"🎤 Solista: {song_item.get('soloist', 'Não informado')} • 🎸 Versão: {song_item.get('versao', 'Original')}"
        self.del_modal_keys_row.controls = [
            ft.Container(
                padding=ft.Padding.symmetric(horizontal=8, vertical=2),
                border_radius=6,
                bgcolor=C_ACCENT,
                content=ft.Text(k, size=10, weight=ft.FontWeight.BOLD, color=C_CARD_BG),
            )
            for k in song_item.get("keys", [])
        ]
        self.delete_confirm_overlay.visible = True
        self.page.update()

    def update_singers_filter_options(self, current_songs: list[dict]) -> None:
        seen = set()
        for s in current_songs:
            sol = (s.get("soloist") or "").strip()
            if sol and sol.lower() != "não informado":
                seen.add(sol)

        prev_val = self.singer_filter_dropdown.value or "todos"
        opts = [ft.DropdownOption(key="todos", text="👥 Todos os Cantores")]
        for c in sorted(seen):
            opts.append(ft.DropdownOption(key=c, text=f"🎤 {c}"))
        self.singer_filter_dropdown.options = opts
        if prev_val in seen:
            self.singer_filter_dropdown.value = prev_val
        else:
            self.singer_filter_dropdown.value = "todos"

    def _render_songs_list_ui(self, songs: list[dict], query: str = "", selected_singer: str = "todos") -> None:
        selected_singer = selected_singer or "todos"
        if selected_singer == "todos" and not query:
            self.all_repertoire_songs.clear()
            self.all_repertoire_songs.extend(songs)
            self.update_singers_filter_options(songs)

        if selected_singer != "todos":
            songs = [
                s for s in songs
                if (s.get("soloist") or "").strip().lower() == selected_singer.strip().lower()
            ]

        total = len(songs)
        suffix = "música cadastrada" if total == 1 else "músicas cadastradas"
        if (selected_singer and selected_singer != "todos") or query:
            self.repertoire_header_count.value = f"{total} {suffix} (filtrado)"
        else:
            self.repertoire_header_count.value = f"{total} {suffix}"

        self.songs_list_column.controls.clear()

        if not songs:
            msg = (
                "Nenhuma música encontrada para os filtros atuais."
                if (query or selected_singer != "todos")
                else "Nenhuma música ensaiada cadastrada ainda."
            )
            self.songs_list_column.controls.append(ft.Text(msg, size=12, color=C_MUTED))
        else:
            for s in songs:
                def _make_delete(song_item: dict):
                    def _del(e: ft.ControlEvent) -> None:
                        self.prompt_delete_song(song_item)
                    return _del

                def _make_schedule(song_item: dict):
                    def _sched(e: ft.ControlEvent) -> None:
                        if self.on_schedule_song:
                            self.on_schedule_song(song_item)
                    return _sched

                keys_badges = ft.Row(
                    wrap=True,
                    spacing=6,
                    controls=[
                        ft.Container(
                            padding=ft.Padding.symmetric(horizontal=8, vertical=3),
                            border_radius=8,
                            bgcolor=C_ACCENT,
                            content=ft.Text(k, size=11, weight=ft.FontWeight.BOLD, color="#18181B"),
                        )
                        for k in s["keys"]
                    ],
                )

                self.songs_list_column.controls.append(
                    ft.Container(
                        padding=12,
                        border_radius=12,
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
                                            spacing=3,
                                            expand=True,
                                            controls=[
                                                ft.Row(
                                                    wrap=True,
                                                    spacing=6,
                                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                                    controls=[
                                                        ft.Text(s["title"], size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                                        ft.Container(
                                                            padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                                                            border_radius=6,
                                                            bgcolor=C_BG,
                                                            border=ft.Border.all(1, C_BORDER),
                                                            content=ft.Text(
                                                                f"🎸 {s.get('versao', 'Original')}",
                                                                size=10,
                                                                weight=ft.FontWeight.W_600,
                                                                color=C_ACCENT,
                                                            ),
                                                        ),
                                                        ft.Container(
                                                            padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                                                            border_radius=6,
                                                            bgcolor=C_BG,
                                                            content=ft.Text(
                                                                s["source_icon"],
                                                                size=11,
                                                            ),
                                                        ),
                                                    ],
                                                ),
                                                ft.Text(f"🎤 Solista: {s['soloist']}", size=12, color=C_MUTED),
                                            ],
                                        ),
                                        ft.IconButton(
                                            icon=ft.Icons.DELETE_OUTLINE,
                                            icon_color=C_DANGER,
                                            tooltip="Remover música",
                                            on_click=_make_delete(s),
                                        ),
                                    ],
                                ),
                                keys_badges,
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    wrap=True,
                                    spacing=8,
                                    controls=[
                                        ft.Text(f"Origem: {s['created_at']}", size=10, color=C_MUTED),
                                        ft.FilledButton(
                                            content="Marcar Repertório",
                                            icon=ft.Icons.EVENT_AVAILABLE_ROUNDED,
                                            style=ft.ButtonStyle(
                                                bgcolor=C_ACCENT,
                                                color="#18181B",
                                                text_style=ft.TextStyle(size=11, weight=ft.FontWeight.BOLD),
                                                padding=ft.Padding.symmetric(horizontal=12, vertical=6),
                                                shape=ft.RoundedRectangleBorder(radius=8),
                                            ),
                                            height=32,
                                            on_click=_make_schedule(s),
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    )
                )
        try:
            self.repertoire_header_count.update()
            self.songs_list_column.update()
        except Exception:
            self.page.update()

    def refresh_songs_list(self, sync_cloud: bool = True) -> None:
        query = (self.search_input.value or "").strip()
        selected_singer = self.singer_filter_dropdown.value or "todos"

        if selected_singer == "todos" and not query:
            all_local = self.vault.load_songs(equipe_id=self.api_client.active_equipe_id)
            self.all_repertoire_songs.clear()
            self.all_repertoire_songs.extend(self._records_to_dicts(all_local))

        local_songs = self.vault.search_songs(
            query=query,
            soloist=selected_singer,
            equipe_id=self.api_client.active_equipe_id,
        )
        initial_songs = self._records_to_dicts(local_songs)
        self._render_songs_list_ui(initial_songs, query=query, selected_singer=selected_singer)

        if sync_cloud:
            def _bg_sync() -> None:
                try:
                    unsynced = self.vault.get_unsynced_songs(equipe_id=self.api_client.active_equipe_id or "*")
                    for off_s in unsynced:
                        try:
                            res_cloud, _ = self.api_client.salvar_musica(
                                titulo=off_s.title,
                                cantor_principal=off_s.soloist,
                                tons=off_s.keys,
                                versao=off_s.versao,
                                equipe_id=off_s.equipe_id or self.api_client.active_equipe_id,
                            )
                            if isinstance(res_cloud, dict) and (res_cloud.get("_id") or res_cloud.get("id")):
                                cloud_id = str(res_cloud.get("_id") or res_cloud.get("id"))
                                self.vault.save_song(
                                    title=off_s.title,
                                    keys=off_s.keys,
                                    soloist=off_s.soloist,
                                    versao=off_s.versao,
                                    synced=True,
                                    equipe_id=off_s.equipe_id or self.api_client.active_equipe_id or "",
                                    song_id=cloud_id,
                                )
                            self.vault.mark_song_as_synced(off_s.id)
                        except Exception as exc:
                            logger.debug("Falha ao sincronizar música offline (%s): %s", off_s.title, exc)
                            break

                    cantor_param = selected_singer if selected_singer != "todos" else None
                    remote_docs, _ = self.api_client.listar_ou_buscar(
                        query=query,
                        cantor=cantor_param,
                        equipe_id=self.api_client.active_equipe_id,
                    )
                    if remote_docs is not None:
                        cloud_songs = []
                        seen_c_keys: set[tuple[str, str, str]] = set()
                        for doc in remote_docs:
                            t = doc.get("titulo", "")
                            cp = doc.get("cantor_principal", "Não informado")
                            ver = doc.get("versao", "Original")
                            cid = str(doc.get("_id") or doc.get("id") or "")
                            norm = (t.strip().lower(), cp.strip().lower(), ver.strip().lower())
                            if not norm[0] or norm in seen_c_keys:
                                continue
                            seen_c_keys.add(norm)
                            cloud_songs.append({
                                "id": cid,
                                "title": t,
                                "soloist": cp,
                                "versao": ver,
                                "keys": doc.get("tons", []),
                                "created_at": "MongoDB Atlas",
                                "source_icon": "☁️",
                            })
                            self.vault.save_song(
                                title=t,
                                keys=doc.get("tons", []),
                                soloist=cp,
                                versao=ver,
                                synced=True,
                                equipe_id=self.api_client.active_equipe_id or "",
                                song_id=cid,
                            )
                        self.vault.reconcile_songs(cloud_songs, equipe_id=self.api_client.active_equipe_id)
                        if not query and selected_singer in ("todos", None):
                            self.all_repertoire_songs.clear()
                            self.all_repertoire_songs.extend(cloud_songs)

                        final_songs = self.vault.search_songs(
                            query=query,
                            soloist=selected_singer,
                            equipe_id=self.api_client.active_equipe_id,
                        )
                        ui_songs = self._records_to_dicts(final_songs)
                        self._render_songs_list_ui(ui_songs, query=query, selected_singer=selected_singer)
                except Exception as exc:
                    logger.debug("Erro na sincronização em segundo plano do repertório: %s", exc)

            threading.Thread(target=_bg_sync, daemon=True).start()

    def _ensure_cached_songs_loaded(self) -> None:
        if not self.all_repertoire_songs:
            all_local = self.vault.load_songs(equipe_id=self.api_client.active_equipe_id)
            self.all_repertoire_songs.extend(self._records_to_dicts(all_local))

    def on_search_change(self, e: ft.ControlEvent) -> None:
        val = getattr(e, "data", None) or getattr(getattr(e, "control", None), "value", None) or self.search_input.value or ""
        selected = self.singer_filter_dropdown.value or "todos"
        query = str(val).strip()
        self._ensure_cached_songs_loaded()
        filtered = self._apply_filters(self.all_repertoire_songs, query=query, selected_singer=selected)
        self._render_songs_list_ui(filtered, query=query, selected_singer=selected)

    def on_singer_filter_change(self, e: ft.ControlEvent) -> None:
        sel_val = getattr(e, "data", None) or getattr(getattr(e, "control", None), "value", None) or self.singer_filter_dropdown.value
        selected = str(sel_val).strip() if sel_val else "todos"
        self.singer_filter_dropdown.value = selected

        query = (self.search_input.value or "").strip()
        self._ensure_cached_songs_loaded()
        filtered = self._apply_filters(self.all_repertoire_songs, query=query, selected_singer=selected)
        self._render_songs_list_ui(filtered, query=query, selected_singer=selected)
        self.refresh_songs_list(sync_cloud=False)

    def handle_save_song(self, e: ft.ControlEvent) -> None:
        title = (self.song_title_input.value or "").strip()
        soloist = (self.soloist_input.value or "").strip()
        version = (self.version_input.value or "").strip() or "Original"
        ordered_keys = [k for k in ALL_MUSICAL_KEYS if k in self.selected_keys_set]

        if not title:
            self.song_feedback_text.color = C_DANGER
            self.song_feedback_text.value = "⚠️ Informe o Nome da Música!"
            self.page.update()
            return

        if not ordered_keys:
            self.song_feedback_text.color = C_DANGER
            self.song_feedback_text.value = "⚠️ Selecione pelo menos 1 Tom (você pode marcar vários)!"
            self.page.update()
            return

        saved_locally = self.vault.save_song(
            title=title,
            keys=ordered_keys,
            soloist=soloist or "Não informado",
            versao=version,
            synced=False,
            equipe_id=self.api_client.active_equipe_id or "",
        )

        self.song_title_input.value = ""
        self.soloist_input.value = ""
        self.version_input.value = ""
        self.selected_keys_set.clear()
        self.selected_keys_display.value = "Tons selecionados: Nenhum (toque nos botões abaixo)"
        self.rebuild_key_selector_buttons()

        self.song_feedback_text.color = C_IN_TUNE
        self.song_feedback_text.value = f"'{title}' salva com sucesso!"

        self.add_song_form_container.visible = False
        self.btn_toggle_add.content = ft.Icon(ft.Icons.ADD, color=C_CARD_BG, size=26)
        self.btn_toggle_add.bgcolor = C_ACCENT
        self.fab_add_song.icon = ft.Icons.ADD
        self.fab_add_song.bgcolor = C_ACCENT
        self.refresh_songs_list(sync_cloud=False)

        def _bg_save_cloud() -> None:
            try:
                res_cloud, _ = self.api_client.salvar_musica(
                    titulo=title,
                    cantor_principal=soloist or "Não informado",
                    tons=ordered_keys,
                    versao=version,
                    equipe_id=self.api_client.active_equipe_id,
                )
                if isinstance(res_cloud, dict) and (res_cloud.get("_id") or res_cloud.get("id")):
                    cloud_id = str(res_cloud.get("_id") or res_cloud.get("id"))
                    self.vault.save_song(
                        title=title,
                        keys=ordered_keys,
                        soloist=soloist or "Não informado",
                        versao=version,
                        synced=True,
                        equipe_id=self.api_client.active_equipe_id or "",
                        song_id=cloud_id,
                    )
                self.vault.mark_song_as_synced(saved_locally.id)
                self.refresh_songs_list(sync_cloud=False)
            except Exception as exc:
                logger.debug("Falha ao salvar música na nuvem em background (%s): %s", title, exc)

        threading.Thread(target=_bg_save_cloud, daemon=True).start()

    def handle_refresh_songs(self, e: ft.ControlEvent | None = None) -> None:
        self.songs_list_column.controls.clear()
        self.songs_list_column.controls.append(create_skeleton_loader(count=3))
        self.repertoire_header_count.value = "Sincronizando com a nuvem..."
        self.page.update()
        self.refresh_songs_list(sync_cloud=True)
