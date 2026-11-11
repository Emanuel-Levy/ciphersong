"""
Aba 5: Equipe, Chamadas Instantâneas ("Pingar"), Gestão Multi-Equipes e Convites WhatsApp (UI/UX Flet 1.0).
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.parse
import webbrowser
from collections.abc import Callable
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
    C_INPUT_BG,
    C_MUTED,
    C_SURFACE,
    C_TEXT,
    C_WHATSAPP,
    C_WHITE,
    create_skeleton_loader,
)

logger = logging.getLogger("ciphersong.ui.team")


class TeamView:
    """Gerencia multi-equipes, listagem de músicos, convites e despachos de pings."""

    def __init__(
        self,
        page: ft.Page,
        vault: EncryptedSessionVault,
        api_client: SongsApiClient,
        show_notification: Callable[..., Any],
        on_team_changed: Callable[[dict], None] | None = None,
    ) -> None:
        self.page = page
        self.vault = vault
        self.api_client = api_client
        self.show_notification = show_notification
        self.on_team_changed = on_team_changed

        self.user_teams: list[dict[str, Any]] = self.vault.get_cached_teams()
        self.active_team: dict[str, Any] | None = self.vault.get_active_team()
        self.call_cooldowns: dict[str, float] = {}

        self.team_name_display = ft.Text(
            f"👥 {(self.active_team.get('nome') if self.active_team else 'Carregando equipe...')}",
            size=15,
            weight=ft.FontWeight.BOLD,
            color=C_TEXT,
        )

        self.team_selector_dropdown = ft.Dropdown(
            label="Alternar Equipe Ativa",
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
            expand=True,
            options=[],
            on_select=self._on_team_dropdown_change,
        )

        self.team_search_input = ft.TextField(
            label="Buscar músico pelo nome...",
            prefix_icon=ft.Icons.SEARCH,
            bgcolor=C_SURFACE,
            border_color=C_BORDER,
            color=C_TEXT,
            on_change=lambda e: self.refresh_team_members(),
        )

        self.team_header_count = ft.Text("0 músicos na equipe", size=11, color=C_MUTED)
        self.team_members_column = ft.Column(spacing=8)

        self.team_code_display = ft.Text(
            f"Código de Convite: {(self.active_team.get('codigo_convite') if self.active_team else '---')}",
            size=11,
            weight=ft.FontWeight.BOLD,
            color=C_ACCENT,
        )

        # Modal de Criação de Nova Equipe
        self.create_team_input = ft.TextField(
            label="Nome da Nova Equipe *",
            hint_text="Ex: Ministério Central, Banda de Jovens",
            prefix_icon=ft.Icons.GROUPS_ROUNDED,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
            max_length=60,
        )
        self.create_team_feedback = ft.Text("", size=11, color=C_DANGER, text_align=ft.TextAlign.CENTER)
        self.btn_confirm_create_team = ft.FilledButton(
            content="Criar Equipe",
            icon=ft.Icons.CHECK,
            bgcolor=C_ACCENT,
            color=C_CARD_BG,
            style=ft.ButtonStyle(
                padding=ft.Padding.symmetric(horizontal=14, vertical=12),
            ),
            expand=True,
            on_click=self.confirm_create_team,
        )

        self.create_team_card = ft.Container(
            width=360,
            padding=20,
            border_radius=16,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1, C_BORDER),
            content=ft.Column(
                tight=True,
                spacing=12,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=8,
                                controls=[
                                    ft.Icon(ft.Icons.GROUP_ADD_ROUNDED, color=C_ACCENT, size=22),
                                    ft.Text("Criar Nova Equipe", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                ],
                            ),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE,
                                icon_size=18,
                                icon_color=C_MUTED,
                                tooltip="Fechar",
                                on_click=self.close_create_team_modal,
                            ),
                        ],
                    ),
                    ft.Text(
                        "Cada equipe tem suas próprias músicas, repertório da semana e sugestões de ensaios totalmente isolados.",
                        size=11,
                        color=C_MUTED,
                        text_align=ft.TextAlign.LEFT,
                    ),
                    self.create_team_input,
                    self.create_team_feedback,
                    ft.Row(
                        spacing=10,
                        controls=[
                            ft.OutlinedButton(
                                content="Cancelar",
                                style=ft.ButtonStyle(
                                    side=ft.BorderSide(1, C_BORDER),
                                    color=C_TEXT,
                                    padding=ft.Padding.symmetric(horizontal=14, vertical=12),
                                ),
                                expand=True,
                                on_click=self.close_create_team_modal,
                            ),
                            self.btn_confirm_create_team,
                        ],
                    ),
                ],
            ),
        )

        self.create_team_overlay = ft.Container(
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
                controls=[self.create_team_card],
            ),
        )

        # Modal para Entrar em Equipe via Código de Convite
        self.join_team_input = ft.TextField(
            label="Código de Convite *",
            hint_text="Ex: CS-A1B2C3",
            prefix_icon=ft.Icons.VPN_KEY_ROUNDED,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
            max_length=30,
        )
        self.join_team_feedback = ft.Text("", size=11, color=C_DANGER, text_align=ft.TextAlign.CENTER)
        self.btn_confirm_join_team = ft.FilledButton(
            content="Entrar na Equipe",
            icon=ft.Icons.LOGIN_ROUNDED,
            bgcolor=C_ACCENT,
            color=C_CARD_BG,
            style=ft.ButtonStyle(
                padding=ft.Padding.symmetric(horizontal=14, vertical=12),
            ),
            expand=True,
            on_click=self.confirm_join_team,
        )

        self.join_team_card = ft.Container(
            width=360,
            padding=20,
            border_radius=16,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1, C_BORDER),
            content=ft.Column(
                tight=True,
                spacing=12,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=8,
                                controls=[
                                    ft.Icon(ft.Icons.VPN_KEY_ROUNDED, color=C_ACCENT, size=22),
                                    ft.Text("Entrar em Equipe", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                ],
                            ),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE,
                                icon_size=18,
                                icon_color=C_MUTED,
                                tooltip="Fechar",
                                on_click=self.close_join_team_modal,
                            ),
                        ],
                    ),
                    ft.Text(
                        "Cole o código de convite enviado pelo WhatsApp pelo líder ou integrante da sua equipe.",
                        size=11,
                        color=C_MUTED,
                        text_align=ft.TextAlign.LEFT,
                    ),
                    self.join_team_input,
                    self.join_team_feedback,
                    ft.Row(
                        spacing=10,
                        controls=[
                            ft.OutlinedButton(
                                content="Cancelar",
                                style=ft.ButtonStyle(
                                    side=ft.BorderSide(1, C_BORDER),
                                    color=C_TEXT,
                                    padding=ft.Padding.symmetric(horizontal=14, vertical=12),
                                ),
                                expand=True,
                                on_click=self.close_join_team_modal,
                            ),
                            self.btn_confirm_join_team,
                        ],
                    ),
                ],
            ),
        )

        self.join_team_overlay = ft.Container(
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
                controls=[self.join_team_card],
            ),
        )

        self.view = ft.Column(
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            visible=False,
            controls=[
                ft.Container(
                    padding=14,
                    border_radius=14,
                    bgcolor=C_SURFACE,
                    border=ft.Border.all(1, C_BORDER),
                    content=ft.Column(
                        spacing=10,
                        controls=[
                            ft.Row(
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                controls=[
                                    ft.Row(
                                        spacing=8,
                                        controls=[
                                            ft.Icon(ft.Icons.GROUPS_ROUNDED, color=C_ACCENT, size=24),
                                            ft.Text("Gerenciar Equipes", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                        ],
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.REFRESH_ROUNDED,
                                        icon_color=C_ACCENT,
                                        icon_size=20,
                                        tooltip="Sincronizar equipes",
                                        on_click=lambda e: self.refresh_user_teams(),
                                    ),
                                ],
                            ),
                            ft.Row(
                                spacing=8,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                controls=[
                                    self.team_selector_dropdown,
                                ],
                            ),
                            ft.Row(
                                spacing=8,
                                controls=[
                                    ft.FilledButton(
                                        content="+ Criar Equipe",
                                        icon=ft.Icons.GROUP_ADD_ROUNDED,
                                        bgcolor=C_ACCENT,
                                        color="#18181B",
                                        expand=True,
                                        style=ft.ButtonStyle(padding=ft.Padding.symmetric(horizontal=8, vertical=10)),
                                        on_click=self.open_create_team_modal,
                                    ),
                                    ft.OutlinedButton(
                                        content="🔑 Entrar por Código",
                                        icon=ft.Icons.VPN_KEY_ROUNDED,
                                        style=ft.ButtonStyle(
                                            side=ft.BorderSide(1, C_BORDER),
                                            color=C_TEXT,
                                            padding=ft.Padding.symmetric(horizontal=8, vertical=10),
                                        ),
                                        expand=True,
                                        on_click=self.open_join_team_modal,
                                    ),
                                ],
                            ),
                            ft.Container(
                                padding=12,
                                border_radius=10,
                                bgcolor=C_BG,
                                border=ft.Border.all(1, "#27272A"),
                                content=ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    controls=[
                                        ft.Column(
                                            spacing=2,
                                            expand=True,
                                            controls=[
                                                self.team_name_display,
                                                self.team_code_display,
                                            ],
                                        ),
                                        ft.FilledButton(
                                            content="📲 Convidar",
                                            icon=ft.Icons.SHARE_ROUNDED,
                                            bgcolor=C_WHATSAPP,
                                            color=C_WHITE,
                                            tooltip="Enviar código e link de convite via WhatsApp",
                                            style=ft.ButtonStyle(
                                                padding=ft.Padding.symmetric(horizontal=10, vertical=8),
                                            ),
                                            on_click=self._share_invite_whatsapp,
                                        ),
                                    ],
                                ),
                            ),
                        ],
                    ),
                ),
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Column(
                            spacing=2,
                            controls=[
                                ft.Text("👥 Músicos da Equipe", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                self.team_header_count,
                            ],
                        ),
                        ft.IconButton(
                            icon=ft.Icons.SYNC,
                            icon_color=C_ACCENT,
                            tooltip="Atualizar membros",
                            on_click=lambda e: self.refresh_team_members(),
                        ),
                    ],
                ),
                ft.Text(
                    "Toque em 'Chamar' para notificar o músico instantaneamente no celular dele.",
                    size=11,
                    color=C_MUTED,
                ),
                self.team_search_input,
                self.team_members_column,
            ],
        )

        self._render_team_options()

    def _render_team_options(self) -> None:
        opts = []
        for t in self.user_teams:
            tid = str(t.get("_id") or t.get("id") or "")
            tnome = t.get("nome", "Sem nome")
            opts.append(ft.DropdownOption(key=tid, text=f"👥 {tnome}"))
        self.team_selector_dropdown.options = opts
        if self.active_team:
            cur_id = str(self.active_team.get("_id") or self.active_team.get("id") or "")
            self.team_selector_dropdown.value = cur_id
            self.team_name_display.value = f"👥 {self.active_team.get('nome', 'Equipe')}"
            self.team_code_display.value = f"Código de Convite: {self.active_team.get('codigo_convite', '---')}"
        elif opts:
            first_t = self.user_teams[0]
            self.team_selector_dropdown.value = str(first_t.get("_id") or first_t.get("id") or "")
            self.team_name_display.value = f"👥 {first_t.get('nome', 'Equipe')}"
            self.team_code_display.value = f"Código de Convite: {first_t.get('codigo_convite', '---')}"
        else:
            self.team_selector_dropdown.value = None
            self.team_name_display.value = "👥 Nenhuma Equipe"
            self.team_code_display.value = "Crie uma nova equipe ou entre com um código"
        try:
            self.page.update()
        except Exception:
            pass

    def _apply_active_team(self, team: dict[str, Any], show_toast: bool = True) -> None:
        self.active_team = team
        self.vault.set_active_team(team)
        t_id = str(team.get("_id") or team.get("id") or "")
        self.api_client.set_active_equipe_id(t_id)
        t_nome = team.get("nome", "Equipe")
        t_cod = team.get("codigo_convite", "---")
        self.team_name_display.value = f"👥 {t_nome}"
        self.team_code_display.value = f"Código de Convite: {t_cod}"
        self.team_selector_dropdown.value = t_id
        self.page.update()

        self.refresh_team_members()
        if self.on_team_changed:
            self.on_team_changed(team)
        if show_toast:
            self.show_notification(f"Equipe alterada para: {t_nome}")

    def _on_team_dropdown_change(self, e: ft.ControlEvent) -> None:
        sel_id = getattr(e, "data", None) or getattr(getattr(e, "control", None), "value", None) or self.team_selector_dropdown.value
        if not sel_id:
            return
        selected = next((t for t in self.user_teams if str(t.get("_id") or t.get("id")) == str(sel_id)), None)
        if selected:
            self._apply_active_team(selected)

    def refresh_user_teams(self) -> None:
        def _bg():
            try:
                teams = self.api_client.listar_minhas_equipes()
                self.user_teams = [t for t in (teams or []) if t.get("nome") != "Teste" and t.get("codigo_convite") != "TESTE123"]
                self.vault.set_cached_teams(self.user_teams)

                target_id = None
                if self.active_team:
                    target_id = str(self.active_team.get("_id") or self.active_team.get("id") or "")
                if not target_id:
                    saved = self.vault.get_active_team()
                    if saved and saved.get("nome") != "Teste":
                        target_id = str(saved.get("_id") or saved.get("id") or "")

                matched = next((t for t in self.user_teams if str(t.get("_id") or t.get("id")) == target_id), None) if target_id else None
                if matched:
                    self.active_team = matched
                elif self.user_teams:
                    self.active_team = self.user_teams[0]
                else:
                    self.active_team = None

                if self.active_team:
                    self.vault.set_active_team(self.active_team)
                    self.api_client.set_active_equipe_id(str(self.active_team.get("_id") or self.active_team.get("id")))
                else:
                    self.vault.set_active_team(None)
                    self.api_client.set_active_equipe_id("")

                self._render_team_options()
                self.refresh_team_members()
            except Exception as exc:
                logger.warning("User Teams Fetch Warning: %s", exc)
        threading.Thread(target=_bg, daemon=True).start()

    def _share_invite_whatsapp(self, e: ft.ControlEvent) -> None:
        if not self.active_team:
            self.show_notification("Selecione uma equipe primeiro.")
            return
        t_nome = (self.active_team.get("nome") or "Nossa Equipe").strip()
        t_cod = (self.active_team.get("codigo_convite") or "---").strip()
        msg = (
            f"Olá! Venha participar da minha equipe *{t_nome}* no aplicativo *CipherSong*!\n\n"
            f"Use o código de convite: *{t_cod}*\n\n"
            f"Abra o app CipherSong e entre com esse código na aba Equipe para acessar todas as músicas, escalas e repertórios."
        )
        try:
            self.page.set_clipboard(msg)
        except Exception:
            pass
        wa_url = f"https://api.whatsapp.com/send?text={urllib.parse.quote(msg)}"
        try:
            self.page.launch_url(wa_url)
        except Exception:
            try:
                webbrowser.open(wa_url)
            except Exception:
                pass
        self.show_notification("Código copiado! Abrindo WhatsApp...")

    def close_create_team_modal(self, e: ft.ControlEvent | None = None) -> None:
        self.create_team_overlay.visible = False
        self.page.update()

    def confirm_create_team(self, e: ft.ControlEvent) -> None:
        if self.btn_confirm_create_team.disabled:
            return
        t_name = (self.create_team_input.value or "").strip()
        if not t_name or len(t_name) < 2:
            self.create_team_feedback.color = C_DANGER
            self.create_team_feedback.value = "⚠️ O nome da equipe deve ter pelo menos 2 caracteres."
            self.page.update()
            return
        self.btn_confirm_create_team.disabled = True
        self.create_team_feedback.color = C_ACCENT
        self.create_team_feedback.value = "Criando equipe..."
        self.page.update()
        try:
            new_eq = self.api_client.criar_equipe(t_name)
            self.create_team_overlay.visible = False
            self.create_team_input.value = ""
            self.create_team_feedback.value = ""
            self.user_teams = [t for t in self.user_teams if str(t.get("_id") or t.get("id")) != str(new_eq.get("_id") or new_eq.get("id"))]
            self.user_teams.append(new_eq)
            self.vault.set_cached_teams(self.user_teams)
            self._render_team_options()
            self._apply_active_team(new_eq, show_toast=False)
            self.show_notification(f"Equipe '{t_name}' criada com sucesso! Código: {new_eq.get('codigo_convite')}")
        except Exception as exc:
            self.create_team_feedback.color = C_DANGER
            self.create_team_feedback.value = f"⚠️ {exc}"
        finally:
            self.btn_confirm_create_team.disabled = False
            self.page.update()

    def open_create_team_modal(self, e: ft.ControlEvent | None = None) -> None:
        self.create_team_input.value = ""
        self.create_team_feedback.value = ""
        self.create_team_overlay.visible = True
        self.page.update()

    def close_join_team_modal(self, e: ft.ControlEvent | None = None) -> None:
        self.join_team_overlay.visible = False
        self.page.update()

    def confirm_join_team(self, e: ft.ControlEvent) -> None:
        if self.btn_confirm_join_team.disabled:
            return
        code = (self.join_team_input.value or "").strip().upper()
        if not code or len(code) < 3:
            self.join_team_feedback.color = C_DANGER
            self.join_team_feedback.value = "⚠️ Digite um código de convite válido."
            self.page.update()
            return
        self.btn_confirm_join_team.disabled = True
        self.join_team_feedback.color = C_ACCENT
        self.join_team_feedback.value = "Localizando equipe..."
        self.page.update()
        try:
            joined_eq = self.api_client.entrar_equipe_por_codigo(code)
            self.join_team_overlay.visible = False
            self.join_team_input.value = ""
            self.join_team_feedback.value = ""
            self.user_teams = [t for t in self.user_teams if str(t.get("_id") or t.get("id")) != str(joined_eq.get("_id") or joined_eq.get("id"))]
            self.user_teams.append(joined_eq)
            self.vault.set_cached_teams(self.user_teams)
            self._render_team_options()
            self._apply_active_team(joined_eq, show_toast=False)
            self.show_notification(f"Você agora faz parte da equipe '{joined_eq.get('nome')}'!")
        except Exception as exc:
            self.join_team_feedback.color = C_DANGER
            self.join_team_feedback.value = f"⚠️ {exc}"
        finally:
            self.btn_confirm_join_team.disabled = False
            self.page.update()

    def open_join_team_modal(self, e: ft.ControlEvent | None = None) -> None:
        self.join_team_input.value = ""
        self.join_team_feedback.value = ""
        self.join_team_overlay.visible = True
        self.page.update()

    def refresh_team_members(self, query: str = "") -> None:
        self.team_members_column.controls.clear()
        self.team_members_column.controls.append(create_skeleton_loader(count=3))
        self.page.update()

        def _bg_fetch_members():
            try:
                members = self.api_client.listar_membros_equipe(equipe_id=self.api_client.active_equipe_id)
            except Exception as exc:
                logger.warning("Listar Membros Error: %s", exc)
                members = []

            q = (self.team_search_input.value or query or "").strip().lower()
            if q:
                members = [
                    m for m in members
                    if q in (m.get("nome") or "").lower() or q in (m.get("email") or "").lower()
                ]

            self.team_members_column.controls.clear()
            self.team_header_count.value = f"{len(members)} {'músico' if len(members) == 1 else 'músicos'} na equipe"

            if not members:
                self.team_members_column.controls.append(
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
                                ft.Icon(ft.Icons.PEOPLE_OUTLINE_ROUNDED, size=42, color=C_MUTED),
                                ft.Text(
                                    "Nenhum outro músico nesta equipe",
                                    size=14,
                                    weight=ft.FontWeight.BOLD,
                                    color=C_TEXT,
                                    text_align=ft.TextAlign.CENTER,
                                ),
                                ft.Text(
                                    "Compartilhe o código de convite via WhatsApp para seus companheiros entrarem!",
                                    size=11,
                                    color=C_MUTED,
                                    text_align=ft.TextAlign.CENTER,
                                ),
                            ],
                        ),
                    )
                )
            else:
                for m in members:
                    m_id = str(m.get("_id") or m.get("id"))
                    m_nome = m.get("nome") or m.get("email") or "Músico"
                    m_email = m.get("email") or ""
                    initial = (m_nome[:1] if m_nome else "M").upper()

                    btn_call = ft.FilledButton(
                        content="📲 Chamar",
                        bgcolor=C_ACCENT,
                        color="#18181B",
                        style=ft.ButtonStyle(
                            padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                        ),
                    )

                    now = time.time()
                    if m_id in self.call_cooldowns and self.call_cooldowns[m_id] > now:
                        rem = int(self.call_cooldowns[m_id] - now) + 1
                        btn_call.content = f"⏳ {rem}s"
                        btn_call.disabled = True

                    def _make_call_handler(target_id: str, target_name: str, call_button: ft.FilledButton):
                        def _handler(e: ft.ControlEvent):
                            now_ts = time.time()
                            if target_id in self.call_cooldowns and self.call_cooldowns[target_id] > now_ts:
                                rem_sec = int(self.call_cooldowns[target_id] - now_ts) + 1
                                self.show_notification(f"⏳ Aguarde {rem_sec}s para chamar {target_name} novamente.")
                                return

                            self.call_cooldowns[target_id] = now_ts + 10.0
                            call_button.disabled = True
                            call_button.content = "⏳ 10s"
                            self.page.update()

                            def _exec_ping_and_countdown():
                                try:
                                    self.api_client.enviar_ping(target_id, target_name, equipe_id=self.api_client.active_equipe_id)
                                    self.show_notification(f"📲 Chamada enviada para {target_name}!")
                                except Exception as p_exc:
                                    self.show_notification(f"⚠️ {p_exc}")

                                for sec in range(9, 0, -1):
                                    time.sleep(1.0)
                                    call_button.content = f"⏳ {sec}s"
                                    try:
                                        self.page.update()
                                    except Exception:
                                        pass
                                time.sleep(1.0)
                                call_button.content = "📲 Chamar"
                                call_button.disabled = False
                                try:
                                    self.page.update()
                                except Exception:
                                    pass

                            threading.Thread(target=_exec_ping_and_countdown, daemon=True).start()
                        return _handler

                    btn_call.on_click = _make_call_handler(m_id, m_nome, btn_call)

                    self.team_members_column.controls.append(
                        ft.Container(
                            padding=12,
                            border_radius=12,
                            bgcolor=C_SURFACE,
                            border=ft.Border.all(1, C_BORDER),
                            content=ft.Row(
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                controls=[
                                    ft.Row(
                                        spacing=10,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                        controls=[
                                            ft.Container(
                                                width=42,
                                                height=42,
                                                border_radius=21,
                                                bgcolor=C_BG,
                                                border=ft.Border.all(1.5, C_ACCENT),
                                                alignment=ft.Alignment.CENTER,
                                                content=ft.Text(initial, size=18, weight=ft.FontWeight.BOLD, color=C_ACCENT),
                                            ),
                                            ft.Column(
                                                spacing=2,
                                                controls=[
                                                    ft.Text(m_nome, size=14, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                                    ft.Text(m_email, size=11, color=C_MUTED),
                                                ],
                                            ),
                                        ],
                                    ),
                                    btn_call,
                                ],
                            ),
                        )
                    )

            try:
                self.page.update()
            except Exception:
                pass

        threading.Thread(target=_bg_fetch_members, daemon=True).start()
