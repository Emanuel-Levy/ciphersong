"""
Componente de Autenticação, Login Google OAuth, Código por E-mail (OTP),
Edição de Perfil de Usuário e Diálogo de Logout (UI/UX Flet 1.0).
"""

from __future__ import annotations

import logging
import os
import threading
import time
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
    C_GOOGLE,
    C_IN_TUNE,
    C_INPUT_BG,
    C_MUTED,
    C_SURFACE,
    C_TEXT,
    C_WHITE,
)

logger = logging.getLogger("ciphersong.ui.auth")

try:
    from flet.auth.providers import GoogleOAuthProvider
except ImportError:
    GoogleOAuthProvider = None  # type: ignore

DEFAULT_GOOGLE_CLIENT_ID = "565867015725-o8orc4t64gie24qqvgqo5df9faramcvi.apps.googleusercontent.com"
DEFAULT_GOOGLE_REDIRECT_URL = "http://localhost:8550/oauth_callback"

GOOGLE_CLIENT_ID = (os.getenv("GOOGLE_CLIENT_ID") or DEFAULT_GOOGLE_CLIENT_ID).strip()
GOOGLE_CLIENT_SECRET = (os.getenv("GOOGLE_CLIENT_SECRET") or "").strip()
GOOGLE_REDIRECT_URL = (os.getenv("GOOGLE_REDIRECT_URL") or DEFAULT_GOOGLE_REDIRECT_URL).strip()


class AuthView:
    """Gerencia toda a interface de autenticação, Google OAuth, OTP e modais de conta."""

    def __init__(
        self,
        page: ft.Page,
        vault: EncryptedSessionVault,
        api_client: SongsApiClient,
        url_launcher: ft.UrlLauncher | None = None,
        on_auth_success: Callable[[str, str], None] | None = None,
        on_logout: Callable[[], None] | None = None,
        on_username_changed: Callable[[str], None] | None = None,
        is_authenticated_initial: bool = False,
    ) -> None:
        self.page = page
        self.vault = vault
        self.api_client = api_client
        self.url_launcher = url_launcher
        self.on_auth_success = on_auth_success
        self.on_logout_callback = on_logout
        self.on_username_changed = on_username_changed

        self.auth_mode = "otp"  # "otp" | "otp_verify" | "login" | "register"
        self.current_otp_email: str = ""
        self.pending_otp_name: str = ""
        self.pending_google_email: str = ""
        self.active_oauth_http_server: list[Any] = [None]

        user_name_initial = self.get_logged_user_display_name()

        self.header_greeting_text = ft.Text(
            f"Olá, {user_name_initial}" if user_name_initial else "Olá, Músico",
            size=22,
            weight=ft.FontWeight.BOLD,
            color=C_TEXT,
        )

        self.btn_edit_username = ft.IconButton(
            icon=ft.Icons.EDIT_OUTLINED,
            icon_size=20,
            icon_color=C_MUTED,
            tooltip="Mudar Nome de Usuário",
            on_click=self.open_edit_username_modal,
        )

        self.btn_logout = ft.IconButton(
            icon=ft.Icons.LOGOUT_ROUNDED,
            icon_size=20,
            icon_color=C_MUTED,
            tooltip="Sair / Trocar de Conta",
            on_click=self.open_logout_modal,
        )

        # Campos da Tela de Login
        self.auth_title = ft.Text(
            "Entrar ou Criar Conta",
            size=18,
            weight=ft.FontWeight.BOLD,
            color=C_TEXT,
            text_align=ft.TextAlign.CENTER,
        )
        self.auth_subtitle = ft.Text(
            "Digite seu e-mail para receber um código temporário de 6 dígitos.",
            size=12,
            color=C_MUTED,
            text_align=ft.TextAlign.CENTER,
        )

        self.auth_name_field = ft.TextField(
            label="Seu Nome de Usuário (opcional)",
            hint_text="Ex: Seu Nome / Apelido",
            prefix_icon=ft.Icons.PERSON_OUTLINE,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
            visible=True,
            autofill_hints=[ft.AutofillHint.NAME],
        )
        self.auth_email_field = ft.TextField(
            label="Seu E-mail *",
            hint_text="voce@email.com",
            prefix_icon=ft.Icons.EMAIL_OUTLINED,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
            keyboard_type=ft.KeyboardType.EMAIL,
            autofill_hints=[ft.AutofillHint.EMAIL],
        )
        self.auth_password_field = ft.TextField(
            label="Sua Senha (mínimo 6 dígitos) *",
            prefix_icon=ft.Icons.LOCK_OUTLINE,
            password=True,
            can_reveal_password=True,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
            visible=False,
            autofill_hints=[ft.AutofillHint.PASSWORD],
        )
        self.auth_feedback_text = ft.Text(
            "",
            size=12,
            color=C_DANGER,
            text_align=ft.TextAlign.CENTER,
            weight=ft.FontWeight.W_600,
        )

        self.btn_mode_otp = ft.FilledButton(
            content="Código por E-mail",
            bgcolor=C_ACCENT,
            color="#18181B",
            expand=True,
            height=38,
            on_click=lambda e: self.switch_auth_mode("otp"),
        )
        self.btn_mode_password = ft.FilledButton(
            content="Com Senha",
            bgcolor=C_BG,
            color=C_MUTED,
            expand=True,
            height=38,
            on_click=lambda e: self.switch_auth_mode("login"),
        )

        self.btn_mode_login = ft.FilledButton(
            content="Entrar",
            bgcolor=C_ACCENT,
            color="#18181B",
            expand=True,
            height=34,
            on_click=lambda e: self.switch_auth_mode("login"),
        )
        self.btn_mode_register = ft.FilledButton(
            content="Criar Conta",
            bgcolor=C_BG,
            color=C_MUTED,
            expand=True,
            height=34,
            on_click=lambda e: self.switch_auth_mode("register"),
        )
        self.password_submode_row = ft.Row(
            spacing=6,
            controls=[self.btn_mode_login, self.btn_mode_register],
            visible=False,
        )

        self.btn_request_otp = ft.FilledButton(
            content="Enviar Código de Acesso",
            icon=ft.Icons.MARK_EMAIL_READ_ROUNDED,
            bgcolor=C_ACCENT,
            color="#18181B",
            width=340,
            height=46,
            visible=True,
            on_click=self.handle_request_otp,
        )

        self.btn_submit_auth = ft.FilledButton(
            content="Entrar no App",
            icon=ft.Icons.LOGIN_ROUNDED,
            bgcolor=C_ACCENT,
            color="#18181B",
            width=340,
            height=46,
            visible=False,
            on_click=self.handle_auth_submit,
        )

        # Campos da Etapa OTP (6 dígitos)
        self.auth_otp_field = ft.TextField(
            label="Código de 6 Dígitos *",
            hint_text="Código de 6 dígitos",
            prefix_icon=ft.Icons.PIN_ROUNDED,
            max_length=6,
            text_align=ft.TextAlign.CENTER,
            text_size=24,
            text_style=ft.TextStyle(weight=ft.FontWeight.BOLD),
            color=C_ACCENT,
            bgcolor=C_BG,
            border_color=C_BORDER,
            keyboard_type=ft.KeyboardType.NUMBER,
            autofill_hints=[ft.AutofillHint.ONE_TIME_CODE],
        )
        self.auth_otp_feedback = ft.Text(
            "",
            size=12,
            color=C_DANGER,
            text_align=ft.TextAlign.CENTER,
            weight=ft.FontWeight.W_600,
        )
        self.otp_dest_info_text = ft.Text(
            "",
            size=12,
            color=C_MUTED,
            text_align=ft.TextAlign.CENTER,
        )
        self.btn_verify_otp = ft.FilledButton(
            content="Confirmar Código e Entrar",
            icon=ft.Icons.CHECK_CIRCLE_ROUNDED,
            bgcolor=C_ACCENT,
            color="#18181B",
            width=340,
            height=46,
            on_click=self.handle_verify_otp,
        )
        self.btn_resend_otp = ft.OutlinedButton(
            content="Reenviar Código",
            icon=ft.Icons.REFRESH_ROUNDED,
            style=ft.ButtonStyle(
                color=C_TEXT,
                side=ft.BorderSide(1, C_BORDER),
                padding=ft.Padding.symmetric(horizontal=12, vertical=10),
            ),
            expand=True,
            on_click=self.handle_request_otp,
        )
        self.btn_back_to_email = ft.OutlinedButton(
            content="Trocar E-mail",
            icon=ft.Icons.ARROW_BACK,
            style=ft.ButtonStyle(
                color=C_MUTED,
                side=ft.BorderSide(1, C_BORDER),
                padding=ft.Padding.symmetric(horizontal=12, vertical=10),
            ),
            expand=True,
            on_click=lambda e: self.switch_auth_mode("otp"),
        )

        # Modal Oficial Google OAuth
        self.google_picker_feedback = ft.Text("", size=11, color=C_DANGER, text_align=ft.TextAlign.CENTER)

        self.google_custom_email_field = ft.TextField(
            label="Seu e-mail Google (@gmail.com)",
            hint_text="seuemail@gmail.com",
            prefix_icon=ft.Icons.ALTERNATE_EMAIL,
            keyboard_type=ft.KeyboardType.EMAIL,
            autofill_hints=[ft.AutofillHint.EMAIL],
            width=310,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )

        self.google_username_field = ft.TextField(
            label="Seu Nome / Apelido no CipherSong *",
            hint_text="Ex: Lucas / Sarah / Gabriel",
            prefix_icon=ft.Icons.PERSON_OUTLINE,
            width=310,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
        )

        self.google_account_card_inner = ft.Column(
            tight=True,
            spacing=12,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        self.google_account_card = ft.Container(
            width=365,
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
            content=self.google_account_card_inner,
        )

        self.google_account_overlay = ft.Container(
            left=0,
            top=0,
            right=0,
            bottom=0,
            alignment=ft.Alignment.CENTER,
            bgcolor=ft.Colors.with_opacity(0.75, "#09090B"),
            blur=ft.Blur(14, 14, tile_mode=ft.BlurTileMode.CLAMP),
            visible=False,
            content=ft.Column(
                scroll=ft.ScrollMode.AUTO,
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[self.google_account_card],
            ),
        )

        self.btn_official_google = ft.Container(
            content=ft.Row(
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=10,
                controls=[
                    ft.Image(
                        src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg",
                        width=22,
                        height=22,
                        fit=ft.BoxFit.CONTAIN,
                        error_content=ft.Icon(ft.Icons.ACCOUNT_CIRCLE, size=22, color="#4285F4"),
                    ),
                    ft.Text("Fazer Login com o Google", size=14, weight=ft.FontWeight.W_600, color=C_TEXT),
                ],
            ),
            width=340,
            height=48,
            border_radius=24,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1.5, C_BORDER),
            alignment=ft.Alignment.CENTER,
            ink=True,
            tooltip="Clique para escolher sua conta Google do dispositivo",
            on_click=self.start_official_google_oauth,
        )

        self.divider_or_email = ft.Row(
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=8,
            controls=[
                ft.Container(width=90, height=1, bgcolor=C_BORDER),
                ft.Text("ou com e-mail", size=12, color=C_MUTED),
                ft.Container(width=90, height=1, bgcolor=C_BORDER),
            ],
        )

        self.email_auth_view = ft.Column(
            visible=True,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            controls=[
                ft.Row(
                    spacing=6,
                    controls=[self.btn_mode_otp, self.btn_mode_password],
                ),
                self.password_submode_row,
                self.auth_title,
                self.auth_subtitle,
                self.auth_name_field,
                self.auth_email_field,
                self.auth_password_field,
                self.auth_feedback_text,
                self.btn_request_otp,
                self.btn_submit_auth,
            ],
        )

        self.otp_verify_view = ft.Column(
            visible=False,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            controls=[
                ft.Container(
                    width=52,
                    height=52,
                    border_radius=26,
                    bgcolor=ft.Colors.with_opacity(0.12, C_ACCENT),
                    alignment=ft.Alignment.CENTER,
                    content=ft.Icon(ft.Icons.MARK_EMAIL_READ_ROUNDED, size=28, color=C_ACCENT),
                ),
                ft.Text("Código de Verificação", size=18, weight=ft.FontWeight.BOLD, color=C_TEXT),
                self.otp_dest_info_text,
                self.auth_otp_field,
                self.auth_otp_feedback,
                self.btn_verify_otp,
                ft.Row(
                    spacing=8,
                    controls=[
                        self.btn_back_to_email,
                        self.btn_resend_otp,
                    ],
                ),
            ],
        )

        self.login_screen_view = ft.Container(
            expand=True,
            visible=not is_authenticated_initial,
            padding=ft.Padding.symmetric(vertical=16),
            content=ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=16,
                scroll=ft.ScrollMode.AUTO,
                controls=[
                    ft.Container(
                        padding=ft.Padding.only(top=12, bottom=4),
                        content=ft.Column(
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=6,
                            controls=[
                                ft.Container(
                                    width=64,
                                    height=64,
                                    border_radius=20,
                                    bgcolor=C_SURFACE,
                                    border=ft.Border.all(2, C_ACCENT),
                                    alignment=ft.Alignment(0, 0),
                                    content=ft.Icon(ft.Icons.MUSIC_NOTE, size=34, color=C_ACCENT),
                                ),
                                ft.Text("CipherSong", size=28, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                ft.Text(
                                    "Detector de Tom & Repertório em Nuvem",
                                    size=13,
                                    color=C_MUTED,
                                ),
                            ],
                        ),
                    ),
                    ft.Container(
                        padding=20,
                        border_radius=18,
                        bgcolor=C_SURFACE,
                        border=ft.Border.all(1, C_BORDER),
                        content=ft.Column(
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=14,
                            controls=[
                                self.btn_official_google,
                                self.divider_or_email,
                                self.email_auth_view,
                                self.otp_verify_view,
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    spacing=6,
                                    controls=[
                                        ft.Icon(ft.Icons.SHIELD_OUTLINED, size=14, color=C_IN_TUNE),
                                        ft.Text(
                                            "Código OTP RAM-Only • Invalidação Pós-Uso • Rate Limit",
                                            size=11,
                                            color=C_MUTED,
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    ),
                ],
            ),
        )

        # Modal de Alteração de Nome de Usuário
        self.edit_username_input = ft.TextField(
            label="Novo Nome de Usuário *",
            hint_text="Ex: Davi, Lucas, Poliana",
            prefix_icon=ft.Icons.PERSON_OUTLINE,
            bgcolor=C_BG,
            border_color=C_BORDER,
            color=C_TEXT,
            width=330,
            max_length=50,
            autofill_hints=[ft.AutofillHint.NAME],
        )
        self.edit_username_feedback = ft.Text("", size=11, color=C_DANGER, text_align=ft.TextAlign.CENTER)

        self.edit_username_card = ft.Container(
            width=360,
            padding=20,
            border_radius=16,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1, C_BORDER),
            content=ft.Column(
                tight=True,
                spacing=12,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=8,
                                controls=[
                                    ft.Icon(ft.Icons.BADGE_OUTLINED, color=C_ACCENT, size=22),
                                    ft.Text("Mudar Nome de Usuário", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                ],
                            ),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE,
                                icon_size=18,
                                icon_color=C_MUTED,
                                tooltip="Fechar",
                                on_click=self.close_edit_username_modal,
                            ),
                        ],
                    ),
                    ft.Text(
                        "Seu nome identifica você nas escalas da semana, sugestões de ensaios e repertório compartilhado.",
                        size=11,
                        color=C_MUTED,
                        text_align=ft.TextAlign.LEFT,
                    ),
                    self.edit_username_input,
                    self.edit_username_feedback,
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
                                on_click=self.close_edit_username_modal,
                            ),
                            ft.FilledButton(
                                content="Salvar Nome",
                                icon=ft.Icons.CHECK,
                                bgcolor=C_ACCENT,
                                color="#18181B",
                                style=ft.ButtonStyle(
                                    padding=ft.Padding.symmetric(horizontal=14, vertical=12),
                                ),
                                expand=True,
                                on_click=self.confirm_save_new_username,
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.edit_username_overlay = ft.Container(
            left=0,
            top=0,
            right=0,
            bottom=0,
            alignment=ft.Alignment.CENTER,
            bgcolor=ft.Colors.with_opacity(0.70, "#09090B"),
            blur=ft.Blur(14, 14, tile_mode=ft.BlurTileMode.CLAMP),
            visible=False,
            content=ft.Column(
                scroll=ft.ScrollMode.AUTO,
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[self.edit_username_card],
            ),
        )

        # Modal de Confirmação de Saída de Conta (Logout)
        self.logout_confirm_card = ft.Container(
            width=380,
            bgcolor=C_SURFACE,
            border=ft.Border.all(1, C_BORDER),
            border_radius=16,
            padding=24,
            shadow=ft.BoxShadow(
                blur_radius=28,
                spread_radius=2,
                color=ft.Colors.with_opacity(0.35, "#000000"),
            ),
            content=ft.Column(
                tight=True,
                spacing=16,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Container(
                        width=54,
                        height=54,
                        border_radius=27,
                        bgcolor=ft.Colors.with_opacity(0.12, C_DANGER),
                        alignment=ft.Alignment.CENTER,
                        content=ft.Icon(ft.Icons.LOGOUT_ROUNDED, size=28, color=C_DANGER),
                    ),
                    ft.Text("Sair da Conta", size=18, weight=ft.FontWeight.BOLD, color=C_TEXT),
                    ft.Text(
                        "Tem certeza de que deseja sair da sua conta? Você precisará entrar novamente para acessar as equipes e o repertório sincronizado.",
                        size=13,
                        color=C_MUTED,
                        text_align=ft.TextAlign.CENTER,
                    ),
                    ft.Row(
                        spacing=12,
                        controls=[
                            ft.OutlinedButton(
                                content="Cancelar",
                                style=ft.ButtonStyle(
                                    color=C_MUTED,
                                    side=ft.BorderSide(1, C_BORDER),
                                    padding=ft.Padding.symmetric(horizontal=18, vertical=12),
                                ),
                                expand=True,
                                on_click=lambda _: self.close_logout_modal(),
                            ),
                            ft.FilledButton(
                                content="Sim, Sair",
                                icon=ft.Icons.LOGOUT_ROUNDED,
                                bgcolor=C_DANGER,
                                color="#FFFFFF",
                                style=ft.ButtonStyle(
                                    padding=ft.Padding.symmetric(horizontal=18, vertical=12),
                                ),
                                expand=True,
                                on_click=lambda _: self.confirm_logout(),
                            ),
                        ],
                    ),
                ],
            ),
        )

        self.logout_confirm_overlay = ft.Container(
            left=0,
            top=0,
            right=0,
            bottom=0,
            alignment=ft.Alignment.CENTER,
            bgcolor=ft.Colors.with_opacity(0.70, "#09090B"),
            blur=ft.Blur(14, 14, tile_mode=ft.BlurTileMode.CLAMP),
            visible=False,
            content=ft.Column(
                scroll=ft.ScrollMode.AUTO,
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[self.logout_confirm_card],
            ),
        )

        self.page.on_login = self.on_google_oauth_completed

    def get_logged_user_display_name(self) -> str | None:
        sess = self.vault.get_auth_session()
        if sess and sess.get("token"):
            return sess.get("name") or sess.get("nome") or (sess.get("email") or "").split("@")[0]
        return None

    def close_google_account_picker(self, e: ft.ControlEvent | None = None) -> None:
        self.google_account_overlay.visible = False
        self.page.update()

    def select_google_account(self, raw_email: str, suggested_name: str) -> None:
        email = (raw_email or "").strip().lower()
        if not email or "@" not in email:
            self.google_picker_feedback.color = C_DANGER
            self.google_picker_feedback.value = "Por favor, informe um e-mail Google válido."
            self.page.update()
            return

        self.pending_google_email = email
        self.google_picker_feedback.color = C_ACCENT
        self.google_picker_feedback.value = "Conectando à sua Conta Google..."
        self.page.update()

        existing_user = None
        try:
            existing_user = self.api_client.buscar_usuario_por_email(email)
        except Exception as exc:
            logger.debug("Falha ao buscar usuário por e-mail durante OAuth Google: %s", exc)

        user_name = ""
        if existing_user:
            user_name = existing_user.get("nome") or suggested_name or email.split("@")[0]
        else:
            user_name = (suggested_name or email.split("@")[0]).strip()

        if not user_name or len(user_name) < 2:
            self.render_google_username_step(email, suggested_name)
            return

        try:
            res = self.api_client.login_com_google(email=email, nome=user_name)
            token = res.get("token")
            user_data = res.get("user", {})
            final_name = user_data.get("nome", user_name)

            self.vault.save_auth_session(
                user_id=user_data.get("id", str(existing_user.get("_id", "") if existing_user else "")),
                email=email,
                token=token,
                name=final_name,
            )
            self.api_client.set_auth_token(token)
            self.google_account_overlay.visible = False
            self.google_picker_feedback.value = ""
            self.auth_feedback_text.value = f"✅ Bem-vindo(a), {final_name}! Conectado via Conta Google."
            self.auth_feedback_text.color = C_IN_TUNE
            if self.on_auth_success:
                self.on_auth_success(final_name, token)
        except Exception as exc:
            self.render_google_username_step(email, suggested_name)
            self.google_picker_feedback.color = C_DANGER
            self.google_picker_feedback.value = f"Ajuste seu nome: {exc}"
            self.page.update()

    def submit_google_new_username(self, e: ft.ControlEvent) -> None:
        chosen = (self.google_username_field.value or "").strip()
        if not chosen or len(chosen) < 2:
            self.google_picker_feedback.color = C_DANGER
            self.google_picker_feedback.value = "Escolha um nome de usuário com pelo menos 2 letras."
            self.page.update()
            return

        self.google_picker_feedback.color = C_ACCENT
        self.google_picker_feedback.value = "Criando sua conta segura vinculada ao Google..."
        self.page.update()

        try:
            res = self.api_client.login_com_google(email=self.pending_google_email, nome=chosen)
            token = res.get("token")
            user_data = res.get("user", {})
            final_name = user_data.get("nome", chosen)

            self.vault.save_auth_session(
                user_id=user_data.get("id", ""),
                email=self.pending_google_email,
                token=token,
                name=final_name,
            )
            self.api_client.set_auth_token(token)
            self.google_account_overlay.visible = False
            self.google_picker_feedback.value = ""
            self.auth_feedback_text.value = f"✅ Conta criada! Bem-vindo(a), {final_name}!"
            self.auth_feedback_text.color = C_IN_TUNE
            if self.on_auth_success:
                self.on_auth_success(final_name, token)
        except Exception as exc:
            self.google_picker_feedback.color = C_DANGER
            self.google_picker_feedback.value = str(exc)
            self.page.update()

    def render_google_username_step(self, email: str, suggested_name: str) -> None:
        self.google_username_field.value = suggested_name or email.split("@")[0]
        self.google_picker_feedback.value = ""
        self.google_account_card_inner.controls = [
            ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Row(
                        spacing=8,
                        controls=[
                            ft.Image(
                                src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg",
                                width=24,
                                height=24,
                                fit=ft.BoxFit.CONTAIN,
                                error_content=ft.Icon(ft.Icons.ACCOUNT_CIRCLE, size=24, color="#4285F4"),
                            ),
                            ft.Text("Quase lá!", size=18, weight=ft.FontWeight.BOLD, color=C_TEXT),
                        ],
                    ),
                    ft.IconButton(
                        icon=ft.Icons.CLOSE,
                        icon_color=C_MUTED,
                        tooltip="Fechar",
                        on_click=self.close_google_account_picker,
                    ),
                ],
            ),
            ft.Container(
                padding=10,
                border_radius=10,
                bgcolor=C_BG,
                border=ft.Border.all(1, C_BORDER),
                content=ft.Row(
                    spacing=8,
                    controls=[
                        ft.Icon(ft.Icons.CHECK_CIRCLE, size=18, color=C_IN_TUNE),
                        ft.Column(
                            spacing=1,
                            controls=[
                                ft.Text("Conta Google Confirmada pela API", size=11, color=C_IN_TUNE, weight=ft.FontWeight.BOLD),
                                ft.Text(email, size=12, color=C_TEXT),
                            ],
                        ),
                    ],
                ),
            ),
            ft.Text(
                "Como você quer ser chamado no CipherSong?\n(Cada integrante possui um nome único)",
                size=12,
                color=C_MUTED,
                text_align=ft.TextAlign.CENTER,
            ),
            self.google_username_field,
            self.google_picker_feedback,
            ft.FilledButton(
                content="Concluir Cadastro e Entrar",
                icon=ft.Icons.ARROW_FORWARD,
                bgcolor=C_ACCENT,
                color="#18181B",
                style=ft.ButtonStyle(
                    padding=ft.Padding.symmetric(horizontal=20, vertical=12),
                ),
                width=310,
                on_click=self.submit_google_new_username,
            ),
        ]
        self.google_account_overlay.visible = True
        self.auth_feedback_text.value = f"✅ Conta Google ({email}) confirmada! Defina seu nome de usuário."
        self.auth_feedback_text.color = C_IN_TUNE
        try:
            self.page.update()
        except Exception:
            pass

    def render_google_account_selector_step(self) -> None:
        self.google_picker_feedback.value = ""

        local_saved_card = None
        try:
            saved_sess = self.vault.get_auth_session()
            if saved_sess and saved_sess.get("email"):
                s_email = str(saved_sess.get("email")).strip()
                s_name = str(saved_sess.get("name") or s_email.split("@")[0]).strip()
                initial_letter = (s_name[0] if s_name else "U").upper()

                local_saved_card = ft.Column(
                    spacing=6,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.Text("Conta conectada neste aparelho:", size=11, color=C_MUTED),
                        ft.Container(
                            width=330,
                            padding=12,
                            border_radius=14,
                            bgcolor=C_BG,
                            border=ft.Border.all(1.2, C_ACCENT),
                            ink=True,
                            on_click=lambda _: self.select_google_account(s_email, s_name),
                            content=ft.Row(
                                spacing=12,
                                controls=[
                                    ft.Container(
                                        width=40,
                                        height=40,
                                        shape=ft.BoxShape.CIRCLE,
                                        bgcolor=C_ACCENT,
                                        alignment=ft.Alignment.CENTER,
                                        content=ft.Text(initial_letter, size=20, weight=ft.FontWeight.BOLD, color="#18181B"),
                                    ),
                                    ft.Column(
                                        spacing=1,
                                        controls=[
                                            ft.Text(s_name, size=14, weight=ft.FontWeight.BOLD, color=C_TEXT),
                                            ft.Text(s_email, size=11, color=C_MUTED),
                                        ],
                                    ),
                                ],
                            ),
                        ),
                    ],
                )
        except Exception:
            local_saved_card = None

        card_controls: list[ft.Control] = [
            ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Row(
                        spacing=8,
                        controls=[
                            ft.Image(
                                src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg",
                                width=24,
                                height=24,
                                fit=ft.BoxFit.CONTAIN,
                                error_content=ft.Icon(ft.Icons.ACCOUNT_CIRCLE, size=24, color="#4285F4"),
                            ),
                            ft.Text("Login com o Google", size=16, weight=ft.FontWeight.BOLD, color=C_TEXT),
                        ],
                    ),
                    ft.IconButton(
                        icon=ft.Icons.CLOSE,
                        icon_color=C_MUTED,
                        tooltip="Fechar",
                        on_click=self.close_google_account_picker,
                    ),
                ],
            ),
            ft.Column(
                spacing=2,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Text("Escolha uma conta", size=18, weight=ft.FontWeight.BOLD, color=C_TEXT),
                    ft.Text("Selecione diretamente uma das contas Google do seu aparelho", size=12, color=C_MUTED, text_align=ft.TextAlign.CENTER),
                ],
            ),
        ]

        if local_saved_card:
            card_controls.append(local_saved_card)

        card_controls.extend([
            ft.FilledButton(
                content="Selecionar Conta Google do Aparelho",
                icon=ft.Icons.ACCOUNT_CIRCLE,
                bgcolor=C_ACCENT,
                color="#18181B",
                width=310,
                on_click=self.start_official_google_oauth,
            ),
            self.google_picker_feedback,
            ft.Container(
                padding=ft.Padding.only(top=4),
                content=ft.Text(
                    "🔒 Ao tocar acima, o Google exibirá as contas conectadas no seu celular para você selecionar com 1 toque, sem precisar digitar.",
                    size=10,
                    color=C_MUTED,
                    text_align=ft.TextAlign.CENTER,
                ),
            ),
        ])

        self.google_account_card_inner.controls = card_controls
        try:
            self.page.update()
        except Exception:
            pass

    def open_google_account_picker(self, e: ft.ControlEvent | None = None) -> None:
        self.render_google_account_selector_step()
        self.google_account_overlay.visible = True
        self.page.update()

    def _build_oauth_success_html(self, title_msg: str, subtitle_msg: str, is_error: bool = False) -> str:
        accent_col = "#EF4444" if is_error else "#22C55E"
        icon_char = "⚠️" if is_error else "✅"
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title_msg} — CipherSong</title>
    <style>
        body {{
            background-color: #18181B;
            color: #F4F4F5;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
            text-align: center;
        }}
        .card {{
            background-color: #27272A;
            padding: 32px 24px;
            border-radius: 20px;
            border: 1.5px solid {accent_col};
            max-width: 380px;
            width: 100%;
            box-shadow: 0 12px 32px rgba(0,0,0,0.6);
        }}
        .icon {{ font-size: 44px; margin-bottom: 12px; }}
        h2 {{ color: {accent_col}; margin: 0 0 10px 0; font-size: 20px; }}
        p {{ color: #A1A1AA; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }}
        .btn {{
            display: inline-block;
            background-color: #06B6D4;
            color: #18181B;
            font-weight: 700;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 24px;
            font-size: 15px;
            border: none;
            cursor: pointer;
            width: 100%;
            box-sizing: border-box;
        }}
        .hint {{
            font-size: 12px;
            color: #71717A;
            margin-top: 14px;
            line-height: 1.4;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">{icon_char}</div>
        <h2>{title_msg}</h2>
        <p>{subtitle_msg}</p>
        <a class="btn" href="ciphersong://oauth_success" onclick="tryClose();">Voltar para o CipherSong</a>
        <p class="hint">Ou retorne ao aplicativo CipherSong pelo seletor de tarefas do celular.</p>
    </div>
    <script>
        function tryClose() {{
            try {{ window.close(); }} catch(e) {{}}
            try {{ window.location.href = "ciphersong://oauth_success"; }} catch(e) {{}}
        }}
        setTimeout(tryClose, 400);
    </script>
</body>
</html>"""

    def _start_loopback_google_oauth_server(self) -> str:
        import http.server
        import secrets
        import urllib.parse

        import httpx

        parsed_redirect = urllib.parse.urlparse(GOOGLE_REDIRECT_URL)
        listen_port = parsed_redirect.port or 8550
        oauth_state = secrets.token_urlsafe(16)

        auth_self = self

        if self.active_oauth_http_server[0] is None:
            class _ReusableHTTPServer(http.server.HTTPServer):
                allow_reuse_address = True

            class _GoogleOAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
                def log_message(self, format: str, *args: Any) -> None:
                    pass

                def do_GET(self) -> None:
                    parsed_path = urllib.parse.urlparse(self.path)
                    if not parsed_path.path.startswith("/oauth_callback"):
                        self.send_response(204)
                        self.end_headers()
                        return

                    qs = urllib.parse.parse_qs(parsed_path.query)
                    err = qs.get("error", [None])[0]
                    code = qs.get("code", [None])[0]

                    if err or not code:
                        html_err = auth_self._build_oauth_success_html(
                            "Autenticação Cancelada",
                            f"O Google retornou: {err or 'Operação cancelada'}. Volte ao CipherSong e tente novamente.",
                            is_error=True,
                        ).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(html_err)))
                        self.end_headers()
                        self.wfile.write(html_err)
                        auth_self.auth_feedback_text.value = f"Autenticação Google cancelada ({err or 'sem código'})."
                        auth_self.auth_feedback_text.color = C_DANGER
                        try:
                            auth_self.page.update()
                        except Exception:
                            pass
                        return

                    try:
                        with httpx.Client(timeout=12.0, follow_redirects=True) as client:
                            token_resp = client.post(
                                "https://oauth2.googleapis.com/token",
                                data={
                                    "code": code,
                                    "client_id": GOOGLE_CLIENT_ID,
                                    "client_secret": GOOGLE_CLIENT_SECRET,
                                    "redirect_uri": GOOGLE_REDIRECT_URL,
                                    "grant_type": "authorization_code",
                                },
                                headers={"Content-Type": "application/x-www-form-urlencoded"},
                            )
                            token_resp.raise_for_status()
                            token_data = token_resp.json()
                            access_token = token_data.get("access_token")

                            user_resp = client.get(
                                "https://www.googleapis.com/oauth2/v3/userinfo",
                                headers={"Authorization": f"Bearer {access_token}"},
                            )
                            user_resp.raise_for_status()
                            u_info = user_resp.json()

                        g_email = str(u_info.get("email") or "").strip().lower()
                        g_name = str(u_info.get("name") or (g_email.split("@")[0] if g_email else "")).strip()

                        html_ok = auth_self._build_oauth_success_html(
                            "Conta Google Confirmada!",
                            f"Identificado como {g_name} ({g_email}). Volte para o aplicativo CipherSong para continuar.",
                            is_error=False,
                        ).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(html_ok)))
                        self.end_headers()
                        self.wfile.write(html_ok)

                        if g_email:
                            auth_self.select_google_account(g_email, g_name)
                            try:
                                async def _try_close_custom_tab() -> None:
                                    try:
                                        if auth_self.url_launcher:
                                            await auth_self.url_launcher.close_in_app_web_view()
                                    except Exception:
                                        pass
                                auth_self.page.run_task(_try_close_custom_tab)
                            except Exception:
                                pass
                    except Exception as ex:
                        html_fail = auth_self._build_oauth_success_html(
                            "Erro na Validação Google",
                            f"Não foi possível validar o token com a API do Google: {ex}",
                            is_error=True,
                        ).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(html_fail)))
                        self.end_headers()
                        self.wfile.write(html_fail)
                        auth_self.auth_feedback_text.value = f"Erro ao validar token Google: {ex}"
                        auth_self.auth_feedback_text.color = C_DANGER
                        try:
                            auth_self.page.update()
                        except Exception:
                            pass

            srv = _ReusableHTTPServer(("127.0.0.1", listen_port), _GoogleOAuthCallbackHandler)
            self.active_oauth_http_server[0] = srv

            def _serve_oauth_loop() -> None:
                try:
                    srv.serve_forever()
                except Exception:
                    pass
                finally:
                    try:
                        srv.server_close()
                    except Exception:
                        pass
                    if auth_self.active_oauth_http_server[0] is srv:
                        auth_self.active_oauth_http_server[0] = None

            threading.Thread(target=_serve_oauth_loop, daemon=True).start()

        params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URL,
            "scope": "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid",
            "state": oauth_state,
            "prompt": "select_account",
            "access_type": "online",
        })
        return f"https://accounts.google.com/o/oauth2/v2/auth?{params}"

    async def _open_google_url_on_device(self, authorization_url: str) -> None:
        try:
            if self.page.web:
                if self.url_launcher:
                    await self.url_launcher.open_window(
                        authorization_url,
                        title="flet_oauth_signin",
                        width=520,
                        height=650,
                    )
            else:
                try:
                    if self.url_launcher:
                        await self.url_launcher.launch_url(
                            authorization_url,
                            mode=ft.LaunchMode.IN_APP_BROWSER_VIEW,
                        )
                except Exception:
                    if self.url_launcher:
                        await self.url_launcher.launch_url(
                            authorization_url,
                            mode=ft.LaunchMode.PLATFORM_DEFAULT,
                        )
        except Exception as ul_err:
            logger.warning("UrlLauncher fallback: %s", ul_err)
            try:
                if self.url_launcher:
                    await self.url_launcher.launch_url(authorization_url)
            except Exception:
                import webbrowser
                webbrowser.open(authorization_url)

    async def start_official_google_oauth(self, e: ft.ControlEvent | None = None) -> None:
        self.google_account_overlay.visible = False
        self.auth_feedback_text.value = "Abrindo seletor de Contas Google do aparelho..."
        self.auth_feedback_text.color = C_ACCENT
        self.page.update()

        if self.page.web and GoogleOAuthProvider is not None and GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
            try:
                google_provider = GoogleOAuthProvider(
                    client_id=GOOGLE_CLIENT_ID,
                    client_secret=GOOGLE_CLIENT_SECRET,
                    redirect_url=GOOGLE_REDIRECT_URL,
                )
                google_provider.authorization_params = {
                    "prompt": "select_account",
                    "access_type": "online",
                }
                await self.page.login(
                    google_provider,
                    fetch_user=True,
                    on_open_authorization_url=self._open_google_url_on_device,
                    complete_page_html=self._build_oauth_success_html(
                        "Conta Google Confirmada!",
                        "Sua conta Google foi verificada com sucesso. Esta janela será fechada automaticamente.",
                        is_error=False,
                    ),
                )
                return
            except Exception as web_oauth_exc:
                logger.warning("Web OAuth Fallback to Loopback: %s", web_oauth_exc)

        try:
            auth_url = self._start_loopback_google_oauth_server()
            await self._open_google_url_on_device(auth_url)
        except Exception as exc:
            logger.warning("Google OAuth Loopback Error: %s", exc)
            self.auth_feedback_text.value = f"Erro ao abrir seletor Google: {exc}"
            self.auth_feedback_text.color = C_DANGER
            self.page.update()

    async def on_google_oauth_completed(self, e: ft.LoginEvent) -> None:
        if e.error:
            self.auth_feedback_text.value = f"Não foi possível autenticar com o Google: {e.error_description or e.error}"
            self.auth_feedback_text.color = C_DANGER
            self.page.update()
            return

        try:
            user_info = getattr(self.page.auth, "user", None)
            if not user_info:
                self.auth_feedback_text.value = "Conta Google não confirmada pela API."
                self.auth_feedback_text.color = C_DANGER
                self.page.update()
                return

            g_email = user_info.get("email") if isinstance(user_info, dict) else getattr(user_info, "email", None)
            g_name = user_info.get("name") if isinstance(user_info, dict) else getattr(user_info, "name", None)
            if not g_name and g_email:
                g_name = str(g_email).split("@")[0]

            if not g_email:
                self.auth_feedback_text.value = "E-mail não retornado pela Conta Google."
                self.auth_feedback_text.color = C_DANGER
                self.page.update()
                return

            self.select_google_account(str(g_email), str(g_name))
        except Exception as exc:
            self.auth_feedback_text.value = f"Erro ao processar conta Google: {exc}"
            self.auth_feedback_text.color = C_DANGER
            self.page.update()

    def switch_auth_mode(self, mode: str) -> None:
        self.auth_mode = mode
        self.auth_feedback_text.value = ""
        self.auth_otp_feedback.value = ""

        self.btn_mode_otp.bgcolor = C_ACCENT if mode == "otp" else C_BG
        self.btn_mode_otp.color = "#18181B" if mode == "otp" else C_MUTED
        self.btn_mode_password.bgcolor = C_ACCENT if mode in ("login", "register") else C_BG
        self.btn_mode_password.color = "#18181B" if mode in ("login", "register") else C_MUTED

        if mode == "otp":
            self.auth_title.value = "Entrar ou Criar Conta"
            self.auth_subtitle.value = "Digite seu e-mail para receber um código temporário de 6 dígitos."
            self.auth_name_field.visible = True
            self.auth_name_field.label = "Seu Nome de Usuário (opcional)"
            self.auth_email_field.visible = True
            self.auth_password_field.visible = False
            self.password_submode_row.visible = False
            self.btn_request_otp.visible = True
            self.btn_submit_auth.visible = False
            self.email_auth_view.visible = True
            self.otp_verify_view.visible = False
            self.btn_official_google.visible = True
            self.divider_or_email.visible = True
        elif mode == "login":
            self.auth_title.value = "Entrar com E-mail e Senha"
            self.auth_subtitle.value = "Informe seu e-mail e sua senha cadastrada."
            self.auth_name_field.visible = False
            self.auth_email_field.visible = True
            self.auth_password_field.visible = True
            self.password_submode_row.visible = True
            self.btn_mode_login.bgcolor = C_ACCENT
            self.btn_mode_login.color = "#18181B"
            self.btn_mode_register.bgcolor = C_BG
            self.btn_mode_register.color = C_MUTED
            self.btn_request_otp.visible = False
            self.btn_submit_auth.visible = True
            self.btn_submit_auth.content = "Entrar no App"
            self.btn_submit_auth.icon = ft.Icons.LOGIN_ROUNDED
            self.email_auth_view.visible = True
            self.otp_verify_view.visible = False
            self.btn_official_google.visible = True
            self.divider_or_email.visible = True
        elif mode == "register":
            self.auth_title.value = "Criar Conta com Senha"
            self.auth_subtitle.value = "Escolha seu nome de usuário e defina sua senha."
            self.auth_name_field.visible = True
            self.auth_name_field.label = "Escolha seu Nome de Usuário *"
            self.auth_email_field.visible = True
            self.auth_password_field.visible = True
            self.password_submode_row.visible = True
            self.btn_mode_login.bgcolor = C_BG
            self.btn_mode_login.color = C_MUTED
            self.btn_mode_register.bgcolor = C_ACCENT
            self.btn_mode_register.color = "#18181B"
            self.btn_request_otp.visible = False
            self.btn_submit_auth.visible = True
            self.btn_submit_auth.content = "Criar Minha Conta"
            self.btn_submit_auth.icon = ft.Icons.VERIFIED_USER_ROUNDED
            self.email_auth_view.visible = True
            self.otp_verify_view.visible = False
            self.btn_official_google.visible = True
            self.divider_or_email.visible = True
        elif mode == "otp_verify":
            self.email_auth_view.visible = False
            self.otp_verify_view.visible = True
            self.btn_official_google.visible = False
            self.divider_or_email.visible = False

        self.page.update()

    def handle_auth_submit(self, e: ft.ControlEvent) -> None:
        if self.btn_submit_auth.disabled:
            return
        email = (self.auth_email_field.value or "").strip().lower()
        pwd = (self.auth_password_field.value or "").strip()
        chosen_name = (self.auth_name_field.value or "").strip()

        if not email:
            self.auth_feedback_text.color = C_DANGER
            self.auth_feedback_text.value = "Por favor, informe seu e-mail."
            self.page.update()
            return

        self.btn_submit_auth.disabled = True
        self.auth_feedback_text.color = C_ACCENT
        self.auth_feedback_text.value = "Autenticando com criptografia segura..."
        self.page.update()

        try:
            if self.auth_mode == "register":
                if not chosen_name or len(chosen_name) < 2:
                    raise ValueError("Escolha seu Nome de Usuário (mínimo 2 letras) para criar a conta.")
                if not pwd:
                    raise ValueError("Crie uma senha de pelo menos 6 caracteres.")
                res = self.api_client.registrar_usuario(email=email, senha=pwd, nome=chosen_name)
            else:
                if not pwd:
                    raise ValueError("Informe sua senha para entrar.")
                res = self.api_client.login_usuario(email=email, senha=pwd)

            token = res.get("token")
            user_data = res.get("user", {})
            final_name = chosen_name or user_data.get("nome") or email.split("@")[0]

            self.vault.save_auth_session(
                user_id=user_data.get("id", ""),
                email=user_data.get("email", email),
                token=token,
                name=final_name,
            )
            self.api_client.set_auth_token(token)
            self.auth_feedback_text.value = ""
            if self.on_auth_success:
                self.on_auth_success(final_name, token)
        except Exception as exc:
            self.auth_feedback_text.color = C_DANGER
            self.auth_feedback_text.value = str(exc)
        finally:
            self.btn_submit_auth.disabled = False
            self.page.update()

    def start_cooldown_countdown(self, seconds: int = 60) -> None:
        def _timer():
            self.btn_resend_otp.disabled = True
            for rem in range(seconds, 0, -1):
                self.btn_resend_otp.content = f"Reenviar ({rem}s)"
                try:
                    self.page.update()
                except Exception:
                    return
                time.sleep(1.0)
            self.btn_resend_otp.disabled = False
            self.btn_resend_otp.content = "Reenviar Código"
            try:
                self.page.update()
            except Exception:
                pass

        threading.Thread(target=_timer, daemon=True).start()

    def handle_request_otp(self, e: ft.ControlEvent | None = None) -> None:
        if self.btn_request_otp.disabled:
            return
        email = (self.auth_email_field.value or "").strip().lower()
        nome = (self.auth_name_field.value or "").strip()

        if not email:
            self.auth_feedback_text.color = C_DANGER
            self.auth_feedback_text.value = "Por favor, digite seu endereço de e-mail."
            self.page.update()
            return

        self.btn_request_otp.disabled = True
        self.auth_feedback_text.color = C_ACCENT
        self.auth_feedback_text.value = "Gerando código seguro e despachando e-mail..."
        self.page.update()

        try:
            res = self.api_client.solicitar_codigo_otp(email=email, nome=nome)
            self.current_otp_email = email
            self.pending_otp_name = nome
            cooldown = int(res.get("cooldown_seconds", 60))
            self.otp_dest_info_text.value = f"Enviamos um código de 6 dígitos para:\n{email}\nVálido por 10 minutos."
            self.auth_otp_field.value = ""
            self.auth_otp_feedback.value = ""
            self.switch_auth_mode("otp_verify")
            self.start_cooldown_countdown(cooldown)
        except Exception as exc:
            self.auth_feedback_text.color = C_DANGER
            self.auth_feedback_text.value = str(exc)
        finally:
            self.btn_request_otp.disabled = False
            self.page.update()

    def handle_verify_otp(self, e: ft.ControlEvent | None = None) -> None:
        if self.btn_verify_otp.disabled:
            return
        code = (self.auth_otp_field.value or "").strip()

        if not code or len(code) != 6 or not code.isdigit():
            self.auth_otp_feedback.color = C_DANGER
            self.auth_otp_feedback.value = "Digite os 6 dígitos numéricos do código recebido."
            self.page.update()
            return

        self.btn_verify_otp.disabled = True
        self.auth_otp_feedback.color = C_ACCENT
        self.auth_otp_feedback.value = "Validando código com criptografia..."
        self.page.update()

        try:
            res = self.api_client.verificar_codigo_otp(
                email=self.current_otp_email,
                codigo=code,
                nome=self.pending_otp_name,
            )
            token = res.get("token")
            user_data = res.get("user", {})
            final_name = user_data.get("nome") or self.pending_otp_name or self.current_otp_email.split("@")[0]

            self.vault.save_auth_session(
                user_id=user_data.get("id", ""),
                email=user_data.get("email", self.current_otp_email),
                token=token,
                name=final_name,
            )
            self.api_client.set_auth_token(token)
            self.auth_otp_feedback.value = ""
            if self.on_auth_success:
                self.on_auth_success(final_name, token)
        except Exception as exc:
            self.auth_otp_feedback.color = C_DANGER
            self.auth_otp_feedback.value = str(exc)
        finally:
            self.btn_verify_otp.disabled = False
            self.page.update()

    def open_logout_modal(self, e: ft.ControlEvent | None = None) -> None:
        self.logout_confirm_overlay.visible = True
        self.page.update()

    def close_logout_modal(self, e: ft.ControlEvent | None = None) -> None:
        self.logout_confirm_overlay.visible = False
        self.page.update()

    def confirm_logout(self, e: ft.ControlEvent | None = None) -> None:
        self.logout_confirm_overlay.visible = False
        self.handle_logout(e)

    def handle_logout(self, e: ft.ControlEvent | None = None) -> None:
        self.vault.clear_auth_session()
        self.api_client.set_auth_token(None)
        self.auth_email_field.value = ""
        self.auth_password_field.value = ""
        self.auth_otp_field.value = ""
        self.auth_feedback_text.value = ""
        self.auth_otp_feedback.value = ""
        self.switch_auth_mode("otp")
        if self.on_logout_callback:
            self.on_logout_callback()

    def open_edit_username_modal(self, e: ft.ControlEvent | None = None) -> None:
        current_name = self.get_logged_user_display_name() or ""
        self.edit_username_input.value = current_name
        self.edit_username_feedback.value = ""
        self.edit_username_overlay.visible = True
        self.page.update()

    def close_edit_username_modal(self, e: ft.ControlEvent | None = None) -> None:
        self.edit_username_overlay.visible = False
        self.page.update()

    def confirm_save_new_username(self, e: ft.ControlEvent) -> None:
        new_name = (self.edit_username_input.value or "").strip()
        if not new_name or len(new_name) < 2:
            self.edit_username_feedback.color = C_DANGER
            self.edit_username_feedback.value = "⚠️ O nome deve ter pelo menos 2 caracteres."
            self.page.update()
            return

        sess = self.vault.get_auth_session()
        if not sess or not sess.get("user_id"):
            self.edit_username_feedback.color = C_DANGER
            self.edit_username_feedback.value = "⚠️ Sessão não encontrada. Faça login novamente."
            self.page.update()
            return

        user_id = str(sess["user_id"])
        self.edit_username_feedback.color = C_ACCENT
        self.edit_username_feedback.value = "Salvando novo nome de usuário..."
        self.page.update()

        try:
            res = self.api_client.atualizar_nome_usuario(user_id=user_id, novo_nome=new_name)
            new_token = res.get("token")
            self.vault.update_auth_user_name(novo_nome=new_name, novo_token=new_token)
            self.header_greeting_text.value = f"Olá, {new_name}"
            self.edit_username_overlay.visible = False
            self.page.update()
            if self.on_username_changed:
                self.on_username_changed(new_name)
        except Exception as exc:
            self.edit_username_feedback.color = C_DANGER
            self.edit_username_feedback.value = f"⚠️ {exc}"
            self.page.update()
