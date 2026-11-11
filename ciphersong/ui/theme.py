"""
Definições de Cores, Temas, Tokens Visuais e Helpers de UI/UX do CipherSong (Flet 1.0).
"""

from __future__ import annotations

from collections.abc import Callable
import logging
from typing import Any

import flet as ft

logger = logging.getLogger(__name__)

# Paleta de Cores Oficial do Sistema (Design System Tokens)
C_BG = "#18181B"             # Fundo Principal (Grafite neutro fosco)
C_CARD_BG = "#18181B"        # Fundo de Cartões Internos / Modais
C_INPUT_BG = "#09090B"       # Fundo Profundo de Inputs / Caixas de Destaque
C_SURFACE = "#27272A"        # Cartões e Superfícies Elevadas (Cinza médio neutro)
C_ELEVATED_BG = "#27272A"    # Superfície Elevada / Hover
C_SKELETON_DIM = "#2A2A30"   # Cinza escuro para placeholders / chips
C_TEXT = "#F4F4F5"           # Texto Principal e Ícones (Branco suave)
C_WHITE = "#FFFFFF"          # Branco puro para contraste máximo em botões primários
C_MUTED = "#A1A1AA"          # Texto Secundário (Zinc 400)
C_SUBTLE_TEXT = "#71717A"    # Texto Terciário / Hints (Zinc 500)
C_BORDER = "#3F3F46"         # Linhas e Bordas (Zinc 700)
C_BORDER_FOCUS = "#3F3F46"   # Borda de Destaque / Divisores
C_BORDER_SUBTLE = "#333338"  # Borda Suave de Cartões
C_ACCENT = "#06B6D4"         # Ciano Luminoso (Marca / Ação Primária)
C_IN_TUNE = "#22C55E"        # Sucesso / Tom Afinado (Verde neutro limpo)
C_OFF_TUNE = "#F59E0B"       # Alerta / Desvio de Frequência (Âmbar/Laranja)
C_WARNING = "#F59E0B"        # Alias semântico para Alerta / Atenção
C_DANGER = "#EF4444"         # Parar / Remover / Erro (Vermelho vivo)
C_WHATSAPP = "#25D366"       # Verde Oficial WhatsApp para compartilhamento
C_GOOGLE = "#4285F4"         # Azul Oficial Google OAuth

# Paleta da Barra de Navegação Flutuante
C_NAV_BG = "#191B21"         # Fundo da pílula (dock) com alto contraste escuro
C_NAV_BORDER = "#2B2E38"     # Borda suave
C_NAV_INACTIVE = "#8E929C"   # Cinza inativo para ícones e textos

# Constantes de Layout Responsivo
MAX_CONTENT_WIDTH = 440
MODAL_MAX_WIDTH = 400

ALL_MUSICAL_KEYS: tuple[str, ...] = (
    "C (Dó)", "C# (Dó#)", "D (Ré)", "D# (Ré#)", "E (Mi)", "F (Fá)",
    "F# (Fá#)", "G (Sol)", "G# (Sol#)", "A (Lá)", "A# (Lá#)", "B (Si)",
    "Cm (Dóm)", "C#m (Dó#m)", "Dm (Rém)", "D#m (Ré#m)", "Em (Mim)", "Fm (Fám)",
    "F#m (Fá#m)", "Gm (Solm)", "G#m (Sol#m)", "Am (Lám)", "A#m (Lá#m)", "Bm (Sim)",
)


def create_skeleton_loader(count: int = 3) -> ft.Column:
    """Renderiza cartões esqueleto durante transições de abas até o conteúdo carregar."""
    cards = []
    for _ in range(count):
        cards.append(
            ft.Container(
                bgcolor=C_SURFACE,
                border=ft.Border.all(1, C_BORDER),
                border_radius=12,
                padding=14,
                content=ft.Column(
                    spacing=8,
                    controls=[
                        ft.Row(
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            controls=[
                                ft.Container(height=16, width=150, bgcolor=C_BORDER, border_radius=4),
                                ft.Container(height=16, width=44, bgcolor=C_BORDER_SUBTLE, border_radius=4),
                            ],
                        ),
                        ft.Container(height=12, width=110, bgcolor=C_BORDER_SUBTLE, border_radius=4),
                        ft.Row(
                            spacing=6,
                            controls=[
                                ft.Container(height=18, width=54, bgcolor=C_SKELETON_DIM, border_radius=6),
                                ft.Container(height=18, width=54, bgcolor=C_SKELETON_DIM, border_radius=6),
                            ],
                        ),
                    ],
                ),
            )
        )
    return ft.Column(spacing=8, controls=cards)


def open_modal_overlay(page: ft.Page, overlay: ft.Control) -> None:
    """Adiciona um modal ao overlay da página com segurança e atualiza a tela."""
    try:
        if overlay not in page.overlay:
            page.overlay.append(overlay)
        overlay.visible = True
        page.update()
    except Exception as exc:
        logger.debug("Erro ao abrir modal overlay: %s", exc)


def close_modal_overlay(page: ft.Page, overlay: ft.Control) -> None:
    """Fecha e remove um modal do overlay da página com segurança."""
    try:
        overlay.visible = False
        if overlay in page.overlay:
            page.overlay.remove(overlay)
        page.update()
    except Exception as exc:
        logger.debug("Erro ao fechar modal overlay: %s", exc)


def set_button_loading(
    btn: Any,
    is_loading: bool,
    loading_text: str = "Processando...",
    default_text: str | None = None,
    page: ft.Page | None = None,
) -> None:
    """
    Ativa ou desativa o estado de carregamento de um botão para prevenir cliques duplos
    e fornecer feedback visual claro ao usuário durante operações assíncronas.
    """
    try:
        btn.disabled = is_loading
        target_label = loading_text if is_loading else default_text
        if target_label is not None:
            if hasattr(btn, "text") and isinstance(getattr(btn, "text", None), str):
                btn.text = target_label
            elif hasattr(btn, "content"):
                content = getattr(btn, "content", None)
                if isinstance(content, ft.Text):
                    content.value = target_label
                elif isinstance(content, str):
                    btn.content = ft.Text(target_label, weight=ft.FontWeight.BOLD)
        if page is not None:
            page.update()
    except Exception as exc:
        logger.debug("Erro ao atualizar estado de loading do botão: %s", exc)


def build_confirm_delete_overlay(
    page: ft.Page,
    title: str,
    item_label: str,
    description: str,
    on_confirm: Callable[[Any], None],
    confirm_text: str = "Sim, Excluir",
) -> ft.Container:
    """Cria um modal padronizado de confirmação de exclusão no Design System do CipherSong."""
    overlay_ref: list[ft.Container] = []

    def _handle_cancel(_e: Any = None) -> None:
        if overlay_ref:
            close_modal_overlay(page, overlay_ref[0])

    btn_confirm = ft.Button(
        content=ft.Text(confirm_text, color=C_WHITE, weight=ft.FontWeight.BOLD),
        bgcolor=C_DANGER,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=10),
            padding=ft.Padding.symmetric(horizontal=16, vertical=10),
        ),
        on_click=on_confirm,
    )

    modal_card = ft.Container(
        width=360,
        padding=22,
        bgcolor=C_CARD_BG,
        border=ft.Border.all(1, C_BORDER),
        border_radius=16,
        on_click=lambda e: None,
        content=ft.Column(
            tight=True,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            controls=[
                ft.Container(
                    width=52,
                    height=52,
                    border_radius=26,
                    bgcolor="#3F1D1D",
                    alignment=ft.Alignment(0, 0),
                    content=ft.Icon(ft.Icons.DELETE_FOREVER_ROUNDED, color=C_DANGER, size=28),
                ),
                ft.Text(title, size=18, weight=ft.FontWeight.BOLD, color=C_TEXT, text_align=ft.TextAlign.CENTER),
                ft.Text(
                    f'"{item_label}"',
                    size=14,
                    weight=ft.FontWeight.W_600,
                    color=C_ACCENT,
                    text_align=ft.TextAlign.CENTER,
                ),
                ft.Text(description, size=12, color=C_MUTED, text_align=ft.TextAlign.CENTER),
                ft.Row(
                    alignment=ft.MainAxisAlignment.END,
                    spacing=10,
                    controls=[
                        ft.TextButton(
                            content=ft.Text("Cancelar", color=C_MUTED),
                            on_click=_handle_cancel,
                        ),
                        btn_confirm,
                    ],
                ),
            ],
        ),
    )

    overlay = ft.Container(
        expand=True,
        bgcolor="#B3000000",
        alignment=ft.Alignment(0, 0),
        padding=16,
        on_click=_handle_cancel,
        content=modal_card,
    )
    overlay_ref.append(overlay)
    return overlay

