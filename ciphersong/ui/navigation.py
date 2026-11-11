"""
Barra de Navegação Flutuante Inferior (Bottom Nav Dock) com badges e indicadores ativos.
"""

from __future__ import annotations

from collections.abc import Callable

import flet as ft

from ciphersong.ui.theme import (
    C_ACCENT,
    C_NAV_BG,
    C_NAV_BORDER,
    C_NAV_INACTIVE,
)


class BottomNavBarManager:
    """Gerencia a Bottom Navigation Bar com 4 abas, badges dinâmicos e estilo flutuante."""

    def __init__(
        self,
        page: ft.Page,
        on_tab_change: Callable[[str], None],
    ) -> None:
        self.page = page
        self.on_tab_change = on_tab_change
        self.current_tab = "songs"
        self.unseen_weekly_count = 0
        self.unseen_to_rehearse_count = 0

        # 1. Músicas
        self.nav_icon_songs = ft.Icon(ft.Icons.MUSIC_NOTE_ROUNDED, size=22, color=C_ACCENT)
        self.nav_label_songs = ft.Text("Músicas", size=10, weight=ft.FontWeight.BOLD, color=C_ACCENT)
        self.nav_ind_songs = ft.Container(width=22, height=3, border_radius=2, bgcolor=C_ACCENT, margin=ft.Margin.only(top=1))

        # 2. Semana
        self.nav_icon_weekly = ft.Icon(ft.Icons.CALENDAR_MONTH_ROUNDED, size=22, color=C_NAV_INACTIVE)
        self.nav_badge_weekly_txt = ft.Text("", size=8, weight=ft.FontWeight.BOLD, color="#18181B")
        self.nav_badge_weekly = ft.Container(
            content=self.nav_badge_weekly_txt,
            bgcolor=C_ACCENT,
            border_radius=8,
            padding=ft.Padding.symmetric(horizontal=3, vertical=0),
            shadow=ft.BoxShadow(spread_radius=1, blur_radius=6, color=C_ACCENT),
            visible=False,
            right=0,
            top=0,
        )
        self.nav_icon_weekly_stack = ft.Stack(
            controls=[
                ft.Container(content=self.nav_icon_weekly, padding=ft.Padding.only(top=2, right=2, left=2)),
                self.nav_badge_weekly,
            ],
            width=32,
            height=26,
            alignment=ft.Alignment.CENTER,
        )
        self.nav_label_weekly = ft.Text("Semana", size=10, weight=ft.FontWeight.W_500, color=C_NAV_INACTIVE)
        self.nav_ind_weekly = ft.Container(width=22, height=3, border_radius=2, bgcolor=ft.Colors.TRANSPARENT, margin=ft.Margin.only(top=1))

        # 3. Ensaio (A Ensaiar)
        self.nav_icon_rehearse = ft.Icon(ft.CupertinoIcons.GUITARS, size=22, color=C_NAV_INACTIVE)
        self.nav_badge_rehearse_txt = ft.Text("", size=8, weight=ft.FontWeight.BOLD, color="#18181B")
        self.nav_badge_rehearse = ft.Container(
            content=self.nav_badge_rehearse_txt,
            bgcolor=C_ACCENT,
            border_radius=8,
            padding=ft.Padding.symmetric(horizontal=3, vertical=0),
            shadow=ft.BoxShadow(spread_radius=1, blur_radius=6, color=C_ACCENT),
            visible=False,
            right=0,
            top=0,
        )
        self.nav_icon_rehearse_stack = ft.Stack(
            controls=[
                ft.Container(content=self.nav_icon_rehearse, padding=ft.Padding.only(top=2, right=2, left=2)),
                self.nav_badge_rehearse,
            ],
            width=32,
            height=26,
            alignment=ft.Alignment.CENTER,
        )
        self.nav_label_rehearse = ft.Text("Ensaio", size=10, weight=ft.FontWeight.W_500, color=C_NAV_INACTIVE)
        self.nav_ind_rehearse = ft.Container(width=22, height=3, border_radius=2, bgcolor=ft.Colors.TRANSPARENT, margin=ft.Margin.only(top=1))

        # 4. Equipe
        self.nav_icon_team = ft.Icon(ft.Icons.PEOPLE_ROUNDED, size=22, color=C_NAV_INACTIVE)
        self.nav_label_team = ft.Text("Equipe", size=10, weight=ft.FontWeight.W_500, color=C_NAV_INACTIVE)
        self.nav_ind_team = ft.Container(width=22, height=3, border_radius=2, bgcolor=ft.Colors.TRANSPARENT, margin=ft.Margin.only(top=1))

        self.tab_item_songs = ft.Container(
            content=ft.Column(
                tight=True,
                spacing=1,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Container(content=self.nav_icon_songs, height=26, alignment=ft.Alignment.CENTER),
                    self.nav_label_songs,
                    self.nav_ind_songs,
                ],
            ),
            expand=True,
            alignment=ft.Alignment.CENTER,
            padding=ft.Padding.symmetric(vertical=2),
            ink=True,
            border_radius=16,
            on_click=lambda _: self.set_current_tab("songs"),
        )

        self.tab_item_weekly = ft.Container(
            content=ft.Column(
                tight=True,
                spacing=1,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    self.nav_icon_weekly_stack,
                    self.nav_label_weekly,
                    self.nav_ind_weekly,
                ],
            ),
            expand=True,
            alignment=ft.Alignment.CENTER,
            padding=ft.Padding.symmetric(vertical=2),
            ink=True,
            border_radius=16,
            on_click=lambda _: self.set_current_tab("weekly"),
        )

        self.tab_item_to_rehearse = ft.Container(
            content=ft.Column(
                tight=True,
                spacing=1,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    self.nav_icon_rehearse_stack,
                    self.nav_label_rehearse,
                    self.nav_ind_rehearse,
                ],
            ),
            expand=True,
            alignment=ft.Alignment.CENTER,
            padding=ft.Padding.symmetric(vertical=2),
            ink=True,
            border_radius=16,
            on_click=lambda _: self.set_current_tab("to_rehearse"),
        )

        self.tab_item_team = ft.Container(
            content=ft.Column(
                tight=True,
                spacing=1,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Container(content=self.nav_icon_team, height=26, alignment=ft.Alignment.CENTER),
                    self.nav_label_team,
                    self.nav_ind_team,
                ],
            ),
            expand=True,
            alignment=ft.Alignment.CENTER,
            padding=ft.Padding.symmetric(vertical=2),
            ink=True,
            border_radius=16,
            on_click=lambda _: self.set_current_tab("team"),
        )

        self.dock = ft.Container(
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_EVENLY,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    self.tab_item_songs,
                    self.tab_item_weekly,
                    self.tab_item_to_rehearse,
                    self.tab_item_team,
                ],
            ),
            bgcolor=C_NAV_BG,
            border=ft.Border.all(1.2, C_NAV_BORDER),
            border_radius=24,
            padding=ft.Padding.symmetric(horizontal=4, vertical=4),
            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=18,
                color=ft.Colors.with_opacity(0.65, "#000000"),
                offset=ft.Offset(0, 4),
            ),
        )

        self.bottom_app_bar = ft.BottomAppBar(
            content=self.dock,
            bgcolor=ft.Colors.TRANSPARENT,
            elevation=0,
            height=74,
            padding=ft.Padding.only(left=12, right=12, bottom=8, top=0),
        )

    def set_current_tab(self, tab: str) -> None:
        self.current_tab = tab
        if tab == "weekly":
            self.unseen_weekly_count = 0
        elif tab == "to_rehearse":
            self.unseen_to_rehearse_count = 0
        self.update_badges_and_glow()
        self.on_tab_change(tab)

    def update_badges(self, weekly: int | None = None, to_rehearse: int | None = None) -> None:
        if weekly is not None:
            self.unseen_weekly_count = weekly
        if to_rehearse is not None:
            self.unseen_to_rehearse_count = to_rehearse
        self.update_badges_and_glow()

    def update_badges_and_glow(self) -> None:
        """Atualiza a Bottom Nav Bar com o indicador ciano ativo, cores e badges de novas músicas."""
        # 1. Músicas
        is_songs = (self.current_tab == "songs")
        self.nav_icon_songs.color = C_ACCENT if is_songs else C_NAV_INACTIVE
        self.nav_label_songs.color = C_ACCENT if is_songs else C_NAV_INACTIVE
        self.nav_label_songs.weight = ft.FontWeight.BOLD if is_songs else ft.FontWeight.W_500
        self.nav_ind_songs.bgcolor = C_ACCENT if is_songs else ft.Colors.TRANSPARENT

        # 3. Semana
        is_wk = (self.current_tab == "weekly")
        has_wk_unseen = (self.unseen_weekly_count > 0)
        self.nav_badge_weekly.visible = has_wk_unseen
        self.nav_badge_weekly_txt.value = f"{self.unseen_weekly_count}" if has_wk_unseen else ""
        if is_wk:
            self.nav_icon_weekly.color = C_ACCENT
            self.nav_label_weekly.color = C_ACCENT
            self.nav_label_weekly.weight = ft.FontWeight.BOLD
            self.nav_ind_weekly.bgcolor = C_ACCENT
        elif has_wk_unseen:
            self.nav_icon_weekly.color = C_ACCENT
            self.nav_label_weekly.color = C_ACCENT
            self.nav_label_weekly.weight = ft.FontWeight.BOLD
            self.nav_ind_weekly.bgcolor = ft.Colors.TRANSPARENT
        else:
            self.nav_icon_weekly.color = C_NAV_INACTIVE
            self.nav_label_weekly.color = C_NAV_INACTIVE
            self.nav_label_weekly.weight = ft.FontWeight.W_500
            self.nav_ind_weekly.bgcolor = ft.Colors.TRANSPARENT

        # 4. Ensaio
        is_tr = (self.current_tab == "to_rehearse")
        has_tr_unseen = (self.unseen_to_rehearse_count > 0)
        self.nav_badge_rehearse.visible = has_tr_unseen
        self.nav_badge_rehearse_txt.value = f"{self.unseen_to_rehearse_count}" if has_tr_unseen else ""
        if is_tr:
            self.nav_icon_rehearse.color = C_ACCENT
            self.nav_label_rehearse.color = C_ACCENT
            self.nav_label_rehearse.weight = ft.FontWeight.BOLD
            self.nav_ind_rehearse.bgcolor = C_ACCENT
        elif has_tr_unseen:
            self.nav_icon_rehearse.color = C_ACCENT
            self.nav_label_rehearse.color = C_ACCENT
            self.nav_label_rehearse.weight = ft.FontWeight.BOLD
            self.nav_ind_rehearse.bgcolor = ft.Colors.TRANSPARENT
        else:
            self.nav_icon_rehearse.color = C_NAV_INACTIVE
            self.nav_label_rehearse.color = C_NAV_INACTIVE
            self.nav_label_rehearse.weight = ft.FontWeight.W_500
            self.nav_ind_rehearse.bgcolor = ft.Colors.TRANSPARENT

        # 5. Equipe
        is_team = (self.current_tab == "team")
        self.nav_icon_team.color = C_ACCENT if is_team else C_NAV_INACTIVE
        self.nav_label_team.color = C_ACCENT if is_team else C_NAV_INACTIVE
        self.nav_label_team.weight = ft.FontWeight.BOLD if is_team else ft.FontWeight.W_500
        self.nav_ind_team.bgcolor = C_ACCENT if is_team else ft.Colors.TRANSPARENT

        try:
            self.page.update()
        except Exception:
            pass
