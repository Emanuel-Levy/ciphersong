"""
Orquestrador Principal da Interface Flet 1.0 (CipherSong).
Monta as visualizações modulares (Músicas, Semana, A Ensaiar, Equipe e Autenticação),
gerencia ciclo de vida, navegação inferior e notificações em segundo plano.
"""

from __future__ import annotations

import logging
import threading
import time

import flet as ft
from ciphersong.security.local_vault import EncryptedSessionVault
from ciphersong.services.microphone_stream import LiveMicrophoneService

from ciphersong.services.api_client import SongsApiClient
from ciphersong.ui.navigation import BottomNavBarManager
from ciphersong.ui.notifications import InAppNotificationManager
from ciphersong.ui.theme import (
    C_BG,
    create_skeleton_loader,
)
from ciphersong.ui.views.auth_view import AuthView
from ciphersong.ui.views.repertoire_view import RepertoireView
from ciphersong.ui.views.team_view import TeamView
from ciphersong.ui.views.to_rehearse_view import ToRehearseView
from ciphersong.ui.views.weekly_view import WeeklyView

logger = logging.getLogger("ciphersong.ui.app")


def build_ciphersong_app(page: ft.Page) -> None:
    """Constrói o aplicativo CipherSong com arquitetura desacoplada e visualizações modulares."""
    page.title = "CipherSong — Gestão de Repertório & Equipes"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = C_BG
    page.padding = ft.Padding.only(left=12, top=36, right=12, bottom=20)
    page.scroll = ft.ScrollMode.AUTO

    vault = EncryptedSessionVault()
    mic_service = LiveMicrophoneService()
    api_client = SongsApiClient()

    # Serviços Nativos: UrlLauncher, HapticFeedback, Wakelock
    app_url_launcher = ft.UrlLauncher()
    haptic = ft.HapticFeedback()
    wakelock = ft.Wakelock()

    try:
        page.services.extend([app_url_launcher, haptic, wakelock])
    except Exception as svc_err:
        logger.warning("Services Init Warning: %s", svc_err)

    # Gerenciador de Notificações In-App e SO
    notification_manager = InAppNotificationManager(page=page, haptic=haptic)
    page.overlay.append(notification_manager.overlay)
    show_notification = notification_manager.show

    # Gerenciador da Barra de Navegação Flutuante Inferior (Bottom Nav Dock)
    _tab_change_callback = None

    def _on_nav_tab_change(tab: str) -> None:
        if _tab_change_callback is not None:
            _tab_change_callback(tab)

    nav_manager = BottomNavBarManager(page=page, on_tab_change=_on_nav_tab_change)
    bottom_nav_bar: ft.BottomAppBar | None = nav_manager.bottom_app_bar

    # Restaura sessão autenticada persistida no cofre criptografado (AES-256-GCM)
    auth_session = vault.get_auth_session()
    if auth_session and auth_session.get("token"):
        api_client.set_auth_token(auth_session["token"])
        u_key = auth_session.get("user_id") or auth_session.get("email")
        if u_key:
            vault.switch_user(u_key)

    # Restaura equipe ativa persistida no cofre criptografado seguro
    saved_active_team = vault.get_active_team()
    if saved_active_team and (saved_active_team.get("_id") or saved_active_team.get("id")):
        api_client.set_active_equipe_id(str(saved_active_team.get("_id") or saved_active_team.get("id")))

    # Forward declarations para callbacks cruzados
    repertoire_view_ctrl: RepertoireView | None = None
    weekly_view_ctrl: WeeklyView | None = None
    to_rehearse_view_ctrl: ToRehearseView | None = None
    team_view_ctrl: TeamView | None = None
    auth_view_ctrl: AuthView | None = None

    # Contadores e controle de polling em segundo plano
    last_known_weekly_count: int | None = None
    last_known_tr_count: int | None = None
    poller_started = False
    stop_polling_event = threading.Event()

    def _get_logged_user_name() -> str | None:
        if auth_view_ctrl:
            return auth_view_ctrl.get_logged_user_display_name()
        sess = vault.get_auth_session()
        if sess and sess.get("token"):
            return sess.get("name") or sess.get("nome") or (sess.get("email") or "").split("@")[0]
        return None

    def _on_schedule_song(song_item: dict) -> None:
        if weekly_view_ctrl:
            weekly_view_ctrl.open_add_weekly_modal(preselected_song=song_item)

    def _on_song_graduated() -> None:
        if repertoire_view_ctrl:
            repertoire_view_ctrl.refresh_songs_list()

    def _on_team_changed(team_data: dict) -> None:
        nonlocal last_known_weekly_count, last_known_tr_count
        # Reseta contadores ao trocar de equipe para evitar falsos alertas de novas músicas
        last_known_weekly_count = None
        last_known_tr_count = None
        nav_manager.unseen_weekly_count = 0
        nav_manager.unseen_to_rehearse_count = 0
        nav_manager.update_badges_and_glow()
        if repertoire_view_ctrl:
            repertoire_view_ctrl.refresh_songs_list(sync_cloud=True)
        if weekly_view_ctrl:
            weekly_view_ctrl.refresh_weekly_schedule(sync_cloud=True)
        if to_rehearse_view_ctrl:
            to_rehearse_view_ctrl.refresh_to_rehearse_list(sync_cloud=True)

    def _on_auth_success(user_name: str, token: str) -> None:
        nonlocal last_known_weekly_count, last_known_tr_count
        last_known_weekly_count = None
        last_known_tr_count = None
        sess = vault.get_auth_session()
        u_key = (sess.get("user_id") or sess.get("email")) if sess else None
        if u_key:
            vault.switch_user(u_key)
        update_auth_ui()
        if team_view_ctrl:
            team_view_ctrl.refresh_user_teams()
        if repertoire_view_ctrl:
            repertoire_view_ctrl.refresh_songs_list(sync_cloud=True)
        if weekly_view_ctrl:
            weekly_view_ctrl.refresh_weekly_schedule(sync_cloud=True)
        if to_rehearse_view_ctrl:
            to_rehearse_view_ctrl.refresh_to_rehearse_list(sync_cloud=True)

    def _on_logout() -> None:
        nonlocal last_known_weekly_count, last_known_tr_count
        if mic_service.is_running:
            mic_service.stop()
        last_known_weekly_count = None
        last_known_tr_count = None
        nav_manager.unseen_weekly_count = 0
        nav_manager.unseen_to_rehearse_count = 0
        nav_manager.update_badges_and_glow()
        api_client.clear_auth_token()
        api_client.set_active_equipe_id("")
        vault.set_active_team(None)
        vault.clear_auth_session()
        vault.switch_user(None)
        update_auth_ui()
        if team_view_ctrl:
            team_view_ctrl.refresh_user_teams()
        if repertoire_view_ctrl:
            repertoire_view_ctrl.refresh_songs_list(sync_cloud=False)
        if weekly_view_ctrl:
            weekly_view_ctrl.refresh_weekly_schedule(sync_cloud=False)
        if to_rehearse_view_ctrl:
            to_rehearse_view_ctrl.refresh_to_rehearse_list(sync_cloud=False)

    def _on_username_changed(new_name: str) -> None:
        if auth_view_ctrl:
            auth_view_ctrl.header_greeting_text.value = f"Olá, {new_name}"

    is_authenticated_initial = bool(_get_logged_user_name() and api_client.auth_token)

    # 1. Instanciação dos Componentes Modulares de Visão
    repertoire_view_ctrl = RepertoireView(
        page=page,
        vault=vault,
        api_client=api_client,
        mic_service=mic_service,
        on_schedule_song=_on_schedule_song,
    )

    weekly_view_ctrl = WeeklyView(
        page=page,
        vault=vault,
        api_client=api_client,
        show_notification=show_notification,
        nav_manager=nav_manager,
        get_logged_user_name=_get_logged_user_name,
    )

    to_rehearse_view_ctrl = ToRehearseView(
        page=page,
        vault=vault,
        api_client=api_client,
        mic_service=mic_service,
        on_song_graduated=_on_song_graduated,
        get_logged_user_name=_get_logged_user_name,
    )

    team_view_ctrl = TeamView(
        page=page,
        vault=vault,
        api_client=api_client,
        show_notification=show_notification,
        on_team_changed=_on_team_changed,
    )

    auth_view_ctrl = AuthView(
        page=page,
        vault=vault,
        api_client=api_client,
        url_launcher=app_url_launcher,
        on_auth_success=_on_auth_success,
        on_logout=_on_logout,
        on_username_changed=_on_username_changed,
        is_authenticated_initial=is_authenticated_initial,
    )

    # 2. Registro de Overlays Modais no Flet (Page Overlays)
    page.overlay.extend([
        auth_view_ctrl.google_account_overlay,
        auth_view_ctrl.edit_username_overlay,
        auth_view_ctrl.logout_confirm_overlay,
        repertoire_view_ctrl.delete_confirm_overlay,
        weekly_view_ctrl.delete_weekly_confirm_overlay,
        weekly_view_ctrl.add_weekly_overlay,
        to_rehearse_view_ctrl.delete_tr_confirm_overlay,
        to_rehearse_view_ctrl.add_to_rehearse_overlay,
        to_rehearse_view_ctrl.graduate_song_overlay,
        team_view_ctrl.create_team_overlay,
        team_view_ctrl.join_team_overlay,
    ])

    # 3. Notificações e Polling em Segundo Plano
    def _check_pings_immediately():
        try:
            pings = api_client.buscar_pings_pendentes()
            for p in pings:
                remetente_n = p.get("remetente_nome") or "Músico da equipe"
                show_notification(
                    message=f"{remetente_n} está te chamando para tocar!",
                    duration_sec=10.0,
                    is_call=True,
                    vibrate=True,
                    title=f"📲 Chamada de {remetente_n}",
                )
                api_client.marcar_ping_lido(str(p.get("_id") or p.get("id")))
        except Exception as exc:
            logger.debug("Falha ao verificar pings imediatos: %s", exc)

    def _handle_app_lifecycle_change(e: ft.ControlEvent):
        state = str(getattr(e, "data", "")).lower()
        if state in ("paused", "hidden", "inactive"):
            try:
                page.run_task(wakelock.enable)
            except Exception as exc:
                logger.debug("Wakelock enable warning: %s", exc)
        elif state in ("detached", "destroyed"):
            stop_polling_event.set()
        elif state == "resumed":
            if poller_started and api_client.auth_token:
                threading.Thread(target=_check_pings_immediately, daemon=True).start()

    page.on_app_lifecycle_state_change = _handle_app_lifecycle_change

    def _start_notifications_poller():
        nonlocal poller_started, last_known_weekly_count, last_known_tr_count
        if poller_started:
            return
        poller_started = True
        stop_polling_event.clear()

        try:
            page.run_task(wakelock.enable)
        except Exception as exc:
            logger.debug("Wakelock startup warning: %s", exc)

        try:
            from ciphersong.services.system_notifications import (
                request_system_notification_permission,
            )
            threading.Thread(target=request_system_notification_permission, daemon=True).start()
        except Exception as exc:
            logger.debug("System notification permission warning: %s", exc)

        def _poll_loop():
            nonlocal last_known_weekly_count, last_known_tr_count
            last_songs_check = 0.0
            while not stop_polling_event.wait(3.5):
                if not api_client.auth_token:
                    continue

                try:
                    pings = api_client.buscar_pings_pendentes()
                    for p in pings:
                        remetente_n = p.get("remetente_nome") or "Músico da equipe"
                        show_notification(
                            message=f"{remetente_n} está te chamando para tocar!",
                            duration_sec=10.0,
                            is_call=True,
                            vibrate=True,
                            title=f"📲 Chamada de {remetente_n}",
                        )
                        api_client.marcar_ping_lido(str(p.get("_id") or p.get("id")))
                except Exception as exc:
                    logger.debug("Falha no polling de pings: %s", exc)

                now = time.time()
                if now - last_songs_check >= 12.0:
                    last_songs_check = now
                    try:
                        active_eq = api_client.active_equipe_id
                        w_items, _ = api_client.listar_repertorio_semana(equipe_id=active_eq)
                        if w_items is not None:
                            curr_w = len(w_items)
                            if last_known_weekly_count is not None and curr_w > last_known_weekly_count:
                                diff = curr_w - last_known_weekly_count
                                nav_manager.unseen_weekly_count += diff
                                show_notification(
                                    message=f"+{diff} {'música adicionada' if diff == 1 else 'músicas adicionadas'} no Repertório da Semana!",
                                    vibrate=True,
                                    title="📅 Repertório da Semana",
                                )
                                nav_manager.update_badges_and_glow()
                            last_known_weekly_count = curr_w

                        tr_items, _ = api_client.listar_a_ensaiar(equipe_id=active_eq)
                        if tr_items is not None:
                            curr_tr = len(tr_items)
                            if last_known_tr_count is not None and curr_tr > last_known_tr_count:
                                diff_tr = curr_tr - last_known_tr_count
                                nav_manager.unseen_to_rehearse_count += diff_tr
                                show_notification(
                                    message=f"+{diff_tr} {'música sugerida' if diff_tr == 1 else 'músicas sugeridas'} em A Ensaiar!",
                                    vibrate=True,
                                    title="⏳ Músicas para Ensaio",
                                )
                                nav_manager.update_badges_and_glow()
                            last_known_tr_count = curr_tr
                    except Exception as exc:
                        logger.debug("Falha no polling de repertório/ensaio: %s", exc)

        threading.Thread(target=_poll_loop, daemon=True).start()

    # 4. Transição de Abas
    def _handle_tab_change(tab: str) -> None:
        if tab == "songs":
            repertoire_view_ctrl.view.visible = True
            weekly_view_ctrl.view.visible = False
            to_rehearse_view_ctrl.view.visible = False
            team_view_ctrl.view.visible = False
            page.floating_action_button = repertoire_view_ctrl.fab_add_song
            repertoire_view_ctrl.songs_list_column.controls.clear()
            repertoire_view_ctrl.songs_list_column.controls.append(create_skeleton_loader(count=3))
            page.update()
            repertoire_view_ctrl.refresh_songs_list()
        elif tab == "weekly":
            repertoire_view_ctrl.view.visible = False
            weekly_view_ctrl.view.visible = True
            to_rehearse_view_ctrl.view.visible = False
            team_view_ctrl.view.visible = False
            page.floating_action_button = weekly_view_ctrl.fab_add_weekly_song
            weekly_view_ctrl.weekly_songs_column.controls.clear()
            weekly_view_ctrl.weekly_songs_column.controls.append(create_skeleton_loader(count=3))
            weekly_view_ctrl.render_subtabs()
            page.update()
            weekly_view_ctrl.refresh_weekly_schedule()
        elif tab == "to_rehearse":
            repertoire_view_ctrl.view.visible = False
            weekly_view_ctrl.view.visible = False
            to_rehearse_view_ctrl.view.visible = True
            team_view_ctrl.view.visible = False
            page.floating_action_button = to_rehearse_view_ctrl.fab_add_to_rehearse
            to_rehearse_view_ctrl.to_rehearse_list_column.controls.clear()
            to_rehearse_view_ctrl.to_rehearse_list_column.controls.append(create_skeleton_loader(count=3))
            page.update()
            to_rehearse_view_ctrl.refresh_to_rehearse_list()
        elif tab == "team":
            repertoire_view_ctrl.view.visible = False
            weekly_view_ctrl.view.visible = False
            to_rehearse_view_ctrl.view.visible = False
            team_view_ctrl.view.visible = True
            page.floating_action_button = None
            team_view_ctrl.team_members_column.controls.clear()
            team_view_ctrl.team_members_column.controls.append(create_skeleton_loader(count=3))
            page.update()
            team_view_ctrl.refresh_user_teams()
            team_view_ctrl.refresh_team_members()

    _tab_change_callback = _handle_tab_change

    # 5. Montagem Estrutural das Telas
    main_app_view = ft.Container(
        expand=True,
        visible=is_authenticated_initial,
        content=ft.Column(
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            controls=[
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.Row(
                            spacing=4,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            controls=[
                                auth_view_ctrl.header_greeting_text,
                                auth_view_ctrl.btn_edit_username,
                            ],
                        ),
                        auth_view_ctrl.btn_logout,
                    ],
                ),
                repertoire_view_ctrl.view,
                weekly_view_ctrl.view,
                to_rehearse_view_ctrl.view,
                team_view_ctrl.view,
                ft.Container(height=40),
            ],
        ),
    )

    def update_auth_ui() -> None:
        logged_name = _get_logged_user_name()
        if logged_name and api_client.auth_token:
            auth_view_ctrl.header_greeting_text.value = f"Olá, {logged_name}"
            auth_view_ctrl.login_screen_view.visible = False
            main_app_view.visible = True
            if bottom_nav_bar is not None:
                page.bottom_appbar = bottom_nav_bar
            if nav_manager.current_tab == "songs":
                page.floating_action_button = repertoire_view_ctrl.fab_add_song
            elif nav_manager.current_tab == "weekly":
                page.floating_action_button = weekly_view_ctrl.fab_add_weekly_song
            elif nav_manager.current_tab == "to_rehearse":
                page.floating_action_button = to_rehearse_view_ctrl.fab_add_to_rehearse
            else:
                page.floating_action_button = None
            try:
                _start_notifications_poller()
            except Exception:
                pass
        else:
            auth_view_ctrl.header_greeting_text.value = "Olá, Músico"
            auth_view_ctrl.login_screen_view.visible = True
            main_app_view.visible = False
            page.bottom_appbar = None
            page.floating_action_button = None
        page.update()

    page.add(
        ft.Column(
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            controls=[
                auth_view_ctrl.login_screen_view,
                main_app_view,
            ],
        )
    )

    # 6. Inicialização do Estado
    if is_authenticated_initial:
        page.bottom_appbar = bottom_nav_bar
        page.floating_action_button = repertoire_view_ctrl.fab_add_song
        repertoire_view_ctrl.refresh_songs_list()
        team_view_ctrl.refresh_user_teams()
        _start_notifications_poller()
    else:
        page.bottom_appbar = None
