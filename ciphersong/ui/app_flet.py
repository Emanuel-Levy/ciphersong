"""
Interface Visual Flet 1.0 em Dark Mode (`ui-ux-designer`).
Organizada em 2 Abas (Mobile-First):
1. Aba "Detector Vocal":
   - Seletor de Microfone físico do sistema + Medidor de Nível de Entrada (Volume RMS).
   - Medidor Circular de Afinação em Tempo Real (Nota, Hz e Cents).
   - Card de Tonalidade Musical Estimada (Tom Maior/Menor + Relativa + Confiança).
   - Histórico local de capturas.
2. Aba "Músicas Ensaiadas":
   - Barra de Pesquisa instantânea (busca por Nome da Música, Solista ou Tom).
   - Formulário de Cadastro: Nome da Música, Seleção de Múltiplos Tons de uma só vez e Solista.
   - Lista de músicas cadastradas criptografadas com AES-256-GCM.
"""

from __future__ import annotations

from typing import Optional

import flet as ft

from ciphersong.core.key_estimator import KeyEstimation
from ciphersong.core.pitch_detector import VoiceFrameResult
from ciphersong.security.local_vault import EncryptedSessionVault
from ciphersong.services.api_client import SongsApiClient
from ciphersong.services.microphone_stream import LiveMicrophoneService

try:
    import flet_audio_recorder as far
except ImportError:
    far = None  # type: ignore

# Opções de Tons (Maiores e Menores) para seleção múltipla rápida
ALL_MUSICAL_KEYS: tuple[str, ...] = (
    "C (Dó)", "C# (Dó#)", "D (Ré)", "D# (Ré#)", "E (Mi)", "F (Fá)",
    "F# (Fá#)", "G (Sol)", "G# (Sol#)", "A (Lá)", "A# (Lá#)", "B (Si)",
    "Cm (Dóm)", "C#m (Dó#m)", "Dm (Rém)", "D#m (Ré#m)", "Em (Mim)", "Fm (Fám)",
    "F#m (Fá#m)", "Gm (Solm)", "G#m (Sol#m)", "Am (Lám)", "A#m (Lá#m)", "Bm (Sim)",
)


def build_ciphersong_app(page: ft.Page) -> None:
    """Constrói o aplicativo CipherSong com 2 abas principais em Dark Mode."""
    page.title = "CipherSong — Detector Vocal & Repertório"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0D1117"
    page.padding = 16
    page.scroll = ft.ScrollMode.AUTO

    vault = EncryptedSessionVault()
    mic_service = LiveMicrophoneService()

    # Registrador de áudio nativo para Mobile (Android / iOS) via PCM16 Stream em RAM
    mobile_recorder = None
    if far is not None:
        def _on_mobile_pcm_stream(e: "far.AudioRecorderStreamEvent") -> None:
            if e.chunk:
                mic_service.handle_pcm16_bytes(e.chunk, sample_rate=44100)

        mobile_recorder = far.AudioRecorder(
            configuration=far.AudioRecorderConfiguration(
                encoder=far.AudioEncoder.PCM16BITS,
                sample_rate=44100,
                channels=1,
                auto_gain=True,
            ),
            on_stream=_on_mobile_pcm_stream,
        )
        page.services.append(mobile_recorder)

    # =========================================================================
    # ABA 1: DETECTOR VOCAL & MICROFONE
    # =========================================================================
    input_devices = mic_service.list_input_devices()
    default_dev_key = str(input_devices[0].index) if input_devices else "default"

    mic_dropdown = ft.Dropdown(
        label="Microfone de Entrada",
        width=390,
        value=default_dev_key,
        options=[
            ft.DropdownOption(key=str(d.index), text=f"{d.name} ({d.default_samplerate} Hz)")
            for d in input_devices
        ]
        or [ft.DropdownOption(key="default", text="Microfone Padrão do Sistema")],
    )

    status_badge = ft.Text(
        "Selecione seu microfone e clique em 'Ouvir Microfone'",
        size=12,
        color="#8B949E",
        text_align=ft.TextAlign.CENTER,
    )

    # Barra visual de nível do sinal do microfone (para o cantor ver que o áudio está chegando)
    mic_level_bar = ft.ProgressBar(
        value=0.0,
        width=320,
        height=6,
        color="#58A6FF",
        bgcolor="#21262D",
        border_radius=3,
    )
    mic_level_label = ft.Text(
        "Sinal do Microfone: Silêncio",
        size=11,
        color="#8B949E",
    )

    note_title = ft.Text(
        "--",
        size=52,
        weight=ft.FontWeight.BOLD,
        color="#58A6FF",
        text_align=ft.TextAlign.CENTER,
    )
    note_subtitle = ft.Text(
        "Cante no microfone",
        size=15,
        color="#C9D1D9",
        text_align=ft.TextAlign.CENTER,
    )
    freq_label = ft.Text(
        "0.0 Hz  |  0.0 cents",
        size=13,
        color="#8B949E",
        text_align=ft.TextAlign.CENTER,
    )

    cents_bar = ft.ProgressBar(
        value=0.5,
        width=220,
        height=8,
        color="#3FB950",
        bgcolor="#21262D",
        border_radius=4,
    )

    tuner_gauge = ft.Container(
        width=240,
        height=240,
        border_radius=120,
        bgcolor="#161B22",
        border=ft.Border.all(4, "#30363D"),
        alignment=ft.Alignment.CENTER,
        content=ft.Column(
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=5,
            controls=[
                note_title,
                note_subtitle,
                freq_label,
                ft.Container(height=4),
                cents_bar,
                ft.Text("♭ (-50c)        Afinado        ♯ (+50c)", size=10, color="#6E7681"),
            ],
        ),
    )

    key_main_text = ft.Text(
        "Aguardando voz...",
        size=22,
        weight=ft.FontWeight.BOLD,
        color="#F0F6FC",
    )
    key_relative_text = ft.Text(
        "Cante por alguns segundos para identificar o Tom",
        size=13,
        color="#8B949E",
    )
    confidence_chip = ft.Text(
        "Confiança: --%",
        size=12,
        weight=ft.FontWeight.W_600,
        color="#A371F7",
    )

    key_card = ft.Container(
        width=390,
        padding=14,
        border_radius=14,
        bgcolor="#161B22",
        border=ft.Border.all(1, "#30363D"),
        content=ft.Column(
            spacing=5,
            horizontal_alignment=ft.CrossAxisAlignment.START,
            controls=[
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Text("TOM DA MÚSICA (ESCALA)", size=11, weight=ft.FontWeight.BOLD, color="#58A6FF"),
                        confidence_chip,
                    ],
                ),
                key_main_text,
                key_relative_text,
            ],
        ),
    )

    history_column = ft.Column(spacing=8)

    def refresh_history_ui() -> None:
        records = vault.load_records()
        history_column.controls.clear()
        if not records:
            history_column.controls.append(
                ft.Text("Nenhum tom salvo ainda no cofre local.", size=12, color="#6E7681")
            )
        else:
            for rec in records[:5]:
                history_column.controls.append(
                    ft.Container(
                        padding=10,
                        border_radius=10,
                        bgcolor="#161B22",
                        border=ft.Border.all(1, "#21262D"),
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
                                            color="#E6EDF3",
                                        ),
                                        ft.Text(
                                            f"Relativa: {rec.relative_key_pt} • Nota: {rec.last_note} ({rec.last_freq_hz} Hz)",
                                            size=11,
                                            color="#8B949E",
                                        ),
                                    ],
                                ),
                                ft.Column(
                                    horizontal_alignment=ft.CrossAxisAlignment.END,
                                    spacing=2,
                                    controls=[
                                        ft.Text(f"{rec.confidence_pct}%", size=12, weight=ft.FontWeight.BOLD, color="#3FB950"),
                                        ft.Text(rec.timestamp, size=10, color="#6E7681"),
                                    ],
                                ),
                            ],
                        ),
                    )
                )
        page.update()

    def on_audio_update(frame: VoiceFrameResult, key_est: Optional[KeyEstimation]) -> None:
        # Atualiza barra de volume do microfone (escala visual sensível)
        norm_vol = min(1.0, frame.rms_volume * 25.0)
        mic_level_bar.value = norm_vol
        if frame.rms_volume >= 0.002:
            mic_level_label.value = f"Sinal do Microfone: Ativo (RMS {frame.rms_volume:.4f})"
            mic_level_bar.color = "#3FB950" if frame.is_singing else "#58A6FF"
        else:
            mic_level_label.value = "Sinal do Microfone: Silêncio (cante mais perto ou troque o mic)"
            mic_level_bar.color = "#6E7681"

        if frame.is_singing and frame.note is not None:
            n = frame.note
            note_title.value = f"{n.note_pt}{n.octave}"
            note_subtitle.value = f"Cifra: {n.full_name_en}"
            freq_label.value = f"{n.frequency_hz:.1f} Hz  |  {n.cents_offset:+.1f} cents"

            norm_cents = max(0.0, min(1.0, (n.cents_offset + 50.0) / 100.0))
            cents_bar.value = norm_cents

            if abs(n.cents_offset) <= 15.0:
                tuner_gauge.border = ft.Border.all(4, "#3FB950")
                cents_bar.color = "#3FB950"
            else:
                tuner_gauge.border = ft.Border.all(4, "#D29922")
                cents_bar.color = "#D29922"

        if key_est is not None:
            key_main_text.value = f"{key_est.key_pt} ({key_est.key_en})"
            key_relative_text.value = f"Escala Relativa: {key_est.relative_key_pt} ({key_est.relative_key_en})"
            confidence_chip.value = f"Confiança: {int(key_est.confidence * 100)}%"

        try:
            page.update()
        except Exception:
            pass

    mic_service.on_update = on_audio_update

    btn_mic = ft.FilledButton(
        content="Ouvir Microfone",
        icon=ft.Icons.MIC,
        bgcolor="#238636",
        color="#FFFFFF",
        expand=True,
    )

    btn_sim = ft.OutlinedButton(
        content="Simular Voz",
        icon=ft.Icons.GRAPHIC_EQ,
        expand=True,
    )

    def _selected_device_index() -> Optional[int]:
        val = mic_dropdown.value
        if val and val.isdigit():
            return int(val)
        return None

    async def toggle_mic(e: ft.ControlEvent) -> None:
        if mic_service.is_running:
            if mic_service._flet_recorder is not None:
                try:
                    await mic_service._flet_recorder.stop_recording()
                except Exception:
                    pass
                mic_service._flet_recorder = None
            mic_service.stop()
            btn_mic.content = "Ouvir Microfone"
            btn_mic.bgcolor = "#238636"
            tuner_gauge.border = ft.Border.all(4, "#30363D")
            mic_level_bar.value = 0.0
            status_badge.value = "Captura pausada • Áudio descartado da RAM"
        else:
            is_mobile = getattr(page, "platform", None) in (
                ft.PagePlatform.ANDROID,
                ft.PagePlatform.IOS,
            )
            if is_mobile and mobile_recorder is not None:
                ok, msg = await mic_service.start_mobile_flet_recorder(mobile_recorder)
            else:
                ok, msg = mic_service.start_microphone(device_index=_selected_device_index())
                if not ok and mobile_recorder is not None:
                    ok_mob, msg_mob = await mic_service.start_mobile_flet_recorder(mobile_recorder)
                    if ok_mob:
                        ok, msg = ok_mob, msg_mob
            status_badge.value = msg
            if ok:
                btn_mic.content = "Parar Microfone"
                btn_mic.bgcolor = "#DA3633"
        page.update()

    def on_mic_device_change(e: ft.ControlEvent) -> None:
        if mic_service.is_running and mic_service._flet_recorder is None:
            ok, msg = mic_service.start_microphone(device_index=_selected_device_index())
            status_badge.value = msg
            page.update()

    mic_dropdown.on_select = on_mic_device_change

    def trigger_simulation(e: ft.ControlEvent) -> None:
        mic_service.start_voice_simulation("Sol Maior")
        btn_mic.content = "Parar Simulação"
        btn_mic.bgcolor = "#DA3633"
        status_badge.value = "Simulando voz cantando em Sol Maior (G)..."
        page.update()

    def save_current_key(e: ft.ControlEvent) -> None:
        if mic_service.last_key is None:
            status_badge.value = "Cante ou simule por alguns segundos antes de salvar o Tom!"
            page.update()
            return

        k = mic_service.last_key
        last_n = mic_service.last_frame.note if (mic_service.last_frame and mic_service.last_frame.note) else None
        rec = vault.create_record(
            key_pt=k.key_pt,
            key_en=k.key_en,
            relative_pt=k.relative_key_pt,
            confidence=k.confidence,
            last_note=last_n.full_name_pt if last_n else k.key_pt,
            last_freq_hz=last_n.frequency_hz if last_n else 0.0,
        )
        vault.save_record(rec)
        status_badge.value = f"Tom {k.key_pt} salvo no cofre criptografado (AES-256-GCM)!"
        refresh_history_ui()

    btn_mic.on_click = toggle_mic
    btn_sim.on_click = trigger_simulation

    btn_save_tuner = ft.FilledButton(
        content="Salvar Tom Detectado no Histórico",
        icon=ft.Icons.LOCK_OUTLINE,
        bgcolor="#1F6FEB",
        color="#FFFFFF",
        width=390,
        on_click=save_current_key,
    )

    detector_view = ft.Column(
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=12,
        controls=[
            mic_dropdown,
            ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=4,
                controls=[mic_level_label, mic_level_bar],
            ),
            status_badge,
            tuner_gauge,
            key_card,
            ft.Row(width=390, spacing=10, controls=[btn_mic, btn_sim]),
            btn_save_tuner,
            ft.Divider(color="#21262D"),
            ft.Row(
                width=390,
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Text("Últimos Tons Capturados", size=14, weight=ft.FontWeight.BOLD, color="#C9D1D9"),
                ],
            ),
            ft.Container(width=390, content=history_column),
        ],
    )

    # =========================================================================
    # ABA 2: CADASTRO E PESQUISA DE MÚSICAS ENSAIADAS
    # =========================================================================
    selected_keys_set: set[str] = set()

    search_input = ft.TextField(
        label="Pesquisar música, solista ou tom...",
        prefix_icon=ft.Icons.SEARCH,
        width=390,
        bgcolor="#161B22",
    )

    song_title_input = ft.TextField(
        label="Nome da Música *",
        hint_text="Ex: Bondade de Deus / Oceanos",
        width=390,
        bgcolor="#0D1117",
    )

    soloist_input = ft.TextField(
        label="Solista *",
        hint_text="Ex: Levy / Ana / Grupo",
        width=390,
        bgcolor="#0D1117",
    )

    selected_keys_display = ft.Text(
        "Tons selecionados: Nenhum (clique nos botões abaixo)",
        size=12,
        color="#58A6FF",
        weight=ft.FontWeight.W_600,
    )

    song_feedback_text = ft.Text(
        "",
        size=12,
        color="#3FB950",
    )

    key_buttons_grid = ft.Row(
        wrap=True,
        spacing=6,
        run_spacing=6,
        width=365,
    )

    def rebuild_key_selector_buttons() -> None:
        key_buttons_grid.controls.clear()
        for k_label in ALL_MUSICAL_KEYS:
            is_sel = k_label in selected_keys_set

            def _make_toggle(key_str: str):
                def _on_click(e: ft.ControlEvent) -> None:
                    if key_str in selected_keys_set:
                        selected_keys_set.remove(key_str)
                    else:
                        selected_keys_set.add(key_str)
                    if selected_keys_set:
                        ordered = [k for k in ALL_MUSICAL_KEYS if k in selected_keys_set]
                        selected_keys_display.value = f"Tons selecionados ({len(ordered)}): " + ", ".join(ordered)
                    else:
                        selected_keys_display.value = "Tons selecionados: Nenhum (clique nos botões abaixo)"
                    rebuild_key_selector_buttons()
                    page.update()
                return _on_click

            btn = ft.FilledButton(
                content=k_label.split(" ")[0],
                tooltip=k_label,
                bgcolor="#238636" if is_sel else "#21262D",
                color="#FFFFFF" if is_sel else "#C9D1D9",
                height=34,
                on_click=_make_toggle(k_label),
            )
            key_buttons_grid.controls.append(btn)

    def use_detected_key_in_form(e: ft.ControlEvent) -> None:
        if mic_service.last_key is not None:
            k_en = mic_service.last_key.key_en
            for full_k in ALL_MUSICAL_KEYS:
                if full_k.startswith(f"{k_en} "):
                    selected_keys_set.add(full_k)
            ordered = [k for k in ALL_MUSICAL_KEYS if k in selected_keys_set]
            selected_keys_display.value = f"Tons selecionados ({len(ordered)}): " + ", ".join(ordered)
            rebuild_key_selector_buttons()
            song_feedback_text.color = "#58A6FF"
            song_feedback_text.value = f"Tom detectado ({k_en}) adicionado à seleção!"
        else:
            song_feedback_text.color = "#D29922"
            song_feedback_text.value = "Nenhum tom detectado ainda na Aba 1."
        page.update()

    api_client = SongsApiClient()
    songs_list_column = ft.Column(spacing=8)

    def refresh_songs_list() -> None:
        query = (search_input.value or "").strip()
        songs = []

        # 1. Tenta buscar via API Cloud (Android/Mobile) ou MongoDB Atlas (Desktop fallback)
        try:
            remote_docs, source_label = api_client.listar_ou_buscar(query)
            for doc in remote_docs:
                songs.append({
                    "id": doc.get("_id", ""),
                    "title": doc.get("titulo", ""),
                    "soloist": doc.get("cantor_principal", ""),
                    "keys": doc.get("tons", []),
                    "created_at": "MongoDB Atlas (musicas_ensaio)",
                    "source": source_label,
                })
        except Exception:
            # 2. Fallback offline: carrega do cofre local criptografado (AES-256-GCM)
            local_songs = vault.search_songs(query)
            for s in local_songs:
                songs.append({
                    "id": s.id,
                    "title": s.title,
                    "soloist": s.soloist,
                    "keys": s.keys,
                    "created_at": s.created_at,
                    "source": "Local 🔒",
                })

        songs_list_column.controls.clear()

        if not songs:
            msg = (
                f"Nenhuma música encontrada para '{query}'."
                if query
                else "Nenhuma música ensaiada cadastrada ainda."
            )
            songs_list_column.controls.append(ft.Text(msg, size=12, color="#6E7681"))
        else:
            for s in songs:
                def _make_delete(song_id: str):
                    def _del(e: ft.ControlEvent) -> None:
                        api_client.deletar_musica(song_id)
                        vault.delete_song(song_id)
                        refresh_songs_list()
                    return _del

                keys_badges = ft.Row(
                    wrap=True,
                    spacing=6,
                    controls=[
                        ft.Container(
                            padding=ft.Padding.symmetric(horizontal=8, vertical=3),
                            border_radius=8,
                            bgcolor="#1F6FEB",
                            content=ft.Text(k, size=11, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                        )
                        for k in s["keys"]
                    ],
                )

                songs_list_column.controls.append(
                    ft.Container(
                        padding=12,
                        border_radius=12,
                        bgcolor="#161B22",
                        border=ft.Border.all(1, "#30363D"),
                        content=ft.Column(
                            spacing=6,
                            controls=[
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    controls=[
                                        ft.Column(
                                            spacing=2,
                                            controls=[
                                                ft.Row(
                                                    spacing=6,
                                                    controls=[
                                                        ft.Text(s["title"], size=16, weight=ft.FontWeight.BOLD, color="#F0F6FC"),
                                                        ft.Container(
                                                            padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                                                            border_radius=6,
                                                            bgcolor="#21262D",
                                                            content=ft.Text(
                                                                s["source"],
                                                                size=10,
                                                                color="#3FB950" if ("Atlas" in s["source"] or "Cloud" in s["source"]) else "#8B949E",
                                                            ),
                                                        ),
                                                    ],
                                                ),
                                                ft.Text(f"🎤 Solista: {s['soloist']}", size=12, color="#C9D1D9"),
                                            ],
                                        ),
                                        ft.IconButton(
                                            icon=ft.Icons.DELETE_OUTLINE,
                                            icon_color="#F85149",
                                            tooltip="Remover música",
                                            on_click=_make_delete(s["id"]),
                                        ),
                                    ],
                                ),
                                keys_badges,
                                ft.Text(f"Origem: {s['created_at']}", size=10, color="#6E7681"),
                            ],
                        ),
                    )
                )
        page.update()

    def on_search_change(e: ft.ControlEvent) -> None:
        refresh_songs_list()

    search_input.on_change = on_search_change

    def handle_save_song(e: ft.ControlEvent) -> None:
        title = (song_title_input.value or "").strip()
        soloist = (soloist_input.value or "").strip()
        ordered_keys = [k for k in ALL_MUSICAL_KEYS if k in selected_keys_set]

        if not title:
            song_feedback_text.color = "#F85149"
            song_feedback_text.value = "⚠️ Informe o Nome da Música!"
            page.update()
            return

        if not ordered_keys:
            song_feedback_text.color = "#F85149"
            song_feedback_text.value = "⚠️ Selecione pelo menos 1 Tom (você pode marcar vários)!"
            page.update()
            return

        # 1. Salva na nuvem (via API HTTP ou fallback MongoDB Atlas no Desktop)
        saved_cloud = False
        cloud_source = ""
        try:
            _, cloud_source = api_client.salvar_musica(
                titulo=title,
                cantor_principal=soloist or "Não informado",
                tons=ordered_keys,
            )
            saved_cloud = True
        except Exception as exc:
            print(f"[Cloud Sync Warning]: {exc}")

        # 2. Salva também no cofre local criptografado (AES-256-GCM) para cache/offline no Android
        vault.save_song(
            title=title,
            keys=ordered_keys,
            soloist=soloist or "Não informado",
        )

        # Limpa formulário
        song_title_input.value = ""
        soloist_input.value = ""
        selected_keys_set.clear()
        selected_keys_display.value = "Tons selecionados: Nenhum (clique nos botões abaixo)"
        rebuild_key_selector_buttons()

        song_feedback_text.color = "#3FB950"
        if saved_cloud:
            song_feedback_text.value = f"✅ Música '{title}' sincronizada ({cloud_source}) e salva no cofre local!"
        else:
            song_feedback_text.value = f"✅ Música '{title}' salva no cofre local criptografado (Modo Offline)!"
        refresh_songs_list()

    rebuild_key_selector_buttons()

    repertoire_view = ft.Column(
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=12,
        visible=False,
        controls=[
            search_input,
            ft.Container(
                width=390,
                padding=14,
                border_radius=14,
                bgcolor="#161B22",
                border=ft.Border.all(1, "#30363D"),
                content=ft.Column(
                    spacing=10,
                    horizontal_alignment=ft.CrossAxisAlignment.START,
                    controls=[
                        ft.Text("Cadastrar Nova Música Ensaiada", size=15, weight=ft.FontWeight.BOLD, color="#F0F6FC"),
                        song_title_input,
                        soloist_input,
                        ft.Row(
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            width=362,
                            controls=[
                                ft.Text("Selecione um ou mais Tons:", size=12, weight=ft.FontWeight.BOLD, color="#C9D1D9"),
                                ft.TextButton(
                                    content="+ Usar Tom Detectado",
                                    on_click=use_detected_key_in_form,
                                ),
                            ],
                        ),
                        selected_keys_display,
                        key_buttons_grid,
                        song_feedback_text,
                        ft.FilledButton(
                            content="Cadastrar Música Ensaiada",
                            icon=ft.Icons.ADD_TASK,
                            bgcolor="#238636",
                            color="#FFFFFF",
                            width=362,
                            on_click=handle_save_song,
                        ),
                    ],
                ),
            ),
            ft.Divider(color="#21262D"),
            ft.Row(
                width=390,
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Text("Músicas Cadastradas", size=14, weight=ft.FontWeight.BOLD, color="#C9D1D9"),
                ],
            ),
            ft.Container(width=390, content=songs_list_column),
        ],
    )

    # =========================================================================
    # BARRA DE NAVEGAÇÃO ENTRE AS 2 ABAS (TOPO)
    # =========================================================================
    tab_btn_detector = ft.FilledButton(
        content="🎙️ Detector de Tom",
        bgcolor="#1F6FEB",
        color="#FFFFFF",
        expand=True,
    )
    tab_btn_songs = ft.FilledButton(
        content="🎵 Músicas Ensaiadas",
        bgcolor="#21262D",
        color="#C9D1D9",
        expand=True,
    )

    def switch_to_detector(e: ft.ControlEvent) -> None:
        detector_view.visible = True
        repertoire_view.visible = False
        tab_btn_detector.bgcolor = "#1F6FEB"
        tab_btn_detector.color = "#FFFFFF"
        tab_btn_songs.bgcolor = "#21262D"
        tab_btn_songs.color = "#C9D1D9"
        page.update()

    def switch_to_songs(e: ft.ControlEvent) -> None:
        detector_view.visible = False
        repertoire_view.visible = True
        tab_btn_detector.bgcolor = "#21262D"
        tab_btn_detector.color = "#C9D1D9"
        tab_btn_songs.bgcolor = "#1F6FEB"
        tab_btn_songs.color = "#FFFFFF"
        refresh_songs_list()

    tab_btn_detector.on_click = switch_to_detector
    tab_btn_songs.on_click = switch_to_songs

    # Montagem Principal
    page.add(
        ft.Column(
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
            controls=[
                ft.Row(
                    width=390,
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Text("CipherSong", size=22, weight=ft.FontWeight.BOLD, color="#F0F6FC"),
                        ft.Container(
                            padding=ft.Padding.symmetric(horizontal=10, vertical=4),
                            border_radius=12,
                            bgcolor="#1F2937",
                            content=ft.Text("🔒 RAM-Only + AES-GCM", size=11, color="#3FB950"),
                        ),
                    ],
                ),
                ft.Row(
                    width=390,
                    spacing=8,
                    controls=[tab_btn_detector, tab_btn_songs],
                ),
                detector_view,
                repertoire_view,
            ],
        )
    )

    refresh_history_ui()
    refresh_songs_list()
