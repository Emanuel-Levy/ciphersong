"""
Módulo de Visões / Telas do CipherSong (UI/UX Flet 1.0).
Exporta os componentes modulares para cada aba e fluxo da aplicação.
"""

from __future__ import annotations

from ciphersong.ui.views.auth_view import AuthView
from ciphersong.ui.views.detector_view import DetectorView
from ciphersong.ui.views.repertoire_view import RepertoireView
from ciphersong.ui.views.team_view import TeamView
from ciphersong.ui.views.to_rehearse_view import ToRehearseView
from ciphersong.ui.views.weekly_view import WeeklyView

__all__ = [
    "AuthView",
    "DetectorView",
    "RepertoireView",
    "TeamView",
    "ToRehearseView",
    "WeeklyView",
]
