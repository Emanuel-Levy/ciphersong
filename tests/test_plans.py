"""
Testes unitários e de integração para regras de monetização, limites do Plano Free,
Planos Pro/Ministério e Cortesia de 3 dias (Grandfathering).
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend_api import app
from ciphersong.security.auth import create_access_token
from ciphersong.core.plans import (
    COURTESY_DAYS,
    PlanLimitError,
    compute_courtesy_expiration,
    get_effective_plan,
    is_exceeding_free_limits,
)


def _auth_header(user_id: str = "user_1", nome: str = "Cantor", email: str = "cantor@teste.com") -> dict[str, str]:
    token = create_access_token(user_id=user_id, email=email)
    return {"Authorization": f"Bearer {token}"}


class TestCorePlans:
    def test_default_free_plan(self) -> None:
        info = get_effective_plan({"_id": "u1", "email": "free@teste.com"})
        assert info["plano"] == "free"
        assert info["is_premium"] is False
        assert info["cortesia_ativa"] is False
        assert info["limites"]["max_owned_teams"] == 1
        assert info["limites"]["max_members"] == 6
        assert info["limites"]["max_songs"] == 50
        assert info["limites"]["custom_avatar"] is False

    def test_manual_premium_emails_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PREMIUM_EMAILS", "lider@igreja.com:pro, pastor@igreja.com")
        pro_info = get_effective_plan({"_id": "u1", "email": "lider@igreja.com"})
        assert pro_info["plano"] == "pro"
        assert pro_info["origem"] == "manual"
        assert pro_info["is_premium"] is True
        assert pro_info["limites"]["max_owned_teams"] == 3
        assert pro_info["limites"]["max_members"] == 12
        assert pro_info["limites"]["max_songs"] is None
        assert pro_info["limites"]["custom_avatar"] is True

        min_info = get_effective_plan({"_id": "u2", "email": "pastor@igreja.com"})
        assert min_info["plano"] == "ministerio"
        assert min_info["limites"]["max_owned_teams"] is None
        assert min_info["limites"]["max_members"] == 30

    def test_courtesy_active_and_expired(self) -> None:
        now = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)
        exp_future = compute_courtesy_expiration(now)
        active = get_effective_plan({"_id": "u1", "email": "x@x.com", "cortesia_ate": exp_future}, now=now)
        assert active["plano"] == "ministerio"
        assert active["cortesia_ativa"] is True
        assert active["origem"] == "cortesia"
        assert active["is_premium"] is True

        after_3_days = now + timedelta(days=COURTESY_DAYS, seconds=1)
        expired = get_effective_plan({"_id": "u1", "email": "x@x.com", "cortesia_ate": exp_future}, now=after_3_days)
        assert expired["plano"] == "free"
        assert expired["cortesia_ativa"] is False
        assert expired["is_premium"] is False

    def test_is_exceeding_free_limits(self) -> None:
        assert is_exceeding_free_limits(owned_teams_count=1, max_team_members_count=6, max_team_songs_count=50) is False
        assert is_exceeding_free_limits(owned_teams_count=2, max_team_members_count=1, max_team_songs_count=0) is True
        assert is_exceeding_free_limits(owned_teams_count=1, max_team_members_count=7, max_team_songs_count=10) is True
        assert is_exceeding_free_limits(owned_teams_count=1, max_team_members_count=3, max_team_songs_count=51) is True


class TestApiPlanLimits:
    def setup_method(self) -> None:
        self.client = TestClient(app)

    @patch("backend_api.UsuariosRepository")
    def test_avatar_blocked_on_free_allowed_on_pro(self, mock_user_repo_cls: MagicMock) -> None:
        mock_repo = mock_user_repo_cls.return_value
        mock_repo.buscar_por_id.return_value = {
            "_id": "user_1",
            "nome": "Cantor",
            "email": "cantor@teste.com",
            "cortesia_concedida": True,
        }

        resp = self.client.put(
            "/api/auth/perfil",
            json={"nome": "Cantor", "foto_url": "data:image/jpeg;base64,AAAA"},
            headers=_auth_header(),
        )
        assert resp.status_code == 402
        body = resp.json()
        assert body["code"] == "PLAN_LIMIT"
        assert body["limit_type"] == "avatar"

        # Agora com plano Pro ativo
        mock_repo.buscar_por_id.return_value["plano"] = "pro"
        mock_repo.atualizar_nome_usuario.return_value = {
            "_id": "user_1",
            "nome": "Cantor Pro",
            "email": "cantor@teste.com",
            "plano": "pro",
        }
        resp_pro = self.client.put(
            "/api/auth/perfil",
            json={"nome": "Cantor Pro", "foto_url": "data:image/jpeg;base64,AAAA"},
            headers=_auth_header(),
        )
        assert resp_pro.status_code == 200

    @patch("backend_api.MusicasEnsaioRepository")
    @patch("backend_api.EquipesRepository")
    @patch("backend_api.UsuariosRepository")
    def test_song_limit_50_free_and_duplicate_merge_allowed(
        self,
        mock_user_cls: MagicMock,
        mock_eq_cls: MagicMock,
        mock_mus_cls: MagicMock,
    ) -> None:
        mock_user = mock_user_cls.return_value
        mock_user.buscar_por_id.return_value = {
            "_id": "user_1",
            "email": "cantor@teste.com",
            "cortesia_concedida": True,
        }
        mock_eq = mock_eq_cls.return_value
        mock_eq.usuario_pertence_a_equipe.return_value = True
        mock_eq.buscar_por_id.return_value = {
            "_id": "eq_1",
            "criado_por": "user_1",
            "membros": [{"id": "user_1", "nome": "Cantor"}],
        }
        mock_mus = mock_mus_cls.return_value
        mock_mus.contar_por_equipe.return_value = 50
        mock_mus.existe_duplicata.return_value = False

        # 51ª música inédita deve ser bloqueada com 402
        resp = self.client.post(
            "/api/musicas",
            json={
                "titulo": "Nova Música 51",
                "cantor_principal": "Cantor",
                "tons": ["C"],
                "equipe_id": "eq_1",
            },
            headers=_auth_header(),
        )
        assert resp.status_code == 402
        assert resp.json()["limit_type"] == "songs"

        # Mesclagem de tom em música já existente (duplicata) com 50/50 deve ser permitida
        mock_mus.existe_duplicata.return_value = True
        mock_mus.salvar_musica.return_value = {"_id": "mus_existing", "titulo": "Música Existente"}
        resp_dup = self.client.post(
            "/api/musicas",
            json={
                "titulo": "Música Existente",
                "cantor_principal": "Cantor",
                "tons": ["G"],
                "equipe_id": "eq_1",
            },
            headers=_auth_header(),
        )
        assert resp_dup.status_code == 201

    @patch("backend_api.MusicasEnsaioRepository")
    @patch("backend_api.EquipesRepository")
    @patch("backend_api.UsuariosRepository")
    def test_team_creation_and_member_limits(
        self,
        mock_user_cls: MagicMock,
        mock_eq_cls: MagicMock,
        mock_mus_cls: MagicMock,
    ) -> None:
        mock_user = mock_user_cls.return_value
        mock_user.buscar_por_id.return_value = {
            "_id": "user_1",
            "email": "cantor@teste.com",
            "cortesia_concedida": True,
        }
        mock_eq = mock_eq_cls.return_value
        mock_eq.contar_equipes_criadas_por.return_value = 1

        # Criar 2ª equipe no plano Free deve retornar 402
        resp_create = self.client.post(
            "/api/equipe/criar",
            json={"nome": "Segunda Equipe"},
            headers=_auth_header(),
        )
        assert resp_create.status_code == 402
        assert resp_create.json()["limit_type"] == "teams"

        # Entrar em equipe com 6 membros (sendo 7º membro) deve retornar 402
        mock_eq.buscar_por_codigo.return_value = {
            "_id": "eq_cheia",
            "criado_por": "user_1",
            "membros": [f"u_{i}" for i in range(6)],
        }
        resp_join = self.client.post(
            "/api/equipe/entrar",
            json={"codigo": "ABC123"},
            headers=_auth_header(user_id="user_novo"),
        )
        assert resp_join.status_code == 402
        assert resp_join.json()["limit_type"] == "members"

    @patch("backend_api.MusicasEnsaioRepository")
    @patch("backend_api.EquipesRepository")
    @patch("backend_api.UsuariosRepository")
    def test_legacy_courtesy_auto_granted_when_exceeding_limits(
        self,
        mock_user_cls: MagicMock,
        mock_eq_cls: MagicMock,
        mock_mus_cls: MagicMock,
    ) -> None:
        mock_user = mock_user_cls.return_value
        mock_user.buscar_por_id.return_value = {
            "_id": "user_legacy",
            "email": "legacy@teste.com",
            "cortesia_concedida": False,
        }
        mock_eq = mock_eq_cls.return_value
        mock_eq.contar_equipes_criadas_por.return_value = 2
        mock_eq.listar_equipes_do_usuario.return_value = [
            {"_id": "eq_1", "criado_por": "user_legacy", "membros": ["user_legacy"]},
            {"_id": "eq_2", "criado_por": "user_legacy", "membros": ["user_legacy"]},
        ]
        mock_mus = mock_mus_cls.return_value
        mock_mus.contar_por_equipe.return_value = 10

        resp = self.client.get(
            "/api/plano",
            headers=_auth_header(user_id="user_legacy", email="legacy@teste.com"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cortesia_ativa"] is True
        assert data["plano"] == "ministerio"
        assert data["origem"] == "cortesia"
        mock_user.conceder_cortesia.assert_called_once()
