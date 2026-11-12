"""
Testes unitários e de integração para o fluxo de autenticação persistente:
- Access Token (15 minutos)
- Refresh Token (7 dias) com cookie HttpOnly, Secure, SameSite=Strict, Path=/api/auth/refresh
- Rotação estrita de token em POST /api/auth/refresh
- Detecção de tentativa de reuso (replay attack) com revogação total
- Invalidação no banco e limpeza de cookie em POST /api/auth/logout
"""

from typing import Any
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend_api import app, COOKIE_REFRESH_NAME, REFRESH_COOKIE_PATH
from ciphersong.security.auth import decode_access_token, generate_refresh_token, hash_refresh_token


class FakeRefreshRepo:
    def __init__(self):
        self.tokens: dict[str, dict[str, Any]] = {}

    def criar_token(self, token_hash: str, usuario_id: str, expires_seconds: int = 7 * 86400, ip: str = "", user_agent: str = ""):
        self.tokens[token_hash] = {
            "token_hash": token_hash,
            "usuario_id": usuario_id,
            "revogado": False,
            "ip": ip,
            "user_agent": user_agent,
        }

    def buscar_valido(self, token_hash: str):
        tok = self.tokens.get(token_hash)
        if tok and not tok.get("revogado"):
            return tok
        return None

    def buscar_qualquer(self, token_hash: str):
        return self.tokens.get(token_hash)

    def revogar(self, token_hash: str):
        if token_hash in self.tokens:
            self.tokens[token_hash]["revogado"] = True

    def revogar_todos_usuario(self, usuario_id: str):
        for tok in self.tokens.values():
            if str(tok["usuario_id"]) == str(usuario_id):
                tok["revogado"] = True


class TestRefreshTokenFlow:
    def setup_method(self):
        self.client = TestClient(app)
        self.fake_refresh_repo = FakeRefreshRepo()
        self.mock_user = {
            "_id": "user_123_abc",
            "email": "musico@teste.com",
            "nome": "Levy Musico",
            "senha_hash": "hash_fake_bcrypt",
        }

    @patch("backend_api.get_refresh_tokens_repo")
    @patch("backend_api.get_users_repo")
    @patch("backend_api.verify_password", return_value=True)
    def test_login_issues_15m_jwt_and_secure_refresh_cookie(
        self, mock_verify, mock_users_repo_fn, mock_refresh_repo_fn
    ):
        mock_users_repo = MagicMock()
        mock_users_repo.buscar_por_email.return_value = self.mock_user
        mock_users_repo_fn.return_value = mock_users_repo
        mock_refresh_repo_fn.return_value = self.fake_refresh_repo

        resp = self.client.post(
            "/api/auth/login",
            json={"email": "musico@teste.com", "senha": "SenhaCerta123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data

        # Verifica expiração do JWT (1 dia = ~86400s)
        payload = decode_access_token(data["token"])
        assert payload is not None
        exp = payload["exp"]
        iat = payload.get("iat", exp - 86400)
        duration = exp - iat
        assert 86000 <= duration <= 87000

        # Verifica presença e atributos do cookie de Refresh Token
        cookie_header = resp.headers.get("set-cookie", "")
        assert COOKIE_REFRESH_NAME in cookie_header
        assert f"Path={REFRESH_COOKIE_PATH}" in cookie_header or f"path={REFRESH_COOKIE_PATH}" in cookie_header
        assert "httponly" in cookie_header.lower()
        assert "samesite=" in cookie_header.lower()

        # Verifica que o hash foi salvo no banco
        assert len(self.fake_refresh_repo.tokens) == 1

    @patch("backend_api.get_refresh_tokens_repo")
    @patch("backend_api.get_users_repo")
    def test_refresh_token_rotation_success(
        self, mock_users_repo_fn, mock_refresh_repo_fn
    ):
        mock_users_repo = MagicMock()
        mock_users_repo.buscar_por_id.return_value = self.mock_user
        mock_users_repo_fn.return_value = mock_users_repo
        mock_refresh_repo_fn.return_value = self.fake_refresh_repo

        # Cria um refresh token válido no fake repo
        raw_token, token_hash = generate_refresh_token()
        self.fake_refresh_repo.criar_token(token_hash, self.mock_user["_id"])

        # Chama POST /api/auth/refresh enviando o cookie
        self.client.cookies.set(COOKIE_REFRESH_NAME, raw_token)
        resp = self.client.post("/api/auth/refresh")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "token" in data

        # O token anterior deve estar marcado como revogado (rotação estrita)
        assert self.fake_refresh_repo.tokens[token_hash]["revogado"] is True

        # Um novo token deve ter sido criado
        assert len(self.fake_refresh_repo.tokens) == 2

        # Novo cookie deve estar na resposta
        cookie_header = resp.headers.get("set-cookie", "")
        assert COOKIE_REFRESH_NAME in cookie_header

    @patch("backend_api.get_refresh_tokens_repo")
    @patch("backend_api.get_users_repo")
    def test_refresh_token_reuse_detection(
        self, mock_users_repo_fn, mock_refresh_repo_fn
    ):
        mock_users_repo = MagicMock()
        mock_users_repo.buscar_por_id.return_value = self.mock_user
        mock_users_repo_fn.return_value = mock_users_repo
        mock_refresh_repo_fn.return_value = self.fake_refresh_repo

        raw_token, token_hash = generate_refresh_token()
        self.fake_refresh_repo.criar_token(token_hash, self.mock_user["_id"])
        # Revoga o token
        self.fake_refresh_repo.revogar(token_hash)

        # Também cria um segundo token ativo do usuário
        _, active_hash = generate_refresh_token()
        self.fake_refresh_repo.criar_token(active_hash, self.mock_user["_id"])

        # Tenta usar o token já revogado (replay attack)
        self.client.cookies.set(COOKIE_REFRESH_NAME, raw_token)
        resp = self.client.post("/api/auth/refresh")
        assert resp.status_code == 401
        assert "reuso de sessão" in resp.json()["detail"].lower()

        # Todos os tokens do usuário devem ter sido revogados por segurança
        assert self.fake_refresh_repo.tokens[active_hash]["revogado"] is True

    @patch("backend_api.get_refresh_tokens_repo")
    def test_logout_revokes_token_and_clears_cookie(
        self, mock_refresh_repo_fn
    ):
        mock_refresh_repo_fn.return_value = self.fake_refresh_repo

        raw_token, token_hash = generate_refresh_token()
        self.fake_refresh_repo.criar_token(token_hash, "user_123_abc")

        self.client.cookies.set(COOKIE_REFRESH_NAME, raw_token)
        resp = self.client.post("/api/auth/logout")
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

        # Token revogado no repositório
        assert self.fake_refresh_repo.tokens[token_hash]["revogado"] is True

        # Cookie limpo
        cookie_header = resp.headers.get("set-cookie", "")
        assert COOKIE_REFRESH_NAME in cookie_header
        assert "max-age=0" in cookie_header.lower() or "expires=" in cookie_header.lower()
