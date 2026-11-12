"""
Testes unitários e de integração para o fluxo de verificação de código por e-mail no cadastro.
"""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend_api import app, default_otp_manager


class TestRegisterOTP:
    @classmethod
    def setup_class(cls) -> None:
        cls.client = TestClient(app)

    @patch("backend_api.UsuariosRepository")
    def test_send_code_invalid_email(self, mock_user_cls: MagicMock) -> None:
        resp = self.client.post(
            "/api/auth/register/send-code",
            json={"email": "email_invalido_sem_arroba", "nome": "Levy"},
        )
        assert resp.status_code == 400
        detail = resp.json()["detail"].lower()
        assert "incorreto" in detail or "inválido" in detail

    @patch("backend_api.UsuariosRepository")
    def test_send_code_existing_user(self, mock_user_cls: MagicMock) -> None:
        mock_user = mock_user_cls.return_value
        mock_user.buscar_por_email.return_value = {"_id": "u1", "email": "jaexiste@teste.com"}

        resp = self.client.post(
            "/api/auth/register/send-code",
            json={"email": "jaexiste@teste.com", "nome": "Levy"},
        )
        assert resp.status_code == 409
        assert "já possui cadastro" in resp.json()["detail"]

    @patch("backend_api.default_email_service")
    @patch("backend_api.UsuariosRepository")
    def test_send_code_success(self, mock_user_cls: MagicMock, mock_email: MagicMock) -> None:
        mock_user = mock_user_cls.return_value
        mock_user.buscar_por_email.return_value = None

        resp = self.client.post(
            "/api/auth/register/send-code",
            json={"email": "novo@teste.com", "nome": "Novo Usuario"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["email"] == "novo@teste.com"
        assert "cooldown_seconds" in data
        mock_email.send_otp_email.assert_called_once()

    @patch("backend_api.UsuariosRepository")
    def test_register_without_code_fails(self, mock_user_cls: MagicMock) -> None:
        resp = self.client.post(
            "/api/auth/register",
            json={
                "email": "teste@teste.com",
                "senha": "senhaValida123",
                "nome": "Teste",
            },
        )
        assert resp.status_code == 400
        assert "código" in resp.json()["detail"].lower()

    @patch("backend_api.UsuariosRepository")
    def test_register_with_wrong_code_fails(self, mock_user_cls: MagicMock) -> None:
        # Request valid code first for an email
        clean_email = "testewrong@teste.com"
        default_otp_manager.request_otp(email=clean_email, name="Teste")

        resp = self.client.post(
            "/api/auth/register",
            json={
                "email": clean_email,
                "senha": "senhaValida123",
                "nome": "Teste",
                "codigo_verificacao": "000000",
            },
        )
        assert resp.status_code == 400
        detail = resp.json()["detail"].lower()
        assert "incorreto" in detail or "inválido" in detail

    @patch("backend_api.UsuariosRepository")
    def test_register_with_correct_code_success(self, mock_user_cls: MagicMock) -> None:
        mock_user = mock_user_cls.return_value
        mock_user.buscar_por_email.return_value = None
        mock_user.criar_usuario.return_value = {
            "_id": "user_otp_123",
            "email": "novovalido@teste.com",
            "nome": "Novo Valido",
        }

        clean_email = "novovalido@teste.com"
        plain_code, _, _ = default_otp_manager.request_otp(email=clean_email, name="Novo Valido")

        resp = self.client.post(
            "/api/auth/register",
            json={
                "email": clean_email,
                "senha": "senhaValida123",
                "nome": "Novo Valido",
                "codigo_verificacao": plain_code,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["token"] is not None
        assert data["user"]["email"] == clean_email
        assert data["user"]["termos_aceitos"] is True

    def test_aceitar_termos_sem_auth(self) -> None:
        resp = self.client.post("/api/auth/aceitar-termos")
        assert resp.status_code == 401

    @patch("backend_api.UsuariosRepository")
    def test_aceitar_termos_com_sucesso(self, mock_user_cls: MagicMock) -> None:
        from ciphersong.security.auth import create_access_token
        token = create_access_token(user_id="user_termos_1", email="termos@teste.com")
        mock_user = mock_user_cls.return_value
        mock_user.collection.update_one.return_value = MagicMock(modified_count=1)

        resp = self.client.post(
            "/api/auth/aceitar-termos",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["termos_aceitos"] is True
