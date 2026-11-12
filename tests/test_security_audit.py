"""
Testes unitários e de integração para a Auditoria de Segurança do CipherSong (AppSec, LGPD, RLS e Idempotência).
"""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend_api import (
    app,
    default_login_rate_limiter,
    _encode_oauth_state,
    _decode_oauth_state,
)
from ciphersong.security.auth import create_access_token, decode_access_token, _b64url_encode
from ciphersong.core.plans import PaymentIdempotencyLedger


class TestSecurityHardening:
    @classmethod
    def setup_class(cls) -> None:
        cls.client = TestClient(app)

    def setup_method(self) -> None:
        default_login_rate_limiter.reset()

    # -------------------------------------------------------------------------
    # 1. Anti-Brute Force Rate Limiting no Login
    # -------------------------------------------------------------------------
    @patch("backend_api.UsuariosRepository")
    def test_login_rate_limiting_blocks_brute_force(self, mock_user_cls: MagicMock) -> None:
        mock_user = mock_user_cls.return_value
        # Simula usuário com senha hash
        mock_user.buscar_por_email.return_value = {
            "_id": "u_target",
            "email": "alvo@teste.com",
            "senha_hash": "pbkdf2_sha256$600000$saltsalt$fakehash",
        }

        # 5 tentativas erradas sucessivas
        for attempt in range(5):
            resp = self.client.post(
                "/api/auth/login",
                json={"email": "alvo@teste.com", "senha": f"senha_errada_{attempt}"},
            )
            assert resp.status_code == 401
            assert "incorretos" in resp.json()["detail"].lower()

        # 6ª tentativa consecutiva deve ser imediatamente bloqueada por Rate Limit (HTTP 429)
        resp_blocked = self.client.post(
            "/api/auth/login",
            json={"email": "alvo@teste.com", "senha": "outra_senha_errada"},
        )
        assert resp_blocked.status_code == 429
        assert "bloqueada" in resp_blocked.json()["detail"].lower()
        assert "Retry-After" in resp_blocked.headers

    # -------------------------------------------------------------------------
    # 2. Assinatura HMAC do State do Google OAuth (Anti-CSRF)
    # -------------------------------------------------------------------------
    def test_oauth_state_hmac_valid_and_tampered(self) -> None:
        valid_redirect = "http://localhost:5173"
        state = _encode_oauth_state(valid_redirect)
        assert state is not None
        assert isinstance(state, str)

        # Decodificação de state válido
        decoded_url = _decode_oauth_state(state)
        assert decoded_url == valid_redirect

        # Tentativa de adulterar o payload do state deve ser rejeitada
        tampered_state = state[:-5] + "AAAAA"
        assert _decode_oauth_state(tampered_state) is None

        # State vazio ou corrompido
        assert _decode_oauth_state("") is None
        assert _decode_oauth_state("invalid_state_123") is None

    # -------------------------------------------------------------------------
    # 3. Validação Estrita de Algoritmo JWT (Anti-Algorithm Confusion)
    # -------------------------------------------------------------------------
    def test_jwt_strict_algorithm_check(self) -> None:
        token = create_access_token(user_id="user_sec_1", email="user@teste.com", name="User")
        payload = decode_access_token(token)
        assert payload is not None
        assert payload["sub"] == "user_sec_1"

        # Simula tentativa de ataque alterando o header para alg="none"
        parts = token.split(".")
        fake_header = _b64url_encode(b'{"alg":"none","typ":"JWT"}')
        tampered_token = f"{fake_header}.{parts[1]}.{parts[2]}"
        assert decode_access_token(tampered_token) is None

    # -------------------------------------------------------------------------
    # 4. Sanitização de foto_url contra esquemas maliciosos (javascript:/file:)
    # -------------------------------------------------------------------------
    @patch("backend_api.UsuariosRepository")
    def test_foto_url_sanitization_blocks_malicious_schemes(self, mock_user_cls: MagicMock) -> None:
        token = create_access_token(user_id="user_avatar_1", email="avatar@teste.com")
        mock_user = mock_user_cls.return_value
        mock_user.buscar_por_id.return_value = {
            "_id": "user_avatar_1",
            "email": "avatar@teste.com",
            "nome": "User Avatar",
        }

        # Tentativa de injetar javascript: URI
        resp_xss = self.client.put(
            "/api/auth/perfil",
            json={"foto_url": "javascript:alert(1)"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp_xss.status_code == 400
        assert "não permitido" in resp_xss.json()["detail"].lower()

    # -------------------------------------------------------------------------
    # 5. Ledger Idempotente para Prevenção de Pagamentos Duplicados
    # -------------------------------------------------------------------------
    def test_payment_idempotency_ledger(self) -> None:
        doc = PaymentIdempotencyLedger.build_transaction_idempotency_doc(
            gateway="mercadopago",
            transaction_id="mp_123456789",
            usuario_id="user_pay_1",
            plano="pro",
            valor_centavos=1490,
            idempotency_key="idemp_key_abc123",
        )
        assert doc["gateway"] == "mercadopago"
        assert doc["transaction_id"] == "mp_123456789"
        assert doc["idempotency_key"] == "idemp_key_abc123"
        assert doc["valor_centavos"] == 1490
        assert "criado_em" in doc

        # ID de transação vazio deve falhar
        with pytest.raises(ValueError, match="não pode ser vazio"):
            PaymentIdempotencyLedger.build_transaction_idempotency_doc(
                gateway="stripe",
                transaction_id="",
                usuario_id="user_pay_1",
                plano="pro",
                valor_centavos=1490,
            )
