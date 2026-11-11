"""
Testes de Autenticação Segura por Código de E-mail (OTP / Passwordless) (`security-specialist` + `senior-architect`).

Valida os 4 pilares AppSec / OWASP solicitados:
1. Geração de código seguro de 6 dígitos e armazenamento com hash.
2. Invalidação imediata pós-uso (prevenção de replay attacks).
3. Rate Limiting com cooldown de 60s e trava de 5 disparos por hora.
4. Limite de tentativas (máximo 5) e expiração por TTL.
5. Proteção de contas Google (usuários Google devem continuar usando Google Auth).
"""

import time
from unittest.mock import MagicMock
from bson import ObjectId
import pytest
from fastapi.testclient import TestClient

import backend_api
from ciphersong.database.mongo_connection import UsuariosRepository
from ciphersong.security.otp import (
    OTPManager,
    OTPRateLimitError,
    OTPVerificationError,
    default_otp_manager,
    generate_otp_code,
    hash_otp_code,
    verify_otp_hash,
)
from ciphersong.services.api_client import SongsApiClient
from ciphersong.services.email_service import TransactionalEmailService


class FakeUsersCollection:
    def __init__(self):
        self.docs = []

    def insert_one(self, doc):
        d = dict(doc)
        if "_id" not in d:
            d["_id"] = ObjectId()
        self.docs.append(d)
        res = MagicMock()
        res.inserted_id = d["_id"]
        return res

    def find_one(self, query):
        for d in self.docs:
            match = True
            for k, v in query.items():
                if d.get(k) != v:
                    match = False
                    break
            if match:
                return dict(d)
        return None

    def update_one(self, query, update):
        for d in self.docs:
            match = True
            for k, v in query.items():
                if d.get(k) != v:
                    match = False
                    break
            if match and "$set" in update:
                d.update(update["$set"])
                break


@pytest.fixture(autouse=True)
def clean_otp_store():
    default_otp_manager.clear_all()
    yield
    default_otp_manager.clear_all()


def test_otp_generation_and_hashing():
    code = generate_otp_code(6)
    assert len(code) == 6
    assert code.isdigit()

    salt = b"test_salt_123456"
    code_hash = hash_otp_code(code, salt)
    assert isinstance(code_hash, str)
    assert len(code_hash) == 64  # SHA-256 hexdigest

    # Validação em tempo constante
    assert verify_otp_hash(code, salt, code_hash) is True
    assert verify_otp_hash("000000", salt, code_hash) is False


def test_otp_manager_lifecycle_and_single_use():
    mgr = OTPManager(ttl_seconds=300, max_attempts=3, cooldown_seconds=10)
    email = "musico@ciphersong.app"

    code, cooldown, expires_min = mgr.request_otp(email, name="Davi")
    assert len(code) == 6
    assert cooldown == 10
    assert expires_min == 5

    # 1. Código errado decrementa tentativas
    with pytest.raises(OTPVerificationError) as exc_info:
        mgr.verify_otp(email, "999999")
    assert "mais 2 tentativas" in str(exc_info.value)
    assert exc_info.value.attempts_left == 2

    # 2. Código correto autentica
    ok, msg, stored_name = mgr.verify_otp(email, code)
    assert ok is True
    assert stored_name == "Davi"

    # 3. Invalidação imediata pós-uso (Replay attack bloqueado)
    with pytest.raises(OTPVerificationError) as exc_info2:
        mgr.verify_otp(email, code)
    assert "Nenhum código ativo encontrado" in str(exc_info2.value)


def test_otp_manager_max_attempts_lockout():
    mgr = OTPManager(ttl_seconds=300, max_attempts=3, cooldown_seconds=0)
    email = "ataque@ciphersong.app"
    code, _, _ = mgr.request_otp(email)

    with pytest.raises(OTPVerificationError):
        mgr.verify_otp(email, "000001")
    with pytest.raises(OTPVerificationError):
        mgr.verify_otp(email, "000002")

    # 3ª tentativa errada esgota as tentativas e destrói o código
    with pytest.raises(OTPVerificationError) as exc_final:
        mgr.verify_otp(email, "000003")
    assert "Limite de tentativas esgotado" in str(exc_final.value)

    # Mesmo que tente o código correto agora, ele foi destruído
    with pytest.raises(OTPVerificationError):
        mgr.verify_otp(email, code)


def test_otp_rate_limiting_cooldown_and_hourly():
    mgr = OTPManager(ttl_seconds=300, max_attempts=5, cooldown_seconds=60, max_per_hour=3)
    email = "spam@ciphersong.app"

    # 1º envio: sucesso
    mgr.request_otp(email)

    # 2º envio imediato: bloqueado por cooldown (60s)
    with pytest.raises(OTPRateLimitError) as exc_cooldown:
        mgr.request_otp(email)
    assert "Aguarde" in str(exc_cooldown.value)
    assert exc_cooldown.value.retry_after_seconds <= 60

    # Simula passagem de 61 segundos
    tracker = mgr._rate_limits[email]
    tracker.last_requested_at -= 61

    # 2º envio com cooldown atendido: sucesso
    mgr.request_otp(email)
    tracker.last_requested_at -= 61

    # 3º envio com cooldown atendido: sucesso
    mgr.request_otp(email)
    tracker.last_requested_at -= 61

    # 4º envio: estoura o limite horário de 3 por hora
    with pytest.raises(OTPRateLimitError) as exc_hour:
        mgr.request_otp(email)
    assert "Limite de 3 solicitações por hora atingido" in str(exc_hour.value)


def test_email_service_mock_delivery():
    svc = TransactionalEmailService()
    svc.sent_history.clear()

    res = svc.send_otp_email(to_email="teste@ciphersong.app", codigo="847291", expires_in_minutes=10)
    assert res["status"] in ("sent", "delivered_dev")
    assert len(svc.sent_history) == 1
    assert svc.sent_history[0]["code"] == "847291"


def test_fastapi_otp_endpoints(monkeypatch):
    fake_col = FakeUsersCollection()
    mock_users_repo = UsuariosRepository(collection=fake_col)
    monkeypatch.setattr(backend_api, "get_users_repo", lambda: mock_users_repo)

    client = TestClient(backend_api.app)

    # 1. Solicita OTP para novo e-mail
    resp = client.post("/api/auth/otp/request", json={"email": "novo@ciphersong.app", "nome": "Lucas"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["cooldown_seconds"] == 60
    assert data["expires_in_minutes"] == 10

    # 2. Tentativa imediata bloqueada por rate limit 429
    resp_429 = client.post("/api/auth/otp/request", json={"email": "novo@ciphersong.app"})
    assert resp_429.status_code == 429

    # Recupera o código gerado em memória
    record = default_otp_manager._records["novo@ciphersong.app"]

    # 3. Código incorreto retorna 400
    resp_wrong = client.post("/api/auth/otp/verify", json={"email": "novo@ciphersong.app", "codigo": "000000"})
    assert resp_wrong.status_code == 400
    assert "Código incorreto" in resp_wrong.json()["detail"]

    # 4. Código correto autentica e cria conta passwordless
    # Extrai o código direto do histórico do email service
    from ciphersong.services.email_service import default_email_service
    last_code = default_email_service.sent_history[-1]["code"]

    resp_ok = client.post(
        "/api/auth/otp/verify",
        json={"email": "novo@ciphersong.app", "codigo": last_code, "nome": "Lucas"},
    )
    assert resp_ok.status_code == 200
    auth_data = resp_ok.json()
    assert auth_data["status"] == "success"
    assert "token" in auth_data
    assert auth_data["user"]["email"] == "novo@ciphersong.app"
    assert auth_data["user"]["nome"] == "Lucas"
    assert auth_data["user"]["provedor"] == "email_otp"

    # 5. Código já consumido não pode ser reutilizado
    resp_replay = client.post(
        "/api/auth/otp/verify",
        json={"email": "novo@ciphersong.app", "codigo": last_code},
    )
    assert resp_replay.status_code == 400


def test_google_user_blocked_from_otp(monkeypatch):
    fake_col = FakeUsersCollection()
    # Insere usuário cadastrado pelo Google Auth
    fake_col.insert_one({
        "email": "googleuser@gmail.com",
        "nome": "Google User",
        "provedor": "google",
    })
    mock_users_repo = UsuariosRepository(collection=fake_col)
    monkeypatch.setattr(backend_api, "get_users_repo", lambda: mock_users_repo)

    client = TestClient(backend_api.app)

    # Tenta solicitar OTP para e-mail do Google Auth -> Bloqueado
    resp = client.post("/api/auth/otp/request", json={"email": "googleuser@gmail.com"})
    assert resp.status_code == 400
    assert "Google" in resp.json()["detail"]
