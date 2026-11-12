"""
Testes automatizados para os endpoints de Billing e Webhooks da Stripe (`senior-architect` + `security-specialist`).
"""

import json
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend_api import app, get_users_repo
from ciphersong.security.auth import create_access_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_header():
    # Cria usuário mock no repositório
    users_repo = get_users_repo()
    test_email = "billing_tester@ciphersong.com.br"
    user = users_repo.buscar_por_email(test_email)
    if not user:
        try:
            user = users_repo.criar_usuario(test_email, "hash_senha_teste_123", "Billing Tester")
        except Exception:
            user = users_repo.buscar_por_email(test_email)
    user_id = str(user["_id"])
    token = create_access_token(user_id, test_email)
    return {"Authorization": f"Bearer {token}"}, user_id


def test_billing_status_requires_auth(client):
    res = client.get("/api/billing/status")
    assert res.status_code == 401


def test_billing_status_authenticated(client, auth_header):
    headers, user_id = auth_header
    res = client.get("/api/billing/status", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "stripe_configured" in data
    assert "plano" in data
    assert "status" in data
    assert data["plano"] in ("free", "pro", "ministerio")


def test_create_checkout_session_missing_key(client, auth_header, monkeypatch):
    headers, _ = auth_header
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    res = client.post(
        "/api/billing/create-checkout-session",
        headers=headers,
        json={"plan": "pro", "cycle": "mensal"},
    )
    assert res.status_code == 503
    assert "STRIPE_SECRET_KEY" in res.json()["detail"]


def test_create_checkout_session_success(client, auth_header, monkeypatch):
    headers, user_id = auth_header
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_mock_key_12345")

    mock_session = MagicMock()
    mock_session.url = "https://checkout.stripe.com/c/pay/cs_test_mock_123"
    mock_session.id = "cs_test_mock_123"

    with patch("stripe.checkout.Session.create", return_value=mock_session) as mock_create:
        res = client.post(
            "/api/billing/create-checkout-session",
            headers=headers,
            json={"plan": "pro", "cycle": "anual"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["url"] == "https://checkout.stripe.com/c/pay/cs_test_mock_123"
        assert data["session_id"] == "cs_test_mock_123"
        mock_create.assert_called_once()


def test_create_portal_session_no_customer(client, auth_header, monkeypatch):
    headers, user_id = auth_header
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_mock_key_12345")

    # Garante que o usuário não possui stripe_customer_id
    users_repo = get_users_repo()
    users_repo.atualizar_assinatura(user_id, {"plano": "free", "status": "free", "stripe_customer_id": None})

    res = client.post(
        "/api/billing/create-portal-session",
        headers=headers,
        json={"return_url": "https://ciphersong.com.br/settings"},
    )
    assert res.status_code == 400
    assert "Nenhuma assinatura ou cliente Stripe" in res.json()["detail"]


def test_create_portal_session_success(client, auth_header, monkeypatch):
    headers, user_id = auth_header
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_mock_key_12345")

    users_repo = get_users_repo()
    users_repo.atualizar_assinatura(user_id, {
        "plano": "pro",
        "status": "active",
        "stripe_customer_id": "cus_mock_test_456",
    })

    mock_portal = MagicMock()
    mock_portal.url = "https://billing.stripe.com/p/session/portal_test_123"

    with patch("stripe.billing_portal.Session.create", return_value=mock_portal) as mock_portal_create:
        res = client.post(
            "/api/billing/create-portal-session",
            headers=headers,
            json={"return_url": "https://ciphersong.com.br/settings"},
        )
        assert res.status_code == 200
        assert res.json()["url"] == "https://billing.stripe.com/p/session/portal_test_123"
        mock_portal_create.assert_called_once()


def test_webhook_checkout_session_completed(client, auth_header, monkeypatch):
    headers, user_id = auth_header
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_mock_key")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)

    payload = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_webhook_test_789",
                "subscription": "sub_webhook_test_123",
                "client_reference_id": user_id,
                "metadata": {
                    "usuario_id": user_id,
                    "plano": "ministerio",
                    "ciclo": "anual",
                },
            }
        },
    }

    res = client.post("/api/webhooks/stripe", json=payload)
    assert res.status_code == 200
    assert res.json()["received"] is True

    # Verifica se o MongoDB foi atualizado com o novo plano e customer_id
    users_repo = get_users_repo()
    updated_user = users_repo.buscar_por_id(user_id)
    sub = updated_user.get("assinatura", {})
    assert sub.get("plano") == "ministerio"
    assert sub.get("status") == "active"
    assert sub.get("stripe_customer_id") == "cus_webhook_test_789"


def test_webhook_live_requires_secret(client, auth_header, monkeypatch):
    headers, user_id = auth_header
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_mock_production_key")
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)

    res = client.post("/api/webhooks/stripe", json={"type": "test"})
    assert res.status_code == 500
    assert "STRIPE_WEBHOOK_SECRET obrigatório" in res.json()["detail"]


def test_schedule_downgrade_requires_ministerio(client, auth_header, monkeypatch):
    headers, user_id = auth_header
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_mock_key_12345")

    # Define usuário como Pro
    users_repo = get_users_repo()
    users_repo.atualizar_assinatura(user_id, {
        "plano": "pro",
        "status": "active",
        "stripe_subscription_id": "sub_test_pro_123",
    })

    res = client.post(
        "/api/billing/schedule-downgrade",
        headers=headers,
        json={"target_plan": "pro", "target_cycle": "mensal"},
    )
    assert res.status_code == 400
    assert "só se aplica a assinantes ativos do Plano Ministério" in res.json()["detail"]


def test_schedule_downgrade_success(client, auth_header, monkeypatch):
    headers, user_id = auth_header
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_mock_key_12345")
    monkeypatch.setenv("STRIPE_PRICE_PRO_MONTHLY", "price_test_pro_monthly_123")

    # Define usuário como Ministério com assinatura ativa
    users_repo = get_users_repo()
    users_repo.atualizar_assinatura(user_id, {
        "plano": "ministerio",
        "ciclo": "anual",
        "status": "active",
        "stripe_customer_id": "cus_test_123",
        "stripe_subscription_id": "sub_test_ministerio_123",
        "expira_em": "2027-11-12T00:00:00+00:00",
    })

    mock_sub = {
        "id": "sub_test_ministerio_123",
        "current_period_end": 1826064000,
        "items": {"data": [{"id": "si_mock_item_123"}]},
        "metadata": {},
    }

    with patch("stripe.Subscription.retrieve", return_value=mock_sub), \
         patch("stripe.Subscription.modify", return_value=mock_sub) as mock_modify:
        res = client.post(
            "/api/billing/schedule-downgrade",
            headers=headers,
            json={"target_plan": "pro", "target_cycle": "mensal"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "downgrade_agendado" in data
        assert data["downgrade_agendado"]["plano_alvo"] == "pro"
        assert data["downgrade_agendado"]["ciclo_alvo"] == "mensal"

        # Verifica chamada ao Stripe com proration_behavior="none"
        mock_modify.assert_called_once()
        modify_args = mock_modify.call_args[1]
        assert modify_args["proration_behavior"] == "none"

    # Confirma que no banco o plano continua "ministerio" até o término do ciclo
    user_db = users_repo.buscar_por_id(user_id)
    sub_db = user_db.get("assinatura", {})
    assert sub_db.get("plano") == "ministerio"
    assert sub_db.get("downgrade_agendado") is not None
    assert sub_db["downgrade_agendado"]["plano_alvo"] == "pro"

    # E que o endpoint de status retorna downgrade_agendado
    res_status = client.get("/api/billing/status", headers=headers)
    assert res_status.status_code == 200
    assert res_status.json()["downgrade_agendado"] is not None


def test_cancel_downgrade_success(client, auth_header, monkeypatch):
    headers, user_id = auth_header
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_mock_key_12345")
    monkeypatch.setenv("STRIPE_PRICE_MINISTERIO_ANUAL", "price_test_min_anual_123")

    users_repo = get_users_repo()
    users_repo.atualizar_assinatura(user_id, {
        "plano": "ministerio",
        "ciclo": "anual",
        "status": "active",
        "stripe_subscription_id": "sub_test_ministerio_123",
        "downgrade_agendado": {
            "plano_alvo": "pro",
            "ciclo_alvo": "mensal",
            "data_efetiva": "2027-11-12T00:00:00+00:00",
        },
    })

    mock_sub = {
        "id": "sub_test_ministerio_123",
        "items": {"data": [{"id": "si_mock_item_123"}]},
        "metadata": {},
    }

    with patch("stripe.Subscription.retrieve", return_value=mock_sub), \
         patch("stripe.Subscription.modify", return_value=mock_sub) as mock_modify:
        res = client.post("/api/billing/cancel-downgrade", headers=headers)
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        mock_modify.assert_called_once()
        assert mock_modify.call_args[1]["proration_behavior"] == "none"

    # Confirma que downgrade_agendado foi limpo e o plano continua ministerio
    user_db = users_repo.buscar_por_id(user_id)
    sub_db = user_db.get("assinatura", {})
    assert sub_db.get("plano") == "ministerio"
    assert sub_db.get("downgrade_agendado") is None
