"""
Testes de Vinculação entre Conta por E-mail e Login com o Google (AppSec + Core Database).
Garante que usuários que criaram conta com e-mail possam logar com o Google sem erros de colisão de nome
e sem perda de dados ou identidade.
"""

from unittest.mock import MagicMock
from bson import ObjectId
import pytest
from fastapi.testclient import TestClient

import backend_api
from ciphersong.database.mongo_connection import UsuariosRepository
from ciphersong.security.auth import hash_password


class FakeCollection:
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
        import re
        for d in self.docs:
            match = True
            for k, v in query.items():
                if isinstance(v, dict) and "$regex" in v:
                    pattern = v["$regex"]
                    flags = re.IGNORECASE if v.get("$options") == "i" else 0
                    if not re.search(pattern, str(d.get(k, "")), flags):
                        match = False
                        break
                elif d.get(k) != v:
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
            if match:
                if "$set" in update:
                    d.update(update["$set"])
                res = MagicMock()
                res.modified_count = 1
                return res
        res = MagicMock()
        res.modified_count = 0
        return res


def test_user_email_then_google_login():
    fake_col = FakeCollection()
    repo = UsuariosRepository(collection=fake_col)

    # 1. Usuário cria conta com e-mail e senha
    user_email = "musico@ciphersong.com"
    u_created = repo.criar_usuario(
        email=user_email,
        senha_hash=hash_password("minhasenha123"),
        nome="Musico Original",
        provedor="email",
    )
    assert u_created["email"] == user_email
    assert u_created["nome"] == "Musico Original"
    assert u_created["provedor"] == "email"
    original_id = str(u_created["_id"])

    # 2. Outro usuário qualquer já cadastrado no banco tem o nome "João Google"
    repo.criar_usuario(
        email="outro@ciphersong.com",
        senha_hash="hash",
        nome="João Google",
        provedor="email",
    )

    # 3. Usuário original faz login com o Google com o mesmo e-mail,
    # e o perfil do Google vem com o nome "João Google" (que colidiria caso não houvesse o tratamento)
    google_hash = hash_password(f"google-oauth2::{user_email}")
    u_google = repo.autenticar_ou_criar_google(
        email=user_email,
        nome="João Google",
        google_token_hash=google_hash,
        foto_url="https://lh3.googleusercontent.com/a/avatar.jpg",
    )

    # 4. Verificações:
    # - O ID da conta permanece o mesmo (mesmo usuário, mesmo repertório)
    assert str(u_google["_id"]) == original_id
    assert u_google["email"] == user_email
    # - O nome original é preservado sem lançar exceção de colisão
    assert u_google["nome"] == "Musico Original"
    # - A conta é marcada com vínculo do Google
    assert u_google.get("google_vinculado") is True
    # - A foto do perfil vinda do Google foi aproveitada
    assert u_google.get("foto_url") == "https://lh3.googleusercontent.com/a/avatar.jpg"


def test_google_login_api_endpoint(monkeypatch):
    fake_col = FakeCollection()
    mock_users_repo = UsuariosRepository(collection=fake_col)

    # Cria usuário previamente por e-mail
    user_email = "guitarrista@ciphersong.com"
    u_created = mock_users_repo.criar_usuario(
        email=user_email,
        senha_hash=hash_password("senha123"),
        nome="Guitarrista Solo",
        provedor="email",
    )

    monkeypatch.setattr(backend_api, "get_users_repo", lambda: mock_users_repo)
    client = TestClient(backend_api.app)

    # Chama o endpoint de login com o Google
    resp = client.post(
        "/api/auth/google",
        json={"email": user_email, "nome": "Guitarrista Google"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "token" in data
    assert data["user"]["email"] == user_email
    assert data["user"]["id"] == str(u_created["_id"])
    assert data["user"]["google_vinculado"] is True


def test_new_user_google_name_collision():
    fake_col = FakeCollection()
    repo = UsuariosRepository(collection=fake_col)

    # Cria usuário com nome "Lucas"
    repo.criar_usuario(
        email="lucas1@ciphersong.com",
        senha_hash="hash",
        nome="Lucas",
        provedor="email",
    )

    # Novo usuário com Google também se chama "Lucas"
    # Não deve quebrar com erro 500/ValueError, deve gerar Lucas_1
    new_user = repo.autenticar_ou_criar_google(
        email="lucas2@ciphersong.com",
        nome="Lucas",
        google_token_hash="ghash",
    )
    assert new_user["email"] == "lucas2@ciphersong.com"
    assert new_user["nome"] == "Lucas_1"
    assert new_user.get("provedor") == "google"
