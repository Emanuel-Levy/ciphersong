"""
Testes de Autenticação Segura e Isolamento de Repertório (`security-specialist` + `senior-architect`).
"""

import re
from unittest.mock import MagicMock
from bson import ObjectId
import pytest
from fastapi.testclient import TestClient

import backend_api
from ciphersong.database.mongo_connection import MusicasEnsaioRepository, UsuariosRepository
from ciphersong.security.auth import (
    create_access_token,
    decode_access_token,
    hash_password,
    validate_email,
    validate_password,
    verify_password,
)
from ciphersong.security.local_vault import EncryptedSessionVault


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
            if match and "$set" in update:
                d.update(update["$set"])
                break

    def find(self, query=None):
        query = query or {}
        results = []
        for d in self.docs:
            match = True
            for k, v in query.items():
                if isinstance(v, dict) and "$regex" in v:
                    pattern = v["$regex"].lower()
                    if pattern not in str(d.get(k, "")).lower():
                        match = False
                        break
                elif d.get(k) != v:
                    match = False
                    break
            if match:
                results.append(dict(d))
        res = MagicMock()
        res.sort.return_value = list(reversed(results))
        res.__iter__.return_value = list(reversed(results))
        return res

    def distinct(self, key):
        values = set()
        for d in self.docs:
            val = d.get(key)
            if val:
                values.add(val)
        return list(values)


def test_auth_crypto_primitives():
    # 1. Hashing e Verificação
    pwd = "MinhaSenhaForte@2026"
    hashed = hash_password(pwd)
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("SenhaErrada", hashed) is False

    # 2. Validação de Email e Senha
    assert validate_email("musico@ciphersong.com") is True
    assert validate_email("email-invalido") is False
    assert validate_email("") is False

    valid, _ = validate_password("123456")
    assert valid is True
    invalid, msg = validate_password("123")
    assert invalid is False
    assert "6 caracteres" in msg

    # 3. JWT Token
    token = create_access_token("user-123", "teste@ciphersong.com", "Levy")
    claims = decode_access_token(token)
    assert claims is not None
    assert claims["sub"] == "user-123"
    assert claims["email"] == "teste@ciphersong.com"
    assert claims["nome"] == "Levy"


def test_encrypted_vault_session(tmp_path):
    vault_file = tmp_path / "test_auth_vault.enc"
    vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="test-secret-key")

    assert vault.get_auth_session() is None

    session = vault.save_auth_session(
        user_id="usr_999",
        email="cantor@ciphersong.com",
        token="jwt.mock.token",
        nome="Cantor Teste",
    )
    assert session["user_id"] == "usr_999"

    loaded = vault.get_auth_session()
    assert loaded is not None
    assert loaded["token"] == "jwt.mock.token"
    assert loaded["email"] == "cantor@ciphersong.com"

    vault.clear_auth_session()
    assert vault.get_auth_session() is None


def test_auth_and_user_repertoire_api(monkeypatch):
    fake_users_col = FakeCollection()
    fake_songs_col = FakeCollection()

    mock_users_repo = UsuariosRepository(collection=fake_users_col)
    mock_songs_repo = MusicasEnsaioRepository(collection=fake_songs_col)

    monkeypatch.setattr(backend_api, "get_users_repo", lambda: mock_users_repo)
    monkeypatch.setattr(backend_api, "get_repo", lambda: mock_songs_repo)

    client = TestClient(backend_api.app)

    # 1. Registro de Usuário A
    reg_resp_a = client.post(
        "/api/auth/register",
        json={"email": "usuarioA@ciphersong.com", "senha": "password123", "nome": "Músico A"},
    )
    assert reg_resp_a.status_code == 201
    data_a = reg_resp_a.json()
    assert "token" in data_a
    token_a = data_a["token"]
    user_id_a = data_a["user"]["id"]

    # 2. Registro com e-mail duplicado deve falhar (409)
    dup_resp = client.post(
        "/api/auth/register",
        json={"email": "usuarioA@ciphersong.com", "senha": "outrasenha", "nome": "Outro"},
    )
    assert dup_resp.status_code == 409

    # 3. Login com senha errada (401)
    bad_login = client.post(
        "/api/auth/login",
        json={"email": "usuarioA@ciphersong.com", "senha": "senha-incorreta"},
    )
    assert bad_login.status_code == 401

    # 4. Login com senha correta (200)
    good_login = client.post(
        "/api/auth/login",
        json={"email": "usuarioA@ciphersong.com", "senha": "password123"},
    )
    assert good_login.status_code == 200
    assert "token" in good_login.json()

    # 5. Registro de Usuário B
    reg_resp_b = client.post(
        "/api/auth/register",
        json={"email": "usuarioB@ciphersong.com", "senha": "password123", "nome": "Músico B"},
    )
    assert reg_resp_b.status_code == 201
    token_b = reg_resp_b.json()["token"]

    # 6. Usuário A cadastra uma música com seu token
    song_resp_a = client.post(
        "/api/musicas",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "titulo": "Eu Navegarei",
            "cantor_principal": "Músico A",
            "tons": ["Am", "Em"],
            "versao": "Original",
        },
    )
    assert song_resp_a.status_code == 201

    # 7. Usuário B cadastra outra música com seu token
    song_resp_b = client.post(
        "/api/musicas",
        headers={"Authorization": f"Bearer {token_b}"},
        json={
            "titulo": "Bondade de Deus",
            "cantor_principal": "Músico B",
            "tons": ["G"],
            "versao": "Isaías Saad",
        },
    )
    assert song_resp_b.status_code == 201

    # 8. Listagem com Token A deve conter apenas as músicas do Usuário A
    list_a = client.get("/api/musicas", headers={"Authorization": f"Bearer {token_a}"})
    assert list_a.status_code == 200
    musicas_a = list_a.json()
    assert len(musicas_a) == 1
    assert musicas_a[0]["titulo"] == "Eu Navegarei"

    # 9. Listagem com Token B deve conter apenas as músicas do Usuário B
    list_b = client.get("/api/musicas", headers={"Authorization": f"Bearer {token_b}"})
    assert list_b.status_code == 200
    musicas_b = list_b.json()
    assert len(musicas_b) == 1
    assert musicas_b[0]["titulo"] == "Bondade de Deus"

    # 10. Rota /api/auth/me valida a identidade do usuário
    me_a = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    assert me_a.status_code == 200
    assert me_a.json()["email"] == "usuarioa@ciphersong.com"

    # 11. Login com Conta Google e escolha de Nome de Usuário
    google_resp = client.post(
        "/api/auth/google",
        json={"email": "levy.google@gmail.com", "nome": "Levy Oficial"},
    )
    assert google_resp.status_code == 200
    g_data = google_resp.json()
    assert g_data["user"]["nome"] == "Levy Oficial"
    assert g_data["user"]["provedor"] == "google"
    assert "token" in g_data

    # 12. Tentativa de cadastrar outro usuário com o MESMO nome deve ser rejeitada
    dup_name_resp = client.post(
        "/api/auth/register",
        json={"email": "outro_levy@ciphersong.com", "senha": "password123", "nome": "Levy Oficial"},
    )
    assert dup_name_resp.status_code == 409
    assert "já está em uso" in dup_name_resp.json()["detail"]

    # 13. Alterar Nome de Usuário via PUT /api/auth/nome
    change_resp = client.put(
        "/api/auth/nome",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"novo_nome": "Levy Tecladista"},
    )
    assert change_resp.status_code == 200
    change_data = change_resp.json()
    assert change_data["user"]["nome"] == "Levy Tecladista"
    new_token_a = change_data["token"]

    # Valida no endpoint /api/auth/me com o novo token
    me_updated = client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_token_a}"})
    assert me_updated.status_code == 200
    assert me_updated.json()["nome"] == "Levy Tecladista"

    # 14. Tentativa de mudar para um nome que já pertence a outro usuário
    conflict_change = client.put(
        "/api/auth/nome",
        headers={"Authorization": f"Bearer {new_token_a}"},
        json={"novo_nome": "Levy Oficial"},
    )
    assert conflict_change.status_code == 400
    assert "já está em uso" in conflict_change.json()["detail"]


def test_vault_update_auth_user_name(tmp_path):
    vault = EncryptedSessionVault(vault_path=tmp_path / ".vault.enc")
    vault.save_auth_session(
        user_id="user_123",
        email="musico@ciphersong.com",
        token="token_abc",
        name="Nome Antigo",
    )
    assert vault.get_auth_session()["name"] == "Nome Antigo"

    updated = vault.update_auth_user_name("Nome Novo", "novo_token_xyz")
    assert updated["name"] == "Nome Novo"
    assert updated["token"] == "novo_token_xyz"
    assert vault.get_auth_session()["name"] == "Nome Novo"


def test_vault_multi_user_database_isolation(tmp_path):
    """Garante que cada usuário possui um banco de dados local criptografado isolado."""
    vault = EncryptedSessionVault(base_dir=tmp_path)

    # 1. User A faz login e cadastra dados
    vault.save_auth_session(
        user_id="user_aaa",
        email="user_a@ciphersong.com",
        token="token_aaa",
        name="Usuário A",
    )
    vault.save_song(title="Música do Usuário A", keys=["G"], soloist="Cantor A")
    vault.save_weekly_item(
        musica_id="m_a1",
        titulo="Semana do Usuário A",
        cantor_principal="Cantor A",
        tom_selecionado="G",
        data_ensaio="2026-10-25",
        dia_semana="Domingo",
    )
    vault.save_a_ensaiar(
        titulo="Ensaio do Usuário A",
        cantor_versao="Cantor A",
        youtube_url="https://youtube.com/watch?v=aaa",
    )

    # Verifica que usuário A vê seus dados
    assert len(vault.load_songs()) == 1
    assert vault.load_songs()[0].title == "Música do Usuário A"
    assert len(vault.load_weekly_schedule("2026-10-25")) == 1
    assert len(vault.load_a_ensaiar()) == 1

    # 2. Usuário A faz logout
    vault.clear_auth_session()
    assert vault.get_auth_session() is None
    # No modo guest / desconectado, não vê as músicas privadas do Usuário A
    assert len(vault.load_songs()) == 0
    assert len(vault.load_weekly_schedule("2026-10-25")) == 0
    assert len(vault.load_a_ensaiar()) == 0

    # 3. Usuário B faz login na mesma máquina
    vault.save_auth_session(
        user_id="user_bbb",
        email="user_b@ciphersong.com",
        token="token_bbb",
        name="Usuário B",
    )
    # Usuário B não vê nenhuma música ou escala do Usuário A
    assert len(vault.load_songs()) == 0
    assert len(vault.load_weekly_schedule("2026-10-25")) == 0
    assert len(vault.load_a_ensaiar()) == 0

    # Usuário B cadastra seus próprios dados
    vault.save_song(title="Música do Usuário B", keys=["A"], soloist="Cantor B")
    vault.save_weekly_item(
        musica_id="m_b1",
        titulo="Semana do Usuário B",
        cantor_principal="Cantor B",
        tom_selecionado="A",
        data_ensaio="2026-10-25",
        dia_semana="Domingo",
    )
    assert len(vault.load_songs()) == 1
    assert vault.load_songs()[0].title == "Música do Usuário B"
    assert len(vault.load_weekly_schedule("2026-10-25")) == 1
    assert vault.load_weekly_schedule("2026-10-25")[0].titulo == "Semana do Usuário B"

    # 4. Usuário B faz logout e Usuário A faz login novamente
    vault.clear_auth_session()
    vault.save_auth_session(
        user_id="user_aaa",
        email="user_a@ciphersong.com",
        token="token_aaa_new",
        name="Usuário A",
    )
    # Usuário A recupera seu próprio repertório intacto e sem dados do Usuário B
    assert len(vault.load_songs()) == 1
    assert vault.load_songs()[0].title == "Música do Usuário A"
    assert len(vault.load_weekly_schedule("2026-10-25")) == 1
    assert vault.load_weekly_schedule("2026-10-25")[0].titulo == "Semana do Usuário A"

    # 5. Verifica existência de arquivos separados e criptografados
    enc_files = list(tmp_path.glob("*.enc"))
    assert len(enc_files) >= 3  # session + vault_user_a + vault_user_b




