"""
Suite de Testes de Segurança Geral (Security Audit Skill - OWASP / AppSec).
Verifica criptografia, isolamento IDOR, proteção contra NoSQL Injection,
privacidade vocal em RAM e isolamento de segredos para APK Mobile.
"""

from pathlib import Path
from unittest.mock import MagicMock
from bson import ObjectId
import pytest
from fastapi.testclient import TestClient

import backend_api
from ciphersong.database.mongo_connection import MusicasEnsaioRepository, UsuariosRepository
from ciphersong.security.auth import (
    PBKDF2_ITERATIONS,
    SALT_SIZE_BYTES,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from ciphersong.security.local_vault import EncryptedSessionVault
from ciphersong.services.microphone_stream import LiveMicrophoneService


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
                if d.get(k) != v:
                    match = False
                    break
            if match:
                return dict(d)
        return None

    def find(self, query=None):
        query = query or {}
        results = []
        for d in self.docs:
            match = True
            for k, v in query.items():
                if isinstance(v, dict) and "$regex" in v:
                    pattern = v["$regex"]
                    # Simula comportamento do regex compilado
                    import re
                    if not re.search(pattern, str(d.get(k, "")), re.IGNORECASE):
                        match = False
                        break
                elif d.get(k) != v:
                    match = False
                    break
            if match:
                results.append(dict(d))
        res = MagicMock()
        res.sort.return_value = results
        res.__iter__.return_value = results
        return res

    def delete_one(self, query):
        initial_len = len(self.docs)
        new_docs = []
        deleted = 0
        for d in self.docs:
            match = True
            for k, v in query.items():
                if d.get(k) != v:
                    match = False
                    break
            if match and deleted == 0:
                deleted += 1
            else:
                new_docs.append(d)
        self.docs = new_docs
        res = MagicMock()
        res.deleted_count = deleted
        return res


def test_audit_cryptographic_standards():
    """Valida requisitos de AppSec para algoritmos e parâmetros criptográficos."""
    assert PBKDF2_ITERATIONS >= 600_000, "OWASP exige no mínimo 600.000 iterações para PBKDF2-HMAC-SHA256"
    assert SALT_SIZE_BYTES >= 16, "O sal criptográfico deve ter pelo menos 16 bytes (128 bits)"

    pwd = "AuditSecretPassword@2026"
    h1 = hash_password(pwd)
    h2 = hash_password(pwd)
    # Dois hashes da mesma senha devem ser diferentes devido ao sal aleatório único
    assert h1 != h2, "O sal deve ser aleatório e único a cada hash gerado"
    assert verify_password(pwd, h1) is True
    assert verify_password(pwd, h2) is True
    assert verify_password("WrongPassword", h1) is False


def test_audit_jwt_integrity_and_tamper_resistance():
    """Valida rejeição de tokens forjados ou adulterados."""
    token = create_access_token("user-777", "sec@ciphersong.com", "Auditor")
    valid = decode_access_token(token)
    assert valid is not None
    assert valid["sub"] == "user-777"

    # 1. Adulteração de assinatura
    tampered_sig = token[:-4] + "AAAA"
    assert decode_access_token(tampered_sig) is None, "Token com assinatura alterada deve ser rejeitado"

    # 2. Token malformado
    assert decode_access_token("not.a.valid.jwt") is None
    assert decode_access_token("") is None


def test_audit_idor_protection_on_delete_song(monkeypatch):
    """Garante que um usuário não possa deletar músicas pertencentes a outro usuário (IDOR)."""
    fake_songs_col = FakeCollection()
    fake_users_col = FakeCollection()

    mock_songs_repo = MusicasEnsaioRepository(collection=fake_songs_col)
    mock_users_repo = UsuariosRepository(collection=fake_users_col)

    monkeypatch.setattr(backend_api, "get_repo", lambda: mock_songs_repo)
    monkeypatch.setattr(backend_api, "get_users_repo", lambda: mock_users_repo)

    client = TestClient(backend_api.app)

    # Cria tokens para dois usuários distintos
    token_victim = create_access_token("victim_id", "vitima@ciphersong.com", "Vítima")
    token_attacker = create_access_token("attacker_id", "atacante@ciphersong.com", "Atacante")

    # Vítima cadastra uma música
    create_resp = client.post(
        "/api/musicas",
        headers={"Authorization": f"Bearer {token_victim}"},
        json={
            "titulo": "Música Protegida",
            "cantor_principal": "Vítima",
            "tons": ["C"],
            "versao": "Original",
        },
    )
    assert create_resp.status_code == 201
    song_id = create_resp.json()["_id"]

    # Atacante tenta deletar a música da vítima com seu próprio token
    del_attack = client.delete(
        f"/api/musicas/{song_id}",
        headers={"Authorization": f"Bearer {token_attacker}"},
    )
    assert del_attack.status_code == 403, "Tentativa de IDOR para deletar recurso de outro usuário deve retornar 403 Forbidden"

    # Vítima deleta a própria música com sucesso
    del_legit = client.delete(
        f"/api/musicas/{song_id}",
        headers={"Authorization": f"Bearer {token_victim}"},
    )
    assert del_legit.status_code == 200
    assert del_legit.json()["deleted"] is True


def test_audit_nosql_regex_sanitization():
    """Garante que caracteres especiais de Regex sejam neutralizados com re.escape contra injeção e ReDoS."""
    fake_col = FakeCollection()
    repo = MusicasEnsaioRepository(collection=fake_col)
    fake_col.insert_one({"titulo": "Normal Song", "cantor_principal": "Cantor", "tons": ["G"], "versao": "Original"})

    # Busca com metacaracteres de regex não deve causar erro nem injeção
    res = repo.buscar_por_filtro(termo=".*|^$|([a-z]+)+")
    assert isinstance(res, list)
    assert len(res) == 0  # Não deve casar "Normal Song" pois busca literalmente pelos caracteres especiais


def test_audit_vault_tamper_detection(tmp_path):
    """Garante que o cofre AES-256-GCM detecta qualquer adulteração física no arquivo cifrado."""
    vault_file = tmp_path / "tamper_test.enc"
    vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="passphrase-audit-2026")

    vault.save_song(title="Hino Santo", keys=["A"], soloist="Levy")
    assert len(vault.load_songs()) == 1

    # Corrompe intencionalmente o ciphertext no arquivo
    import json
    raw = json.loads(vault_file.read_text(encoding="utf-8"))
    ct = list(raw["ciphertext"])
    ct[10] = "X" if ct[10] != "X" else "Y"
    raw["ciphertext"] = "".join(ct)
    vault_file.write_text(json.dumps(raw), encoding="utf-8")

    # A decodificação com tag GCM inválida é rejeitada e não vaza dados
    tampered_vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="passphrase-audit-2026")
    assert tampered_vault.load_songs() == []


def test_audit_apk_packaging_security_boundaries():
    """Verifica se os arquivos sensíveis de servidor (.env e backend_api.py) estão protegidos contra inclusão no APK."""
    pyproject_path = Path("pyproject.toml")
    assert pyproject_path.exists(), "pyproject.toml deve existir"
    content = pyproject_path.read_text(encoding="utf-8")

    # Verifica lista de exclusão do Flet
    assert '".env"' in content, ".env DEVE estar na lista de exclusão do pacote da aplicação"
    assert '"backend_api.py"' in content, "backend_api.py DEVE estar na lista de exclusão do APK mobile"

    gitignore_path = Path(".gitignore")
    assert gitignore_path.exists()
    gi_content = gitignore_path.read_text(encoding="utf-8")
    assert ".env" in gi_content, ".env DEVE estar listado no .gitignore"


def test_audit_youtube_url_sanitization_against_xss_and_invalid_schemes():
    """Garante que links de YouTube rejeitem esquemas maliciosos (javascript:, data:, file:) e normalizem HTTPS."""
    from ciphersong.security.local_vault import sanitize_youtube_url

    assert sanitize_youtube_url("") == ""
    assert sanitize_youtube_url(None) == ""
    assert sanitize_youtube_url("youtube.com/watch?v=abc123") == "https://youtube.com/watch?v=abc123"
    assert sanitize_youtube_url("https://youtu.be/xyz987") == "https://youtu.be/xyz987"

    for malicious in [
        "javascript:alert(document.cookie)",
        "JAVASCRIPT:evil()",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
    ]:
        with pytest.raises(ValueError):
            sanitize_youtube_url(malicious)


def test_audit_vault_memory_and_kdf_cache_performance(tmp_path):
    """Garante que o cache de chave PBKDF2 e store em RAM funcionam sem perder integridade."""
    vault_file = tmp_path / "perf_vault.enc"
    vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="fast-secure-key")

    vault.save_song(title="Oceanos", keys=["D", "Bm"], soloist="Geisa")
    assert vault._cached_key is not None
    assert vault._memory_store is not None

    # Leituras subsequentes usam o cache O(1) em RAM
    songs_1 = vault.load_songs()
    songs_2 = vault.load_songs()
    assert len(songs_1) == 1
    assert songs_1[0].title == "Oceanos"
    assert songs_2[0].soloist == "Geisa"


def test_audit_traceback_sanitizer_removes_developer_paths():
    """Valida que caminhos de desenvolvimento (ex: C:\\Users\\Levy\\...) são removidos de tracebacks."""
    from main import sanitize_traceback

    raw_tb = (
        'File "C:\\Users\\Levy\\Documents\\CipherSong\\build\\site-packages\\arm64-v8a\\flet\\messaging\\session.py", line 459, in dispatch_event\n'
        'File "C:\\Users\\Levy\\AppData\\Local\\Temp\\serious_python_temp72b27b55\\ciphersong\\ui\\app_flet.py", line 3104, in confirm_add_weekly_song\n'
        'UnboundLocalError: cannot access local variable \'unseen_weekly_count\' where it is not associated with a value'
    )
    clean_tb = sanitize_traceback(raw_tb)
    assert "Levy" not in clean_tb
    assert "serious_python_temp" not in clean_tb
    assert "C:\\Users" not in clean_tb
    assert "/site-packages/flet/messaging/session.py" in clean_tb
    assert "/ciphersong/ui/app_flet.py" in clean_tb


def test_audit_vault_concurrent_threads_safety_and_atomicity(tmp_path):
    """
    Valida que múltiplas threads gravando simultaneamente em coleções distintas
    (songs, weekly, a_ensaiar, notifications_meta) do mesmo EncryptedSessionVault
    não sofrem Lost Update nem corrompem o arquivo AES-256-GCM.
    """
    import threading

    vault_file = tmp_path / "concurrent_vault.enc"
    vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="thread-safe-key-2026")
    errors: list[Exception] = []

    def _worker_songs() -> None:
        try:
            for i in range(10):
                vault.save_song(
                    title=f"Song Thread {i}",
                    keys=["C", "G"],
                    soloist="Cantor A",
                    equipe_id="eq1",
                )
        except Exception as exc:
            errors.append(exc)

    def _worker_weekly() -> None:
        try:
            for i in range(10):
                vault.save_weekly_item(
                    musica_id=f"m_{i}",
                    titulo=f"Weekly Thread {i}",
                    cantor_principal="Cantor B",
                    tom_selecionado="D",
                    data_ensaio="2026-10-25",
                    dia_semana="Domingo",
                    equipe_id="eq1",
                )
        except Exception as exc:
            errors.append(exc)

    def _worker_a_ensaiar() -> None:
        try:
            for i in range(10):
                vault.save_a_ensaiar(
                    titulo=f"ToRehearse Thread {i}",
                    cantor_versao="Versão C",
                    equipe_id="eq1",
                )
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=_worker_songs),
        threading.Thread(target=_worker_weekly),
        threading.Thread(target=_worker_a_ensaiar),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15.0)

    assert errors == [], f"Erros de concorrência detectados: {errors}"
    assert len(vault.load_songs(equipe_id="eq1")) == 10
    assert len(vault.load_weekly_schedule(data_ensaio="2026-10-25", equipe_id="eq1")) == 10
    assert len(vault.load_a_ensaiar(equipe_id="eq1")) == 10


