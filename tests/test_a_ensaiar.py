"""
Testes unitários e de integração para a aba 'A Ensaiar' (Músicas para o Próximo Ensaio).
"""

import pytest
from fastapi.testclient import TestClient

from backend_api import app
from ciphersong.database.mongo_connection import MusicasAEnsaiarRepository
from ciphersong.security.local_vault import EncryptedSessionVault


@pytest.fixture
def api_test_client():
    return TestClient(app)


def test_a_ensaiar_repository_mock():
    """Testa o repositório MusicasAEnsaiarRepository com mock de coleção MongoDB."""
    mock_storage = []

    class MockCollection:
        def insert_one(self, doc):
            doc["_id"] = f"mock_a_{len(mock_storage) + 1}"
            mock_storage.append(dict(doc))
            class Res:
                inserted_id = doc["_id"]
            return Res()

        def find(self, query=None):
            results = list(mock_storage)
            class MockCursor:
                def sort(self, *args, **kwargs):
                    return results
                def __iter__(self):
                    return iter(results)
            return MockCursor()

        def delete_one(self, query):
            target = str(query.get("_id"))
            for i, it in enumerate(mock_storage):
                if str(it.get("_id")) == target:
                    mock_storage.pop(i)
                    class Res:
                        deleted_count = 1
                    return Res()
            class Res:
                deleted_count = 0
            return Res()

    repo = MusicasAEnsaiarRepository(collection=MockCollection())

    # 1. Adicionar música a ensaiar
    doc = repo.adicionar_musica(
        titulo="Ruja o Leão",
        cantor_versao="Talita Catanzaro / Ao Vivo",
        youtube_url="https://www.youtube.com/watch?v=mock123",
        status="Próximo Ensaio",
        adicionado_por="Levy",
    )
    assert doc["titulo"] == "Ruja o Leão"
    assert doc["status"] == "Próximo Ensaio"
    assert doc["youtube_url"] == "https://www.youtube.com/watch?v=mock123"

    # 2. Listar todas
    todas = repo.listar_todas()
    assert len(todas) == 1
    assert todas[0]["cantor_versao"] == "Talita Catanzaro / Ao Vivo"

    # 3. Remover
    removido = repo.remover_musica(doc["_id"])
    assert removido is True
    assert len(repo.listar_todas()) == 0


def test_a_ensaiar_local_vault(tmp_path):
    """Testa salvar, listar e excluir no cofre local criptografado."""
    vault_file = tmp_path / "test_a_ensaiar.enc"
    vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="test-passphrase")

    rec = vault.save_a_ensaiar(
        titulo="Lindo Momento",
        cantor_versao="Julliany Souza / Acústico",
        youtube_url="https://youtube.com/watch?v=mock456",
        adicionado_por="Geisa",
    )
    assert rec.titulo == "Lindo Momento"
    assert rec.status == "Próximo Ensaio"

    carregadas = vault.load_a_ensaiar()
    assert len(carregadas) == 1
    assert carregadas[0].titulo == "Lindo Momento"

    atualizadas = vault.delete_a_ensaiar(rec.id)
    assert len(atualizadas) == 0


def test_api_routes_a_ensaiar(api_test_client, monkeypatch):
    """Testa os endpoints REST /api/a-ensaiar (POST, GET, DELETE)."""
    fake_db = []

    class MockAEnsaiarRepo:
        def __init__(self, *args, **kwargs):
            self.collection = None

        def listar_todas(self):
            return list(fake_db)

        def adicionar_musica(self, **kwargs):
            doc = dict(kwargs)
            doc["_id"] = f"a_{len(fake_db) + 1}"
            fake_db.append(doc)
            return doc

        def remover_musica(self, item_id, *args, **kwargs):
            for i, d in enumerate(fake_db):
                if d["_id"] == item_id:
                    fake_db.pop(i)
                    return True
            return False

    monkeypatch.setattr("backend_api.get_a_ensaiar_repo", lambda: MockAEnsaiarRepo())

    # 1. POST
    payload = {
        "titulo": "Bondade de Deus",
        "cantor_versao": "Isaías Saad / Versão Oficial",
        "youtube_url": "https://youtu.be/abcdef",
        "adicionado_por": "Levy",
    }
    resp_post = api_test_client.post("/api/a-ensaiar", json=payload)
    assert resp_post.status_code == 201
    created = resp_post.json()
    assert created["titulo"] == "Bondade de Deus"
    assert created["status"] == "Próximo Ensaio"

    # 2. GET
    resp_get = api_test_client.get("/api/a-ensaiar")
    assert resp_get.status_code == 200
    lista = resp_get.json()
    assert len(lista) == 1
    assert lista[0]["youtube_url"] == "https://youtu.be/abcdef"

    # 3. DELETE
    resp_del = api_test_client.delete(f"/api/a-ensaiar/{created['_id']}")
    assert resp_del.status_code == 200
    assert resp_del.json()["deleted"] is True


def test_a_ensaiar_fallback_single_delete():
    """Garante que a exclusão na aba Ensaio funcione na primeira tentativa via fallback de título e versão."""
    mock_storage = []

    class MockCollection:
        def insert_one(self, doc):
            doc["_id"] = "cloud_mongo_id_999"
            mock_storage.append(dict(doc))
            class Res:
                inserted_id = doc["_id"]
            return Res()

        def delete_one(self, query):
            # Tenta casar por _id
            target_id = query.get("_id")
            if target_id is not None:
                for i, it in enumerate(mock_storage):
                    if it.get("_id") == target_id:
                        mock_storage.pop(i)
                        class Res:
                            deleted_count = 1
                        return Res()
            # Tenta casar por regex de titulo
            if "titulo" in query:
                regex_pattern = query["titulo"].get("$regex", "")
                import re
                for i, it in enumerate(mock_storage):
                    if re.search(regex_pattern, it.get("titulo", ""), re.IGNORECASE):
                        mock_storage.pop(i)
                        class Res:
                            deleted_count = 1
                        return Res()
            class Res:
                deleted_count = 0
            return Res()

        def find(self, query=None):
            results = list(mock_storage)
            class MockCursor:
                def sort(self, *args, **kwargs):
                    return results
                def __iter__(self):
                    return iter(results)
            return MockCursor()

    repo = MusicasAEnsaiarRepository(collection=MockCollection())
    doc = repo.adicionar_musica(
        titulo="Ruja o Leão",
        cantor_versao="Talita Catanzaro",
        youtube_url="https://youtube.com/watch?v=123",
    )
    assert len(mock_storage) == 1

    # Tenta remover passando ID local não sincronizado ("local_random_id_x1") mas com título e versão
    deleted = repo.remover_musica(
        item_id="local_random_id_x1",
        titulo="Ruja o Leão",
        cantor_versao="Talita Catanzaro",
    )
    assert deleted is True
    assert len(mock_storage) == 0


def test_bottom_nav_four_tabs_and_no_detector():
    """Garante que a barra de navegação possui 4 abas (sem Detector) e inicializa em 'songs'."""
    from unittest.mock import MagicMock
    from ciphersong.ui.navigation import BottomNavBarManager

    mock_page = MagicMock()
    tab_changed = []
    nav = BottomNavBarManager(page=mock_page, on_tab_change=lambda t: tab_changed.append(t))

    assert nav.current_tab == "songs"
    assert not hasattr(nav, "tab_item_detector")
    assert hasattr(nav, "tab_item_songs")
    assert hasattr(nav, "tab_item_weekly")
    assert hasattr(nav, "tab_item_to_rehearse")
    assert hasattr(nav, "tab_item_team")
    assert len(nav.dock.content.controls) == 4
    assert nav.dock.content.controls[0] == nav.tab_item_songs
    assert nav.dock.content.controls[1] == nav.tab_item_weekly
    assert nav.dock.content.controls[2] == nav.tab_item_to_rehearse
    assert nav.dock.content.controls[3] == nav.tab_item_team


def test_delete_a_ensaiar_local_vault_fallback(tmp_path):
    """Garante exclusão no cofre local por fallback de título mesmo com ID divergente."""
    vault_file = tmp_path / "test_a_ensaiar_fb.enc"
    vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="test-passphrase")

    rec = vault.save_a_ensaiar(
        titulo="Bondade de Deus",
        cantor_versao="Isaías Saad",
        youtube_url="https://youtube.com/watch?v=mock789",
    )
    assert len(vault.load_a_ensaiar()) == 1

    # Deleta passando um ID falso mas com o título correto
    vault.delete_a_ensaiar("fake_id_123", titulo="Bondade de Deus", cantor_versao="Isaías Saad")
    assert len(vault.load_a_ensaiar()) == 0
