"""
Testes unitários e de integração para o Repertório da Semana (Escala Compartilhada).
"""

from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient

from backend_api import app, get_semana_repo
from ciphersong.database.mongo_connection import RepertorioSemanaRepository
from ciphersong.security.local_vault import EncryptedSessionVault
from ciphersong.services.api_client import SongsApiClient


@pytest.fixture
def api_test_client():
    return TestClient(app)


def test_repertorio_semana_repository_mock(monkeypatch):
    """Testa o repositório RepertorioSemanaRepository com um mock de coleção MongoDB."""
    mock_storage = []

    class MockCollection:
        def insert_one(self, doc):
            doc["_id"] = f"mock_id_{len(mock_storage) + 1}"
            mock_storage.append(dict(doc))
            class Res:
                inserted_id = doc["_id"]
            return Res()

        def find(self, query=None):
            results = []
            for item in mock_storage:
                match = True
                if query:
                    if "data_ensaio" in query:
                        val = query["data_ensaio"]
                        if isinstance(val, dict):
                            gte = val.get("$gte")
                            lte = val.get("$lte")
                            if gte and item.get("data_ensaio", "") < gte:
                                match = False
                            if lte and item.get("data_ensaio", "") > lte:
                                match = False
                        else:
                            if item.get("data_ensaio") != val:
                                match = False
                if match:
                    results.append(dict(item))
            class MockCursor:
                def sort(self, *args, **kwargs):
                    return results
                def __iter__(self):
                    return iter(results)
            return MockCursor()

        def delete_one(self, query):
            from bson import ObjectId
            target = query.get("_id")
            for i, it in enumerate(mock_storage):
                if str(it.get("_id")) == str(target):
                    mock_storage.pop(i)
                    class Res:
                        deleted_count = 1
                    return Res()
            class Res:
                deleted_count = 0
            return Res()

    repo = RepertorioSemanaRepository(collection=MockCollection())

    # 1. Agendar música
    item = repo.agendar_musica(
        musica_id="song_123",
        titulo="Bondade de Deus",
        cantor_principal="Geisa",
        tom_selecionado="G (Sol)",
        data_ensaio="2026-10-17",
        dia_semana="Sábado",
        versao="Original",
        adicionado_por="Levy",
    )
    assert item["titulo"] == "Bondade de Deus"
    assert item["tom_selecionado"] == "G (Sol)"
    assert item["data_ensaio"] == "2026-10-17"

    # 2. Listar por data
    items_sabado = repo.listar_por_data("2026-10-17")
    assert len(items_sabado) == 1
    assert items_sabado[0]["titulo"] == "Bondade de Deus"

    # 3. Remover música da escala
    removido = repo.remover_musica_escala(item["_id"])
    assert removido is True
    assert len(repo.listar_por_data("2026-10-17")) == 0


def test_repertorio_semana_local_vault(tmp_path):
    """Testa armazenamento offline criptografado no cofre local."""
    vault_file = tmp_path / "test_vault_weekly.enc"
    vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="test-secret-vault")

    item = vault.save_weekly_item(
        musica_id="m1",
        titulo="Ruja o Leão",
        cantor_principal="Levy",
        tom_selecionado="Am (Lám)",
        data_ensaio="2026-10-17",
        dia_semana="Sábado",
        versao="Ao Vivo",
        adicionado_por="Levy",
    )
    assert item.titulo == "Ruja o Leão"
    assert item.dia_semana == "Sábado"

    loaded = vault.load_weekly_schedule("2026-10-17")
    assert len(loaded) == 1
    assert loaded[0].tom_selecionado == "Am (Lám)"

    updated = vault.delete_weekly_item(item.id)
    assert len(updated) == 0


def test_api_routes_repertorio_semana(api_test_client, monkeypatch):
    """Testa as rotas REST /api/repertorio-semana (GET, POST, DELETE)."""
    fake_db = []

    class MockWeeklyRepo:
        def __init__(self, *args, **kwargs):
            self.collection = None

        def listar_por_data(self, data_ensaio):
            return [d for d in fake_db if d["data_ensaio"] == data_ensaio]

        def listar_por_intervalo_datas(self, data_inicio, data_fim):
            return [d for d in fake_db if data_inicio <= d["data_ensaio"] <= data_fim]

        def agendar_musica(self, **kwargs):
            doc = dict(kwargs)
            doc["_id"] = f"week_{len(fake_db) + 1}"
            fake_db.append(doc)
            return doc

        def remover_musica_escala(self, item_id):
            for i, d in enumerate(fake_db):
                if d["_id"] == item_id:
                    fake_db.pop(i)
                    return True
            return False

    monkeypatch.setattr("backend_api.get_semana_repo", lambda: MockWeeklyRepo())

    # 1. POST
    post_payload = {
        "musica_id": "mus_abc",
        "titulo": "A Bênção",
        "cantor_principal": "Coral",
        "tom_selecionado": "Bb (Sib)",
        "data_ensaio": "2026-10-17",
        "dia_semana": "Sábado",
        "versao": "Original",
        "adicionado_por": "Levy",
    }
    resp_post = api_test_client.post("/api/repertorio-semana", json=post_payload)
    assert resp_post.status_code == 201
    created = resp_post.json()
    assert created["titulo"] == "A Bênção"
    assert created["_id"] == "week_1"

    # 2. GET por data
    resp_get = api_test_client.get("/api/repertorio-semana", params={"data": "2026-10-17"})
    assert resp_get.status_code == 200
    items = resp_get.json()
    assert len(items) == 1
    assert items[0]["titulo"] == "A Bênção"

    # 3. DELETE
    resp_del = api_test_client.delete(f"/api/repertorio-semana/{created['_id']}")
    assert resp_del.status_code == 200
    assert resp_del.json()["deleted"] is True


def test_api_client_and_weekly_delete_aliases(monkeypatch):
    """Testa se SongsApiClient possui os métodos de remoção e se o WeeklyView aciona corretamente."""
    from unittest.mock import MagicMock
    from ciphersong.ui.views.weekly_view import WeeklyView

    client = SongsApiClient()
    assert hasattr(client, "remover_repertorio_semana")
    assert hasattr(client, "deletar_repertorio_semana")
    assert client.deletar_repertorio_semana == client.remover_repertorio_semana

    # Mock no weekly_repo do client
    removed_ids = []
    def mock_remove(item_id, titulo=None, data_ensaio=None, equipe_id=None):
        removed_ids.append((item_id, titulo, data_ensaio))
        return True

    monkeypatch.setattr(client, "_should_try_http", lambda: False)
    monkeypatch.setattr(client.weekly_repo, "remover_musica_escala", mock_remove)

    assert client.remover_repertorio_semana("id_123", titulo="Música Teste", data_ensaio="2026-10-20") is True
    assert ("id_123", "Música Teste", "2026-10-20") in removed_ids

    # Testa exclusão na view
    mock_page = MagicMock()
    mock_vault = MagicMock()
    mock_vault.load_weekly_schedule.return_value = []
    view = WeeklyView(
        page=mock_page,
        vault=mock_vault,
        api_client=client,
        show_notification=lambda m, o: None,
        nav_manager=MagicMock(),
        get_logged_user_name=lambda: "Tester",
    )

    test_item = {"_id": "test_mongo_id", "id": "test_mongo_id", "titulo": "Caminho no Deserto", "data_ensaio": "2026-10-20"}
    view.prompt_delete_weekly_song(test_item)
    assert view.pending_delete_weekly_id == "test_mongo_id"
    assert view.delete_weekly_confirm_overlay.visible is True

    view.confirm_delete_weekly_song(None)
    assert view.pending_delete_weekly_id is None
    assert view.delete_weekly_confirm_overlay.visible is False
    mock_vault.delete_weekly_item.assert_called()
