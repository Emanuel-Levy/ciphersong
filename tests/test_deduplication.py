"""
Testes abrangentes de sincronização e prevenção de duplicação em todas as camadas:
1. LocalVault (save_song, load_songs, save_weekly_item, load_weekly_schedule, save_a_ensaiar, load_a_ensaiar)
2. Repositórios MongoDB (MusicasEnsaioRepository, RepertorioSemanaRepository, MusicasAEnsaiarRepository)
"""
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
from ciphersong.security.local_vault import EncryptedSessionVault
from ciphersong.database.mongo_connection import (
    MusicasEnsaioRepository,
    RepertorioSemanaRepository,
    MusicasAEnsaiarRepository,
)


def test_vault_song_deduplication_and_tone_merging():
    with tempfile.TemporaryDirectory() as tmp_dir:
        vault_path = Path(tmp_dir) / ".test_vault.enc"
        vault = EncryptedSessionVault(vault_path=vault_path)

        # 1. Salvar primeira vez
        s1 = vault.save_song(
            title="Bondade de Deus",
            keys=["G (Sol)"],
            soloist="Poliana",
            versao="Original",
        )
        assert len(vault.load_songs()) == 1

        # 2. Salvar mesma música com novo tom (ex: vindo da sincronização na nuvem ou outro dispositivo)
        s2 = vault.save_song(
            title=" bondade de deus ",
            keys=["A (Lá)"],
            soloist="poliana ",
            versao="original",
        )
        songs = vault.load_songs()
        assert len(songs) == 1
        assert "G (Sol)" in songs[0].keys
        assert "A (Lá)" in songs[0].keys


def test_vault_auto_cleans_legacy_duplicates():
    with tempfile.TemporaryDirectory() as tmp_dir:
        vault_path = Path(tmp_dir) / ".test_vault.enc"
        vault = EncryptedSessionVault(vault_path=vault_path)

        # Simula arquivo antigo contendo duplicatas geradas por sincronizações passadas
        store = vault._empty_store()
        store["songs"] = [
            {"id": "1", "title": "Rei e Santo", "soloist": "Poliana", "keys": ["C"], "versao": "Original", "synced": True, "created_at": "10/10"},
            {"id": "2", "title": "rei e santo", "soloist": "poliana", "keys": ["D"], "versao": "original", "synced": True, "created_at": "11/10"},
            {"id": "3", "title": "Rei e Santo", "soloist": "Poliana", "keys": ["E"], "versao": "Original", "synced": True, "created_at": "12/10"},
        ]
        vault._save_raw_store(store)

        # Ao chamar load_songs, deve limpar automaticamente
        cleaned = vault.load_songs()
        assert len(cleaned) == 1
        assert cleaned[0].title == "Rei e Santo"
        assert set(cleaned[0].keys) == {"C", "D", "E"}

        # Verifica se gravou limpo no cofre em disco
        raw_store = vault._load_raw_store()
        assert len(raw_store["songs"]) == 1


def test_vault_weekly_and_a_ensaiar_deduplication():
    with tempfile.TemporaryDirectory() as tmp_dir:
        vault_path = Path(tmp_dir) / ".test_vault.enc"
        vault = EncryptedSessionVault(vault_path=vault_path)

        # Weekly
        vault.save_weekly_item(
            musica_id="m1",
            titulo="Bondade de Deus",
            cantor_principal="Poliana",
            tom_selecionado="G",
            data_ensaio="2026-10-20",
            dia_semana="Terça",
        )
        vault.save_weekly_item(
            musica_id="m1",
            titulo="bondade de deus",
            cantor_principal="poliana",
            tom_selecionado="A",
            data_ensaio="2026-10-20",
            dia_semana="Terça",
        )
        weekly = vault.load_weekly_schedule()
        assert len(weekly) == 1
        assert weekly[0].tom_selecionado == "A"

        # A Ensaiar
        vault.save_a_ensaiar(
            titulo="Nova Canção",
            cantor_versao="Gabriel Guedes",
            youtube_url="https://youtu.be/123",
        )
        vault.save_a_ensaiar(
            titulo="nova canção",
            cantor_versao="gabriel guedes",
            youtube_url="https://youtu.be/456",
        )
        a_ensaiar = vault.load_a_ensaiar()
        assert len(a_ensaiar) == 1
        assert a_ensaiar[0].youtube_url == "https://youtu.be/456"


import re


def test_mongo_repo_deduplication_upsert():
    # Simula mock de coleção MongoDB que suporta find_one e update_one
    docs = []

    class MockMongoCol:
        def find_one(self, filter_query):
            for doc in docs:
                t_reg = filter_query.get("titulo", {}).get("$regex", "")
                c_reg = filter_query.get("cantor_principal", {}).get("$regex", "")
                t_match = bool(re.search(t_reg, doc.get("titulo", ""), re.I)) if t_reg else True
                c_match = bool(re.search(c_reg, doc.get("cantor_principal", ""), re.I)) if c_reg else True
                if t_match and c_match:
                    return dict(doc)
            return None

        def insert_one(self, doc):
            doc["_id"] = "mock_id_99"
            docs.append(dict(doc))
            class Res:
                inserted_id = "mock_id_99"
            return Res()

        def update_one(self, filter_query, update_doc):
            for d in docs:
                if d.get("_id") == filter_query.get("_id"):
                    d.update(update_doc.get("$set", {}))

    col = MockMongoCol()
    repo = MusicasEnsaioRepository(collection=col)

    # 1. Primeira inserção
    r1 = repo.salvar_musica(
        titulo="Bondade de Deus",
        cantor_principal="Poliana",
        tons=["G"],
    )
    assert len(docs) == 1

    # 2. Segunda inserção com novos tons -> deve mesclar sem criar novo documento
    r2 = repo.salvar_musica(
        titulo="bondade de deus",
        cantor_principal="poliana",
        tons=["C", "D"],
    )
    assert len(docs) == 1
    assert "G" in docs[0]["tons"]
    assert "C" in docs[0]["tons"]
    assert "D" in docs[0]["tons"]
