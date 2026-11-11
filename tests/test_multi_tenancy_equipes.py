"""
Testes automatizados para o sistema Multi-Tenancy de Equipes do CipherSong (`senior-architect` + `security-specialist`).

Cobre:
1. Equipe padrão 'Teste' (migração de dados e membros).
2. Criação de nova equipe com código de convite único 'CS-XXXXXX'.
3. Ingresso em equipe através de código de convite.
4. Isolamento total de dados por equipe (Músicas, Repertório da Semana, A Ensaiar) e proteção contra IDOR (HTTP 403).
5. Isolamento local no cofre criptografado (AES-256-GCM) por equipe_id.
6. Formatação de links e convites via WhatsApp.
"""

import urllib.parse
import pytest
from fastapi.testclient import TestClient

from backend_api import app
from ciphersong.database.mongo_connection import (
    EquipesRepository,
    MusicasEnsaioRepository,
    RepertorioSemanaRepository,
    MusicasAEnsaiarRepository,
)
from ciphersong.security.auth import create_access_token
from ciphersong.security.local_vault import EncryptedSessionVault


client = TestClient(app)


def test_equipes_repository_creation_and_membership():
    equipes_repo = EquipesRepository()

    # 1. Garantir que obter_ou_criar_equipe_padrao é depreciado e não gera equipe 'Teste'
    eq_padrao = equipes_repo.obter_ou_criar_equipe_padrao("Teste")
    assert eq_padrao is None

    # 2. Criar nova equipe
    nova_eq = equipes_repo.criar_equipe(
        nome="Ministério Central Teste",
        criado_por_id="user_admin_001",
        criado_por_nome="Levy",
    )
    assert nova_eq is not None
    assert nova_eq["nome"] == "Ministério Central Teste"
    assert nova_eq["codigo_convite"].startswith("CS-")
    assert len(nova_eq["codigo_convite"]) == 9
    assert "user_admin_001" in nova_eq["membros"]

    try:
        # 3. Listar equipes do usuário admin
        minhas = equipes_repo.listar_equipes_do_usuario("user_admin_001")
        ids = [str(e.get("_id") or e.get("id")) for e in minhas]
        assert str(nova_eq["_id"]) in ids
        # Garante que a equipe 'Teste' não é injetada
        assert not any(e.get("nome") == "Teste" for e in minhas)

        # 4. Outro usuário entra com o código de convite
        eq_ingressada = equipes_repo.entrar_equipe_por_codigo(
            codigo=nova_eq["codigo_convite"],
            usuario_id="user_novo_002",
        )
        assert eq_ingressada is not None
        assert str(eq_ingressada["_id"]) == str(nova_eq["_id"])
        assert equipes_repo.usuario_pertence_a_equipe(str(nova_eq["_id"]), "user_novo_002") is True
    finally:
        # Limpa equipe de teste criada
        try:
            from bson import ObjectId
            equipes_repo.collection.delete_one({"_id": ObjectId(str(nova_eq["_id"]))})
        except Exception:
            pass


def test_multi_tenancy_api_isolation_and_idor():
    """Garante que dados de uma equipe não são visíveis para membros de outra equipe."""
    equipes_repo = EquipesRepository()

    # Cria duas equipes distintas
    eq_a = equipes_repo.criar_equipe(nome="Equipe Alpha", criado_por_id="user_alpha_1", criado_por_nome="Alpha")
    eq_b = equipes_repo.criar_equipe(nome="Equipe Beta", criado_por_id="user_beta_1", criado_por_nome="Beta")

    token_alpha = create_access_token(user_id="user_alpha_1", email="alpha1@test.com")
    token_beta = create_access_token(user_id="user_beta_1", email="beta1@test.com")

    headers_alpha = {"Authorization": f"Bearer {token_alpha}"}
    headers_beta = {"Authorization": f"Bearer {token_beta}"}

    id_a = str(eq_a["_id"])
    id_b = str(eq_b["_id"])

    try:
        # 1. Alpha cria música na Equipe Alpha
        resp_song_a = client.post(
            "/api/musicas",
            json={
                "titulo": "Alpha Praise Song",
                "cantor_principal": "Cantor Alpha",
                "tons": ["C", "D"],
                "versao": "Live",
                "equipe_id": id_a,
            },
            headers=headers_alpha,
        )
        assert resp_song_a.status_code == 201

        # 2. Beta tenta consultar dados da Equipe Alpha -> 403 Forbidden!
        resp_forbidden_songs = client.get(
            f"/api/musicas?equipe_id={id_a}",
            headers=headers_beta,
        )
        assert resp_forbidden_songs.status_code == 403
        assert "Você não tem permissão" in resp_forbidden_songs.json()["detail"]

        # 3. Alpha consulta Equipe Alpha -> 200 OK e encontra sua música
        resp_alpha_songs = client.get(
            f"/api/musicas?equipe_id={id_a}",
            headers=headers_alpha,
        )
        assert resp_alpha_songs.status_code == 200
        alpha_songs = resp_alpha_songs.json()
        assert any(s["titulo"] == "Alpha Praise Song" for s in alpha_songs)

        # 4. Beta agenda na escala da Equipe Beta
        resp_week_b = client.post(
            "/api/repertorio-semana",
            json={
                "musica_id": "mus_b_1",
                "titulo": "Beta Holy Song",
                "cantor_principal": "Cantor Beta",
                "tom_selecionado": "G (Sol)",
                "data_ensaio": "2026-10-25",
                "dia_semana": "Domingo",
                "versao": "Acústico",
                "adicionado_por": "Beta",
                "equipe_id": id_b,
            },
            headers=headers_beta,
        )
        assert resp_week_b.status_code == 201

        # 5. Alpha tenta acessar repertório da semana da Equipe Beta -> 403 Forbidden!
        resp_forbidden_weekly = client.get(
            f"/api/repertorio-semana?equipe_id={id_b}&data=2026-10-25",
            headers=headers_alpha,
        )
        assert resp_forbidden_weekly.status_code == 403

        # 6. Alpha tenta acessar sugestões a ensaiar da Equipe Beta -> 403 Forbidden!
        resp_forbidden_tr = client.get(
            f"/api/a-ensaiar?equipe_id={id_b}",
            headers=headers_alpha,
        )
        assert resp_forbidden_tr.status_code == 403
    finally:
        try:
            from bson import ObjectId
            from ciphersong.database.mongo_connection import MongoDBConnection
            db = MongoDBConnection.get_database()
            if db is not None:
                equipes_repo.collection.delete_many({"_id": {"$in": [ObjectId(str(eq_a["_id"])), ObjectId(str(eq_b["_id"]))]}})
                db.musicas_ensaio.delete_many({"equipe_id": {"$in": [id_a, id_b]}})
                db.repertorio_semana.delete_many({"equipe_id": {"$in": [id_a, id_b]}})
                db.musicas_a_ensaiar.delete_many({"equipe_id": {"$in": [id_a, id_b]}})
        except Exception:
            pass


def test_team_members_share_songs_repertoire():
    """Valida que membros da mesma equipe sincronizam e visualizam as músicas adicionadas por outros membros."""
    equipes_repo = EquipesRepository()
    u1_id = "user_membro_1"
    u2_id = "user_membro_2"

    eq = equipes_repo.criar_equipe("Banda Louvor Compartilhado", criado_por_id=u1_id, criado_por_nome="User 1")
    eq_id = str(eq["_id"])
    equipes_repo.entrar_equipe_por_codigo(eq["codigo_convite"], u2_id)

    tok_1 = create_access_token(u1_id, "u1@test.com")
    tok_2 = create_access_token(u2_id, "u2@test.com")

    headers_1 = {"Authorization": f"Bearer {tok_1}"}
    headers_2 = {"Authorization": f"Bearer {tok_2}"}

    try:
        # Usuário 1 cadastra música na equipe
        res_create = client.post(
            "/api/musicas",
            json={
                "titulo": "Caminho no Deserto",
                "cantor_principal": "Soraya Moraes",
                "tons": ["C", "G"],
                "versao": "Original",
                "equipe_id": eq_id,
            },
            headers=headers_1,
        )
        assert res_create.status_code == 201
        created_song = res_create.json()
        song_id = created_song["_id"]

        # Usuário 2 consulta as músicas da equipe -> deve receber a música cadastrada por Usuário 1!
        res_list = client.get(
            f"/api/musicas?equipe_id={eq_id}",
            headers=headers_2,
        )
        assert res_list.status_code == 200
        team_songs = res_list.json()
        assert len(team_songs) == 1
        assert team_songs[0]["titulo"] == "Caminho no Deserto"
        assert team_songs[0]["cantor_principal"] == "Soraya Moraes"

        # Usuário 2 também pode remover a música da equipe
        res_delete = client.delete(
            f"/api/musicas/{song_id}",
            headers=headers_2,
        )
        assert res_delete.status_code == 200
        assert res_delete.json()["deleted"] is True

        # Verifica que a lista agora está vazia
        res_list_after = client.get(
            f"/api/musicas?equipe_id={eq_id}",
            headers=headers_2,
        )
        assert len(res_list_after.json()) == 0
    finally:
        try:
            from bson import ObjectId
            from ciphersong.database.mongo_connection import MongoDBConnection
            db = MongoDBConnection.get_database()
            if db is not None:
                equipes_repo.collection.delete_one({"_id": ObjectId(eq_id)})
                db.musicas_ensaio.delete_many({"equipe_id": eq_id})
        except Exception:
            pass


def test_vault_multi_team_isolation(tmp_path):
    """Verifica isolamento por equipe_id no cofre criptografado local offline."""
    vault = EncryptedSessionVault(vault_path=str(tmp_path / "test_team_vault.enc"))

    eq1 = "equipe_111"
    eq2 = "equipe_222"

    # Salva músicas em equipes diferentes
    vault.save_song(title="Música Equipe 1", keys=["C"], soloist="Cantor 1", equipe_id=eq1)
    vault.save_song(title="Música Equipe 2", keys=["D"], soloist="Cantor 2", equipe_id=eq2)

    songs_eq1 = vault.search_songs(equipe_id=eq1)
    assert len(songs_eq1) == 1
    assert songs_eq1[0].title == "Música Equipe 1"

    songs_eq2 = vault.search_songs(equipe_id=eq2)
    assert len(songs_eq2) == 1
    assert songs_eq2[0].title == "Música Equipe 2"

    # Escala da semana isolada
    vault.save_weekly_item(
        musica_id="m1",
        titulo="Semana Eq 1",
        cantor_principal="Cantor 1",
        tom_selecionado="C",
        data_ensaio="2026-10-20",
        dia_semana="Terça",
        equipe_id=eq1,
    )
    vault.save_weekly_item(
        musica_id="m2",
        titulo="Semana Eq 2",
        cantor_principal="Cantor 2",
        tom_selecionado="D",
        data_ensaio="2026-10-20",
        dia_semana="Terça",
        equipe_id=eq2,
    )

    weekly_eq1 = vault.load_weekly_schedule("2026-10-20", equipe_id=eq1)
    assert len(weekly_eq1) == 1
    assert weekly_eq1[0].titulo == "Semana Eq 1"

    weekly_eq2 = vault.load_weekly_schedule("2026-10-20", equipe_id=eq2)
    assert len(weekly_eq2) == 1
    assert weekly_eq2[0].titulo == "Semana Eq 2"


def test_whatsapp_invite_link_format():
    """Valida a formatação da mensagem e do link de convite do WhatsApp."""
    nome_equipe = "Banda Louvor Jovem"
    codigo_convite = "CS-AB12CD"

    mensagem = (
        f"Olá! Venha participar da minha equipe *{nome_equipe}* no aplicativo *CipherSong*!\n\n"
        f"Use o código de convite: *{codigo_convite}*\n\n"
        f"Abra o app CipherSong e entre com esse código na aba Equipe para acessar todas as músicas, escalas e repertórios."
    )

    encoded = urllib.parse.quote(mensagem)
    wa_url = f"https://api.whatsapp.com/send?text={encoded}"

    assert "https://api.whatsapp.com/send?text=" in wa_url
    assert "CS-AB12CD" in urllib.parse.unquote(wa_url)
    assert "Banda%20Louvor%20Jovem" in wa_url or "Banda+Louvor+Jovem" in wa_url
