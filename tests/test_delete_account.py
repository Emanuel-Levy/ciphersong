import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend_api import (
    app,
    get_users_repo,
    get_refresh_tokens_repo,
    get_equipes_repo,
    hash_password,
    create_access_token,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_excluir_conta_remove_do_mongodb(client):
    users_repo = get_users_repo()
    refresh_repo = get_refresh_tokens_repo()
    equipes_repo = get_equipes_repo()

    test_email = "delete_mongo_test@ciphersong.com.br"
    test_nome = "DeleteMongoTester"

    # Garante que não haja resquícios
    users_repo.excluir_usuario("fake_id", email=test_email)

    # 1. Cria usuário
    user_doc = users_repo.criar_usuario(
        email=test_email,
        senha_hash=hash_password("SenhaForte123!"),
        nome=test_nome,
        provedor="email",
    )
    user_id = str(user_doc["_id"])

    # 2. Cria refresh token associado
    refresh_repo.criar_token(
        token_hash="mock_refresh_hash_delete_test",
        usuario_id=user_id,
    )

    # 3. Cria equipe com esse usuário
    equipe_doc = equipes_repo.criar_equipe(
        nome="Equipe Delete Test",
        criado_por_id=user_id,
        criado_por_nome=test_nome,
    )
    eq_id = str(equipe_doc["_id"])

    # Gera token de acesso
    token = create_access_token(user_id, email=test_email)
    headers = {"Authorization": f"Bearer {token}"}

    # 4. Executa a exclusão de conta via API
    resp = client.delete("/api/auth/conta", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["deleted"] is True
    assert data["user_id"] == user_id

    # 5. VERIFICAÇÃO NO MONGODB: O usuário NÃO deve mais existir
    assert users_repo.buscar_por_id(user_id) is None
    assert users_repo.buscar_por_email(test_email) is None

    # 6. VERIFICAÇÃO NO MONGODB: Os refresh tokens foram expurgados
    refresh_docs = list(refresh_repo.collection.find({"usuario_id": user_id}))
    assert len(refresh_docs) == 0

    # 7. VERIFICAÇÃO NO MONGODB: O usuário foi removido da lista de membros da equipe
    eq_atualizada = equipes_repo.buscar_por_id(eq_id)
    if eq_atualizada:
        membros_ids = [str(m) for m in eq_atualizada.get("membros", [])]
        assert user_id not in membros_ids

    # 8. Limpa equipe de teste
    try:
        equipes_repo.collection.delete_one({"_id": equipe_doc["_id"]})
    except Exception:
        pass
