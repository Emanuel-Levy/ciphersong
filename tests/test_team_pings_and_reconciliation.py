"""
Testes automatizados para a feature de Equipe / Pings e Reconciliação do Cofre Local (`senior-architect` + `security-specialist`).
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend_api import app
from ciphersong.database.mongo_connection import PingsRepository, UsuariosRepository
from ciphersong.security.auth import create_access_token
from ciphersong.security.local_vault import EncryptedSessionVault


client = TestClient(app)


def test_pings_repository_cooldown_and_lifecycle():
    pings_repo = PingsRepository()

    remetente_id = "test_user_a_123"
    remetente_nome = "Músico A"
    destinatario_id = "test_user_b_456"
    destinatario_nome = "Músico B"

    # 1. Enviar primeiro ping
    ping_doc = pings_repo.enviar_ping(remetente_id, remetente_nome, destinatario_id, destinatario_nome)
    assert ping_doc is not None
    assert ping_doc["remetente_id"] == remetente_id
    assert ping_doc["destinatario_id"] == destinatario_id
    assert ping_doc["lido"] is False

    # 2. Tentar enviar imediatamente (deve disparar ValueError de cooldown de 10s)
    with pytest.raises(ValueError, match="Aguarde"):
        pings_repo.enviar_ping(remetente_id, remetente_nome, destinatario_id, destinatario_nome)

    # 3. Buscar pings pendentes para o destinatário
    pendentes = pings_repo.buscar_pings_pendentes(destinatario_id)
    assert len(pendentes) >= 1
    found = [p for p in pendentes if str(p.get("_id") or p.get("id")) == str(ping_doc["_id"])]
    assert len(found) == 1

    # 4. Marcar como lido
    marcou = pings_repo.marcar_como_lido(str(ping_doc["_id"]))
    assert marcou is True

    # 5. Após marcar como lido, não deve mais aparecer como pendente
    pendentes_apos = pings_repo.buscar_pings_pendentes(destinatario_id)
    found_apos = [p for p in pendentes_apos if str(p.get("_id") or p.get("id")) == str(ping_doc["_id"])]
    assert len(found_apos) == 0


def test_vault_reconcile_cloud_deletions(tmp_path):
    vault = EncryptedSessionVault(vault_path=str(tmp_path / "test_reconcile_vault.enc"))

    # Salva músicas locais
    s1 = vault.save_song(title="Música 1", keys=["C"], soloist="Cantor 1", synced=True)
    s2 = vault.save_song(title="Música 2", keys=["D"], soloist="Cantor 2", synced=True)
    s_offline = vault.save_song(title="Música Offline Nova", keys=["E"], soloist="Cantor 3", synced=False)

    all_local = vault.load_songs()
    assert len(all_local) == 3

    # Nuvem retorna apenas Música 1 (Música 2 foi apagada na nuvem!)
    cloud_songs = [
        {"title": "Música 1", "soloist": "Cantor 1", "versao": "Original", "tons": ["C"]}
    ]

    reconciled = vault.reconcile_songs(cloud_songs)
    assert len(reconciled) == 2

    # Verifica que Música 2 foi removida, Música 1 permanece e Música Offline não sincronizada foi preservada
    after_reconcile = vault.load_songs()
    titles = [s.title for s in after_reconcile]
    assert "Música 1" in titles
    assert "Música Offline Nova" in titles
    assert "Música 2" not in titles


def test_api_equipe_endpoints():
    token = create_access_token(user_id="user_test_token_999", email="musico999@test.com")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Listar membros da equipe
    resp = client.get("/api/equipe/membros", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # 2. Enviar ping via API
    ping_payload = {
        "destinatario_id": "user_dest_888",
        "destinatario_nome": "Destinatário Teste",
    }
    resp_ping = client.post("/api/equipe/ping", json=ping_payload, headers=headers)
    assert resp_ping.status_code == 201
    ping_data = resp_ping.json()
    assert ping_data["destinatario_id"] == "user_dest_888"

    # 3. Tentar chamar novamente imediatamente -> 400 Cooldown
    resp_cooldown = client.post("/api/equipe/ping", json=ping_payload, headers=headers)
    assert resp_cooldown.status_code == 400
    assert "Aguarde" in resp_cooldown.json()["detail"]

    # 4. Buscar pings com token do destinatário
    dest_token = create_access_token(user_id="user_dest_888", email="dest888@test.com")
    resp_meus_pings = client.get("/api/equipe/meus-pings", headers={"Authorization": f"Bearer {dest_token}"})
    assert resp_meus_pings.status_code == 200
    pings_list = resp_meus_pings.json()
    assert len(pings_list) >= 1

    # 5. Marcar como lido
    ping_id = ping_data["_id"]
    resp_lido = client.post(f"/api/equipe/ping/{ping_id}/lido", headers={"Authorization": f"Bearer {dest_token}"})
    assert resp_lido.status_code == 200
    assert resp_lido.json()["lido"] is True


def test_vibration_and_background_services_configuration():
    """Valida permissões de vibração, wakelock e serviços nativos para notificações em 2º plano."""
    import flet as ft
    from pathlib import Path

    # 1. Serviços Flet 1.0 existem e podem ser instanciados
    haptic = ft.HapticFeedback()
    assert haptic is not None
    assert hasattr(haptic, "vibrate")

    wakelock = ft.Wakelock()
    assert wakelock is not None
    assert hasattr(wakelock, "enable")

    # 2. Permissões no pyproject.toml
    pyproject_text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert '"android.permission.VIBRATE" = true' in pyproject_text
    assert '"android.permission.WAKE_LOCK" = true' in pyproject_text
    assert '"android.permission.POST_NOTIFICATIONS" = true' in pyproject_text
    assert '"android.permission.FOREGROUND_SERVICE" = true' in pyproject_text
    assert '"android.permission.FOREGROUND_SERVICE_DATA_SYNC" = true' in pyproject_text

    # 3. Permissões no AndroidManifest.xml
    manifest_path = Path("build/flutter/android/app/src/main/AndroidManifest.xml")
    if manifest_path.exists():
        manifest_text = manifest_path.read_text(encoding="utf-8")
        assert "android.permission.VIBRATE" in manifest_text
        assert "android.permission.WAKE_LOCK" in manifest_text
        assert "android.permission.POST_NOTIFICATIONS" in manifest_text
        assert "android.permission.FOREGROUND_SERVICE" in manifest_text
        assert "android.permission.FOREGROUND_SERVICE_DATA_SYNC" in manifest_text
