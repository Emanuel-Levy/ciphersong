"""
Cofre Local Criptografado & Proteção de Privacidade Vocal (`security-specialist`).

Gerencia com criptografia autenticada AES-256-GCM (PBKDF2-HMAC-SHA256):
1. Histórico de sessões de detecção de tom vocal (`VocalSessionRecord`).
2. Repertório de músicas ensaiadas (`RehearsedSongRecord`) com Nome da Música,
   múltiplos Tons selecionados e nome do Solista, além de busca instantânea.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class VocalSessionRecord:
    """Registro de uma sessão de detecção de tom vocal salva pelo cantor."""
    timestamp: str
    detected_key_pt: str
    detected_key_en: str
    relative_key_pt: str
    confidence_pct: int
    last_note: str
    last_freq_hz: float


@dataclass
class RehearsedSongRecord:
    """Registro de uma música ensaiada com suporte a múltiplos tons e solista."""
    id: str
    title: str
    soloist: str
    keys: list[str] = field(default_factory=list)
    created_at: str = ""


class EncryptedSessionVault:
    """
    Gerencia o armazenamento local criptografado (AES-256-GCM) do histórico de tons
    e do repertório de músicas ensaiadas.
    """

    SALT_SIZE = 16
    NONCE_SIZE = 12
    KDF_ITERATIONS = 200_000

    def __init__(
        self,
        vault_path: Optional[Path] = None,
        secret_passphrase: Optional[str] = None,
    ) -> None:
        self.vault_path = vault_path or Path(".ciphersong_vault.enc")
        raw_secret = (
            secret_passphrase
            or os.getenv("SECRET_KEY")
            or "ciphersong-default-local-device-secret-key"
        )
        self._passphrase_bytes = raw_secret.encode("utf-8")

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
        )
        return kdf.derive(self._passphrase_bytes)

    def _load_raw_store(self) -> dict[str, Any]:
        """Carrega e descriptografa o dicionário interno do cofre (`records` e `songs`)."""
        if not self.vault_path.exists():
            return {"records": [], "songs": []}

        try:
            payload = json.loads(self.vault_path.read_text(encoding="utf-8"))
            salt = base64.b64decode(payload["salt"])
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])

            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=b"ciphersong-v1")
            data = json.loads(decrypted_bytes.decode("utf-8"))

            # Compatibilidade retroativa caso o cofre antigo fosse uma lista simples
            if isinstance(data, list):
                return {"records": data, "songs": []}
            if isinstance(data, dict):
                return {
                    "records": data.get("records", []),
                    "songs": data.get("songs", []),
                }
            return {"records": [], "songs": []}
        except Exception:
            return {"records": [], "songs": []}

    def _save_raw_store(self, store: dict[str, Any]) -> None:
        """Criptografa e salva o dicionário completo no arquivo local."""
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        plaintext = json.dumps(store, ensure_ascii=False).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=b"ciphersong-v1")

        envelope = {
            "version": 2,
            "cipher": "AES-256-GCM",
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        self.vault_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    # --- Gerenciamento de Sessões de Afinação/Tom ---

    def load_records(self) -> list[VocalSessionRecord]:
        store = self._load_raw_store()
        return [VocalSessionRecord(**item) for item in store.get("records", [])]

    def save_record(self, record: VocalSessionRecord, max_history: int = 25) -> list[VocalSessionRecord]:
        store = self._load_raw_store()
        records = [VocalSessionRecord(**item) for item in store.get("records", [])]
        records.insert(0, record)
        records = records[:max_history]
        store["records"] = [asdict(r) for r in records]
        self._save_raw_store(store)
        return records

    @staticmethod
    def create_record(
        key_pt: str,
        key_en: str,
        relative_pt: str,
        confidence: float,
        last_note: str,
        last_freq_hz: float,
    ) -> VocalSessionRecord:
        return VocalSessionRecord(
            timestamp=datetime.now().strftime("%d/%m %H:%M"),
            detected_key_pt=key_pt,
            detected_key_en=key_en,
            relative_key_pt=relative_pt,
            confidence_pct=int(round(confidence * 100)),
            last_note=last_note,
            last_freq_hz=round(last_freq_hz, 1),
        )

    # --- Gerenciamento de Músicas Ensaiadas (Repertório) ---

    def load_songs(self) -> list[RehearsedSongRecord]:
        """Carrega todas as músicas ensaiadas salvas no cofre."""
        store = self._load_raw_store()
        return [RehearsedSongRecord(**item) for item in store.get("songs", [])]

    def save_song(
        self,
        title: str,
        keys: list[str],
        soloist: str,
    ) -> RehearsedSongRecord:
        """
        Cadastra uma nova música ensaiada com Nome, múltiplos Tons e Solista.
        """
        clean_title = title.strip()
        clean_soloist = soloist.strip() or "Não informado"
        clean_keys = [k.strip() for k in keys if k.strip()]

        if not clean_title:
            raise ValueError("O nome da música é obrigatório.")
        if not clean_keys:
            raise ValueError("Selecione pelo menos um Tom para a música.")

        song = RehearsedSongRecord(
            id=base64.urlsafe_b64encode(os.urandom(6)).decode("ascii"),
            title=clean_title,
            soloist=clean_soloist,
            keys=clean_keys,
            created_at=datetime.now().strftime("%d/%m/%Y %H:%M"),
        )

        store = self._load_raw_store()
        songs_raw = store.get("songs", [])
        songs_raw.insert(0, asdict(song))
        store["songs"] = songs_raw
        self._save_raw_store(store)
        return song

    def delete_song(self, song_id: str) -> list[RehearsedSongRecord]:
        """Remove uma música pelo ID e retorna a lista atualizada."""
        store = self._load_raw_store()
        songs = [
            RehearsedSongRecord(**item)
            for item in store.get("songs", [])
            if item.get("id") != song_id
        ]
        store["songs"] = [asdict(s) for s in songs]
        self._save_raw_store(store)
        return songs

    def search_songs(self, query: str) -> list[RehearsedSongRecord]:
        """
        Filtra as músicas cadastradas por Nome da Música, Solista ou qualquer um dos Tons.
        """
        all_songs = self.load_songs()
        q = query.strip().lower()
        if not q:
            return all_songs

        results: list[RehearsedSongRecord] = []
        for song in all_songs:
            in_title = q in song.title.lower()
            in_soloist = q in song.soloist.lower()
            in_keys = any(q in k.lower() for k in song.keys)
            if in_title or in_soloist or in_keys:
                results.append(song)
        return results

    def clear_vault(self) -> None:
        if self.vault_path.exists():
            self.vault_path.unlink()
