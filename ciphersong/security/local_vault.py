"""
Cofre Local Criptografado & Proteção de Privacidade Vocal (`security-specialist`).

Gerencia com criptografia autenticada AES-256-GCM (PBKDF2-HMAC-SHA256):
1. Histórico de sessões de detecção de tom vocal (`VocalSessionRecord`).
2. Repertório de músicas ensaiadas (`RehearsedSongRecord`) com Nome da Música,
   múltiplos Tons selecionados e nome do Solista, além de busca instantânea.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import logging
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


def sanitize_youtube_url(raw_url: Optional[str]) -> str:
    """
    Valida e higieniza URLs externas (como links do YouTube) contra injeção de esquemas
    maliciosos (`javascript:`, `data:`, `vbscript:`, `file:`).
    """
    if not raw_url:
        return ""
    cleaned = "".join(ch for ch in str(raw_url).strip() if ord(ch) >= 32)
    if not cleaned:
        return ""

    lower = cleaned.lower()
    if lower.startswith(("javascript:", "data:", "vbscript:", "file:", "blob:")):
        raise ValueError("Link inválido ou inseguro. Utilize apenas links HTTP ou HTTPS.")

    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise ValueError("Link inválido. Informe um endereço web válido (ex: https://youtube.com/...).")

    return cleaned


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
    """Registro de uma música ensaiada com suporte a múltiplos tons, solista, versão e status de sincronização."""
    id: str
    title: str
    soloist: str
    keys: list[str] = field(default_factory=list)
    versao: str = "Original"
    created_at: str = ""
    synced: bool = True
    equipe_id: str = ""


@dataclass
class RepertorioSemanaRecord:
    """Registro de uma música agendada na escala do Repertório da Semana."""
    id: str
    musica_id: str
    titulo: str
    cantor_principal: str
    tom_selecionado: str
    data_ensaio: str
    dia_semana: str
    versao: str = "Original"
    adicionado_por: str = "Equipe"
    created_at: str = ""
    synced: bool = True
    equipe_id: str = ""


@dataclass
class MusicaAEnsaiarRecord:
    """Registro de uma música a ser ensaiada com link do YouTube no próximo ensaio."""
    id: str
    titulo: str
    cantor_versao: str
    youtube_url: str = ""
    status: str = "Próximo Ensaio"
    adicionado_por: str = "Equipe"
    created_at: str = ""
    synced: bool = True
    equipe_id: str = ""


class EncryptedSessionVault:
    """
    Gerencia o armazenamento local criptografado (AES-256-GCM) do histórico de tons
    e do repertório de músicas ensaiadas, com cache inteligente em RAM.
    """

    SALT_SIZE = 16
    NONCE_SIZE = 12
    KDF_ITERATIONS = 200_000

    @staticmethod
    def _resolve_default_base_dir() -> Path:
        """Resolve o diretório base para arquivos do cofre (Desktop multiplataforma ou sandbox Android/iOS)."""
        flet_storage = os.getenv("FLET_APP_STORAGE_DATA", "").strip()
        if flet_storage:
            p = Path(flet_storage)
            try:
                p.mkdir(parents=True, exist_ok=True)
                if os.access(p, os.W_OK):
                    return p
            except OSError as exc:
                logger.debug("Falha ao acessar FLET_APP_STORAGE_DATA (%s): %s", p, exc)

        local_default = Path(".")
        try:
            parent = local_default.resolve()
            has_local_vault = (
                (parent / ".ciphersong_session.enc").exists()
                or (parent / ".ciphersong_vault.enc").exists()
                or (parent / "pyproject.toml").exists()
            )
            if has_local_vault and os.access(parent, os.W_OK):
                return parent
        except OSError as exc:
            logger.debug("Falha ao verificar diretório de trabalho atual: %s", exc)

        try:
            user_home_dir = Path.home() / ".ciphersong"
            user_home_dir.mkdir(parents=True, exist_ok=True)
            if os.access(user_home_dir, os.W_OK):
                return user_home_dir
        except OSError as exc:
            logger.debug("Falha ao criar diretório em Path.home(): %s", exc)

        try:
            parent = local_default.resolve()
            if os.access(parent, os.W_OK):
                return parent
        except OSError:
            pass

        return Path(tempfile.gettempdir())

    @classmethod
    def _resolve_default_vault_path(cls) -> Path:
        """Resolve o caminho padrão do cofre (mantido para compatibilidade)."""
        return cls._resolve_default_base_dir() / ".ciphersong_vault.enc"

    @staticmethod
    def _hash_user_id(user_identifier: str) -> str:
        """Gera hash SHA-256 de 16 caracteres para isolar com segurança o cofre por usuário."""
        clean = str(user_identifier).strip().lower()
        return hashlib.sha256(clean.encode("utf-8")).hexdigest()[:16]

    def _resolve_user_vault_path(self, user_identifier: Optional[str] = None) -> Path:
        """Calcula o caminho do arquivo de banco local criptografado para o usuário específico."""
        if not user_identifier or not str(user_identifier).strip():
            return self.base_dir / ".ciphersong_vault_guest.enc"
        u_hash = self._hash_user_id(user_identifier)
        return self.base_dir / f".ciphersong_vault_{u_hash}.enc"

    def __init__(
        self,
        vault_path: Optional[Union[Path, str]] = None,
        secret_passphrase: Optional[str] = None,
        base_dir: Optional[Union[Path, str]] = None,
    ) -> None:
        self._lock = threading.RLock()
        raw_secret = (
            secret_passphrase
            or os.getenv("SECRET_KEY")
            or "ciphersong-default-local-device-secret-key"
        )
        self._passphrase_bytes = raw_secret.encode("utf-8")
        self._cached_salt: Optional[bytes] = None
        self._cached_key: Optional[bytes] = None
        self._memory_store: Optional[dict[str, Any]] = None
        self._last_mtime_ns: Optional[int] = None

        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = self._resolve_default_base_dir()

        self._is_explicit_path = vault_path is not None
        if self._is_explicit_path:
            self.vault_path = Path(vault_path)
            self.session_vault_path = self.vault_path
            self.current_user: Optional[str] = None
        else:
            self.session_vault_path = self.base_dir / ".ciphersong_session.enc"
            self.vault_path = self._resolve_user_vault_path(None)
            self._migrate_legacy_vault_if_needed()
            sess = self.get_auth_session()
            active_u = (sess.get("user_id") or sess.get("email")) if sess else None
            self.current_user = active_u
            if active_u:
                self.vault_path = self._resolve_user_vault_path(active_u)
            self._migrate_user_data_if_needed(active_u)

    def _migrate_legacy_vault_if_needed(self) -> None:
        """Migra sessão autenticada antiga do arquivo único legado se existir."""
        with self._lock:
            legacy_file = self.base_dir / ".ciphersong_vault.enc"
            if not legacy_file.exists():
                return
            if not self.session_vault_path.exists():
                try:
                    legacy_data = self._read_encrypted_file(legacy_file)
                    if legacy_data.get("auth"):
                        session_store = self._empty_store()
                        session_store["auth"] = legacy_data["auth"]
                        self._write_encrypted_file(self.session_vault_path, session_store)
                except Exception as exc:
                    logger.warning("Não foi possível migrar sessão do cofre legado: %s", exc)

    def _migrate_user_data_if_needed(self, user_identifier: Optional[str]) -> None:
        """Migra repertório existente do arquivo legado para o novo banco isolado do usuário."""
        with self._lock:
            if not user_identifier:
                return
            legacy_file = self.base_dir / ".ciphersong_vault.enc"
            if not legacy_file.exists() or self.vault_path.exists():
                return
            try:
                legacy_data = self._read_encrypted_file(legacy_file)
                if any(legacy_data.get(k) for k in ("songs", "records", "weekly", "a_ensaiar")):
                    self._write_encrypted_file(self.vault_path, legacy_data)
            except Exception as exc:
                logger.warning("Não foi possível migrar dados do usuário no cofre legado: %s", exc)

    def switch_user(self, user_identifier: Optional[str] = None) -> None:
        """
        Alterna o banco de dados local criptografado para o usuário identificado (por user_id ou email).
        Se user_identifier for None ou vazio, alterna para o cofre de convidado (guest).
        """
        with self._lock:
            clean_u = str(user_identifier).strip().lower() if user_identifier else None
            self.current_user = clean_u
            if not self._is_explicit_path:
                self.vault_path = self._resolve_user_vault_path(clean_u)
            self._memory_store = None
            self._last_mtime_ns = None

    def _derive_key(self, salt: bytes) -> bytes:
        with self._lock:
            if self._cached_salt == salt and self._cached_key is not None:
                return self._cached_key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=self.KDF_ITERATIONS,
            )
            derived = kdf.derive(self._passphrase_bytes)
            self._cached_salt = salt
            self._cached_key = derived
            return derived

    @staticmethod
    def _empty_store() -> dict[str, Any]:
        return {
            "records": [],
            "songs": [],
            "auth": None,
            "weekly": [],
            "a_ensaiar": [],
            "notifications_meta": {"seen_weekly_count": 0, "seen_to_rehearse_count": 0},
            "active_team": None,
            "cached_teams": [],
        }

    def _read_encrypted_file(self, target_path: Path) -> dict[str, Any]:
        """Lê e descriptografa com segurança qualquer arquivo AES-256-GCM do cofre."""
        with self._lock:
            if not target_path.exists():
                return self._empty_store()
            try:
                payload = json.loads(target_path.read_text(encoding="utf-8"))
                salt = base64.b64decode(payload["salt"])
                nonce = base64.b64decode(payload["nonce"])
                ciphertext = base64.b64decode(payload["ciphertext"])

                key = self._derive_key(salt)
                aesgcm = AESGCM(key)
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=b"ciphersong-v1")
                data = json.loads(decrypted_bytes.decode("utf-8"))

                if isinstance(data, list):
                    normalized = self._empty_store()
                    normalized["records"] = data
                elif isinstance(data, dict):
                    normalized = {
                        "records": data.get("records", []),
                        "songs": data.get("songs", []),
                        "auth": data.get("auth"),
                        "weekly": data.get("weekly", []),
                        "a_ensaiar": data.get("a_ensaiar", []),
                        "notifications_meta": data.get("notifications_meta", {}),
                        "active_team": data.get("active_team"),
                        "cached_teams": data.get("cached_teams", []),
                    }
                else:
                    normalized = self._empty_store()
                return normalized
            except Exception as exc:
                logger.warning("Falha ao ler/descriptografar cofre em %s: %s", target_path, exc)
                return self._empty_store()

    def _write_encrypted_file(self, target_path: Path, store: dict[str, Any]) -> None:
        """Criptografa com nonce inédito e salva o payload AES-256-GCM de forma atômica."""
        with self._lock:
            salt = self._cached_salt if self._cached_salt is not None else os.urandom(self.SALT_SIZE)
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
            serialized = json.dumps(envelope, indent=2)
            tmp_path = target_path.with_name(
                f"{target_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
            )
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                tmp_path.write_text(serialized, encoding="utf-8")
                os.replace(tmp_path, target_path)
            except OSError as exc:
                logger.warning("Erro ao gravar cofre em %s (%s), tentando fallback temp.", target_path, exc)
                try:
                    if tmp_path.exists():
                        tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass
                try:
                    fallback_path = Path(tempfile.gettempdir()) / target_path.name
                    fallback_path.write_text(serialized, encoding="utf-8")
                except OSError as fallback_exc:
                    logger.error("Falha crítica ao gravar fallback do cofre: %s", fallback_exc)

    def _load_raw_store(self) -> dict[str, Any]:
        """Carrega e descriptografa o dicionário interno do cofre com cache O(1) validado por mtime."""
        with self._lock:
            if not self.vault_path.exists():
                if self._memory_store is not None:
                    return copy.deepcopy(self._memory_store)
                self._last_mtime_ns = None
                return self._empty_store()

            try:
                current_mtime = self.vault_path.stat().st_mtime_ns
                if self._memory_store is not None and self._last_mtime_ns == current_mtime:
                    return copy.deepcopy(self._memory_store)

                normalized = self._read_encrypted_file(self.vault_path)
                self._memory_store = copy.deepcopy(normalized)
                self._last_mtime_ns = current_mtime
                return normalized
            except Exception as exc:
                logger.warning("Falha ao carregar store do cofre (%s): %s", self.vault_path, exc)
                self._memory_store = None
                self._last_mtime_ns = None
                return self._empty_store()

    def _save_raw_store(self, store: dict[str, Any]) -> None:
        """Criptografa com nonce inédito e salva o dicionário completo no arquivo local do usuário."""
        with self._lock:
            self._write_encrypted_file(self.vault_path, store)
            self._memory_store = copy.deepcopy(store)
            try:
                if self.vault_path.exists():
                    self._last_mtime_ns = self.vault_path.stat().st_mtime_ns
            except OSError:
                self._last_mtime_ns = None

    def _load_session_store(self) -> dict[str, Any]:
        """Carrega dados da sessão de login ativa a partir do cofre de sessão mestre."""
        with self._lock:
            if self._is_explicit_path:
                return self._load_raw_store()
            if hasattr(self, "vault_path") and self.session_vault_path == self.vault_path:
                return self._load_raw_store()
            return self._read_encrypted_file(self.session_vault_path)

    def _save_session_store(self, store: dict[str, Any]) -> None:
        """Salva dados da sessão de login ativa no cofre de sessão mestre."""
        with self._lock:
            if self._is_explicit_path:
                self._save_raw_store(store)
            elif hasattr(self, "vault_path") and self.session_vault_path == self.vault_path:
                self._save_raw_store(store)
            else:
                self._write_encrypted_file(self.session_vault_path, store)

    # --- Gerenciamento de Sessões de Afinação/Tom ---

    def load_records(self) -> list[VocalSessionRecord]:
        with self._lock:
            store = self._load_raw_store()
            return [VocalSessionRecord(**item) for item in store.get("records", [])]

    def save_record(self, record: VocalSessionRecord, max_history: int = 25) -> list[VocalSessionRecord]:
        with self._lock:
            store = self._load_raw_store()
            records = [VocalSessionRecord(**item) for item in store.get("records", [])]
            records.insert(0, record)
            records = records[:max_history]
            store["records"] = [asdict(r) for r in records]
            self._save_raw_store(store)
            return records

    # --- Gerenciamento de Sessão de Autenticação (Login / JWT) ---

    def save_auth_session(
        self,
        user_id: str,
        email: str,
        token: str,
        name: Optional[str] = None,
        nome: Optional[str] = None,
    ) -> dict[str, Any]:
        """Salva a sessão do usuário com token JWT no cofre criptografado (AES-256-GCM) e isola o banco local."""
        with self._lock:
            user_name = (name or nome or "").strip()
            session_data = {
                "user_id": str(user_id),
                "email": str(email).strip().lower(),
                "name": user_name,
                "nome": user_name,
                "token": str(token).strip(),
                "updated_at": datetime.now().strftime("%d/%m/%Y %H:%M"),
            }

            # Salva a sessão no arquivo de sessão mestre
            session_store = self._load_session_store()
            session_store["auth"] = session_data
            self._save_session_store(session_store)

            # Alterna o cofre de dados ativo para o usuário logado
            u_key = str(user_id or email).strip().lower()
            self.switch_user(u_key)

            # Também persiste a sessão no cofre individual do usuário
            user_store = self._load_raw_store()
            user_store["auth"] = session_data
            self._save_raw_store(user_store)

            return session_data

    def get_auth_session(self) -> Optional[dict[str, Any]]:
        """Recupera a sessão do usuário autenticado se existir no cofre."""
        with self._lock:
            session_store = self._load_session_store()
            auth = session_store.get("auth")
            if isinstance(auth, dict) and auth.get("token"):
                return auth
            if not self._is_explicit_path:
                raw = self._load_raw_store().get("auth")
                if isinstance(raw, dict) and raw.get("token"):
                    return raw
            return None

    def clear_auth_session(self) -> None:
        """Desconecta o usuário limpando as credenciais salvas no cofre local e alternando para guest."""
        with self._lock:
            session_store = self._load_session_store()
            session_store["auth"] = None
            self._save_session_store(session_store)

            user_store = self._load_raw_store()
            user_store["auth"] = None
            self._save_raw_store(user_store)

            self.switch_user(None)

    def update_auth_user_name(self, novo_nome: str, novo_token: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Atualiza o nome de exibição do usuário na sessão persistida no cofre criptografado (AES-256-GCM)."""
        with self._lock:
            session_store = self._load_session_store()
            auth = session_store.get("auth")
            if isinstance(auth, dict) and auth.get("token"):
                clean_name = novo_nome.strip()
                auth["name"] = clean_name
                auth["nome"] = clean_name
                if novo_token and novo_token.strip():
                    auth["token"] = novo_token.strip()
                auth["updated_at"] = datetime.now().strftime("%d/%m/%Y %H:%M")
                session_store["auth"] = auth
                self._save_session_store(session_store)

                user_store = self._load_raw_store()
                user_store["auth"] = auth
                self._save_raw_store(user_store)
                return auth
            return None

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

    def load_songs(self, equipe_id: Optional[str] = None) -> list[RehearsedSongRecord]:
        """Carrega todas as músicas ensaiadas salvas no cofre com deduplicação por chave composta e auto-limpeza."""
        with self._lock:
            store = self._load_raw_store()
            seen = set()
            cleaned_raw = []
            needs_save = False

            for item in store.get("songs", []):
                item.setdefault("versao", "Original")
                item.setdefault("synced", True)
                item.setdefault("equipe_id", "")

                norm_key = (
                    str(item.get("title", "")).strip().lower(),
                    str(item.get("soloist", "")).strip().lower(),
                    str(item.get("versao", "Original")).strip().lower(),
                    str(item.get("equipe_id", "")).strip(),
                )
                if not norm_key[0]:
                    needs_save = True
                    continue

                if norm_key in seen:
                    # Se já vimos essa música no cofre, funde os tons se houver novos
                    idx = [
                        i for i, c in enumerate(cleaned_raw)
                        if (
                            str(c.get("title", "")).strip().lower(),
                            str(c.get("soloist", "")).strip().lower(),
                            str(c.get("versao", "Original")).strip().lower(),
                            str(c.get("equipe_id", "")).strip(),
                        ) == norm_key
                    ][0]
                    existing_keys = list(cleaned_raw[idx].get("keys", []))
                    for k in item.get("keys", []):
                        if k not in existing_keys:
                            existing_keys.append(k)
                    cleaned_raw[idx]["keys"] = existing_keys
                    needs_save = True
                    continue

                seen.add(norm_key)
                cleaned_raw.append(item)

            if needs_save:
                store["songs"] = cleaned_raw
                self._save_raw_store(store)

            results = []
            for it in cleaned_raw:
                it.setdefault("equipe_id", "")
                it_eq = str(it.get("equipe_id", "")).strip()
                if equipe_id and equipe_id != "*":
                    if it_eq != str(equipe_id).strip():
                        continue
                elif equipe_id != "*":
                    if it_eq:
                        continue
                results.append(RehearsedSongRecord(**it))
            return results

    def save_song(
        self,
        title: str,
        keys: list[str],
        soloist: str,
        versao: str = "Original",
        synced: bool = True,
        equipe_id: str = "",
        song_id: Optional[str] = None,
    ) -> RehearsedSongRecord:
        """
        Cadastra ou atualiza uma música ensaiada com Nome, múltiplos Tons, Solista, Versão, Equipe e status de sincronização.
        Deduplica por chave composta (título, solista, versão, equipe).
        """
        clean_title = title.strip()
        clean_soloist = soloist.strip() or "Não informado"
        clean_keys = [k.strip() for k in keys if k.strip()]
        clean_versao = versao.strip() or "Original"
        clean_equipe = (equipe_id or "").strip()
        assigned_id = str(song_id).strip() if song_id else None

        if not clean_title:
            raise ValueError("O nome da música é obrigatório.")
        if not clean_keys:
            raise ValueError("Selecione pelo menos um Tom para a música.")

        target_norm = (clean_title.lower(), clean_soloist.lower(), clean_versao.lower(), clean_equipe)

        with self._lock:
            store = self._load_raw_store()
            songs_raw = store.get("songs", [])

            existing_idx = None
            for i, item in enumerate(songs_raw):
                item_norm = (
                    str(item.get("title", "")).strip().lower(),
                    str(item.get("soloist", "")).strip().lower(),
                    str(item.get("versao", "Original")).strip().lower(),
                    str(item.get("equipe_id", "")).strip(),
                )
                if item_norm == target_norm:
                    existing_idx = i
                    break

            if existing_idx is not None:
                existing = songs_raw[existing_idx]
                if assigned_id:
                    existing["id"] = assigned_id
                    existing["_id"] = assigned_id
                # Mescla tons mantendo a ordem sem repetições
                merged_keys = list(existing.get("keys", []))
                for k in clean_keys:
                    if k not in merged_keys:
                        merged_keys.append(k)
                existing["keys"] = merged_keys
                existing["title"] = clean_title
                existing["soloist"] = clean_soloist
                existing["versao"] = clean_versao
                existing["synced"] = synced
                existing["equipe_id"] = clean_equipe
                song = RehearsedSongRecord(
                    id=existing.get("id") or assigned_id or base64.urlsafe_b64encode(os.urandom(6)).decode("ascii"),
                    title=clean_title,
                    soloist=clean_soloist,
                    keys=merged_keys,
                    versao=clean_versao,
                    created_at=existing.get("created_at") or datetime.now().strftime("%d/%m/%Y %H:%M"),
                    synced=synced,
                    equipe_id=clean_equipe,
                )
                songs_raw[existing_idx] = asdict(song)
            else:
                record_id = assigned_id or base64.urlsafe_b64encode(os.urandom(6)).decode("ascii")
                song = RehearsedSongRecord(
                    id=record_id,
                    title=clean_title,
                    soloist=clean_soloist,
                    keys=clean_keys,
                    versao=clean_versao,
                    created_at=datetime.now().strftime("%d/%m/%Y %H:%M"),
                    synced=synced,
                    equipe_id=clean_equipe,
                )
                songs_raw.insert(0, asdict(song))

            store["songs"] = songs_raw
            self._save_raw_store(store)
            return song

    def get_unsynced_songs(self, equipe_id: Optional[str] = "*") -> list[RehearsedSongRecord]:
        """Retorna todas as músicas salvas offline que ainda não foram enviadas ao banco de dados."""
        with self._lock:
            return [s for s in self.load_songs(equipe_id=equipe_id) if not s.synced]

    def mark_song_as_synced(self, song_id: str) -> None:
        """Marca uma música local como sincronizada online no banco de dados."""
        with self._lock:
            clean_id = str(song_id).strip()
            store = self._load_raw_store()
            songs_raw = store.get("songs", [])
            for item in songs_raw:
                if str(item.get("id", "")).strip() == clean_id or str(item.get("_id", "")).strip() == clean_id:
                    item["synced"] = True
            store["songs"] = songs_raw
            self._save_raw_store(store)

    def delete_song(self, song_id: str) -> list[RehearsedSongRecord]:
        """Remove uma música pelo ID e retorna a lista atualizada."""
        with self._lock:
            clean_id = str(song_id).strip()
            store = self._load_raw_store()
            songs = []
            for item in store.get("songs", []):
                it_id = str(item.get("id", "")).strip()
                it_oid = str(item.get("_id", "")).strip()
                if clean_id and (it_id == clean_id or it_oid == clean_id):
                    continue
                item.setdefault("versao", "Original")
                item.setdefault("synced", True)
                songs.append(RehearsedSongRecord(**item))
            store["songs"] = [asdict(s) for s in songs]
            self._save_raw_store(store)
            return songs

    def reconcile_songs(
        self, cloud_songs: list[dict[str, Any]], equipe_id: Optional[str] = None
    ) -> list[RehearsedSongRecord]:
        """
        Reconciliação bi-direcional estrita com a nuvem (MongoDB Atlas).
        - Se uma música foi apagada na nuvem por outro usuário, ela é removida do cofre local.
        - Preserva apenas itens cadastrados offline ainda não sincronizados ou pertencentes a outras equipes.
        """
        with self._lock:
            store = self._load_raw_store()
            songs_raw = store.get("songs", [])

            cloud_keys: dict[tuple[str, str, str], dict[str, Any]] = {}
            for cs in cloud_songs:
                t = str(cs.get("titulo") or cs.get("title") or "").strip()
                sol = str(cs.get("cantor_principal") or cs.get("soloist") or "Não informado").strip()
                v = str(cs.get("versao") or "Original").strip()
                if t:
                    cloud_keys[(t.lower(), sol.lower(), v.lower())] = cs

            reconciled_raw: list[dict[str, Any]] = []

            # 1. Preserva músicas salvas offline que ainda não foram enviadas ou pertencentes a outras equipes
            for item in songs_raw:
                it_eq = str(item.get("equipe_id", "")).strip()
                if not item.get("synced", True):
                    reconciled_raw.append(item)
                elif equipe_id and it_eq and it_eq != str(equipe_id).strip():
                    reconciled_raw.append(item)
                elif not equipe_id and it_eq:
                    reconciled_raw.append(item)

            # 2. Adiciona/atualiza músicas ativas confirmadas pela nuvem
            for norm_key, cs in cloud_keys.items():
                t = str(cs.get("titulo") or cs.get("title") or "").strip()
                sol = str(cs.get("cantor_principal") or cs.get("soloist") or "Não informado").strip()
                v = str(cs.get("versao") or "Original").strip()
                tons = cs.get("tons") or cs.get("keys") or []
                cid = str(cs.get("_id") or cs.get("id") or base64.urlsafe_b64encode(os.urandom(6)).decode("ascii"))
                eq_val = str(cs.get("equipe_id") or equipe_id or "").strip()
                reconciled_raw.append({
                    "id": cid,
                    "title": t,
                    "soloist": sol,
                    "keys": [str(k).strip() for k in tons if str(k).strip()],
                    "versao": v,
                    "created_at": cs.get("criado_em") or datetime.now().strftime("%d/%m/%Y %H:%M"),
                    "synced": True,
                    "equipe_id": eq_val,
                })

            store["songs"] = reconciled_raw
            self._save_raw_store(store)
            return self.load_songs(equipe_id=equipe_id)

    def search_songs(
        self, query: str = "", soloist: Optional[str] = None, equipe_id: Optional[str] = None
    ) -> list[RehearsedSongRecord]:
        """
        Filtra as músicas cadastradas por termo de busca, solista e equipe.
        """
        with self._lock:
            all_songs = self.load_songs(equipe_id=equipe_id)
            q = query.strip().lower()
            sol = (soloist or "").strip().lower()

            results: list[RehearsedSongRecord] = []
            for song in all_songs:
                if sol and sol != "todos" and song.soloist.strip().lower() != sol:
                    continue

                if not q:
                    results.append(song)
                    continue

                in_title = q in song.title.lower()
                in_soloist = q in song.soloist.lower()
                in_versao = q in song.versao.lower()
                in_keys = any(q in k.lower() for k in song.keys)
                if in_title or in_soloist or in_versao or in_keys:
                    results.append(song)
            return results

    # --- Gerenciamento do Repertório da Semana (Escala de Ensaios) ---

    def load_weekly_schedule(
        self, data_ensaio: Optional[str] = None, equipe_id: Optional[str] = None
    ) -> list[RepertorioSemanaRecord]:
        """Carrega os itens da escala semanal salvos localmente, com deduplicação automática e filtro por data e equipe."""
        with self._lock:
            store = self._load_raw_store()
            items = []
            seen = set()
            cleaned_raw = []
            needs_save = False

            for raw in store.get("weekly", []):
                raw.setdefault("versao", "Original")
                raw.setdefault("adicionado_por", "Equipe")
                raw.setdefault("synced", True)
                raw.setdefault("equipe_id", "")

                norm_key = (
                    str(raw.get("titulo", "")).strip().lower(),
                    str(raw.get("cantor_principal", "")).strip().lower(),
                    str(raw.get("data_ensaio", "")).strip(),
                    str(raw.get("equipe_id", "")).strip(),
                )
                if not norm_key[0] or not norm_key[2]:
                    needs_save = True
                    continue

                if norm_key in seen:
                    needs_save = True
                    continue

                seen.add(norm_key)
                cleaned_raw.append(raw)
                it_eq = str(raw.get("equipe_id", "")).strip()
                if equipe_id and equipe_id != "*":
                    if it_eq != str(equipe_id).strip():
                        continue
                elif equipe_id != "*":
                    if it_eq:
                        continue
                if data_ensaio and raw.get("data_ensaio") != str(data_ensaio).strip():
                    continue
                items.append(RepertorioSemanaRecord(**raw))

            if needs_save:
                store["weekly"] = cleaned_raw
                self._save_raw_store(store)

            return items

    def save_weekly_item(
        self,
        musica_id: str,
        titulo: str,
        cantor_principal: str,
        tom_selecionado: str,
        data_ensaio: str,
        dia_semana: str,
        versao: str = "Original",
        adicionado_por: str = "Equipe",
        synced: bool = True,
        equipe_id: str = "",
        item_id: Optional[str] = None,
    ) -> RepertorioSemanaRecord:
        """Salva uma música agendada para a escala semanal no cofre seguro local prevenindo duplicatas."""
        clean_tit = titulo.strip()
        clean_cp = cantor_principal.strip() or "Não informado"
        clean_tom = tom_selecionado.strip()
        clean_data = data_ensaio.strip()
        clean_dia = dia_semana.strip() or "Ensaio"
        clean_versao = versao.strip() or "Original"
        clean_user = adicionado_por.strip() or "Equipe"
        clean_equipe = (equipe_id or "").strip()
        assigned_id = str(item_id).strip() if item_id else None

        with self._lock:
            store = self._load_raw_store()
            weekly = store.get("weekly", [])

            target_norm = (clean_tit.lower(), clean_cp.lower(), clean_data, clean_equipe)
            existing_idx = None
            for i, item in enumerate(weekly):
                item_norm = (
                    str(item.get("titulo", "")).strip().lower(),
                    str(item.get("cantor_principal", "")).strip().lower(),
                    str(item.get("data_ensaio", "")).strip(),
                    str(item.get("equipe_id", "")).strip(),
                )
                if item_norm == target_norm:
                    existing_idx = i
                    break

            if existing_idx is not None:
                existing = weekly[existing_idx]
                if assigned_id:
                    existing["id"] = assigned_id
                    existing["_id"] = assigned_id
                existing["tom_selecionado"] = clean_tom
                existing["versao"] = clean_versao
                existing["dia_semana"] = clean_dia
                existing["adicionado_por"] = clean_user
                existing["synced"] = synced
                existing["equipe_id"] = clean_equipe
                record = RepertorioSemanaRecord(**existing)
                weekly[existing_idx] = asdict(record)
            else:
                record_id = assigned_id or base64.urlsafe_b64encode(os.urandom(6)).decode("ascii")
                record = RepertorioSemanaRecord(
                    id=record_id,
                    musica_id=musica_id,
                    titulo=clean_tit,
                    cantor_principal=clean_cp,
                    tom_selecionado=clean_tom,
                    data_ensaio=clean_data,
                    dia_semana=clean_dia,
                    versao=clean_versao,
                    adicionado_por=clean_user,
                    created_at=datetime.now().strftime("%d/%m/%Y %H:%M"),
                    synced=synced,
                    equipe_id=clean_equipe,
                )
                weekly.insert(0, asdict(record))

            store["weekly"] = weekly
            self._save_raw_store(store)
            return record

    def get_unsynced_weekly_items(self, equipe_id: Optional[str] = "*") -> list[RepertorioSemanaRecord]:
        """Retorna itens da escala semanal salvos offline ainda não sincronizados com a nuvem."""
        with self._lock:
            return [w for w in self.load_weekly_schedule(equipe_id=equipe_id) if not w.synced]

    def mark_weekly_as_synced(self, item_id: str) -> None:
        """Marca um item da escala semanal como sincronizado na nuvem."""
        with self._lock:
            store = self._load_raw_store()
            weekly = store.get("weekly", [])
            for item in weekly:
                if item.get("id") == item_id:
                    item["synced"] = True
            store["weekly"] = weekly
            self._save_raw_store(store)

    def delete_weekly_item(
        self,
        item_id: str,
        titulo: Optional[str] = None,
        data_ensaio: Optional[str] = None,
    ) -> list[RepertorioSemanaRecord]:
        """Remove um item da escala semanal local pelo seu id ou pelo par título + data."""
        with self._lock:
            clean_id = str(item_id).strip()
            store = self._load_raw_store()
            weekly = []
            for item in store.get("weekly", []):
                it_id = str(item.get("id", "")).strip()
                it_oid = str(item.get("_id", "")).strip()
                it_tit = str(item.get("titulo", "")).strip().lower()
                it_dt = str(item.get("data_ensaio", "")).strip()

                is_match = False
                if clean_id and (it_id == clean_id or it_oid == clean_id):
                    is_match = True
                elif titulo and data_ensaio:
                    if it_tit == str(titulo).strip().lower() and it_dt == str(data_ensaio).strip():
                        is_match = True

                if not is_match:
                    weekly.append(item)

            store["weekly"] = weekly
            self._save_raw_store(store)
            res = []
            for item in weekly:
                item.setdefault("versao", "Original")
                item.setdefault("adicionado_por", "Equipe")
                item.setdefault("synced", True)
                item.setdefault("equipe_id", "")
                res.append(RepertorioSemanaRecord(**item))
            return res

    def reconcile_weekly_items(
        self,
        cloud_items: list[dict[str, Any]],
        data_ensaio: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> list[RepertorioSemanaRecord]:
        """
        Reconcilia a escala semanal com o MongoDB Atlas.
        Se uma música foi excluída da escala na nuvem, ela é eliminada do cofre local.
        """
        with self._lock:
            store = self._load_raw_store()
            weekly_raw = store.get("weekly", [])

            cloud_keys: dict[tuple[str, str, str], dict[str, Any]] = {}
            for ci in cloud_items:
                t = str(ci.get("titulo", "")).strip()
                cp = str(ci.get("cantor_principal", "Não informado")).strip()
                d = str(ci.get("data_ensaio", "")).strip()
                if t and d:
                    cloud_keys[(t.lower(), cp.lower(), d)] = ci

            reconciled_weekly: list[dict[str, Any]] = []

            # 1. Preserva itens de outras equipes ou de outras datas ou itens criados offline
            for item in weekly_raw:
                it_eq = str(item.get("equipe_id", "")).strip()
                d_local = str(item.get("data_ensaio", "")).strip()
                if not item.get("synced", True):
                    reconciled_weekly.append(item)
                elif equipe_id and it_eq and it_eq != str(equipe_id).strip():
                    reconciled_weekly.append(item)
                elif not equipe_id and it_eq:
                    reconciled_weekly.append(item)
                elif data_ensaio and d_local != str(data_ensaio).strip():
                    reconciled_weekly.append(item)

            # 2. Adiciona todos os itens confirmados da nuvem
            for key, ci in cloud_keys.items():
                t = str(ci.get("titulo", "")).strip()
                cp = str(ci.get("cantor_principal", "Não informado")).strip()
                d = str(ci.get("data_ensaio", "")).strip()
                cid = str(ci.get("_id") or ci.get("id") or base64.urlsafe_b64encode(os.urandom(6)).decode("ascii"))
                eq_val = str(ci.get("equipe_id") or equipe_id or "").strip()
                reconciled_weekly.append({
                    "id": cid,
                    "musica_id": str(ci.get("musica_id") or cid),
                    "titulo": t,
                    "cantor_principal": cp,
                    "tom_selecionado": str(ci.get("tom_selecionado", "")).strip(),
                    "data_ensaio": d,
                    "dia_semana": str(ci.get("dia_semana", "Ensaio")).strip(),
                    "versao": str(ci.get("versao", "Original")).strip(),
                    "adicionado_por": str(ci.get("adicionado_por", "Equipe")).strip(),
                    "created_at": ci.get("criado_em") or datetime.now().strftime("%d/%m/%Y %H:%M"),
                    "synced": True,
                    "equipe_id": eq_val,
                })

            store["weekly"] = reconciled_weekly
            self._save_raw_store(store)
            return self.load_weekly_schedule(data_ensaio=data_ensaio, equipe_id=equipe_id)

    # --- Gerenciamento de Músicas A Ensaiar (Próximo Ensaio) ---

    def load_a_ensaiar(self, equipe_id: Optional[str] = None) -> list[MusicaAEnsaiarRecord]:
        """Carrega a lista de músicas a ensaiar salvas no cofre seguro local com deduplicação e filtro por equipe."""
        with self._lock:
            store = self._load_raw_store()
            items = []
            seen = set()
            cleaned_raw = []
            needs_save = False

            for raw in store.get("a_ensaiar", []):
                raw.setdefault("status", "Próximo Ensaio")
                raw.setdefault("youtube_url", "")
                raw.setdefault("adicionado_por", "Equipe")
                raw.setdefault("synced", True)
                raw.setdefault("equipe_id", "")

                norm_key = (
                    str(raw.get("titulo", "")).strip().lower(),
                    str(raw.get("cantor_versao", "")).strip().lower(),
                    str(raw.get("equipe_id", "")).strip(),
                )
                if not norm_key[0]:
                    needs_save = True
                    continue

                if norm_key in seen:
                    needs_save = True
                    continue

                seen.add(norm_key)
                cleaned_raw.append(raw)
                it_eq = str(raw.get("equipe_id", "")).strip()
                if equipe_id and equipe_id != "*":
                    if it_eq != str(equipe_id).strip():
                        continue
                elif equipe_id != "*":
                    if it_eq:
                        continue
                items.append(MusicaAEnsaiarRecord(**raw))

            if needs_save:
                store["a_ensaiar"] = cleaned_raw
                self._save_raw_store(store)

            return items

    def save_a_ensaiar(
        self,
        titulo: str,
        cantor_versao: str,
        youtube_url: str = "",
        status: str = "Próximo Ensaio",
        adicionado_por: str = "Equipe",
        synced: bool = True,
        equipe_id: str = "",
        item_id: Optional[str] = None,
    ) -> MusicaAEnsaiarRecord:
        """Salva ou atualiza uma música a ensaiar no cofre local seguro prevenindo duplicatas."""
        clean_title = titulo.strip()
        clean_cv = cantor_versao.strip()
        if not clean_title:
            raise ValueError("O nome da música é obrigatório.")
        if not clean_cv:
            raise ValueError("O cantor / versão da música é obrigatório.")

        safe_yt_url = sanitize_youtube_url(youtube_url)
        clean_status = status.strip() or "Próximo Ensaio"
        clean_user = (adicionado_por or "").strip() or "Equipe"
        clean_equipe = (equipe_id or "").strip()
        assigned_id = str(item_id).strip() if item_id else None

        with self._lock:
            store = self._load_raw_store()
            a_ensaiar = store.get("a_ensaiar", [])

            target_norm = (clean_title.lower(), clean_cv.lower(), clean_equipe)
            existing_idx = None
            for i, item in enumerate(a_ensaiar):
                item_norm = (
                    str(item.get("titulo", "")).strip().lower(),
                    str(item.get("cantor_versao", "")).strip().lower(),
                    str(item.get("equipe_id", "")).strip(),
                )
                if item_norm == target_norm:
                    existing_idx = i
                    break

            if existing_idx is not None:
                existing = a_ensaiar[existing_idx]
                if assigned_id:
                    existing["id"] = assigned_id
                    existing["_id"] = assigned_id
                if safe_yt_url:
                    existing["youtube_url"] = safe_yt_url
                existing["status"] = clean_status
                existing["adicionado_por"] = clean_user
                existing["synced"] = synced
                existing["equipe_id"] = clean_equipe
                record = MusicaAEnsaiarRecord(**existing)
                a_ensaiar[existing_idx] = asdict(record)
            else:
                record_id = assigned_id or base64.urlsafe_b64encode(os.urandom(6)).decode("ascii")
                record = MusicaAEnsaiarRecord(
                    id=record_id,
                    titulo=clean_title,
                    cantor_versao=clean_cv,
                    youtube_url=safe_yt_url,
                    status=clean_status,
                    adicionado_por=clean_user,
                    created_at=datetime.now().strftime("%d/%m/%Y %H:%M"),
                    synced=synced,
                    equipe_id=clean_equipe,
                )
                a_ensaiar.insert(0, asdict(record))

            store["a_ensaiar"] = a_ensaiar
            self._save_raw_store(store)
            return record

    def get_unsynced_a_ensaiar_items(self, equipe_id: Optional[str] = "*") -> list[MusicaAEnsaiarRecord]:
        """Retorna sugestões de músicas a ensaiar salvas offline que ainda não subiram para a nuvem."""
        with self._lock:
            return [item for item in self.load_a_ensaiar(equipe_id=equipe_id) if not item.synced]

    def mark_a_ensaiar_as_synced(self, item_id: str) -> None:
        """Marca uma sugestão de música a ensaiar como sincronizada na nuvem."""
        with self._lock:
            store = self._load_raw_store()
            a_ensaiar = store.get("a_ensaiar", [])
            for item in a_ensaiar:
                if item.get("id") == item_id or item.get("_id") == item_id:
                    item["synced"] = True
            store["a_ensaiar"] = a_ensaiar
            self._save_raw_store(store)

    def delete_a_ensaiar(
        self,
        item_id: str,
        titulo: Optional[str] = None,
        cantor_versao: Optional[str] = None,
    ) -> list[MusicaAEnsaiarRecord]:
        """Remove uma música da fila a ensaiar pelo seu id ou por fallback de título e versão."""
        with self._lock:
            clean_id = str(item_id).strip()
            clean_tit = str(titulo).strip().lower() if titulo and str(titulo).strip() else None
            clean_cv = str(cantor_versao).strip().lower() if cantor_versao and str(cantor_versao).strip() else None

            store = self._load_raw_store()
            a_ensaiar = []
            for item in store.get("a_ensaiar", []):
                it_id = str(item.get("id", "")).strip()
                it_oid = str(item.get("_id", "")).strip()
                it_tit = str(item.get("titulo", "")).strip().lower()
                it_cv = str(item.get("cantor_versao", "")).strip().lower()

                if clean_id and (it_id == clean_id or it_oid == clean_id):
                    continue
                if clean_tit and it_tit == clean_tit:
                    if clean_cv is None or it_cv == clean_cv:
                        continue
                a_ensaiar.append(item)
            store["a_ensaiar"] = a_ensaiar
            self._save_raw_store(store)
            res = []
            for item in a_ensaiar:
                item.setdefault("status", "Próximo Ensaio")
                item.setdefault("youtube_url", "")
                item.setdefault("adicionado_por", "Equipe")
                item.setdefault("synced", True)
                item.setdefault("equipe_id", "")
                res.append(MusicaAEnsaiarRecord(**item))
            return res

    def reconcile_a_ensaiar(
        self, cloud_items: list[dict[str, Any]], equipe_id: Optional[str] = None
    ) -> list[MusicaAEnsaiarRecord]:
        """
        Reconcilia a fila de Músicas a Ensaiar com o MongoDB Atlas.
        Se uma música foi excluída da lista na nuvem, ela é eliminada do cofre local.
        """
        with self._lock:
            store = self._load_raw_store()
            a_ensaiar_raw = store.get("a_ensaiar", [])

            cloud_keys: dict[tuple[str, str], dict[str, Any]] = {}
            for ci in cloud_items:
                t = str(ci.get("titulo", "")).strip()
                cv = str(ci.get("cantor_versao", "")).strip()
                if t:
                    cloud_keys[(t.lower(), cv.lower())] = ci

            reconciled_ae: list[dict[str, Any]] = []

            # 1. Preserva itens criados offline ou pertencentes a outras equipes
            for item in a_ensaiar_raw:
                it_eq = str(item.get("equipe_id", "")).strip()
                if not item.get("synced", True):
                    reconciled_ae.append(item)
                elif equipe_id and it_eq and it_eq != str(equipe_id).strip():
                    reconciled_ae.append(item)
                elif not equipe_id and it_eq:
                    reconciled_ae.append(item)

            # 2. Adiciona todos os itens confirmados da nuvem
            for key, ci in cloud_keys.items():
                t = str(ci.get("titulo", "")).strip()
                cv = str(ci.get("cantor_versao", "")).strip()
                cid = str(ci.get("_id") or ci.get("id") or base64.urlsafe_b64encode(os.urandom(6)).decode("ascii"))
                eq_val = str(ci.get("equipe_id") or equipe_id or "").strip()
                reconciled_ae.append({
                    "id": cid,
                    "titulo": t,
                    "cantor_versao": cv,
                    "youtube_url": str(ci.get("youtube_url", "")).strip(),
                    "status": str(ci.get("status", "Próximo Ensaio")).strip(),
                    "adicionado_por": str(ci.get("adicionado_por", "Equipe")).strip(),
                    "created_at": ci.get("criado_em") or datetime.now().strftime("%d/%m/%Y %H:%M"),
                    "synced": True,
                    "equipe_id": eq_val,
                })

            store["a_ensaiar"] = reconciled_ae
            self._save_raw_store(store)
            return self.load_a_ensaiar(equipe_id=equipe_id)

    # --- Gerenciamento de Multi-Equipes no Cofre Seguro ---

    def get_active_team(self) -> Optional[dict[str, Any]]:
        """Recupera a equipe ativa selecionada pelo usuário no cofre local."""
        with self._lock:
            store = self._load_raw_store()
            return store.get("active_team")

    def set_active_team(self, team: Optional[dict[str, Any]]) -> None:
        """Salva a equipe ativa selecionada no cofre local seguro."""
        with self._lock:
            store = self._load_raw_store()
            store["active_team"] = team
            self._save_raw_store(store)

    def get_cached_teams(self) -> list[dict[str, Any]]:
        """Recupera a lista de equipes do usuário salvas no cofre local."""
        with self._lock:
            store = self._load_raw_store()
            return store.get("cached_teams", [])

    def set_cached_teams(self, teams: list[dict[str, Any]]) -> None:
        """Atualiza a lista de equipes salvas no cofre local seguro."""
        with self._lock:
            store = self._load_raw_store()
            store["cached_teams"] = teams
            self._save_raw_store(store)

    def get_notification_metadata(self) -> dict[str, Any]:
        """Recupera contadores de músicas visualizadas para cálculo de badges de novidades."""
        with self._lock:
            store = self._load_raw_store()
            meta = store.get("notifications_meta")
            if not isinstance(meta, dict):
                meta = {"seen_weekly_count": 0, "seen_to_rehearse_count": 0}
            return meta

    def update_notification_metadata(self, **kwargs: Any) -> None:
        """Atualiza contadores de notificações e novidades de músicas."""
        with self._lock:
            store = self._load_raw_store()
            meta = store.get("notifications_meta")
            if not isinstance(meta, dict):
                meta = {}
            meta.update(kwargs)
            store["notifications_meta"] = meta
            self._save_raw_store(store)

    def clear_vault(self) -> None:
        with self._lock:
            self._memory_store = None
            self._last_mtime_ns = None
            if self.vault_path.exists():
                self.vault_path.unlink()


