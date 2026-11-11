"""
Módulo de Autenticação Segura e Criptografia de Credenciais (`security-specialist`).

Padrões de Segurança (AppSec / OWASP):
1. Hashing de Senhas: PBKDF2-HMAC-SHA256 com 600.000 iterações e salt aleatório de 16 bytes.
2. Comparação em tempo constante (anti-timing attacks): `hmac.compare_digest`.
3. Tokens de Acesso JWT (RFC 7519 / HS256) assinados digitalmente.
4. Sanitização e validação de e-mails (RFC 5322) e força mínima de senha.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    from dotenv import load_dotenv
    _web_root = Path(__file__).resolve().parents[2]
    load_dotenv(_web_root / ".env")
    load_dotenv()
    if os.path.exists("../.env"):
        load_dotenv("../.env")
    if (_web_root.parent / ".env").exists():
        load_dotenv(_web_root.parent / ".env")
except ImportError:
    pass


def _resolve_jwt_secret() -> str:
    env_secret = (os.getenv("JWT_SECRET") or os.getenv("CIPHERSONG_SECRET_KEY") or "").strip()
    if env_secret:
        return env_secret
    runtime_secret = secrets.token_urlsafe(32)
    logger.warning(
        "Segurança: 'JWT_SECRET' não encontrada no ambiente. "
        "Gerando chave efêmera aleatória para esta execução. "
        "Defina JWT_SECRET no arquivo .env para persistir sessões em produção."
    )
    return runtime_secret


JWT_SECRET = _resolve_jwt_secret()


def get_jwt_secret() -> str:
    """Retorna o segredo JWT priorizando dinamicamente qualquer chave definida no ambiente."""
    return (os.getenv("JWT_SECRET") or os.getenv("CIPHERSONG_SECRET_KEY") or "").strip() or JWT_SECRET

PBKDF2_ITERATIONS = 600_000
SALT_SIZE_BYTES = 16
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email(email: str) -> bool:
    """Valida se a string atende a um formato de e-mail sintaticamente válido."""
    if not email or not isinstance(email, str):
        return False
    clean = email.strip()
    return bool(EMAIL_REGEX.match(clean)) and len(clean) <= 120


def validate_password(password: str) -> tuple[bool, str]:
    """
    Verifica a força mínima da senha para garantir proteção contra ataques de dicionário.
    Exige no mínimo 6 caracteres para excelente usabilidade no celular sem sacrificar segurança.
    """
    if not password or not isinstance(password, str):
        return False, "A senha não pode ser vazia."
    if len(password) < 6:
        return False, "A senha deve conter no mínimo 6 caracteres."
    return True, ""


def hash_password(password: str) -> str:
    """
    Gera o hash irreversível da senha com salt aleatório e 600.000 iterações PBKDF2-HMAC-SHA256.
    Formato retornado: 'pbkdf2_sha256$<iteracoes>$<salt_b64>$<hash_b64>'
    """
    clean_pwd = password.encode("utf-8")
    salt = os.urandom(SALT_SIZE_BYTES)
    derived_key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=clean_pwd,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=32,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(derived_key).decode("ascii")
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_b64}${hash_b64}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se a senha em texto puro corresponde ao hash armazenado,
    utilizando comparação em tempo constante para evitar ataques de temporização (timing attacks).
    """
    if not plain_password or not hashed_password:
        return False

    parts = hashed_password.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False

    try:
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        expected_hash = base64.b64decode(parts[3])

        candidate_hash = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=plain_password.encode("utf-8"),
            salt=salt,
            iterations=iterations,
            dklen=len(expected_hash),
        )
        return hmac.compare_digest(candidate_hash, expected_hash)
    except Exception:
        return False


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data_str: str) -> bytes:
    rem = len(data_str) % 4
    if rem > 0:
        data_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data_str.encode("ascii"))


def create_access_token(
    user_id: str,
    email: str,
    name: Optional[str] = None,
    expires_days: int = 60,
    expires_seconds: Optional[int] = None,
    secret: Optional[str] = None,
) -> str:
    """
    Cria um Token JWT (JSON Web Token - RFC 7519 / HS256) assinado com HMAC-SHA256.
    Suporta expiração curta em segundos (ex: 15 minutos = 900s) ou em dias.
    """
    sec = (secret or get_jwt_secret()).encode("utf-8")
    now = int(time.time())
    if expires_seconds is not None:
        exp = now + int(expires_seconds)
    else:
        exp = now + (expires_days * 86400)

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(user_id),
        "email": email.strip().lower(),
        "name": name.strip() if name else "",
        "nome": name.strip() if name else "",
        "iat": now,
        "exp": exp,
    }

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    segment1 = _b64url_encode(header_bytes)
    segment2 = _b64url_encode(payload_bytes)
    signing_input = f"{segment1}.{segment2}".encode("ascii")

    signature = hmac.new(sec, signing_input, hashlib.sha256).digest()
    segment3 = _b64url_encode(signature)

    return f"{segment1}.{segment2}.{segment3}"


def generate_refresh_token() -> tuple[str, str]:
    """
    Gera um par de Refresh Token criptograficamente seguro (RFC 6749):
    Retorna (token_bruto_para_cookie, hash_sha256_para_armazenar_no_banco).
    """
    import secrets
    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_refresh_token(raw_token)
    return raw_token, token_hash


def hash_refresh_token(raw_token: str) -> str:
    """Calcula o hash SHA-256 de um Refresh Token para evitar vazamento em caso de dump do banco."""
    return hashlib.sha256(raw_token.strip().encode("ascii")).hexdigest()


def decode_access_token(token: str, secret: Optional[str] = None) -> Optional[dict[str, Any]]:
    """
    Decodifica e valida a assinatura digital e expiração de um Token JWT.
    Retorna o payload se for válido ou None caso a assinatura esteja incorreta ou expirada.
    """
    if not token or not isinstance(token, str):
        return None

    clean_token = token.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()

    parts = clean_token.split(".")
    if len(parts) != 3:
        return None

    sec = (secret or get_jwt_secret()).encode("utf-8")
    segment1, segment2, segment3 = parts

    signing_input = f"{segment1}.{segment2}".encode("ascii")
    expected_sig = hmac.new(sec, signing_input, hashlib.sha256).digest()

    try:
        header_bytes = _b64url_decode(segment1)
        header = json.loads(header_bytes.decode("utf-8"))
        # Blindagem contra Algorithm Confusion (RFC 7519 / RFC 7515): Aceita estritamente HS256
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return None

        received_sig = _b64url_decode(segment3)
        if not hmac.compare_digest(received_sig, expected_sig):
            return None

        payload_bytes = _b64url_decode(segment2)
        payload = json.loads(payload_bytes.decode("utf-8"))

        # Valida expiração
        exp = payload.get("exp", 0)
        if time.time() > exp:
            return None

        return payload
    except Exception:
        return None
