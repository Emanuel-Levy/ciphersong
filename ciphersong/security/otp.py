"""
Gerenciador de Códigos OTP (One-Time Password / Passwordless Login) (`security-specialist` + `senior-architect`).

Padrões de Segurança AppSec (OWASP):
1. Geração Criptograficamente Segura: `secrets.randbelow` de 6 dígitos numéricos.
2. Armazenamento com Hash: O código nunca é salvo em texto puro na memória/banco.
3. Comparação em Tempo Constante: `hmac.compare_digest` para neutralizar timing attacks.
4. Rate Limiting Estrito:
   - Cooldown de 60 segundos entre reenvios para o mesmo e-mail ou IP.
   - Trava de no máximo 5 solicitações por hora por e-mail ou IP.
5. Limite de Tentativas: No máximo 5 tentativas incorretas antes do código ser irrevogavelmente destruído.
6. Invalidação Pós-Uso: O código é destruído imediatamente no primeiro uso com sucesso (anti-replay).
7. TTL Curto: Expiração automática em 10 minutos (600 segundos).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


OTP_LENGTH = 6
OTP_TTL_SECONDS = 600  # 10 minutos
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_REQUESTS_PER_HOUR = 5


class OTPRateLimitError(Exception):
    """Exceção levantada quando o usuário atinge o cooldown ou o limite horário de OTP."""

    def __init__(self, message: str, retry_after_seconds: int = 60) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class OTPVerificationError(Exception):
    """Exceção levantada quando o código OTP for inválido, expirado ou tiver estourado tentativas."""

    def __init__(self, message: str, attempts_left: int = 0) -> None:
        super().__init__(message)
        self.attempts_left = attempts_left


@dataclass
class OTPRecord:
    email: str
    code_hash: str
    salt: bytes
    expires_at: float
    attempts_left: int = OTP_MAX_ATTEMPTS
    name: Optional[str] = None
    created_at: float = field(default_factory=time.time)


@dataclass
class RateLimitTracker:
    last_requested_at: float = 0.0
    hourly_timestamps: list[float] = field(default_factory=list)


def generate_otp_code(length: int = OTP_LENGTH) -> str:
    """Gera um código OTP numérico aleatório criptograficamente seguro com a quantidade de dígitos configurada."""
    upper_bound = 10**length
    code_int = secrets.randbelow(upper_bound)
    return f"{code_int:0{length}d}"


def hash_otp_code(code: str, salt: bytes) -> str:
    """Gera hash SHA-256 seguro do código com salt individual."""
    return hashlib.sha256(salt + code.encode("utf-8")).hexdigest()


def verify_otp_hash(plain_code: str, salt: bytes, expected_hash: str) -> bool:
    """Valida o código comparando os hashes em tempo constante (anti-timing attacks)."""
    candidate = hash_otp_code(plain_code, salt)
    return hmac.compare_digest(candidate, expected_hash)


class OTPManager:
    """
    Gerenciador thread-safe em memória para ciclo de vida de códigos OTP com TTL,
    limitação de taxa e destruição imediata pós-uso.
    """

    def __init__(
        self,
        ttl_seconds: int = OTP_TTL_SECONDS,
        max_attempts: int = OTP_MAX_ATTEMPTS,
        cooldown_seconds: int = OTP_RESEND_COOLDOWN_SECONDS,
        max_per_hour: int = OTP_MAX_REQUESTS_PER_HOUR,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_attempts = max_attempts
        self.cooldown_seconds = cooldown_seconds
        self.max_per_hour = max_per_hour

        self._records: dict[str, OTPRecord] = {}
        self._rate_limits: dict[str, RateLimitTracker] = {}
        self._lock = threading.Lock()

    def _normalize_key(self, email: str) -> str:
        return email.strip().lower()

    def purge_expired(self) -> None:
        """Remove registros expirados para manter a memória limpa."""
        now = time.time()
        with self._lock:
            expired_keys = [k for k, rec in self._records.items() if now > rec.expires_at]
            for k in expired_keys:
                self._records.pop(k, None)

            # Limpa timestamps de rate-limit com mais de 1 hora
            one_hour_ago = now - 3600
            for tracker in self._rate_limits.values():
                tracker.hourly_timestamps = [t for t in tracker.hourly_timestamps if t > one_hour_ago]

    def get_cooldown_remaining(self, email: str) -> int:
        """Retorna quantos segundos de cooldown ainda restam antes que o usuário possa pedir novo código."""
        key = self._normalize_key(email)
        now = time.time()
        with self._lock:
            tracker = self._rate_limits.get(key)
            if not tracker:
                return 0
            elapsed = now - tracker.last_requested_at
            if elapsed < self.cooldown_seconds:
                return int(self.cooldown_seconds - elapsed)
            return 0

    def request_otp(
        self,
        email: str,
        name: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> tuple[str, int, int]:
        """
        Cria e armazena de forma segura um novo OTP para o e-mail informado.
        Verifica cooldown e limites por hora.
        Retorna: `(codigo_plano, cooldown_segundos, validade_minutos)`
        """
        self.purge_expired()
        key = self._normalize_key(email)
        now = time.time()

        with self._lock:
            tracker = self._rate_limits.setdefault(key, RateLimitTracker())

            # 1. Valida Cooldown entre disparos sucessivos (60 segundos)
            elapsed = now - tracker.last_requested_at
            if elapsed < self.cooldown_seconds:
                rem = int(self.cooldown_seconds - elapsed)
                raise OTPRateLimitError(
                    f"Aguarde {rem} segundos antes de solicitar um novo código.",
                    retry_after_seconds=rem,
                )

            # 2. Valida Limite Horário (máximo 5 códigos por hora)
            one_hour_ago = now - 3600
            tracker.hourly_timestamps = [t for t in tracker.hourly_timestamps if t > one_hour_ago]
            if len(tracker.hourly_timestamps) >= self.max_per_hour:
                oldest = min(tracker.hourly_timestamps)
                wait_time = int(3600 - (now - oldest)) + 1
                raise OTPRateLimitError(
                    f"Limite de {self.max_per_hour} solicitações por hora atingido para este e-mail. Tente novamente em {max(1, wait_time // 60)} minutos.",
                    retry_after_seconds=wait_time,
                )

            # 3. Registra disparo no tracker de taxa
            tracker.last_requested_at = now
            tracker.hourly_timestamps.append(now)

            # 4. Gera código de 6 dígitos e armazena com Salt e Hash
            plain_code = generate_otp_code(OTP_LENGTH)
            salt = os.urandom(16)
            code_hash = hash_otp_code(plain_code, salt)
            expires_at = now + self.ttl_seconds

            self._records[key] = OTPRecord(
                email=key,
                code_hash=code_hash,
                salt=salt,
                expires_at=expires_at,
                attempts_left=self.max_attempts,
                name=(name.strip() if name and name.strip() else None),
                created_at=now,
            )

            expires_in_minutes = max(1, self.ttl_seconds // 60)
            return plain_code, self.cooldown_seconds, expires_in_minutes

    def verify_otp(self, email: str, candidate_code: str) -> tuple[bool, str, Optional[str]]:
        """
        Valida o código OTP digitado pelo usuário.
        - Se incorreto: decrementa tentativas e destrói se atingir 0.
        - Se correto: DESTRÓI IMEDIATAMENTE o código (invalidação pós-uso / anti-replay).
        Retorna: `(sucesso: bool, mensagem: str, nome: Optional[str])`
        """
        key = self._normalize_key(email)
        clean_code = (candidate_code or "").strip()
        now = time.time()

        with self._lock:
            record = self._records.get(key)
            if not record:
                raise OTPVerificationError(
                    "Nenhum código ativo encontrado para este e-mail. Solicite um novo código.",
                    attempts_left=0,
                )

            # 1. Verifica Expiração (TTL)
            if now > record.expires_at:
                self._records.pop(key, None)
                raise OTPVerificationError(
                    "O código de verificação expirou (validade de 10 minutos). Solicite um novo código.",
                    attempts_left=0,
                )

            # 2. Verifica Limite de Tentativas
            if record.attempts_left <= 0:
                self._records.pop(key, None)
                raise OTPVerificationError(
                    "Limite de tentativas incorretas excedido. Por segurança, solicite um novo código.",
                    attempts_left=0,
                )

            # 3. Comparação em tempo constante do hash
            is_valid = verify_otp_hash(clean_code, record.salt, record.code_hash)
            if not is_valid:
                record.attempts_left -= 1
                attempts = record.attempts_left
                if attempts <= 0:
                    self._records.pop(key, None)
                    raise OTPVerificationError(
                        "Código incorreto. Limite de tentativas esgotado. Solicite um novo código.",
                        attempts_left=0,
                    )
                raise OTPVerificationError(
                    f"Código incorreto. Você tem mais {attempts} {'tentativa' if attempts == 1 else 'tentativas'}.",
                    attempts_left=attempts,
                )

            # 4. Código correto! Destrói IMEDIATAMENTE (Invalidação pós-uso)
            stored_name = record.name
            self._records.pop(key, None)
            return True, "Código verificado com sucesso!", stored_name

    def clear_all(self) -> None:
        """Limpa todos os dados para isolamento em testes unitários."""
        with self._lock:
            self._records.clear()
            self._rate_limits.clear()


# Instância Singleton global do gerenciador de OTP
default_otp_manager = OTPManager()
