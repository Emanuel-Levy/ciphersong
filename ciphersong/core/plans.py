"""
Regras de negócio, limites e resolução de planos (Free, Pro, Ministério e Cortesia) do CipherSong.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

COURTESY_DAYS = 3

PLAN_LIMITS: dict[str, dict[str, Any]] = {
    "free": {
        "max_owned_teams": 1,
        "max_members": 6,
        "max_songs": 50,
        "custom_avatar": False,
        "label": "Plano Gratuito (Essencial)",
    },
    "pro": {
        "max_owned_teams": 3,
        "max_members": 12,
        "max_songs": None,  # ilimitado
        "custom_avatar": True,
        "label": "CipherSong Pro",
    },
    "ministerio": {
        "max_owned_teams": None,  # ilimitado
        "max_members": 30,
        "max_songs": None,  # ilimitado
        "custom_avatar": True,
        "label": "Plano Ministério",
    },
}


class PlanLimitError(Exception):
    """Exceção lançada quando uma operação excede o limite do plano ativo."""

    def __init__(
        self,
        limit_type: str,
        message: str,
        limit: Optional[int],
        current: int,
    ) -> None:
        super().__init__(message)
        self.limit_type = limit_type
        self.message = message
        self.limit = limit
        self.current = current

    def to_dict(self) -> dict[str, Any]:
        return {
            "detail": self.message,
            "code": "PLAN_LIMIT",
            "limit_type": self.limit_type,
            "limit": self.limit,
            "current": self.current,
        }


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            if cleaned.endswith("Z"):
                cleaned = cleaned[:-1] + "+00:00"
            dt = datetime.fromisoformat(cleaned)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def _get_manual_premium_plan(email: str) -> Optional[str]:
    """
    Lê a variável de ambiente PREMIUM_EMAILS.
    Aceita 'email@x.com' (assume 'ministerio') ou 'email@x.com:pro' / 'email@x.com:ministerio'.
    """
    if not email:
        return None
    raw_env = os.getenv("PREMIUM_EMAILS", "").strip()
    if not raw_env:
        return None
    clean_email = email.strip().lower()
    for entry in raw_env.split(","):
        part = entry.strip().lower()
        if not part:
            continue
        if ":" in part:
            em, plan_slug = part.split(":", 1)
            if em.strip() == clean_email:
                plan_slug = plan_slug.strip()
                return plan_slug if plan_slug in ("pro", "ministerio") else "ministerio"
        elif part == clean_email:
            return "ministerio"
    return None


def get_effective_plan(
    user_doc: Optional[dict[str, Any]],
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """
    Determina o plano efetivo do usuário considerando:
    1. Liberação manual via variável de ambiente PREMIUM_EMAILS.
    2. Assinatura ativa no documento do usuário (`assinatura` ou `plano`).
    3. Período de cortesia de 3 dias (`cortesia_ate`) ainda vigente.
    4. Fallback para o plano 'free'.
    """
    current_time = now or datetime.now(timezone.utc)
    if not user_doc:
        limits = dict(PLAN_LIMITS["free"])
        return {
            "plano": "free",
            "label": limits.pop("label"),
            "origem": "free",
            "is_premium": False,
            "expira_em": None,
            "cortesia_ativa": False,
            "limites": limits,
        }

    email = str(user_doc.get("email") or "").strip().lower()

    # 1. Verificação de liberação manual (PREMIUM_EMAILS)
    manual_plan = _get_manual_premium_plan(email)
    if manual_plan and manual_plan in PLAN_LIMITS:
        limits = dict(PLAN_LIMITS[manual_plan])
        return {
            "plano": manual_plan,
            "label": limits.pop("label"),
            "origem": "manual",
            "is_premium": True,
            "expira_em": None,
            "cortesia_ativa": False,
            "limites": limits,
        }

    # 2. Verificação de assinatura paga ativa no documento do usuário
    assinatura = user_doc.get("assinatura")
    if isinstance(assinatura, dict):
        sub_plan = str(assinatura.get("plano") or "").strip().lower()
        sub_status = str(assinatura.get("status") or "active").strip().lower()
        sub_exp = _parse_iso_datetime(assinatura.get("expira_em"))
        if sub_plan in ("pro", "ministerio") and sub_status == "active":
            if sub_exp is None or sub_exp > current_time:
                limits = dict(PLAN_LIMITS[sub_plan])
                return {
                    "plano": sub_plan,
                    "label": limits.pop("label"),
                    "origem": "assinatura",
                    "is_premium": True,
                    "expira_em": sub_exp.isoformat() if sub_exp else None,
                    "cortesia_ativa": False,
                    "limites": limits,
                }

    direct_plan = str(user_doc.get("plano") or "").strip().lower()
    if direct_plan in ("pro", "ministerio"):
        plan_exp = _parse_iso_datetime(user_doc.get("plano_expira_em"))
        if plan_exp is None or plan_exp > current_time:
            limits = dict(PLAN_LIMITS[direct_plan])
            return {
                "plano": direct_plan,
                "label": limits.pop("label"),
                "origem": "assinatura",
                "is_premium": True,
                "expira_em": plan_exp.isoformat() if plan_exp else None,
                "cortesia_ativa": False,
                "limites": limits,
            }

    # 3. Verificação de Cortesia de 3 dias (Grandfathering)
    cortesia_ate = _parse_iso_datetime(user_doc.get("cortesia_ate"))
    if cortesia_ate and cortesia_ate > current_time:
        limits = dict(PLAN_LIMITS["ministerio"])
        return {
            "plano": "ministerio",
            "label": "Cortesia Premium (Teste)",
            "origem": "cortesia",
            "is_premium": True,
            "expira_em": cortesia_ate.isoformat(),
            "cortesia_ativa": True,
            "limites": limits,
        }

    # 4. Plano Free padrão
    limits = dict(PLAN_LIMITS["free"])
    return {
        "plano": "free",
        "label": limits.pop("label"),
        "origem": "free",
        "is_premium": False,
        "expira_em": cortesia_ate.isoformat() if cortesia_ate else None,
        "cortesia_ativa": False,
        "limites": limits,
    }


def compute_courtesy_expiration(now: Optional[datetime] = None) -> str:
    """Retorna o timestamp ISO de expiração para a cortesia de 3 dias."""
    base = now or datetime.now(timezone.utc)
    return (base + timedelta(days=COURTESY_DAYS)).isoformat()


def is_exceeding_free_limits(
    owned_teams_count: int,
    max_team_members_count: int,
    max_team_songs_count: int,
) -> bool:
    """Verifica se o usuário já possui recursos acima dos limites do plano Free."""
    free_limits = PLAN_LIMITS["free"]
    if free_limits["max_owned_teams"] is not None and owned_teams_count > free_limits["max_owned_teams"]:
        return True
    if free_limits["max_members"] is not None and max_team_members_count > free_limits["max_members"]:
        return True
    if free_limits["max_songs"] is not None and max_team_songs_count > free_limits["max_songs"]:
        return True
    return False


class PaymentIdempotencyError(Exception):
    """Lançada quando uma transação de pagamento já foi processada anteriormente (idempotência)."""


class PaymentIdempotencyLedger:
    """
    Controlador de idempotência e prevenção de pagamentos duplicados e replay attacks
    para webhooks e checkouts de gateways (Stripe, Mercado Pago, Asaas, PIX).
    """

    @staticmethod
    def build_transaction_idempotency_doc(
        gateway: str,
        transaction_id: str,
        usuario_id: str,
        plano: str,
        valor_centavos: int,
        status: str = "approved",
        idempotency_key: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Cria o documento seguro de transação com chave idempotente para persistência atômica no MongoDB."""
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_gateway = (gateway or "manual").strip().lower()
        clean_tx_id = str(transaction_id or "").strip()
        if not clean_tx_id:
            raise ValueError("ID de transação não pode ser vazio.")

        return {
            "gateway": clean_gateway,
            "transaction_id": clean_tx_id,
            "idempotency_key": (idempotency_key or "").strip() or None,
            "usuario_id": str(usuario_id).strip(),
            "plano": plano.strip().lower(),
            "valor_centavos": int(valor_centavos),
            "status": status.strip().lower(),
            "criado_em": now_iso,
            "processado_em": now_iso,
            "metadata": metadata or {},
        }
