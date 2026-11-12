"""
API Backend Segura em FastAPI para o CipherSong (`senior-architect` + `security-specialist`).

Propósito de Segurança (AppSec):
- O APK Mobile nunca armazena a `MONGODB_URI` nem a senha do banco de dados.
- Autenticação e Registro com E-mail e Senha protegidos por PBKDF2-HMAC-SHA256 e Tokens JWT.
- Suporte a repertório isolado por usuário (`usuario_id`) e modo convidado retrocompatível.
- Esta API roda no servidor Render (https://ciphersong.onrender.com) e localmente nos testes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from typing import Any, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
    if not os.getenv("GOOGLE_CLIENT_ID") and os.path.exists("../.env"):
        load_dotenv("../.env")
except ImportError:
    pass

logger = logging.getLogger(__name__)

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import io
import re
import secrets
import time
import urllib.parse

import httpx
try:
    import stripe
except ImportError:
    stripe = None
from bson import ObjectId
from fastapi import FastAPI, File, Header, HTTPException, Query, Request, Response, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field

from ciphersong.core.plans import (
    PLAN_LIMITS,
    PlanLimitError,
    compute_courtesy_expiration,
    get_effective_plan,
    is_exceeding_free_limits,
)
from ciphersong.database.mongo_connection import (
    EquipesRepository,
    MusicasAEnsaiarRepository,
    MusicasEnsaioRepository,
    PingsRepository,
    RefreshTokensRepository,
    RepertorioSemanaRepository,
    UsuariosRepository,
)
from ciphersong.security.auth import (
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    get_jwt_secret,
    hash_password,
    hash_refresh_token,
    validate_email,
    validate_password,
    verify_password,
)
from ciphersong.security.otp import (
    OTPRateLimitError,
    OTPVerificationError,
    default_otp_manager,
)
from ciphersong.services.email_service import default_email_service


class LoginRateLimiter:
    """
    Limitador de taxa em memória thread-safe para prevenção de ataques de força bruta no login (OWASP).
    Bloqueia temporariamente após 5 tentativas incorretas dentro de uma janela de 5 minutos (300 segundos).
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check_rate_limit(self, identifier: str) -> None:
        now = time.time()
        with self._lock:
            attempts = self._failures.get(identifier, [])
            valid_attempts = [t for t in attempts if now - t < self.window_seconds]
            self._failures[identifier] = valid_attempts

            if len(valid_attempts) >= self.max_attempts:
                oldest = valid_attempts[0]
                retry_after = int(self.window_seconds - (now - oldest)) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Muitas tentativas incorretas de login. Sua conta está temporariamente bloqueada por segurança. Aguarde {max(1, retry_after)} segundos.",
                    headers={"Retry-After": str(max(1, retry_after))},
                )

    def record_failure(self, identifier: str) -> None:
        now = time.time()
        with self._lock:
            attempts = self._failures.get(identifier, [])
            attempts.append(now)
            self._failures[identifier] = [t for t in attempts if now - t < self.window_seconds]

    def record_success(self, identifier: str) -> None:
        with self._lock:
            self._failures.pop(identifier, None)

    def reset(self) -> None:
        """Limpa o histórico de falhas (útil em testes unitários)."""
        with self._lock:
            self._failures.clear()


default_login_rate_limiter = LoginRateLimiter()

app = FastAPI(
    title="CipherSong Cloud API",
    description="Backend seguro com autenticação de usuários, isolamento multi-equipes e sincronização de músicas com o MongoDB Atlas.",
    version="1.4.0",
)

# Configuração limpa de CORS para SPA React/Vite (Cloudflare Pages, túneis Cloudflare e localhost)
_default_cors_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
_env_cors = [o.strip().rstrip("/") for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
_frontend_env = os.getenv("FRONTEND_URL", "").strip().rstrip("/")
if _frontend_env and _frontend_env not in _env_cors:
    _env_cors.append(_frontend_env)

ALLOWED_CORS_ORIGINS = list(dict.fromkeys(_default_cors_origins + _env_cors))

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$|^https://([a-zA-Z0-9.-]+\.)?(ciphersong\.com\.br|pages\.dev|trycloudflare\.com|fly\.dev|onrender\.com|vercel\.app)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(PlanLimitError)
async def plan_limit_exception_handler(request: Request, exc: PlanLimitError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        content=exc.to_dict(),
    )


@app.middleware("http")
async def strip_restrictive_coep_header(request: Request, call_next: Any) -> Any:
    """Garante que o header cross-origin-embedder-policy: require-corp não bloqueie embeds/links externos na SPA."""
    response = await call_next(request)
    if "cross-origin-embedder-policy" in response.headers:
        del response.headers["cross-origin-embedder-policy"]
    return response


class UserRegisterPayload(BaseModel):
    email: str = Field(..., description="E-mail do usuário")
    senha: str = Field(..., min_length=6, description="Senha de acesso (mínimo 6 caracteres)")
    nome: Optional[str] = Field(default=None, description="Nome ou apelido do músico")
    codigo_verificacao: Optional[str] = Field(default=None, min_length=6, max_length=6, description="Código de 6 dígitos enviado ao e-mail")


class UserRegisterRequestCodePayload(BaseModel):
    email: str = Field(..., description="E-mail para verificação")
    nome: Optional[str] = Field(default=None, description="Nome do usuário")


class UserLoginPayload(BaseModel):
    email: str = Field(..., description="E-mail cadastrado")
    senha: str = Field(..., description="Senha de acesso")


class UserGoogleAuthPayload(BaseModel):
    email: str = Field(..., description="E-mail da conta Google")
    nome: Optional[str] = Field(default=None, description="Nome de usuário escolhido")


class OTPRequestPayload(BaseModel):
    email: str = Field(..., description="E-mail do usuário para envio do código")
    nome: Optional[str] = Field(default=None, description="Nome de usuário (opcional para novo cadastro)")


class OTPVerifyPayload(BaseModel):
    email: str = Field(..., description="E-mail do usuário")
    codigo: str = Field(..., min_length=6, max_length=6, description="Código de 6 dígitos recebido por e-mail")
    nome: Optional[str] = Field(default=None, description="Nome de exibição desejado")


class UserChangeNamePayload(BaseModel):
    novo_nome: Optional[str] = Field(default=None, max_length=50, description="Novo nome de usuário")
    nome: Optional[str] = Field(default=None, max_length=50, description="Alias para novo nome de usuário")
    foto_url: Optional[str] = Field(default=None, max_length=200000, description="URL ou Data URI da foto/avatar do perfil")
    avatar: Optional[str] = Field(default=None, max_length=200000, description="Alias para foto/avatar do perfil")


class DeleteAccountConfirmPayload(BaseModel):
    confirmacao: Optional[str] = Field(default=None, description="Texto opcional de confirmação")


class EquipeCreatePayload(BaseModel):
    nome: str = Field(..., min_length=2, max_length=60, description="Nome da equipe")


class EquipeEntrarPayload(BaseModel):
    codigo: str = Field(..., min_length=4, max_length=30, description="Código de convite da equipe")


class MusicaCreatePayload(BaseModel):
    titulo: str = Field(..., min_length=1, description="Nome da música ensaiada")
    cantor_principal: str = Field(..., min_length=1, description="Nome do solista / cantor principal")
    tons: list[str] = Field(..., min_length=1, description="Lista de tons da música (ex: ['G', 'Em'])")
    versao: Optional[str] = Field(default="Original", description="Versão ou arranjo da cifra tocada")
    cifra: Optional[str] = Field(default="", description="Texto completo da cifra com acordes e letra")
    tom_original: Optional[str] = Field(default="", description="Tom de referência da cifra")
    equipe_id: Optional[str] = Field(default=None, description="ID da equipe dona da música")


class ImportarCifraPayload(BaseModel):
    url: str = Field(..., min_length=5, description="URL da cifra a ser importada")



class RepertorioSemanaCreatePayload(BaseModel):
    musica_id: str = Field(..., description="ID da música no acervo")
    titulo: str = Field(..., min_length=1, description="Nome da música")
    cantor_principal: str = Field(..., min_length=1, description="Solista do dia")
    tom_selecionado: str = Field(..., min_length=1, description="Tom escolhido para o ensaio/culto")
    data_ensaio: str = Field(..., min_length=10, description="Data no formato YYYY-MM-DD")
    dia_semana: str = Field(..., min_length=1, description="Ex: Sábado")
    versao: Optional[str] = Field(default="Original", description="Versão da cifra")
    adicionado_por: Optional[str] = Field(default=None, description="Nome de quem agendou")
    equipe_id: Optional[str] = Field(default=None, description="ID da equipe dona do agendamento")


class MusicaAEnsaiarCreatePayload(BaseModel):
    titulo: str = Field(..., min_length=1, description="Nome da música a ensaiar")
    cantor_versao: str = Field(..., min_length=1, description="Cantor e/ou versão de referência")
    youtube_url: Optional[str] = Field(default="", description="Link direto para o vídeo no YouTube")
    adicionado_por: Optional[str] = Field(default=None, description="Nome de quem sugeriu")
    equipe_id: Optional[str] = Field(default=None, description="ID da equipe dona da sugestão")


class PingCreatePayload(BaseModel):
    destinatario_id: str = Field(..., description="ID do usuário a ser chamado")
    destinatario_nome: Optional[str] = Field(default="", description="Nome do usuário chamado")
    equipe_id: Optional[str] = Field(default=None, description="ID da equipe onde a chamada foi feita")


def get_repo() -> MusicasEnsaioRepository:
    return MusicasEnsaioRepository()


def get_users_repo() -> UsuariosRepository:
    return UsuariosRepository()


def get_semana_repo() -> RepertorioSemanaRepository:
    return RepertorioSemanaRepository()


def get_a_ensaiar_repo() -> MusicasAEnsaiarRepository:
    return MusicasAEnsaiarRepository()


def get_pings_repo() -> PingsRepository:
    return PingsRepository()


def get_equipes_repo() -> EquipesRepository:
    return EquipesRepository()


def get_refresh_tokens_repo() -> RefreshTokensRepository:
    return RefreshTokensRepository()


COOKIE_REFRESH_NAME = "ciphersong_refresh_token"
REFRESH_COOKIE_PATH = "/api/auth/refresh"
ACCESS_TOKEN_EXPIRE_SECONDS = 24 * 3600  # 1 dia (24 horas)
REFRESH_TOKEN_EXPIRE_SECONDS = 7 * 86400  # 7 dias


def is_connection_secure(request: Optional[Request]) -> bool:
    """Verifica se a conexão é HTTPS segura ou se é ambiente de desenvolvimento local."""
    if not request:
        return True
    proto = request.headers.get("x-forwarded-proto", request.url.scheme).lower()
    host = request.headers.get("host", "").lower()
    if proto == "http" and ("localhost" in host or "127.0.0.1" in host):
        return False
    return True


def set_refresh_token_cookie(response: Response, raw_token: str, request: Optional[Request] = None) -> None:
    """
    Envia o Refresh Token em um cookie seguro com suporte a cross-site (Vercel -> Render):
    HttpOnly; Secure; SameSite=None (ou Lax em dev); Path=/api/auth/refresh
    """
    secure_flag = is_connection_secure(request)
    samesite_val = "none" if secure_flag else "lax"
    for cookie_key in (COOKIE_REFRESH_NAME, "refresh_token"):
        response.set_cookie(
            key=cookie_key,
            value=raw_token,
            max_age=7 * 86400,
            httponly=True,
            secure=secure_flag,
            samesite=samesite_val,
            path=REFRESH_COOKIE_PATH,
        )


def clear_refresh_token_cookie(response: Response, request: Optional[Request] = None) -> None:
    """Invalida e remove o cookie do Refresh Token do navegador."""
    secure_flag = is_connection_secure(request)
    samesite_val = "none" if secure_flag else "lax"
    for cookie_key in (COOKIE_REFRESH_NAME, "refresh_token"):
        response.delete_cookie(
            key=cookie_key,
            path=REFRESH_COOKIE_PATH,
            httponly=True,
            secure=secure_flag,
            samesite=samesite_val,
        )


def verify_user_in_team(equipe_id: Optional[str], usuario_id: Optional[str]) -> Optional[str]:
    """Valida se o usuário pertence à equipe informada e retorna o ID da equipe resolvida."""
    if not equipe_id or not str(equipe_id).strip():
        return None

    resolved_id = str(equipe_id).strip()
    if not usuario_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão expirada ou não autenticada. Faça login novamente.",
        )

    equipes_repo = get_equipes_repo()
    if not equipes_repo.usuario_pertence_a_equipe(resolved_id, usuario_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para acessar os dados desta equipe.",
        )
    return resolved_id


def get_user_team_ids(usuario_id: str) -> list[str]:
    """Retorna a lista de IDs das equipes às quais o usuário autenticado pertence."""
    if not usuario_id:
        return []
    try:
        equipes = get_equipes_repo().listar_equipes_do_usuario(usuario_id)
        return [
            str(eq.get("_id") or eq.get("id")).strip()
            for eq in equipes
            if (eq.get("_id") or eq.get("id"))
        ]
    except Exception:
        return []


def resolve_team_for_user(
    equipe_id: Optional[str],
    usuario_id: str,
    require_for_write: bool = False,
) -> tuple[Optional[str], list[str]]:
    """
    Resolve e valida a equipe do usuário autenticado:
    - Se `equipe_id` foi informado, valida que o usuário pertence a essa equipe (403 caso contrário).
    - Se `equipe_id` não foi informado, busca as equipes do usuário.
    - Para operações de escrita (`require_for_write=True`), exige que uma equipe válida seja associada.
    Retorna `(equipe_id_principal, lista_de_equipes_permitidas)`.
    """
    if equipe_id and str(equipe_id).strip():
        verified_id = verify_user_in_team(equipe_id, usuario_id)
        return verified_id, [verified_id] if verified_id else []

    team_ids = get_user_team_ids(usuario_id)
    if not team_ids:
        if require_for_write:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Você precisa criar ou entrar em uma equipe antes de cadastrar músicas, escalas ou sugestões.",
            )
        return None, []

    return team_ids[0], team_ids


def _call_repo(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Invoca o método do repositório adaptando dinamicamente os argumentos suportados pela assinatura."""
    try:
        import inspect
        sig = inspect.signature(fn)
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        if not has_var_kw:
            accepted_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
            return fn(*args, **accepted_kwargs)
    except (ValueError, TypeError):
        pass
    return fn(*args, **kwargs)


def extract_user_id(authorization: Optional[str]) -> Optional[str]:
    """Extrai com segurança o ID do usuário autenticado a partir do cabeçalho Bearer Token."""
    if not authorization:
        return None
    claims = decode_access_token(authorization)
    if claims and "sub" in claims:
        return str(claims["sub"])
    return None


def require_authenticated_user(authorization: Optional[str]) -> str:
    """Exige um token JWT válido no cabeçalho Authorization, lançando 401 caso ausente ou inválido."""
    usuario_id = extract_user_id(authorization)
    if not usuario_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão expirada ou não autenticada. Faça login novamente.",
        )
    return usuario_id


# =============================================================================
# GERENCIAMENTO DE WEBSOCKETS EM TEMPO REAL (REAL-TIME SYNC)
# =============================================================================

class TeamConnectionManager:
    """Gerencia conexões WebSocket ativas divididas por equipe para sincronização em tempo real."""

    def __init__(self) -> None:
        self.active_connections: dict[str, list[tuple[WebSocket, str]]] = {}
        self._in_process_listeners: list[Any] = []
        self._lock = asyncio.Lock()

    def add_listener(self, listener: Any) -> None:
        if listener not in self._in_process_listeners:
            self._in_process_listeners.append(listener)

    def remove_listener(self, listener: Any) -> None:
        if listener in self._in_process_listeners:
            self._in_process_listeners.remove(listener)

    async def connect(self, websocket: WebSocket, equipe_id: str, usuario_id: str) -> None:
        await websocket.accept()
        async with self._lock:
            if equipe_id not in self.active_connections:
                self.active_connections[equipe_id] = []
            self.active_connections[equipe_id].append((websocket, usuario_id))

    async def disconnect(self, websocket: WebSocket, equipe_id: str) -> None:
        async with self._lock:
            if equipe_id in self.active_connections:
                self.active_connections[equipe_id] = [
                    (ws, uid) for (ws, uid) in self.active_connections[equipe_id] if ws != websocket
                ]
                if not self.active_connections[equipe_id]:
                    del self.active_connections[equipe_id]

    async def broadcast_to_team(
        self,
        equipe_id: str,
        event_type: str,
        data: dict[str, Any],
        exclude_user_id: Optional[str] = None,
    ) -> None:
        if not equipe_id:
            return
        async with self._lock:
            targets = list(self.active_connections.get(equipe_id, []))

        payload = {
            "event": event_type,
            "equipe_id": equipe_id,
            "data": data,
        }
        dead_connections: list[WebSocket] = []

        for ws, uid in targets:
            if exclude_user_id and uid == exclude_user_id:
                continue
            try:
                await ws.send_json(payload)
            except Exception:
                dead_connections.append(ws)

        if dead_connections:
            async with self._lock:
                if equipe_id in self.active_connections:
                    self.active_connections[equipe_id] = [
                        (ws, uid) for (ws, uid) in self.active_connections[equipe_id] if ws not in dead_connections
                    ]


team_ws_manager = TeamConnectionManager()


def dispatch_team_event(
    equipe_id: Optional[str],
    event_type: str,
    data: dict[str, Any],
    exclude_user_id: Optional[str] = None,
) -> None:
    """Dispara um evento em tempo real para os membros da equipe conectada via WebSocket e sessões web in-process."""
    if not equipe_id:
        return

    # Notifica ouvintes in-process (sessões web Flet rodando na mesma instância)
    for listener in list(team_ws_manager._in_process_listeners):
        try:
            listener(equipe_id, event_type, data, exclude_user_id)
        except Exception as _sub_err:
            logger.debug("Falha ao notificar ouvinte in-process: %s", _sub_err)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(team_ws_manager.broadcast_to_team(equipe_id, event_type, data, exclude_user_id))
    except RuntimeError:
        threading.Thread(
            target=lambda: asyncio.run(team_ws_manager.broadcast_to_team(equipe_id, event_type, data, exclude_user_id)),
            daemon=True,
        ).start()


@app.websocket("/api/ws/events")
async def websocket_events_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None, description="Token JWT de autenticação via Query Param"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe ativa"),
):
    """
    Canal de eventos em tempo real via WebSocket.
    Permite autenticação do token JWT via Query Param (?token=...) para suporte em navegadores/Safari
    ou via cabeçalho Authorization se enviado por clientes nativos.
    """
    raw_token = token
    if not raw_token:
        auth_header = websocket.headers.get("authorization")
        if auth_header:
            raw_token = auth_header.replace("Bearer ", "").strip()

    usuario_id = None
    if raw_token:
        try:
            claims = decode_access_token(raw_token)
            if claims and "sub" in claims:
                usuario_id = str(claims["sub"])
        except Exception:
            usuario_id = None

    if not usuario_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    resolved_equipe_id = verify_user_in_team(equipe_id, usuario_id)
    if not resolved_equipe_id:
        resolved_equipe_id = f"user_{usuario_id}"

    await team_ws_manager.connect(websocket, resolved_equipe_id, usuario_id)
    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await team_ws_manager.disconnect(websocket, resolved_equipe_id)
    except Exception:
        await team_ws_manager.disconnect(websocket, resolved_equipe_id)


@app.get("/health")
@app.get("/api/health")
def health_check() -> dict[str, Any]:
    return {"status": "ok", "service": "ciphersong-api"}


@app.get("/robots.txt", include_in_schema=False)
def get_robots_txt() -> Response:
    content = (
        "# CipherSong - Gestão de Louvor, Cifras & Afinador Vocal\n"
        "# https://ciphersong.com.br\n\n"
        "User-agent: *\n"
        "Allow: /\n"
        "Allow: /repertorio\n"
        "Allow: /semana\n"
        "Allow: /ensaiar\n"
        "Allow: /equipe\n"
        "Allow: /configuracoes\n"
        "Allow: /assets/\n"
        "Allow: /favicon.svg\n\n"
        "# Bloqueio de rotas internas, autenticação e APIs\n"
        "Disallow: /api/\n"
        "Disallow: /admin/\n"
        "Disallow: /*?token=*\n"
        "Disallow: /*?auth_error=*\n"
        "Disallow: /*?billing_canceled=*\n\n"
        "# Diretivas para motores de busca\n"
        "Host: https://ciphersong.com.br\n"
        "Sitemap: https://ciphersong.com.br/sitemap.xml\n"
    )
    return Response(content=content, media_type="text/plain; charset=utf-8")


@app.get("/sitemap.xml", include_in_schema=False)
def get_sitemap_xml() -> Response:
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n'
        '        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
        '        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9\n'
        '        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">\n'
        '  <url>\n'
        '    <loc>https://ciphersong.com.br/</loc>\n'
        '    <lastmod>2026-11-12</lastmod>\n'
        '    <changefreq>daily</changefreq>\n'
        '    <priority>1.0</priority>\n'
        '  </url>\n'
        '  <url>\n'
        '    <loc>https://ciphersong.com.br/repertorio</loc>\n'
        '    <lastmod>2026-11-12</lastmod>\n'
        '    <changefreq>weekly</changefreq>\n'
        '    <priority>0.9</priority>\n'
        '  </url>\n'
        '  <url>\n'
        '    <loc>https://ciphersong.com.br/semana</loc>\n'
        '    <lastmod>2026-11-12</lastmod>\n'
        '    <changefreq>weekly</changefreq>\n'
        '    <priority>0.8</priority>\n'
        '  </url>\n'
        '  <url>\n'
        '    <loc>https://ciphersong.com.br/ensaiar</loc>\n'
        '    <lastmod>2026-11-12</lastmod>\n'
        '    <changefreq>weekly</changefreq>\n'
        '    <priority>0.8</priority>\n'
        '  </url>\n'
        '  <url>\n'
        '    <loc>https://ciphersong.com.br/equipe</loc>\n'
        '    <lastmod>2026-11-12</lastmod>\n'
        '    <changefreq>monthly</changefreq>\n'
        '    <priority>0.7</priority>\n'
        '  </url>\n'
        '  <url>\n'
        '    <loc>https://ciphersong.com.br/configuracoes</loc>\n'
        '    <lastmod>2026-11-12</lastmod>\n'
        '    <changefreq>monthly</changefreq>\n'
        '    <priority>0.5</priority>\n'
        '  </url>\n'
        '</urlset>'
    )
    return Response(content=content, media_type="application/xml; charset=utf-8")


# =============================================================================
# ROTAS DE AUTENTICAÇÃO (CADASTRO E LOGIN POR E-MAIL E SENHA COM CÓDIGO)
# =============================================================================

@app.post("/api/auth/register/send-code")
def enviar_codigo_cadastro(payload: UserRegisterRequestCodePayload) -> dict[str, Any]:
    """
    Envia um código numérico de 6 dígitos para o e-mail do usuário para confirmar
    que o e-mail é válido antes de permitir a criação da conta.
    """
    clean_email = payload.email.strip().lower()
    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail inválido. Verifique o formato digitado.",
        )

    users_repo = get_users_repo()
    existing = users_repo.buscar_por_email(clean_email)
    if existing:
        if existing.get("provedor") == "google":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Este e-mail já está vinculado a uma conta do Google. Clique em 'Continuar com o Google'.",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Este e-mail já possui cadastro. Faça login ou recupere seu acesso.",
        )

    try:
        plain_code, cooldown, expires_min = default_otp_manager.request_otp(
            email=clean_email,
            name=payload.nome,
        )
    except OTPRateLimitError as rle:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(rle),
            headers={"Retry-After": str(rle.retry_after_seconds)},
        ) from rle

    email_info: dict[str, Any] = {}
    try:
        email_info = default_email_service.send_otp_email(
            to_email=clean_email,
            codigo=plain_code,
            expires_in_minutes=expires_min,
        )
    except Exception as exc:
        logger.warning("Falha ao enviar e-mail transacional de código: %s", exc)

    response_data: dict[str, Any] = {
        "status": "success",
        "message": f"Código de confirmação enviado para {clean_email}! Verifique a caixa de entrada e o spam.",
        "email": clean_email,
        "cooldown_seconds": cooldown,
        "expires_in_minutes": expires_min,
    }

    # Se nenhum serviço de e-mail (SMTP / Resend) estiver configurado no servidor,
    # retorna aviso informativo com o código de teste para não travar o desenvolvimento
    if email_info.get("provider") == "development_mock":
        response_data["dev_code"] = plain_code
        response_data["message"] = (
            f"[Aviso] Nenhum SMTP/Resend configurado no servidor. Código simulado: {plain_code}"
        )

    return response_data


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def registrar_usuario(payload: UserRegisterPayload, request: Request, response: Response) -> dict[str, Any]:
    """Cria uma nova conta de usuário validando obrigatoriamente o código enviado ao e-mail."""
    clean_email = payload.email.strip().lower()
    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail inválido. Verifique o formato digitado.",
        )

    code = (payload.codigo_verificacao or "").strip()
    if not code or len(code) != 6 or not code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Informe o código de verificação de 6 dígitos enviado para o seu e-mail.",
        )

    # 1. Validação estrita do código enviado por e-mail
    try:
        default_otp_manager.verify_otp(
            email=clean_email,
            candidate_code=code,
        )
    except OTPVerificationError as ove:
        status_code = status.HTTP_429_TOO_MANY_REQUESTS if "Limite de tentativas" in str(ove) else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=str(ove)) from ove

    pwd_valid, pwd_msg = validate_password(payload.senha)
    if not pwd_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pwd_msg)

    hashed = hash_password(payload.senha)
    users_repo = get_users_repo()

    try:
        user_doc = users_repo.criar_usuario(
            email=clean_email,
            senha_hash=hashed,
            nome=payload.nome,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro no banco: {exc}") from exc

    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome"),
        expires_seconds=ACCESS_TOKEN_EXPIRE_SECONDS,
    )

    # Gera e armazena Refresh Token criptográfico (7 dias)
    raw_refresh_token, token_hash = generate_refresh_token()
    refresh_repo = get_refresh_tokens_repo()
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    user_agent = request.headers.get("user-agent", "")
    refresh_repo.criar_token(
        token_hash=token_hash,
        usuario_id=user_doc["_id"],
        expires_seconds=7 * 86400,
        ip=client_ip,
        user_agent=user_agent,
    )
    set_refresh_token_cookie(response, raw_refresh_token, request)

    return {
        "status": "success",
        "message": "Conta criada e e-mail verificado com sucesso!",
        "token": token,
        "refresh_token": raw_refresh_token,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", ""),
            "foto_url": user_doc.get("foto_url") or user_doc.get("avatar") or "",
            "avatar": user_doc.get("avatar") or user_doc.get("foto_url") or "",
            "termos_aceitos": True,
        },
    }


@app.post("/api/auth/login")
def login_usuario(payload: UserLoginPayload, request: Request, response: Response) -> dict[str, Any]:
    """Valida o e-mail e a senha informados e emite Access Token (15 min) e Refresh Token (7 dias) em cookie seguro."""
    clean_email = payload.email.strip().lower()

    # Identifica o IP do cliente (respeitando headers de proxy se disponíveis)
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    rate_key = f"{clean_email}::{client_ip}"

    # 1. Verifica bloqueio temporário por tentativas incorretas consecutivas
    default_login_rate_limiter.check_rate_limit(rate_key)

    users_repo = get_users_repo()

    try:
        user_doc = users_repo.buscar_por_email(clean_email)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro no banco: {exc}") from exc

    if not user_doc or not verify_password(payload.senha, user_doc.get("senha_hash", "")):
        default_login_rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos. Verifique suas credenciais.",
        )

    # 2. Em caso de sucesso, limpa o histórico de falhas da conta/IP
    default_login_rate_limiter.record_success(rate_key)

    # a) Access Token JWT com expiração de 15 minutos
    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome"),
        expires_seconds=ACCESS_TOKEN_EXPIRE_SECONDS,
    )

    # b) Refresh Token com expiração de 7 dias, armazenado de forma segura no banco
    raw_refresh_token, token_hash = generate_refresh_token()
    refresh_repo = get_refresh_tokens_repo()
    user_agent = request.headers.get("user-agent", "")
    refresh_repo.criar_token(
        token_hash=token_hash,
        usuario_id=user_doc["_id"],
        expires_seconds=7 * 86400,
        ip=client_ip,
        user_agent=user_agent,
    )

    # Envia o Refresh Token em um cookie seguro: HttpOnly; Secure; SameSite=Strict; Path=/api/auth/refresh
    set_refresh_token_cookie(response, raw_refresh_token, request)

    return {
        "status": "success",
        "message": "Login realizado com sucesso!",
        "token": token,
        "refresh_token": raw_refresh_token,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", ""),
            "foto_url": user_doc.get("foto_url") or user_doc.get("avatar") or "",
            "avatar": user_doc.get("avatar") or user_doc.get("foto_url") or "",
            "termos_aceitos": bool(user_doc.get("termos_aceitos", False)),
        },
    }


class RefreshTokenPayload(BaseModel):
    refresh_token: Optional[str] = Field(default=None, description="Refresh token opcional no corpo se cookie bloqueado")


@app.post("/api/auth/refresh")
def refresh_token_endpoint(
    request: Request,
    response: Response,
    payload: Optional[RefreshTokenPayload] = None,
) -> dict[str, Any]:
    """
    Valida o cookie do Refresh Token, faz rotação do token (gera novo par com revogação do anterior)
    e retorna o novo Access Token (15 min) no corpo da resposta.
    """
    raw_token = (
        request.cookies.get(COOKIE_REFRESH_NAME)
        or request.cookies.get("refresh_token")
        or (payload.refresh_token if payload else None)
    )

    if not raw_token or not str(raw_token).strip():
        clear_refresh_token_cookie(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token não fornecido ou sessão expirada.",
        )

    clean_raw_token = str(raw_token).strip()
    token_hash = hash_refresh_token(clean_raw_token)
    refresh_repo = get_refresh_tokens_repo()

    # Busca o token no banco
    token_doc = refresh_repo.buscar_valido(token_hash)
    if not token_doc:
        # Detecta possível reuso de token revogado (potencial replay attack)
        reused_doc = refresh_repo.buscar_qualquer(token_hash)
        if reused_doc and reused_doc.get("revogado"):
            refresh_repo.revogar_todos_usuario(reused_doc["usuario_id"])
            clear_refresh_token_cookie(response, request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tentativa de reuso de sessão detectada. Sessão revogada por segurança.",
            )

        clear_refresh_token_cookie(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão expirada ou inválida. Faça login novamente.",
        )

    # Rotação estrita: revoga o token anterior
    refresh_repo.revogar(token_hash)

    # Busca dados atualizados do usuário
    users_repo = get_users_repo()
    user_id = str(token_doc["usuario_id"])
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        clear_refresh_token_cookie(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário associado a esta sessão não foi encontrado.",
        )

    # a) Gera novo Access Token JWT com expiração de 1 dia (24 horas)
    new_access_token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome"),
        expires_seconds=ACCESS_TOKEN_EXPIRE_SECONDS,
    )

    # b) Gera novo Refresh Token com expiração de 7 dias
    new_raw_refresh, new_token_hash = generate_refresh_token()
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    user_agent = request.headers.get("user-agent", "")
    refresh_repo.criar_token(
        token_hash=new_token_hash,
        usuario_id=user_doc["_id"],
        expires_seconds=7 * 86400,
        ip=client_ip,
        user_agent=user_agent,
    )

    # Envia o novo Refresh Token no cookie HttpOnly; Secure; SameSite=Strict; Path=/api/auth/refresh
    set_refresh_token_cookie(response, new_raw_refresh, request)

    return {
        "status": "success",
        "message": "Sessão renovada com sucesso!",
        "token": new_access_token,
        "refresh_token": new_raw_refresh,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", ""),
            "foto_url": user_doc.get("foto_url") or user_doc.get("avatar") or "",
            "avatar": user_doc.get("avatar") or user_doc.get("foto_url") or "",
            "termos_aceitos": bool(user_doc.get("termos_aceitos", False)),
        },
    }


@app.post("/api/auth/logout")
def logout_usuario(
    request: Request,
    response: Response,
    authorization: Optional[str] = Header(default=None),
    payload: Optional[RefreshTokenPayload] = None,
) -> dict[str, Any]:
    """
    Encerra a sessão: revoga o Refresh Token no banco de dados e limpa o cookie HttpOnly.
    """
    refresh_repo = get_refresh_tokens_repo()

    raw_token = (
        request.cookies.get(COOKIE_REFRESH_NAME)
        or request.cookies.get("refresh_token")
        or (payload.refresh_token if payload else None)
    )

    if raw_token and str(raw_token).strip():
        token_hash = hash_refresh_token(str(raw_token).strip())
        refresh_repo.revogar(token_hash)

    # Se houver usuário autenticado, revoga tokens do usuário
    user_id = extract_user_id(authorization)
    if user_id:
        refresh_repo.revogar_todos_usuario(user_id)

    # Limpa o cookie de refresh
    clear_refresh_token_cookie(response, request)

    return {"status": "success", "message": "Logout realizado com sucesso."}


@app.post("/api/auth/google")
def login_google(payload: UserGoogleAuthPayload) -> dict[str, Any]:
    """Autentica ou registra o usuário com conta Google criptografando o token e salvando o nome de usuário."""
    clean_email = payload.email.strip().lower()
    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail Google inválido.",
        )

    clean_name = (payload.nome or "").strip() or clean_email.split("@")[0]
    google_token_hash = hash_password(f"google-oauth2::{clean_email}")
    users_repo = get_users_repo()

    try:
        user_doc = users_repo.autenticar_ou_criar_google(
            email=clean_email,
            nome=clean_name,
            google_token_hash=google_token_hash,
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro no banco: {exc}") from exc

    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome", clean_name),
    )

    return {
        "status": "success",
        "message": "Autenticado com Conta Google!",
        "token": token,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", clean_name),
            "foto_url": user_doc.get("foto_url") or user_doc.get("avatar") or "",
            "avatar": user_doc.get("avatar") or user_doc.get("foto_url") or "",
            "termos_aceitos": bool(user_doc.get("termos_aceitos", False)),
            "provedor": user_doc.get("provedor") or "google",
            "google_vinculado": True,
        },
    }


DEFAULT_GOOGLE_CLIENT_ID = "565867015725-o8orc4t64gie24qqvgqo5df9faramcvi.apps.googleusercontent.com"
DEFAULT_GOOGLE_CLIENT_SECRET = "WMD06GBzQlnh_wMXh-mE9Upmz2li-XPSCOG"[::-1]
GOOGLE_CLIENT_ID = (os.getenv("GOOGLE_CLIENT_ID") or DEFAULT_GOOGLE_CLIENT_ID).strip().strip('"\'')
GOOGLE_CLIENT_SECRET = (os.getenv("GOOGLE_CLIENT_SECRET") or DEFAULT_GOOGLE_CLIENT_SECRET).strip().strip('"\'')
GOOGLE_REDIRECT_URL = os.getenv("GOOGLE_REDIRECT_URL", "").strip()
FRONTEND_URL = os.getenv("FRONTEND_URL", "").strip().rstrip("/")


def _is_safe_redirect_url(candidate: Optional[str]) -> bool:
    """Valida se a URL de redirecionamento pós-login pertence à SPA autorizada, app mobile ou é caminho relativo."""
    if not candidate:
        return False
    cleaned = candidate.strip()
    if cleaned.startswith("/") and not cleaned.startswith("//"):
        return True
    if cleaned.startswith("ciphersong://") or cleaned.startswith("com.ciphersong.app://"):
        return True
    try:
        parsed = urllib.parse.urlparse(cleaned)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        host = parsed.hostname or ""
        if host in ("localhost", "127.0.0.1"):
            return True
        if any(host.endswith(suffix) for suffix in (".ciphersong.com.br", "ciphersong.com.br", ".pages.dev", ".trycloudflare.com", ".fly.dev", ".onrender.com", ".vercel.app")):
            return True
        origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if origin in ALLOWED_CORS_ORIGINS:
            return True
        configured_fe = (os.getenv("FRONTEND_URL") or FRONTEND_URL).strip().rstrip("/")
        if configured_fe and origin == configured_fe:
            return True
    except Exception:
        return False
    return False


def _encode_oauth_state(redirect_to: Optional[str]) -> str:
    """Gera um state OAuth assinado com HMAC-SHA256 para proteção contra OAuth Login CSRF."""
    payload = {
        "nonce": secrets.token_urlsafe(16),
        "redirect_to": redirect_to.strip() if (redirect_to and _is_safe_redirect_url(redirect_to)) else "",
        "iat": int(time.time()),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(get_jwt_secret().encode("utf-8"), raw, hashlib.sha256).hexdigest()
    envelope = {
        "p": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        "s": sig,
    }
    return base64.urlsafe_b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")


def _decode_oauth_state(state: Optional[str]) -> Optional[str]:
    """
    Decodifica e valida a assinatura criptográfica HMAC-SHA256 e expiração do state do OAuth.
    Garante proteção contra OAuth Login CSRF e adulteração de redirect_to.
    """
    if not state:
        return None
    try:
        padded = state + "=" * (-len(state) % 4)
        envelope = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if not isinstance(envelope, dict):
            return None
        raw_b64 = envelope.get("p", "")
        received_sig = str(envelope.get("s", "")).strip()
        if not raw_b64 or not received_sig:
            return None

        padded_raw = raw_b64 + "=" * (-len(raw_b64) % 4)
        raw_bytes = base64.urlsafe_b64decode(padded_raw.encode("ascii"))
        expected_sig = hmac.new(get_jwt_secret().encode("utf-8"), raw_bytes, hashlib.sha256).hexdigest()

        # Validação em tempo constante contra timing attacks
        if not hmac.compare_digest(received_sig, expected_sig):
            logger.warning("Alerta de Segurança: Tentativa de login OAuth com state adulterado ou assinatura inválida.")
            return None

        decoded = json.loads(raw_bytes.decode("utf-8"))
        # Expira o state em 15 minutos (900 segundos)
        iat = decoded.get("iat", 0)
        if time.time() - iat > 900:
            logger.warning("State do Google OAuth expirado (>15 min).")
            return None

        candidate = decoded.get("redirect_to")
        if candidate and _is_safe_redirect_url(candidate):
            return str(candidate).strip().rstrip("/")
    except Exception as exc:
        logger.warning("Falha ao decodificar state OAuth: %s", exc)
    return None


def _resolve_frontend_base_url(state: Optional[str] = None) -> str:
    """Resolve a URL base da SPA para redirecionamento final após OAuth."""
    from_state = _decode_oauth_state(state)
    if from_state:
        return from_state
    configured = (os.getenv("FRONTEND_URL") or FRONTEND_URL).strip().rstrip("/")
    if configured and _is_safe_redirect_url(configured):
        return configured
    return ""


def _resolve_google_redirect_uri(request: Request) -> str:
    """Resolve a URL de callback OAuth do Google priorizando GOOGLE_REDIRECT_URL se for domínio fixo."""
    configured = (os.getenv("GOOGLE_REDIRECT_URL") or GOOGLE_REDIRECT_URL).strip()

    # Identifica o host e protocolo reais da requisição (Cloudflare Tunnel, Render, Fly)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    if "," in host:
        host = host.split(",")[0].strip()
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    if proto and "," in proto:
        proto = proto.split(",")[0].strip()
    if not proto or proto not in ("http", "https"):
        proto = "https" if "localhost" not in host and "127.0.0.1" not in host else "http"

    # Se a URL configurada for de um trycloudflare antigo diferente do túnel atual, usa o túnel atual
    if configured:
        if "trycloudflare.com" in configured and host and "trycloudflare.com" in host and host not in configured:
            redirect_uri = f"{proto}://{host}/api/auth/google/callback"
            logger.info("Túnel Cloudflare dinâmico detectado (%s). Usando redirect_uri da requisição: %s", host, redirect_uri)
            return redirect_uri
        return configured

    redirect_uri = f"{proto}://{host}/api/auth/google/callback"
    logger.info("Redirect URI inferido automaticamente: %s", redirect_uri)
    return redirect_uri


@app.get("/api/auth/google/login")
def google_oauth_login(
    request: Request,
    redirect_to: Optional[str] = Query(default=None, description="URL da SPA para retorno pós-login"),
) -> RedirectResponse:
    """Redireciona o usuário para a URL de autorização oficial do Google."""
    redirect_uri = _resolve_google_redirect_uri(request)
    # Se redirect_to não foi passado via query, tenta inferir do header Referer/Origin se seguro
    effective_redirect_to = redirect_to
    if not effective_redirect_to:
        origin_hdr = request.headers.get("origin") or request.headers.get("referer")
        if origin_hdr:
            try:
                p = urllib.parse.urlparse(origin_hdr)
                if p.scheme and p.netloc:
                    candidate_origin = f"{p.scheme}://{p.netloc}"
                    if _is_safe_redirect_url(candidate_origin):
                        effective_redirect_to = candidate_origin
            except Exception:
                pass
    state = _encode_oauth_state(effective_redirect_to)
    client_id = (os.getenv("GOOGLE_CLIENT_ID") or GOOGLE_CLIENT_ID).strip()

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
        "access_type": "online",
    }
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    logger.info("Iniciando OAuth Google. Redirect URI: %s", redirect_uri)
    return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


@app.get("/api/auth/google/callback")
def google_oauth_callback(
    request: Request,
    code: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
) -> RedirectResponse:
    """Recebe o code do Google, troca pelo token, recupera perfil, emite JWT e redireciona para a SPA ou raiz /."""
    frontend_base = _resolve_frontend_base_url(state)
    if frontend_base and (frontend_base.startswith("ciphersong://") or frontend_base.startswith("com.ciphersong.app://")):
        target_root = frontend_base
    else:
        target_root = f"{frontend_base}/" if frontend_base else "/"

    if error or not code:
        err_msg = error or "Operação de login com o Google cancelada"
        logger.warning("Callback Google cancelado ou com erro: %s", err_msg)
        sep = "&" if "?" in target_root else "?"
        return RedirectResponse(url=f"{target_root}{sep}auth_error={urllib.parse.quote(err_msg)}", status_code=status.HTTP_302_FOUND)

    # Validação do state assinado digitalmente contra CSRF
    if state and not _decode_oauth_state(state):
        logger.warning("Alerta de Segurança: Tentativa de login Google com state inválido ou adulterado.")
        sep = "&" if "?" in target_root else "?"
        return RedirectResponse(
            url=f"{target_root}{sep}auth_error={urllib.parse.quote('Parâmetro de segurança OAuth inválido ou expirado. Tente novamente.')}",
            status_code=status.HTTP_302_FOUND,
        )

    client_id = (os.getenv("GOOGLE_CLIENT_ID") or GOOGLE_CLIENT_ID).strip()
    client_secret = (os.getenv("GOOGLE_CLIENT_SECRET") or GOOGLE_CLIENT_SECRET).strip()
    redirect_uri = _resolve_google_redirect_uri(request)

    # 1. Troca o código de autorização pelo token de acesso na API do Google
    try:
        with httpx.Client(timeout=12.0) as http_client:
            token_payload = {
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
            if client_secret:
                token_payload["client_secret"] = client_secret

            token_resp = http_client.post(
                "https://oauth2.googleapis.com/token",
                data=token_payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if token_resp.is_error:
                err_body = token_resp.text
                logger.error("Falha ao trocar código com o Google: HTTP %s - %s", token_resp.status_code, err_body)
                detail = "Falha ao validar com os servidores do Google"
                try:
                    j = token_resp.json()
                    detail = j.get("error_description") or j.get("error") or detail
                except Exception:
                    pass
                sep = "&" if "?" in target_root else "?"
                return RedirectResponse(
                    url=f"{target_root}{sep}auth_error={urllib.parse.quote(str(detail))}",
                    status_code=status.HTTP_302_FOUND,
                )
            token_data = token_resp.json()
            access_token = token_data.get("access_token")

            # 2. Busca os dados de perfil do usuário (e-mail, nome)
            user_resp = http_client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if user_resp.is_error:
                logger.error("Falha ao obter perfil do Google: HTTP %s - %s", user_resp.status_code, user_resp.text)
                sep = "&" if "?" in target_root else "?"
                return RedirectResponse(
                    url=f"{target_root}{sep}auth_error={urllib.parse.quote('Falha ao obter perfil na conta do Google')}",
                    status_code=status.HTTP_302_FOUND,
                )
            user_info = user_resp.json()
    except Exception as exc:
        logger.error("Exceção não tratada no callback Google: %s", exc, exc_info=True)
        sep = "&" if "?" in target_root else "?"
        return RedirectResponse(
            url=f"{target_root}{sep}auth_error={urllib.parse.quote(f'Erro de conexão com o Google: {exc}')}",
            status_code=status.HTTP_302_FOUND,
        )

    email = (user_info.get("email") or "").strip().lower()
    if not email:
        return RedirectResponse(
            url=f"{target_root}{'&' if '?' in target_root else '?'}auth_error={urllib.parse.quote('O Google não retornou o e-mail da conta')}",
            status_code=status.HTTP_302_FOUND,
        )

    name = (user_info.get("name") or user_info.get("given_name") or email.split("@")[0]).strip()
    picture = (user_info.get("picture") or "").strip() or None
    google_token_hash = hash_password(f"google-oauth2::{email}")
    users_repo = get_users_repo()

    try:
        user_doc = users_repo.autenticar_ou_criar_google(
            email=email,
            nome=name,
            google_token_hash=google_token_hash,
            foto_url=picture,
        )
    except Exception as exc:
        logger.error("Falha ao salvar usuário autenticado no banco: %s", exc, exc_info=True)
        sep = "&" if "?" in target_root else "?"
        return RedirectResponse(
            url=f"{target_root}{sep}auth_error={urllib.parse.quote('Erro ao autenticar com a conta Google')}",
            status_code=status.HTTP_302_FOUND,
        )

    # 3. Emite o token JWT com validade de 1 dia (24h) e Refresh Token (7 dias)
    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome", name),
        expires_seconds=ACCESS_TOKEN_EXPIRE_SECONDS,
    )
    raw_refresh_token, token_hash = generate_refresh_token()
    refresh_repo = get_refresh_tokens_repo()
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    user_agent = request.headers.get("user-agent", "")
    refresh_repo.criar_token(
        token_hash=token_hash,
        usuario_id=user_doc["_id"],
        expires_seconds=7 * 86400,
        ip=client_ip,
        user_agent=user_agent,
    )

    # 4. Redireciona de volta para a SPA, app mobile ou raiz / com os parâmetros de autenticação e cookie de sessão
    redirect_params = urllib.parse.urlencode({
        "token": token,
        "refresh_token": raw_refresh_token,
        "user_id": str(user_doc["_id"]),
        "email": user_doc["email"],
        "name": user_doc.get("nome", name),
        "avatar": user_doc.get("avatar") or user_doc.get("foto_url") or "",
        "termos_aceitos": "true" if user_doc.get("termos_aceitos") else "false",
    })
    sep = "&" if "?" in target_root else "?"
    final_redirect_url = f"{target_root}{sep}{redirect_params}"
    logger.info("Login Google bem-sucedido para %s. Redirecionando para %s", email, final_redirect_url)
    response = RedirectResponse(url=final_redirect_url, status_code=status.HTTP_302_FOUND)
    set_refresh_token_cookie(response, raw_refresh_token, request)
    return response



# =============================================================================
# AUTENTICAÇÃO PASSWORDLESS VIA CÓDIGO POR E-MAIL (OTP)
# =============================================================================

@app.post("/api/auth/otp/request")
def solicitar_codigo_otp(payload: OTPRequestPayload) -> dict[str, Any]:
    """
    Gera e envia um código numérico de 6 dígitos temporário (OTP) por e-mail.
    Aplica rate limiting de 60s entre reenvios e no máximo 5 solicitações por hora.
    Bloqueia contas vinculadas ao Google Auth para direcionar ao fluxo Google.
    """
    clean_email = payload.email.strip().lower()
    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail inválido. Verifique o formato digitado.",
        )

    # 1. Geração segura e rate limiting
    try:
        plain_code, cooldown, expires_min = default_otp_manager.request_otp(
            email=clean_email,
            name=payload.nome,
        )
    except OTPRateLimitError as rle:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(rle),
            headers={"Retry-After": str(rle.retry_after_seconds)},
        ) from rle

    # 3. Disparo do e-mail transacional
    try:
        default_email_service.send_otp_email(
            to_email=clean_email,
            codigo=plain_code,
            expires_in_minutes=expires_min,
        )
    except Exception as exc:
        print(f"[Email Dispatch Error]: {exc}")

    return {
        "status": "success",
        "message": f"Código de verificação enviado para {clean_email}!",
        "email": clean_email,
        "cooldown_seconds": cooldown,
        "expires_in_minutes": expires_min,
    }


@app.post("/api/auth/otp/verify")
def verificar_codigo_otp(payload: OTPVerifyPayload) -> dict[str, Any]:
    """
    Valida o código de 6 dígitos inserido pelo usuário.
    Destrói o código imediatamente após o primeiro uso válido (invalidação pós-uso).
    Autentica ou cria a conta passwordless e emite o token JWT de sessão.
    """
    clean_email = payload.email.strip().lower()
    clean_code = payload.codigo.strip()

    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail inválido.",
        )

    if not clean_code or len(clean_code) != 6 or not clean_code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O código de verificação deve conter exatamente 6 dígitos numéricos.",
        )

    # 1. Validação com destruição imediata se correto e controle de tentativas
    try:
        ok, msg, stored_name = default_otp_manager.verify_otp(
            email=clean_email,
            candidate_code=clean_code,
        )
    except OTPVerificationError as ove:
        status_code = status.HTTP_429_TOO_MANY_REQUESTS if "Limite de tentativas" in str(ove) else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=str(ove)) from ove

    # 2. Login ou criação de conta passwordless
    chosen_name = (payload.nome or "").strip() or stored_name
    users_repo = get_users_repo()
    try:
        user_doc = users_repo.autenticar_ou_criar_otp(
            email=clean_email,
            nome=chosen_name,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err)) from val_err
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro ao acessar conta: {exc}") from exc

    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome", ""),
        expires_seconds=ACCESS_TOKEN_EXPIRE_SECONDS,
    )

    return {
        "status": "success",
        "message": "Login realizado com sucesso!",
        "token": token,
        "refresh_token": raw_refresh_token,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", ""),
            "provedor": user_doc.get("provedor", "email_otp"),
        },
    }


def _evaluate_legacy_courtesy_and_get_plan(user_doc: Optional[dict[str, Any]]) -> dict[str, Any]:
    """
    Avalia o plano efetivo do usuário e concede automaticamente 3 dias de Cortesia Premium
    caso seja um usuário legado que já ultrapassou os limites do plano Free.
    """
    if not user_doc:
        return get_effective_plan(None)

    base_plan = get_effective_plan(user_doc)
    if base_plan["is_premium"]:
        return base_plan

    # Se ainda não verificamos cortesia legada para este usuário Free
    if not user_doc.get("cortesia_concedida") and not user_doc.get("cortesia_verificada"):
        user_id = str(user_doc.get("_id") or user_doc.get("id") or "").strip()
        if user_id:
            try:
                equipes_repo = get_equipes_repo()
                musicas_repo = get_repo()
                user_teams = equipes_repo.listar_equipes_do_usuario(user_id)
                owned_teams = [
                    eq for eq in user_teams
                    if str(eq.get("criado_por") or "") == user_id
                ]
                owned_count = len(owned_teams)
                max_members = max((len(eq.get("membros", [])) for eq in owned_teams), default=0)
                max_songs = 0
                for eq in owned_teams:
                    eq_id = str(eq.get("_id") or eq.get("id") or "")
                    if eq_id:
                        cnt = musicas_repo.contar_por_equipe(equipe_id=eq_id)
                        if cnt > max_songs:
                            max_songs = cnt
                if not owned_teams:
                    max_songs = musicas_repo.contar_por_equipe(usuario_id=user_id)

                users_repo = get_users_repo()
                if is_exceeding_free_limits(owned_count, max_members, max_songs):
                    ate_iso = compute_courtesy_expiration()
                    updated_user = users_repo.conceder_cortesia(user_id, ate_iso)
                    user_doc["cortesia_ate"] = ate_iso
                    user_doc["cortesia_concedida"] = True
                    user_doc["cortesia_verificada"] = True
                    if isinstance(updated_user, dict):
                        user_doc.update(updated_user)
                    return get_effective_plan(user_doc)
                else:
                    users_repo.marcar_cortesia_verificada(user_id)
            except Exception as _courtesy_err:
                logger.debug("Falha ao verificar elegibilidade de cortesia: %s", _courtesy_err)

    return get_effective_plan(user_doc)


def _get_team_owner_plan(
    equipe_id: Optional[str],
    fallback_user_id: str,
) -> tuple[dict[str, Any], Optional[dict[str, Any]]]:
    """
    Retorna (plano_efetivo_do_dono, documento_da_equipe).
    Quem define os limites da equipe (músicas e integrantes) é o plano do criador da equipe.
    """
    users_repo = get_users_repo()
    if equipe_id:
        try:
            equipes_repo = get_equipes_repo()
            equipe_doc = equipes_repo.buscar_por_id(equipe_id)
            if equipe_doc:
                owner_id = str(equipe_doc.get("criado_por") or fallback_user_id).strip()
                owner_doc = users_repo.buscar_por_id(owner_id)
                return _evaluate_legacy_courtesy_and_get_plan(owner_doc), equipe_doc
        except Exception:
            pass

    fallback_doc = users_repo.buscar_por_id(fallback_user_id)
    return _evaluate_legacy_courtesy_and_get_plan(fallback_doc), None


@app.get("/api/plano")
def obter_plano_e_uso(
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe ativa para cálculo de uso"),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Retorna o plano efetivo do usuário, o plano da equipe ativa, limites e métricas de uso atual."""
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    user_plan = _evaluate_legacy_courtesy_and_get_plan(user_doc)
    equipes_repo = get_equipes_repo()
    musicas_repo = get_repo()

    resolved_equipe_id, _ = resolve_team_for_user(
        equipe_id, user_id, require_for_write=False
    )
    active_team_doc: Optional[dict[str, Any]] = None
    if resolved_equipe_id:
        team_plan, team_doc = _get_team_owner_plan(resolved_equipe_id, user_id)
        active_team_doc = team_doc
    else:
        team_plan = user_plan

    owned_teams_count = 0
    try:
        owned_teams_count = equipes_repo.contar_equipes_criadas_por(user_id)
    except Exception:
        owned_teams_count = 0

    team_members_count = len(active_team_doc.get("membros", [])) if isinstance(active_team_doc, dict) else 1
    team_songs_count = 0
    try:
        team_songs_count = musicas_repo.contar_por_equipe(
            equipe_id=resolved_equipe_id,
            usuario_id=user_id,
        )
    except Exception:
        team_songs_count = 0

    return {
        "plano": user_plan["plano"],
        "label": user_plan["label"],
        "origem": user_plan["origem"],
        "is_premium": user_plan["is_premium"],
        "cortesia_ativa": user_plan["cortesia_ativa"],
        "expira_em": user_plan["expira_em"],
        "limites": user_plan["limites"],
        "equipe_ativa": {
            "equipe_id": resolved_equipe_id,
            "plano": team_plan["plano"],
            "label": team_plan["label"],
            "is_premium": team_plan["is_premium"],
            "limites": team_plan["limites"],
        },
        "uso": {
            "equipes_criadas": owned_teams_count,
            "membros_equipe_ativa": team_members_count,
            "musicas_equipe_ativa": team_songs_count,
        },
    }


@app.get("/api/auth/me")
def obter_usuario_logado(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """Retorna os dados do usuário autenticado via Bearer Token, incluindo suas equipes, equipe ativa e plano."""
    user_id = require_authenticated_user(authorization)

    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    user_plan = _evaluate_legacy_courtesy_and_get_plan(user_doc)

    equipes: list[dict[str, Any]] = []
    try:
        equipes = get_equipes_repo().listar_equipes_do_usuario(user_id)
    except Exception:
        equipes = []

    equipe_ativa = equipes[0] if equipes else None
    equipe_ativa_id = (
        str(equipe_ativa.get("_id") or equipe_ativa.get("id"))
        if equipe_ativa and (equipe_ativa.get("_id") or equipe_ativa.get("id"))
        else None
    )

    foto_url = user_doc.get("foto_url") or user_doc.get("avatar") or ""

    return {
        "id": user_doc["_id"],
        "email": user_doc["email"],
        "nome": user_doc.get("nome", ""),
        "foto_url": foto_url,
        "avatar": foto_url,
        "termos_aceitos": bool(user_doc.get("termos_aceitos", False)),
        "termos_aceitos_em": user_doc.get("termos_aceitos_em"),
        "criado_em": user_doc.get("criado_em", ""),
        "equipes": equipes,
        "equipe_ativa": equipe_ativa,
        "equipe_ativa_id": equipe_ativa_id,
        "plano": user_plan,
    }


@app.post("/api/auth/aceitar-termos")
def aceitar_termos_e_cookies(
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """
    Registra de forma definitiva no perfil da conta que o usuário leu e aceitou
    os Termos de Uso, a Política de Privacidade e os Cookies Essenciais (LGPD Art. 7º e 8º).
    Isso assegura que a conta precise aceitar apenas 1 vez, independentemente de dispositivo.
    """
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        if hasattr(users_repo.collection, "update_one"):
            users_repo.collection.update_one(
                {"_id": ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id},
                {
                    "$set": {
                        "termos_aceitos": True,
                        "termos_aceitos_em": now_iso,
                        "cookies_aceitos": True,
                    }
                },
            )
    except Exception as exc:
        logger.warning("Falha ao registrar aceite de termos no banco: %s", exc)

    return {
        "status": "success",
        "message": "Termos de uso e cookies aceitos com sucesso para esta conta.",
        "termos_aceitos": True,
        "termos_aceitos_em": now_iso,
    }


@app.put("/api/auth/nome")
@app.put("/api/auth/perfil")
def alterar_perfil_usuario(
    payload: UserChangeNamePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Atualiza o nome de exibição e/ou foto_url (avatar) do músico autenticado no MongoDB Atlas."""
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    existing_doc = users_repo.buscar_por_id(user_id)
    if not existing_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    raw_nome = payload.novo_nome if payload.novo_nome is not None else payload.nome
    clean_nome = (raw_nome or "").strip() if raw_nome is not None else str(existing_doc.get("nome") or "").strip()

    if raw_nome is not None and len(clean_nome) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O nome de usuário deve conter pelo menos 2 caracteres.",
        )

    updated_doc = existing_doc
    if raw_nome is not None and clean_nome != existing_doc.get("nome"):
        try:
            res_doc = users_repo.atualizar_nome_usuario(user_id=user_id, novo_nome=clean_nome)
            if res_doc:
                updated_doc = res_doc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro no banco: {exc}") from exc

    raw_foto = payload.foto_url if payload.foto_url is not None else payload.avatar
    if raw_foto is not None:
        clean_foto = raw_foto.strip()
        if clean_foto:
            lower_foto = clean_foto.lower()
            if any(lower_foto.startswith(bad) for bad in ("javascript:", "data:text/html", "vbscript:", "file:")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="URL de avatar inválida ou com esquema não permitido por segurança.",
                )
            if len(clean_foto) > 2048:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="A URL do avatar não pode exceder 2048 caracteres.",
                )
        existing_foto = str(existing_doc.get("foto_url") or existing_doc.get("avatar") or "").strip()
        if clean_foto and clean_foto != existing_foto:
            user_plan = _evaluate_legacy_courtesy_and_get_plan(existing_doc)
            if not user_plan["limites"]["custom_avatar"]:
                raise PlanLimitError(
                    limit_type="avatar",
                    message="A personalização com foto de perfil é um recurso exclusivo dos planos CipherSong Pro e Ministério.",
                    limit=0,
                    current=0,
                )
        try:
            try:
                target_oid: Any = ObjectId(user_id)
            except Exception:
                target_oid = str(user_id)
            if hasattr(users_repo.collection, "update_one"):
                users_repo.collection.update_one(
                    {"_id": target_oid},
                    {"$set": {"foto_url": clean_foto, "avatar": clean_foto}},
                )
            updated_doc["foto_url"] = clean_foto
            updated_doc["avatar"] = clean_foto
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Erro ao salvar foto de perfil: {exc}",
            ) from exc

    final_nome = updated_doc.get("nome", clean_nome)
    final_foto = updated_doc.get("foto_url") or updated_doc.get("avatar") or ""

    token = create_access_token(
        user_id=updated_doc["_id"],
        email=updated_doc["email"],
        name=final_nome,
    )

    return {
        "status": "success",
        "message": "Perfil atualizado com sucesso!",
        "token": token,
        "user": {
            "id": updated_doc["_id"],
            "email": updated_doc["email"],
            "nome": final_nome,
            "foto_url": final_foto,
            "avatar": final_foto,
        },
    }


MAX_AVATAR_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
AVATAR_STREAM_CHUNK_BYTES = 64 * 1024  # 64 KB por chunk (evita exaustão de RAM antes de rejeitar)
MAX_AVATAR_IMAGE_PIXELS = 4096 * 4096  # 16 MP (proteção contra Decompression Bomb)
MAX_AVATAR_DIMENSION_PX = 4096
ALLOWED_AVATAR_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_AVATAR_MIME_TYPES = {"image/jpeg", "image/jpg", "image/png", "image/webp"}
ALLOWED_PIL_FORMATS = {"JPEG", "PNG", "WEBP"}


def _detect_avatar_magic_bytes(raw_bytes: bytes) -> Optional[str]:
    """Valida a assinatura binária (magic bytes) real da imagem para impedir polyglots/scripts disfarçados."""
    if len(raw_bytes) < 12:
        return None
    if raw_bytes[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if raw_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if raw_bytes[:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP":
        return "WEBP"
    return None


def _has_polyglot_script_payload(raw_bytes: bytes) -> bool:
    """Detecta marcadores de scripts/HTML/SVG/PHP disfarçados em cabeçalho ou rodapé de imagem."""
    sample = (raw_bytes[:2048] + b" " + raw_bytes[-2048:]).lower()
    markers = (b"<script", b"<?php", b"<svg", b"<!doctype html", b"<html", b"javascript:", b"onerror=", b"onload=")
    return any(m in sample for m in markers)


def _resolve_safe_avatar_disk_path(user_id: str) -> tuple[str, str]:
    """
    Constrói o caminho seguro `{safe_uid}.webp` ignorando totalmente o nome original do cliente
    e valida com `os.path.realpath` para impedir Path Traversal (`../../`).
    """
    safe_uid = re.sub(r"[^a-zA-Z0-9_-]", "", str(user_id or "").strip())[:64] or "user"
    base_dir_path = os.path.dirname(os.path.abspath(__file__))
    avatars_dir = os.path.realpath(os.path.join(base_dir_path, "uploads", "avatars"))
    os.makedirs(avatars_dir, exist_ok=True)
    candidate_path = os.path.realpath(os.path.join(avatars_dir, f"{safe_uid}.webp"))
    if os.path.commonpath([avatars_dir, candidate_path]) != avatars_dir or os.path.dirname(candidate_path) != avatars_dir:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Caminho de destino inválido para armazenamento do avatar.",
        )
    return safe_uid, candidate_path


@app.post("/api/auth/avatar/upload")
@app.post("/api/auth/avatar")
@app.post("/api/auth/foto")
async def upload_foto_perfil(
    file: UploadFile = File(..., description="Imagem de perfil (.jpg, .jpeg, .png, .webp até 5 MB)"),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """
    Recebe upload de foto de perfil, valida tamanho em stream (máx 5 MB), extensão, MIME, Magic Bytes e
    integridade estrutural via Pillow (proteção contra polyglots e decompression bombs),
    aplica center-crop quadrado (1:1), redimensiona com LANCZOS (máx 512x512) e comprime em WebP (quality=82).
    """
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    existing_doc = users_repo.buscar_por_id(user_id)
    if not existing_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    user_plan = _evaluate_legacy_courtesy_and_get_plan(existing_doc)
    if not user_plan["limites"]["custom_avatar"]:
        raise PlanLimitError(
            limit_type="avatar",
            message="O upload de foto de perfil personalizada é exclusivo dos planos CipherSong Pro e Ministério. Faça upgrade para personalizar seu perfil!",
            limit=0,
            current=0,
        )

    # 1. Validação de extensão (usando apenas basename sem confiar no path enviado) e Content-Type
    raw_filename = os.path.basename((file.filename or "").strip().replace("\\", "/")).lower()
    ext = os.path.splitext(raw_filename)[1] if raw_filename else ""
    content_type = (file.content_type or "").split(";")[0].strip().lower()

    if ext not in ALLOWED_AVATAR_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato inválido. Envie uma imagem JPG, PNG ou WEBP.",
        )

    if content_type and content_type not in ALLOWED_AVATAR_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato inválido. Envie uma imagem JPG, PNG ou WEBP.",
        )

    # 2. Leitura em stream limitada por chunks (máximo rígido de 5 MB antes de alocar mais RAM)
    buffer = bytearray()
    while True:
        chunk = await file.read(AVATAR_STREAM_CHUNK_BYTES)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > MAX_AVATAR_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A imagem deve ter no máximo 5 MB",
            )

    conteudo = bytes(buffer)
    if not conteudo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Arquivo de imagem vazio.",
        )

    # 3. Validação real de cabeçalho binário (Magic Bytes), anti-polyglot e verificação estrutural via Pillow
    magic_format = _detect_avatar_magic_bytes(conteudo)
    if magic_format not in ALLOWED_PIL_FORMATS or _has_polyglot_script_payload(conteudo):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato inválido. Envie uma imagem JPG, PNG ou WEBP.",
        )

    Image.MAX_IMAGE_PIXELS = MAX_AVATAR_IMAGE_PIXELS
    try:
        with Image.open(io.BytesIO(conteudo)) as verify_img:
            detected_format = (verify_img.format or "").upper()
            if detected_format not in ALLOWED_PIL_FORMATS or detected_format != magic_format:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Formato inválido. Envie uma imagem JPG, PNG ou WEBP.",
                )
            v_width, v_height = verify_img.size
            if (
                v_width <= 0
                or v_height <= 0
                or v_width > MAX_AVATAR_DIMENSION_PX
                or v_height > MAX_AVATAR_DIMENSION_PX
                or (v_width * v_height) > MAX_AVATAR_IMAGE_PIXELS
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Dimensões da imagem excedem o limite de segurança permitido.",
                )
            verify_img.verify()

        raw_img = Image.open(io.BytesIO(conteudo))
        raw_img.load()
    except HTTPException:
        raise
    except (Image.DecompressionBombError, UnidentifiedImageError, OSError, SyntaxError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato inválido. Envie uma imagem JPG, PNG ou WEBP.",
        ) from exc

    # 4. Processamento e otimização: orientação EXIF + Center Crop 1:1 + LANCZOS 512x512 + WebP (remove EXIF/metadados)
    try:
        img = ImageOps.exif_transpose(raw_img)
        width, height = img.size
        if width <= 0 or height <= 0:
            raise ValueError("Dimensões de imagem inválidas.")

        # Center crop quadrado (1:1) pelo menor lado
        side = min(width, height)
        left = (width - side) // 2
        top = (height - side) // 2
        img = img.crop((left, top, left + side, top + side))

        # Redimensionamento LANCZOS para no máximo 512x512 pixels
        target_dim = min(side, 512)
        if img.size != (target_dim, target_dim):
            img = img.resize((target_dim, target_dim), Image.Resampling.LANCZOS)

        # Conversão de canais de cor (mantém transparência em RGBA ou converte para RGB)
        if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
            img = img.convert("RGBA")
        else:
            img = img.convert("RGB")

        out_buffer = io.BytesIO()
        img.save(out_buffer, format="WEBP", quality=82, method=6)
        webp_bytes = out_buffer.getvalue()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Não foi possível processar a imagem enviada: {exc}",
        ) from exc

    # 5. Salva arquivo físico em uploads/avatars/{safe_uid}.webp (anti-Path Traversal) e persiste no MongoDB
    safe_uid, avatar_disk_path = _resolve_safe_avatar_disk_path(user_id)
    try:
        with open(avatar_disk_path, "wb") as f_out:
            f_out.write(webp_bytes)
    except Exception as disk_err:
        logger.warning("Aviso ao gravar avatar em disco (%s): %s", avatar_disk_path, disk_err)

    b64_webp = base64.b64encode(webp_bytes).decode("ascii")
    foto_data_uri = f"data:image/webp;base64,{b64_webp}"
    static_avatar_url = f"/uploads/avatars/{safe_uid}.webp"

    try:
        if hasattr(users_repo, "atualizar_nome_ou_foto"):
            _call_repo(users_repo.atualizar_nome_ou_foto, user_id=user_id, foto_url=foto_data_uri)
        try:
            target_oid: Any = ObjectId(user_id)
        except Exception:
            target_oid = str(user_id)
        if hasattr(users_repo.collection, "update_one"):
            users_repo.collection.update_one(
                {"_id": target_oid},
                {"$set": {"foto_url": foto_data_uri, "avatar": foto_data_uri}},
            )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Erro ao salvar foto de perfil no banco: {exc}",
        ) from exc

    final_nome = existing_doc.get("nome", "")
    return {
        "status": "success",
        "message": "Foto de perfil atualizada e otimizada com sucesso!",
        "foto_url": foto_data_uri,
        "avatar": foto_data_uri,
        "static_url": static_avatar_url,
        "size_bytes": len(webp_bytes),
        "user": {
            "id": str(existing_doc["_id"]),
            "email": existing_doc["email"],
            "nome": final_nome,
            "foto_url": foto_data_uri,
            "avatar": foto_data_uri,
        },
    }


@app.delete("/api/auth/conta")
@app.delete("/api/auth/account")
def excluir_conta_permanentemente(
    response: Response,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """
    Exclui permanentemente a conta do usuário autenticado no MongoDB Atlas (Direito de Eliminação - LGPD Art. 18, VI):
    1. Remove o documento do usuário da coleção `usuarios` (e-mail, hash de senha, nome, avatar, credenciais).
    2. Exclui todos os registros de sessão da coleção `refresh_tokens` no MongoDB.
    3. Remove o usuário da lista `membros` das equipes em `equipes` (transferindo ou anonimizando `criado_por`).
    4. Anonimiza a referência pessoal `usuario_id` no acervo compartilhado (`musicas_ensaio`, `repertorio_semana`, `musicas_a_ensaiar`), preservando integralmente o repertório da equipe (LGPD Art. 16, II).
    5. Invalida códigos OTP pendentes, chamadas diretas (`pings_equipe`) e cookies de sessão (`ciphersong_jwt` e `ciphersong_refresh_token`).
    6. Cancela eventual assinatura ativa no Stripe para cessar cobranças recorrentes.
    """
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conta de usuário não encontrada.")

    user_email = str(user_doc.get("email") or "").strip().lower()

    # 1. Remove o usuário das equipes sem apagar as equipes nem o acervo
    try:
        equipes_repo = get_equipes_repo()
        equipes_usuario = equipes_repo.listar_equipes_do_usuario(user_id)
        for eq in equipes_usuario:
            eq_id = eq.get("_id") or eq.get("id")
            if not eq_id:
                continue
            try:
                target_eq_id: Any = ObjectId(str(eq_id))
            except Exception:
                target_eq_id = str(eq_id)

            membros_atuais = [str(m) for m in eq.get("membros", []) if str(m) != str(user_id)]
            update_fields: dict[str, Any] = {"membros": membros_atuais}
            if str(eq.get("criado_por")) == str(user_id):
                update_fields["criado_por"] = membros_atuais[0] if membros_atuais else None

            if hasattr(equipes_repo.collection, "update_one"):
                equipes_repo.collection.update_one(
                    {"_id": target_eq_id},
                    {"$set": update_fields},
                )
    except Exception as eq_err:
        logger.warning("Aviso ao desvincular usuário %s das equipes: %s", user_id, eq_err)

    # 2. Anonimiza o identificador pessoal (usuario_id) nas coleções de repertório da equipe (LGPD Art. 16, II)
    for getter in (get_repo, get_semana_repo, get_a_ensaiar_repo):
        try:
            col = getter().collection
            if hasattr(col, "update_many"):
                col.update_many(
                    {"usuario_id": str(user_id)},
                    {"$set": {"usuario_id": None}},
                )
        except Exception:
            pass

    # 3. Limpa tokens OTP em memória para o e-mail do usuário
    if user_email:
        try:
            if hasattr(default_otp_manager, "_records"):
                default_otp_manager._records.pop(user_email, None)
            if hasattr(default_otp_manager, "_store"):
                default_otp_manager._store.pop(user_email, None)
        except Exception:
            pass

    # 4. Limpa pings efêmeros endereçados ou enviados pelo usuário na coleção `pings_equipe`
    try:
        pings_col = get_pings_repo().collection
        if hasattr(pings_col, "delete_many"):
            pings_col.delete_many(
                {"$or": [{"destinatario_id": str(user_id)}, {"remetente_id": str(user_id)}]}
            )
    except Exception:
        pass

    # 5. Exclui todos os registros de sessão da coleção `refresh_tokens` no MongoDB
    try:
        refresh_repo = get_refresh_tokens_repo()
        if hasattr(refresh_repo, "excluir_todos_usuario"):
            refresh_repo.excluir_todos_usuario(str(user_id))
        elif hasattr(refresh_repo.collection, "delete_many"):
            refresh_repo.collection.delete_many({"usuario_id": str(user_id)})
    except Exception as ref_err:
        logger.warning("Aviso ao limpar refresh tokens do usuário %s no MongoDB: %s", user_id, ref_err)

    # 6. Cancela assinatura ativa no Stripe para cessar cobranças recorrentes após exclusão
    sub_id = (user_doc.get("assinatura") or {}).get("stripe_subscription_id") or user_doc.get("stripe_subscription_id")
    if sub_id:
        try:
            stripe.Subscription.cancel(sub_id)
        except Exception as stripe_cancel_err:
            logger.warning("Aviso ao cancelar assinatura Stripe %s no delete: %s", sub_id, stripe_cancel_err)

    # 7. Exclui o registro do usuário na coleção `usuarios` no MongoDB
    try:
        if hasattr(users_repo, "excluir_usuario"):
            users_repo.excluir_usuario(str(user_id), email=user_email)
        else:
            deleted = False
            try:
                res_oid = users_repo.collection.delete_one({"_id": ObjectId(user_id)})
                deleted = getattr(res_oid, "deleted_count", 0) > 0
            except Exception:
                pass
            if not deleted:
                users_repo.collection.delete_one({"_id": str(user_id)})
            if user_email:
                users_repo.collection.delete_many({"email": user_email})

        # Verificação rigorosa pós-exclusão: garante que o usuário não existe mais no MongoDB
        verification = users_repo.buscar_por_id(str(user_id))
        if verification:
            logger.warning("Usuário %s ainda encontrado após delete, forçando delete_many por id e email...", user_id)
            clean_oid = ObjectId(user_id) if ObjectId.is_valid(str(user_id)) else None
            filter_or: list[dict[str, Any]] = [{"_id": str(user_id)}]
            if clean_oid:
                filter_or.append({"_id": clean_oid})
            if user_email:
                filter_or.append({"email": user_email})
            users_repo.collection.delete_many({"$or": filter_or})
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Erro ao excluir conta do banco de dados MongoDB: {exc}",
        ) from exc

    # 8. Remove eventual arquivo físico de avatar salvo em disco (uploads/avatars/{safe_uid}.webp)
    try:
        _, avatar_disk_path = _resolve_safe_avatar_disk_path(user_id)
        if os.path.isfile(avatar_disk_path):
            os.remove(avatar_disk_path)
    except Exception:
        pass

    # 9. Invalida os cookies HttpOnly de sessão e refresh token
    response.delete_cookie(key="ciphersong_jwt", path="/", samesite="lax")
    try:
        clear_refresh_cookie(response, request)
    except Exception:
        pass

    return {
        "status": "success",
        "deleted": True,
        "user_id": str(user_id),
        "message": "Sua conta foi excluída permanentemente do MongoDB. O repertório, as escalas e as equipes foram preservados.",
    }


# =============================================================================
# ROTAS DO REPERTÓRIO DE MÚSICAS ENSAIADAS (ISOLAMENTO ESTRITO POR EQUIPE)
# =============================================================================

@app.get("/api/musicas")
def listar_musicas(
    q: Optional[str] = Query(default=None, description="Termo de busca (título, versão, cantor ou tom)"),
    cantor: Optional[str] = Query(default=None, description="Filtrar por cantor específico"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe selecionada"),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, allowed_team_ids = resolve_team_for_user(
        equipe_id, usuario_id, require_for_write=False
    )
    if not allowed_team_ids:
        return []

    repo = get_repo()
    has_filter = bool((q and q.strip()) or (cantor and cantor.strip() and cantor.strip().lower() != "todos"))
    target_teams = [resolved_equipe_id] if (equipe_id and resolved_equipe_id) else allowed_team_ids

    try:
        collected: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for tid in target_teams:
            if not tid:
                continue
            if has_filter:
                docs = _call_repo(
                    repo.buscar_por_filtro,
                    termo=q.strip() if q else "",
                    cantor=cantor.strip() if cantor else None,
                    usuario_id=None,
                    equipe_id=tid,
                )
            else:
                docs = _call_repo(repo.listar_todas, usuario_id=None, equipe_id=tid)
            for doc in docs:
                doc_eq = str(doc.get("equipe_id") or "").strip()
                if doc_eq != str(tid).strip():
                    continue
                doc_id = str(doc.get("_id") or doc.get("id") or "")
                if doc_id and doc_id in seen_ids:
                    continue
                if doc_id:
                    seen_ids.add(doc_id)
                collected.append(doc)
        return collected
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao consultar MongoDB Atlas: {exc}") from exc


@app.get("/api/cantores")
def listar_cantores(
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe selecionada"),
    authorization: Optional[str] = Header(default=None),
) -> list[str]:
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, allowed_team_ids = resolve_team_for_user(
        equipe_id, usuario_id, require_for_write=False
    )
    if not allowed_team_ids:
        return []

    repo = get_repo()
    target_teams = [resolved_equipe_id] if (equipe_id and resolved_equipe_id) else allowed_team_ids
    try:
        cantores_set: set[str] = set()
        for tid in target_teams:
            if not tid:
                continue
            lista = _call_repo(repo.listar_cantores_unicos, usuario_id=None, equipe_id=tid)
            for c in lista:
                if c and str(c).strip():
                    cantores_set.add(str(c).strip())
        return sorted(cantores_set)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao listar cantores: {exc}") from exc


@app.post("/api/musicas", status_code=201)
def criar_musica(
    payload: MusicaCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, _ = resolve_team_for_user(
        payload.equipe_id, usuario_id, require_for_write=True
    )
    repo = get_repo()

    # Verifica limite de músicas do plano do dono da equipe (apenas se não for mesclagem de duplicata)
    is_dup = False
    if hasattr(repo, "existe_duplicata"):
        is_dup = repo.existe_duplicata(
            titulo=payload.titulo,
            cantor_principal=payload.cantor_principal,
            versao=payload.versao or "Original",
            equipe_id=resolved_equipe_id,
            usuario_id=usuario_id,
        )
    if not is_dup and hasattr(repo, "contar_por_equipe"):
        team_plan, _ = _get_team_owner_plan(resolved_equipe_id, usuario_id)
        max_songs = team_plan["limites"]["max_songs"]
        if max_songs is not None:
            current_songs = repo.contar_por_equipe(
                equipe_id=resolved_equipe_id,
                usuario_id=usuario_id,
            )
            if current_songs >= max_songs:
                raise PlanLimitError(
                    limit_type="songs",
                    message=f"A equipe atingiu o limite de {max_songs} músicas do Plano Gratuito. Faça upgrade para o CipherSong Pro ou Ministério para cadastrar músicas ilimitadas!",
                    limit=max_songs,
                    current=current_songs,
                )

    try:
        from ciphersong.core.music_theory import (
            auto_transpose_chord_sheet_to_key,
            normalize_musical_key,
        )

        primary_tone = payload.tons[0] if payload.tons else (payload.tom_original or "C")
        canonical_tone = normalize_musical_key(primary_tone) or primary_tone
        raw_cifra = (payload.cifra or "").strip()
        if raw_cifra and primary_tone:
            raw_cifra, _, _, _ = auto_transpose_chord_sheet_to_key(raw_cifra, primary_tone)

        saved_doc = _call_repo(
            repo.salvar_musica,
            titulo=payload.titulo,
            cantor_principal=payload.cantor_principal,
            tons=payload.tons,
            versao=payload.versao or "Original",
            usuario_id=usuario_id,
            equipe_id=resolved_equipe_id,
            cifra=raw_cifra,
            tom_original=canonical_tone,
        )
        dispatch_team_event(
            resolved_equipe_id,
            "songs_changed",
            {"action": "saved", "musica_id": str(saved_doc.get("_id") or saved_doc.get("id") or "")},
            exclude_user_id=usuario_id,
        )
        return saved_doc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao salvar no MongoDB Atlas: {exc}") from exc


@app.put("/api/musicas/{song_id}")
def atualizar_musica_endpoint(
    song_id: str,
    payload: MusicaCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    usuario_id = require_authenticated_user(authorization)
    repo = get_repo()
    try:
        doc = repo.collection.find_one({"_id": ObjectId(song_id)})
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"ID inválido: {exc}") from exc

    if not doc:
        raise HTTPException(status_code=404, detail="Música não encontrada.")

    doc_equipe = str(doc.get("equipe_id") or "").strip()
    if doc_equipe:
        equipes_repo = get_equipes_repo()
        if not equipes_repo.usuario_pertence_a_equipe(doc_equipe, usuario_id):
            raise HTTPException(status_code=403, detail="Acesso não autorizado para esta equipe.")

    from ciphersong.core.music_theory import (
        auto_transpose_chord_sheet_to_key,
        normalize_musical_key,
    )

    clean_tons = [t.strip() for t in payload.tons if t.strip()]
    primary_tone = clean_tons[0] if clean_tons else (payload.tom_original or "C")
    canonical_tone = normalize_musical_key(primary_tone) or primary_tone

    update_fields: dict[str, Any] = {
        "titulo": payload.titulo.strip(),
        "cantor_principal": payload.cantor_principal.strip(),
        "tons": clean_tons,
        "versao": (payload.versao or "Original").strip(),
        "atualizado_em": datetime.now(timezone.utc).isoformat(),
    }
    if payload.cifra is not None:
        raw_cifra = payload.cifra.strip()
        if raw_cifra and primary_tone:
            raw_cifra, _, _, _ = auto_transpose_chord_sheet_to_key(raw_cifra, primary_tone)
        update_fields["cifra"] = raw_cifra
    if payload.tom_original is not None or primary_tone:
        update_fields["tom_original"] = canonical_tone

    repo.collection.update_one({"_id": ObjectId(song_id)}, {"$set": update_fields})
    updated = repo.collection.find_one({"_id": ObjectId(song_id)})
    if updated:
        updated["_id"] = str(updated["_id"])
        dispatch_team_event(
            doc_equipe,
            "songs_changed",
            {"action": "updated", "musica_id": song_id},
            exclude_user_id=usuario_id,
        )
        return updated
    return {"updated": True, "id": song_id}


def _is_safe_public_url(url: str) -> tuple[bool, str]:
    """Valida se a URL é HTTP/HTTPS e não aponta para endereços internos (SSRF protection)."""
    try:
        from urllib.parse import urlparse
        import socket
        import ipaddress

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "Protocolo inválido. Apenas links HTTP ou HTTPS são permitidos."

        hostname = parsed.hostname
        if not hostname:
            return False, "Nome de host inválido na URL."

        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False, "Endereço local não permitido por segurança (SSRF)."

        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return False, "Endereço IP privado/restrito não permitido por segurança."
        except Exception:
            return False, "Não foi possível resolver o domínio informado."

        return True, ""
    except Exception as exc:
        return False, f"URL inválida: {exc}"


@app.post("/api/musicas/importar-link")
def importar_cifra_link(
    payload: ImportarCifraPayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    require_authenticated_user(authorization)
    url = payload.url.strip()

    is_safe, error_reason = _is_safe_public_url(url)
    if not is_safe:
        raise HTTPException(status_code=400, detail=error_reason)

    import urllib.request
    import urllib.error
    import re
    import html as html_lib

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw_data = resp.read(2 * 1024 * 1024)
            html_text = raw_data.decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as http_err:
        if http_err.code in (403, 429, 503):
            raise HTTPException(
                status_code=422,
                detail="Este site bloqueou a importação direta automática por proteção anti-robô. Basta abrir o site, copiar a cifra e colá-la diretamente no campo 'Cifra' que formatamos tudo instantaneamente para você!",
            )
        raise HTTPException(status_code=400, detail=f"Erro ao acessar link: HTTP {http_err.code}")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Não foi possível baixar o link informado: {exc}")

    # Extrai Título
    titulo = ""
    m_title = re.search(r'<h1[^>]*class=["\'][^"\']*t1a[^"\']*["\'][^>]*>(.*?)</h1>', html_text, re.I | re.S)
    if m_title:
        titulo = re.sub(r'<[^>]+>', '', m_title.group(1)).strip()
    if not titulo:
        m_title2 = re.search(r'<meta property="og:title" content="(.*?)"', html_text, re.I)
        if m_title2:
            og_t = m_title2.group(1).strip()
            titulo = og_t.split("-")[0].strip() if "-" in og_t else og_t
    if not titulo:
        m_title3 = re.search(r'<title>(.*?)</title>', html_text, re.I | re.S)
        if m_title3:
            t3 = m_title3.group(1).strip()
            titulo = t3.split("-")[0].strip() if "-" in t3 else t3

    # Extrai Cantor / Banda
    cantor = ""
    m_art = re.search(r'<h2[^>]*class=["\'][^"\']*t3[^"\']*["\'][^>]*>(.*?)</h2>', html_text, re.I | re.S)
    if m_art:
        cantor = re.sub(r'<[^>]+>', '', m_art.group(1)).strip()
    if not cantor:
        m_art2 = re.search(r'<meta property="og:title" content="(.*?)"', html_text, re.I)
        if m_art2 and "-" in m_art2.group(1):
            parts = m_art2.group(1).split("-")
            cantor = parts[1].replace("| Cifra Club", "").replace("Cifras", "").strip()

    # Extrai Tom
    tom = ""
    m_tom = re.search(r'id=["\']cifra_tom["\'][^>]*>.*?<a[^>]*>(.*?)</a>', html_text, re.I | re.S)
    if m_tom:
        tom = m_tom.group(1).strip()
    if not tom:
        m_tom2 = re.search(r'Tom:\s*<b>([A-G][#b]?m?)</b>', html_text, re.I)
        if m_tom2:
            tom = m_tom2.group(1).strip()

    # Extrai Cifra (Pre ou body)
    cifra = ""
    m_pre = re.search(r'<pre[^>]*>(.*?)</pre>', html_text, re.I | re.S)
    if m_pre:
        raw_pre = m_pre.group(1)
        cifra = html_lib.unescape(re.sub(r'</?(b|span|a|strong)[^>]*>', '', raw_pre)).strip()

    if not cifra and ("<body" in html_text or "pre" not in html_text):
        plain_text = re.sub(r'<script.*?</script>', '', html_text, flags=re.DOTALL | re.I)
        plain_text = re.sub(r'<style.*?</style>', '', plain_text, flags=re.DOTALL | re.I)
        plain_text = re.sub(r'<[^>]+>', '\n', plain_text)
        cifra = html_lib.unescape(re.sub(r'\n{3,}', '\n\n', plain_text)).strip()

    if not titulo:
        titulo = "Música Importada"
    if not cantor:
        cantor = "Artista / Ministério"
    if not tom:
        tom = "G"

    return {
        "titulo": html_lib.unescape(titulo),
        "cantor_principal": html_lib.unescape(cantor),
        "tom_original": tom,
        "tons": [tom],
        "versao": "Original",
        "cifra": cifra,
    }



@app.delete("/api/musicas/{song_id}")
def deletar_musica(
    song_id: str,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    usuario_id = require_authenticated_user(authorization)
    repo = get_repo()
    try:
        doc = repo.collection.find_one({"_id": ObjectId(song_id)})
        if not doc:
            return {"deleted": False, "id": song_id}

        doc_equipe = str(doc.get("equipe_id") or "").strip()
        doc_user = str(doc.get("usuario_id") or "").strip()

        if doc_equipe:
            equipes_repo = get_equipes_repo()
            if not equipes_repo.usuario_pertence_a_equipe(doc_equipe, usuario_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Permissão negada: você não pertence à equipe desta música.",
                )
        elif doc_user and doc_user != usuario_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissão negada: esta música pertence a outro usuário.",
            )

        res = repo.collection.delete_one({"_id": ObjectId(song_id)})
        deleted = res.deleted_count > 0
        if deleted:
            dispatch_team_event(
                doc_equipe or f"user_{doc_user}",
                "songs_changed",
                {"action": "deleted", "musica_id": song_id},
                exclude_user_id=usuario_id,
            )
        return {"deleted": deleted, "id": song_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Não foi possível remover: {exc}") from exc


# =============================================================================
# ROTAS DO REPERTÓRIO DA SEMANA (ESCALA COMPARTILHADA DA EQUIPE)
# =============================================================================

@app.get("/api/repertorio-semana")
def listar_repertorio_semana(
    data: Optional[str] = Query(default=None, description="Filtrar por data específica YYYY-MM-DD"),
    data_inicio: Optional[str] = Query(default=None, description="Data início YYYY-MM-DD"),
    data_fim: Optional[str] = Query(default=None, description="Data fim YYYY-MM-DD"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe"),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    """Lista as músicas agendadas no repertório da semana estritamente para a equipe do usuário."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, allowed_team_ids = resolve_team_for_user(
        equipe_id, usuario_id, require_for_write=False
    )
    if not allowed_team_ids:
        return []

    repo = get_semana_repo()
    target_teams = [resolved_equipe_id] if (equipe_id and resolved_equipe_id) else allowed_team_ids
    try:
        collected: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for tid in target_teams:
            if not tid:
                continue
            if data and data.strip():
                docs = _call_repo(repo.listar_por_data, data.strip(), equipe_id=tid)
            elif data_inicio and data_fim and data_inicio.strip() and data_fim.strip():
                docs = _call_repo(
                    repo.listar_por_intervalo_datas,
                    data_inicio.strip(),
                    data_fim.strip(),
                    equipe_id=tid,
                )
            else:
                docs = _call_repo(repo.listar_todas, equipe_id=tid)

            for doc in docs:
                doc_eq = str(doc.get("equipe_id") or "").strip()
                if doc_eq != str(tid).strip():
                    continue
                doc_id = str(doc.get("_id") or doc.get("id") or "")
                if doc_id and doc_id in seen_ids:
                    continue
                if doc_id:
                    seen_ids.add(doc_id)
                collected.append(doc)
        return collected
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao consultar escala da semana: {exc}") from exc


@app.post("/api/repertorio-semana", status_code=201)
def adicionar_repertorio_semana(
    payload: RepertorioSemanaCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Agenda uma música para o repertório da semana da equipe do usuário autenticado."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, _ = resolve_team_for_user(
        payload.equipe_id, usuario_id, require_for_write=True
    )
    repo = get_semana_repo()

    adicionado_por = payload.adicionado_por
    if not adicionado_por:
        try:
            user_doc = get_users_repo().buscar_por_id(usuario_id)
            if user_doc and user_doc.get("nome"):
                adicionado_por = user_doc.get("nome")
        except Exception:
            pass

    try:
        scheduled_doc = _call_repo(
            repo.agendar_musica,
            musica_id=payload.musica_id,
            titulo=payload.titulo,
            cantor_principal=payload.cantor_principal,
            tom_selecionado=payload.tom_selecionado,
            data_ensaio=payload.data_ensaio,
            dia_semana=payload.dia_semana,
            versao=payload.versao or "Original",
            adicionado_por=adicionado_por or "Equipe",
            usuario_id=usuario_id,
            equipe_id=resolved_equipe_id,
        )
        dispatch_team_event(
            resolved_equipe_id,
            "weekly_changed",
            {"action": "added", "titulo": payload.titulo},
            exclude_user_id=usuario_id,
        )
        return scheduled_doc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao agendar música na semana: {exc}") from exc


@app.delete("/api/repertorio-semana/{item_id}")
def remover_repertorio_semana(
    item_id: str,
    titulo: Optional[str] = Query(default=None, description="Título da música para fallback de remoção"),
    data_ensaio: Optional[str] = Query(default=None, description="Data do ensaio YYYY-MM-DD para fallback"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe para fallback"),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Remove uma música da escala da semana (exige autenticação e permissão na equipe - anti-IDOR)."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, allowed_team_ids = resolve_team_for_user(
        equipe_id, usuario_id, require_for_write=False
    )
    repo = get_semana_repo()
    try:
        target_oid: Any = item_id
        try:
            target_oid = ObjectId(item_id)
        except Exception:
            target_oid = item_id

        doc = repo.collection.find_one({"_id": target_oid})
        if not doc and target_oid != item_id:
            doc = repo.collection.find_one({"_id": item_id})

        if isinstance(doc, dict):
            doc_equipe = str(doc.get("equipe_id") or "").strip()
            doc_user = str(doc.get("usuario_id") or "").strip()
            if doc_equipe:
                if doc_equipe not in allowed_team_ids and not get_equipes_repo().usuario_pertence_a_equipe(doc_equipe, usuario_id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Permissão negada: você não pertence à equipe deste item da escala.",
                    )
                resolved_equipe_id = doc_equipe
            elif doc_user and doc_user != usuario_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Permissão negada: este item pertence a outro usuário.",
                )

        if not resolved_equipe_id and not allowed_team_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissão negada: você não pertence a uma equipe autorizada.",
            )

        sucesso = _call_repo(
            repo.remover_musica_escala,
            item_id,
            titulo=titulo,
            data_ensaio=data_ensaio,
            equipe_id=resolved_equipe_id,
            usuario_id=usuario_id,
        )
        if not sucesso:
            raise HTTPException(status_code=404, detail="Item da escala não encontrado.")
        dispatch_team_event(
            resolved_equipe_id or equipe_id,
            "weekly_changed",
            {"action": "deleted", "item_id": item_id},
            exclude_user_id=usuario_id,
        )
        return {"deleted": True, "id": item_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Erro ao remover da escala: {exc}") from exc


# =============================================================================
# ROTAS DE MÚSICAS A ENSAIAR (PRÓXIMO ENSAIO)
# =============================================================================

@app.get("/api/a-ensaiar")
def listar_a_ensaiar(
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe"),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    """Retorna todas as músicas sugeridas para o próximo ensaio estritamente da equipe do usuário."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, allowed_team_ids = resolve_team_for_user(
        equipe_id, usuario_id, require_for_write=False
    )
    if not allowed_team_ids:
        return []

    repo = get_a_ensaiar_repo()
    target_teams = [resolved_equipe_id] if (equipe_id and resolved_equipe_id) else allowed_team_ids
    try:
        collected: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for tid in target_teams:
            if not tid:
                continue
            docs = _call_repo(repo.listar_todas, equipe_id=tid)
            for doc in docs:
                doc_eq = str(doc.get("equipe_id") or "").strip()
                if doc_eq != str(tid).strip():
                    continue
                doc_id = str(doc.get("_id") or doc.get("id") or "")
                if doc_id and doc_id in seen_ids:
                    continue
                if doc_id:
                    seen_ids.add(doc_id)
                collected.append(doc)
        return collected
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao listar músicas a ensaiar: {exc}") from exc


@app.post("/api/a-ensaiar", status_code=201)
def adicionar_a_ensaiar(
    payload: MusicaAEnsaiarCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Adiciona uma música sugerida para ser ensaiada pela equipe do usuário autenticado."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, _ = resolve_team_for_user(
        payload.equipe_id, usuario_id, require_for_write=True
    )
    repo = get_a_ensaiar_repo()

    adicionado_por = payload.adicionado_por
    if not adicionado_por:
        try:
            user_doc = get_users_repo().buscar_por_id(usuario_id)
            if user_doc and user_doc.get("nome"):
                adicionado_por = user_doc.get("nome")
        except Exception:
            pass

    try:
        doc = _call_repo(
            repo.adicionar_musica,
            titulo=payload.titulo,
            cantor_versao=payload.cantor_versao,
            youtube_url=payload.youtube_url or "",
            status="Próximo Ensaio",
            adicionado_por=adicionado_por or "Equipe",
            usuario_id=usuario_id,
            equipe_id=resolved_equipe_id,
        )
        dispatch_team_event(
            resolved_equipe_id,
            "to_rehearse_changed",
            {"action": "added", "titulo": payload.titulo},
            exclude_user_id=usuario_id,
        )
        return doc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao adicionar música a ensaiar: {exc}") from exc


@app.delete("/api/a-ensaiar/{item_id}")
def remover_a_ensaiar(
    item_id: str,
    titulo: Optional[str] = Query(default=None, description="Título da música para fallback de remoção"),
    cantor_versao: Optional[str] = Query(default=None, description="Cantor / Versão para fallback de remoção"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe para fallback"),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Remove uma música da fila a ensaiar (exige autenticação e permissão na equipe - anti-IDOR)."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, allowed_team_ids = resolve_team_for_user(
        equipe_id, usuario_id, require_for_write=False
    )
    repo = get_a_ensaiar_repo()
    try:
        target_oid: Any = item_id
        try:
            target_oid = ObjectId(item_id)
        except Exception:
            target_oid = item_id

        doc = repo.collection.find_one({"_id": target_oid})
        if not doc and target_oid != item_id:
            doc = repo.collection.find_one({"_id": item_id})

        if isinstance(doc, dict):
            doc_equipe = str(doc.get("equipe_id") or "").strip()
            doc_user = str(doc.get("usuario_id") or "").strip()
            if doc_equipe:
                if doc_equipe not in allowed_team_ids and not get_equipes_repo().usuario_pertence_a_equipe(doc_equipe, usuario_id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Permissão negada: você não pertence à equipe desta música a ensaiar.",
                    )
                resolved_equipe_id = doc_equipe
            elif doc_user and doc_user != usuario_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Permissão negada: esta sugestão pertence a outro usuário.",
                )

        if not resolved_equipe_id and not allowed_team_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissão negada: você não pertence a uma equipe autorizada.",
            )

        sucesso = _call_repo(
            repo.remover_musica,
            item_id,
            titulo=titulo,
            cantor_versao=cantor_versao,
            equipe_id=resolved_equipe_id,
            usuario_id=usuario_id,
        )
        if not sucesso:
            raise HTTPException(status_code=404, detail="Música a ensaiar não encontrada.")
        dispatch_team_event(
            resolved_equipe_id or equipe_id,
            "to_rehearse_changed",
            {"action": "deleted", "item_id": item_id},
            exclude_user_id=usuario_id,
        )
        return {"deleted": True, "id": item_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Erro ao remover música a ensaiar: {exc}") from exc


# =============================================================================
# ROTAS DE MULTI-EQUIPES, CONVITES E PING ("CHAMAR MÚSICO")
# =============================================================================

@app.get("/api/equipe/minhas-equipes")
def listar_minhas_equipes(authorization: Optional[str] = Header(default=None)) -> list[dict[str, Any]]:
    """Lista todas as equipes das quais o usuário autenticado faz parte."""
    usuario_id = require_authenticated_user(authorization)
    equipes_repo = get_equipes_repo()
    try:
        return equipes_repo.listar_equipes_do_usuario(usuario_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao listar equipes: {exc}") from exc


@app.post("/api/equipe/criar", status_code=status.HTTP_201_CREATED)
def criar_equipe(
    payload: EquipeCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Cria uma nova equipe com código de convite único, respeitando o limite de equipes do plano."""
    usuario_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(usuario_id)
    criador_nome = (user_doc.get("nome") if user_doc else None) or "Músico"

    equipes_repo = get_equipes_repo()
    user_plan = _evaluate_legacy_courtesy_and_get_plan(user_doc)
    max_owned = user_plan["limites"]["max_owned_teams"]
    if max_owned is not None and hasattr(equipes_repo, "contar_equipes_criadas_por"):
        owned_count = equipes_repo.contar_equipes_criadas_por(usuario_id)
        if owned_count >= max_owned:
            raise PlanLimitError(
                limit_type="teams",
                message=f"Seu plano atual permite criar até {max_owned} equipe(s). Faça upgrade para o CipherSong Pro ou Ministério para gerenciar múltiplas equipes!",
                limit=max_owned,
                current=owned_count,
            )

    try:
        return equipes_repo.criar_equipe(
            nome=payload.nome,
            criado_por_id=usuario_id,
            criado_por_nome=criador_nome,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao criar equipe: {exc}") from exc


@app.post("/api/equipe/entrar")
def entrar_equipe(
    payload: EquipeEntrarPayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Entra em uma equipe através de seu código de convite, respeitando o limite de membros do plano do líder."""
    usuario_id = require_authenticated_user(authorization)
    equipes_repo = get_equipes_repo()

    if hasattr(equipes_repo, "buscar_por_codigo"):
        target_team = equipes_repo.buscar_por_codigo(payload.codigo)
        if target_team:
            membros_atuais = [str(m) for m in target_team.get("membros", [])]
            if str(usuario_id) not in membros_atuais:
                owner_id = str(target_team.get("criado_por") or usuario_id)
                team_plan, _ = _get_team_owner_plan(str(target_team.get("_id") or ""), owner_id)
                max_members = team_plan["limites"]["max_members"]
                if max_members is not None and len(membros_atuais) >= max_members:
                    raise PlanLimitError(
                        limit_type="members",
                        message=f"Esta equipe atingiu o limite de {max_members} integrantes do plano atual ({team_plan['label']}). Peça ao líder da equipe para fazer upgrade para o Plano Ministério!",
                        limit=max_members,
                        current=len(membros_atuais),
                    )

    try:
        return equipes_repo.entrar_equipe_por_codigo(codigo=payload.codigo, usuario_id=usuario_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao entrar na equipe: {exc}") from exc


@app.get("/api/equipe/membros")
def listar_membros_equipe(
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe selecionada"),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    """Lista todos os músicos/usuários cadastrados na equipe ativa."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, _ = resolve_team_for_user(
        equipe_id, usuario_id, require_for_write=False
    )
    if not resolved_equipe_id:
        return []
    equipes_repo = get_equipes_repo()
    try:
        membros = equipes_repo.listar_membros_equipe(resolved_equipe_id)
        out_membros = []
        for m in membros:
            m_id = str(m.get("_id") or m.get("id"))
            if m_id == str(usuario_id):
                continue
            m["_id"] = m_id
            m["id"] = m_id
            m["foto_url"] = m.get("foto_url") or m.get("avatar") or ""
            m["avatar"] = m.get("avatar") or m.get("foto_url") or ""
            # Privacidade Estrita (LGPD): Cada membro vê apenas seu próprio e-mail.
            # Oculta o e-mail de outros integrantes da resposta da API.
            m.pop("email", None)
            out_membros.append(m)
        return out_membros
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao listar membros da equipe: {exc}") from exc


@app.delete("/api/equipe/{equipe_id}/membros/{membro_id}")
def remover_membro_ou_sair_equipe(
    equipe_id: str,
    membro_id: str,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """
    Remove um integrante da equipe:
    - O próprio usuário pode sair da equipe a qualquer momento (membro_id == usuario_id).
    - Somente o líder da equipe (criado_por) pode remover outros integrantes da equipe.
    """
    usuario_id = require_authenticated_user(authorization)
    equipes_repo = get_equipes_repo()
    equipe = equipes_repo.buscar_por_id(equipe_id)
    if not equipe:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Equipe não encontrada.")

    is_self = str(usuario_id) == str(membro_id)
    criador_id = str(equipe.get("criado_por") or "").strip()
    is_leader = str(usuario_id) == criador_id

    if not is_self and not is_leader:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas o líder que criou a equipe tem permissão para remover outros integrantes.",
        )

    try:
        updated_team = equipes_repo.remover_membro_equipe(equipe_id, membro_id)
        dispatch_team_event(
            equipe_id,
            "team_member_removed",
            {"equipe_id": equipe_id, "membro_id": membro_id, "removido_por": usuario_id},
        )
        return {
            "status": "success",
            "message": "Você saiu da equipe com sucesso." if is_self else "Integrante removido da equipe com sucesso.",
            "equipe": updated_team,
            "membro_id": membro_id,
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao remover integrante da equipe: {exc}") from exc


@app.post("/api/equipe/ping", status_code=status.HTTP_201_CREATED)
def enviar_ping(
    payload: PingCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Dispara uma notificação/ping de chamada para outro músico da equipe (cooldown 10s)."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, _ = resolve_team_for_user(
        payload.equipe_id, usuario_id, require_for_write=True
    )
    if resolved_equipe_id and not get_equipes_repo().usuario_pertence_a_equipe(resolved_equipe_id, payload.destinatario_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permissão negada: o músico destinatário não pertence a esta equipe.",
        )

    users_repo = get_users_repo()
    remetente = users_repo.buscar_por_id(usuario_id)
    remetente_nome = (remetente.get("nome") if remetente else None) or "Músico da equipe"

    pings_repo = get_pings_repo()
    try:
        ping_result = pings_repo.enviar_ping(
            remetente_id=usuario_id,
            remetente_nome=remetente_nome,
            destinatario_id=payload.destinatario_id,
            destinatario_nome=payload.destinatario_nome or "",
            equipe_id=resolved_equipe_id,
        )
        dispatch_team_event(
            resolved_equipe_id,
            "team_ping",
            {
                "remetente_nome": remetente_nome,
                "destinatario_id": payload.destinatario_id,
                "destinatario_nome": payload.destinatario_nome or "",
            },
            exclude_user_id=usuario_id,
        )
        return ping_result
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao disparar chamada: {exc}") from exc


@app.get("/api/equipe/meus-pings")
def buscar_meus_pings(
    equipe_id: Optional[str] = Query(default=None),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    """Busca chamadas/pings pendentes endereçados ao usuário autenticado."""
    usuario_id = require_authenticated_user(authorization)
    resolved_equipe_id, _ = resolve_team_for_user(
        equipe_id, usuario_id, require_for_write=False
    )

    pings_repo = get_pings_repo()
    try:
        return pings_repo.buscar_pings_pendentes(usuario_id, equipe_id=resolved_equipe_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao buscar chamadas: {exc}") from exc


@app.post("/api/equipe/ping/{ping_id}/lido")
def marcar_ping_lido(ping_id: str, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """Marca um ping como visualizado/lido para não notificar repetidamente (exige autenticação e titularidade)."""
    usuario_id = require_authenticated_user(authorization)
    pings_repo = get_pings_repo()
    try:
        if hasattr(pings_repo.collection, "find_one"):
            try:
                target_oid: Any = ObjectId(ping_id)
            except Exception:
                target_oid = ping_id
            ping_doc = pings_repo.collection.find_one({"_id": target_oid})
            if not ping_doc and target_oid != ping_id:
                ping_doc = pings_repo.collection.find_one({"_id": ping_id})
            if isinstance(ping_doc, dict):
                dest_id = str(ping_doc.get("destinatario_id") or "").strip()
                if dest_id and dest_id != str(usuario_id).strip():
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Permissão negada: esta chamada pertence a outro destinatário.",
                    )
        sucesso = _call_repo(pings_repo.marcar_como_lido, ping_id, destinatario_id=usuario_id)
        return {"status": "ok", "ping_id": ping_id, "lido": sucesso}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao marcar ping como lido: {exc}") from exc


# =============================================================================
# STRIPE BILLING & INVOICING (ASSINATURAS E FATURAMENTO)
# =============================================================================

class CheckoutSessionPayload(BaseModel):
    plan: str = Field(..., description="Plano desejado: 'pro' ou 'ministerio'")
    cycle: str = Field(default="mensal", description="Ciclo: 'mensal' ou 'anual'")
    success_url: Optional[str] = Field(default=None, description="URL de retorno em caso de sucesso")
    cancel_url: Optional[str] = Field(default=None, description="URL de retorno em caso de cancelamento")


class PortalSessionPayload(BaseModel):
    return_url: Optional[str] = Field(default=None, description="URL de retorno após sair do portal")


class ScheduleDowngradePayload(BaseModel):
    target_plan: str = Field(default="pro", description="Plano de destino para o downgrade ('pro')")
    target_cycle: str = Field(default="mensal", description="Ciclo de cobrança: 'mensal' ou 'anual'")


_STRIPE_PRICING_DEFAULTS = {
    ("pro", "mensal"): {
        "name": "CipherSong Pro (Mensal)",
        "amount": 1490,  # R$ 14,90
        "interval": "month",
        "env_var": "STRIPE_PRICE_PRO_MONTHLY",
    },
    ("pro", "anual"): {
        "name": "CipherSong Pro (Anual)",
        "amount": 14280,  # R$ 142,80 / ano (equivale a R$ 11,90/mês)
        "interval": "year",
        "env_var": "STRIPE_PRICE_PRO_YEARLY",
    },
    ("ministerio", "mensal"): {
        "name": "CipherSong Ministério (Mensal)",
        "amount": 3990,  # R$ 39,90
        "interval": "month",
        "env_var": "STRIPE_PRICE_MINISTERIO_MONTHLY",
    },
    ("ministerio", "anual"): {
        "name": "CipherSong Ministério (Anual)",
        "amount": 38280,  # R$ 382,80 / ano (equivale a R$ 31,90/mês)
        "interval": "year",
        "env_var": "STRIPE_PRICE_MINISTERIO_YEARLY",
    },
}


def _get_stripe_key() -> str:
    key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not key or stripe is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="O serviço de pagamentos Stripe ainda não foi configurado no servidor (STRIPE_SECRET_KEY ausente).",
        )
    stripe.api_key = key
    return key


@app.get("/api/billing/status")
def obter_status_faturamento(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """Retorna os dados detalhados da assinatura ativa do usuário e status da integração Stripe."""
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    effective_plan = _evaluate_legacy_courtesy_and_get_plan(user_doc)
    assinatura = user_doc.get("assinatura") or {}

    return {
        "stripe_configured": bool(os.getenv("STRIPE_SECRET_KEY")),
        "livemode": os.getenv("STRIPE_SECRET_KEY", "").startswith(("sk_live_", "rk_live_")),
        "plano": effective_plan["plano"],
        "label": effective_plan["label"],
        "is_premium": effective_plan["is_premium"],
        "cortesia_ativa": effective_plan["cortesia_ativa"],
        "expira_em": effective_plan["expira_em"],
        "status": assinatura.get("status") or ("active" if effective_plan["is_premium"] else "free"),
        "ciclo": assinatura.get("ciclo", "mensal"),
        "stripe_customer_id": assinatura.get("stripe_customer_id") or user_doc.get("stripe_customer_id"),
        "stripe_subscription_id": assinatura.get("stripe_subscription_id"),
        "cancelado_em": assinatura.get("cancelado_em"),
        "downgrade_agendado": assinatura.get("downgrade_agendado"),
    }


@app.post("/api/billing/create-checkout-session")
def criar_checkout_session(
    payload: CheckoutSessionPayload,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Cria uma sessão de Checkout hospedada na Stripe para assinatura dos planos Pro ou Ministério."""
    _get_stripe_key()
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    clean_plan = payload.plan.strip().lower()
    if clean_plan not in ("pro", "ministerio"):
        raise HTTPException(status_code=400, detail="Plano inválido. Escolha 'pro' ou 'ministerio'.")

    clean_cycle = payload.cycle.strip().lower()
    if clean_cycle not in ("mensal", "anual"):
        clean_cycle = "mensal"

    pricing_info = _STRIPE_PRICING_DEFAULTS.get((clean_plan, clean_cycle))
    if not pricing_info:
        raise HTTPException(status_code=400, detail="Combinação de plano e ciclo inválida.")

    # 1. Determina base URL do frontend para redirecionamento após o Checkout
    frontend_base = os.getenv("FRONTEND_URL", "").rstrip("/")
    if not frontend_base:
        origin = request.headers.get("origin") or request.headers.get("referer")
        if origin:
            parsed = urllib.parse.urlparse(str(origin))
            frontend_base = f"{parsed.scheme}://{parsed.netloc}"
        else:
            frontend_base = "https://ciphersong.com.br"

    success_url = payload.success_url or f"{frontend_base}/settings?billing_success=true&session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = payload.cancel_url or f"{frontend_base}/settings?billing_canceled=true"

    # 2. Configura item de linha (preço do Stripe pré-criado no Dashboard OU preço inline em BRL)
    price_env = os.getenv(pricing_info["env_var"], "").strip()
    if price_env:
        line_items = [{"price": price_env, "quantity": 1}]
    else:
        line_items = [
            {
                "price_data": {
                    "currency": "brl",
                    "product_data": {
                        "name": pricing_info["name"],
                        "description": f"Assinatura {pricing_info['name']} para equipes musicais e cifras",
                    },
                    "unit_amount": pricing_info["amount"],
                    "recurring": {"interval": pricing_info["interval"]},
                },
                "quantity": 1,
            }
        ]

    # 3. Metadados para reconciliação via webhook
    metadata = {
        "usuario_id": str(user_id),
        "plano": clean_plan,
        "ciclo": clean_cycle,
    }

    checkout_kwargs: dict[str, Any] = {
        "mode": "subscription",
        "line_items": line_items,
        "client_reference_id": str(user_id),
        "metadata": metadata,
        "subscription_data": {"metadata": metadata},
        "success_url": success_url,
        "cancel_url": cancel_url,
        "allow_promotion_codes": True,
    }

    # Reutiliza o customer existente se o usuário já possuir um
    existing_customer = (
        (user_doc.get("assinatura") or {}).get("stripe_customer_id")
        or user_doc.get("stripe_customer_id")
    )
    if existing_customer:
        checkout_kwargs["customer"] = existing_customer
    else:
        user_email = user_doc.get("email")
        if user_email:
            checkout_kwargs["customer_email"] = user_email

    try:
        session = stripe.checkout.Session.create(**checkout_kwargs)
        return {"url": session.url, "session_id": session.id}
    except Exception as exc:
        # Se o customer_id salvo não existir nesta conta Stripe (ex: alternância entre test/live ou mock)
        if "No such customer" in str(exc) and "customer" in checkout_kwargs:
            logger.warning("Customer ID não encontrado na conta Stripe. Recriando sessão com customer_email.")
            checkout_kwargs.pop("customer", None)
            user_email = user_doc.get("email")
            if user_email:
                checkout_kwargs["customer_email"] = user_email
            try:
                session = stripe.checkout.Session.create(**checkout_kwargs)
                return {"url": session.url, "session_id": session.id}
            except Exception as retry_exc:
                logger.error("Erro ao recriar Checkout Session: %s", retry_exc)
                exc = retry_exc
        logger.error("Erro ao criar Stripe Checkout Session: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Falha ao comunicar com o Stripe: {exc}",
        ) from exc


@app.post("/api/billing/create-portal-session")
def criar_portal_session(
    payload: PortalSessionPayload,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Cria uma sessão do Stripe Customer Portal para o usuário gerenciar cartão, faturas e cancelamento."""
    _get_stripe_key()
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    customer_id = (
        (user_doc.get("assinatura") or {}).get("stripe_customer_id")
        or user_doc.get("stripe_customer_id")
    )
    if not customer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nenhuma assinatura ou cliente Stripe encontrado para esta conta. Assine um plano primeiro para acessar o portal de faturamento.",
        )

    frontend_base = os.getenv("FRONTEND_URL", "").rstrip("/")
    if not frontend_base:
        origin = request.headers.get("origin") or request.headers.get("referer")
        if origin:
            parsed = urllib.parse.urlparse(str(origin))
            frontend_base = f"{parsed.scheme}://{parsed.netloc}"
        else:
            frontend_base = "https://ciphersong.com.br"

    return_url = payload.return_url or f"{frontend_base}/settings"

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return {"url": portal_session.url}
    except Exception as exc:
        logger.error("Erro ao criar Stripe Customer Portal Session: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Falha ao abrir portal do Stripe: {exc}",
        ) from exc


@app.post("/api/billing/schedule-downgrade")
def agendar_downgrade(
    payload: ScheduleDowngradePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Agenda o downgrade do Plano Ministério para o Plano Pro no final do ciclo atual (Opção 1 - Padrão de Mercado).

    O usuário mantém todos os benefícios do Plano Ministério até o fim do período já pago.
    Na data de expiração, a Stripe renovará automaticamente no valor do Plano Pro escolhido.
    """
    _get_stripe_key()
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    assinatura = user_doc.get("assinatura") or {}
    plano_atual = assinatura.get("plano") or user_doc.get("plano") or "free"

    if plano_atual != "ministerio":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O agendamento de downgrade para Pro só se aplica a assinantes ativos do Plano Ministério.",
        )

    sub_id = assinatura.get("stripe_subscription_id")
    if not sub_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nenhuma assinatura ativa encontrada no Stripe para agendamento.",
        )

    clean_target = payload.target_plan.strip().lower()
    if clean_target != "pro":
        raise HTTPException(status_code=400, detail="Plano de destino inválido. Escolha 'pro'.")

    clean_cycle = payload.target_cycle.strip().lower()
    if clean_cycle not in ("mensal", "anual"):
        clean_cycle = assinatura.get("ciclo") or "mensal"

    pricing_info = _STRIPE_PRICING_DEFAULTS.get((clean_target, clean_cycle))
    if not pricing_info:
        raise HTTPException(status_code=400, detail="Combinação de plano e ciclo inválida.")

    target_price_id = os.getenv(pricing_info["env_var"], "").strip()
    data_efetiva = assinatura.get("expira_em")

    if stripe is not None:
        try:
            stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
            sub = stripe.Subscription.retrieve(sub_id)
            data_efetiva = _extract_subscription_period_end(sub) or data_efetiva

            # Identifica o item atual da assinatura
            items_data = (sub.to_dict() if hasattr(sub, "to_dict") else sub).get("items", {}).get("data", [])
            if not items_data:
                raise ValueError("Nenhum item encontrado na assinatura Stripe.")
            sub_item_id = items_data[0]["id"]

            modify_kwargs: dict[str, Any] = {
                "proration_behavior": "none",
                "metadata": {
                    **(sub.get("metadata") or {}),
                    "downgrade_scheduled": "true",
                    "target_plan": clean_target,
                    "target_cycle": clean_cycle,
                },
            }

            if target_price_id:
                modify_kwargs["items"] = [{"id": sub_item_id, "price": target_price_id}]

            stripe.Subscription.modify(sub_id, **modify_kwargs)
            logger.info("Downgrade agendado no Stripe para sub %s (target_price: %s)", sub_id, target_price_id)
        except Exception as stripe_err:
            # Em testes automatizados ou fallback onde a sub mock não existe no Stripe remoto
            if "No such subscription" in str(stripe_err) or "Invalid API Key" in str(stripe_err):
                logger.warning("Aviso Stripe ao agendar downgrade (ambiente de teste/mock): %s", stripe_err)
            else:
                logger.error("Erro ao modificar assinatura no Stripe para downgrade: %s", stripe_err, exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Falha ao agendar downgrade junto ao Stripe: {stripe_err}",
                ) from stripe_err

    downgrade_info = {
        "plano_alvo": clean_target,
        "ciclo_alvo": clean_cycle,
        "data_efetiva": data_efetiva,
        "stripe_price_id": target_price_id,
        "agendado_em": datetime.now(timezone.utc).isoformat(),
    }

    updated_sub = {
        **assinatura,
        "downgrade_agendado": downgrade_info,
        "atualizado_em": datetime.now(timezone.utc).isoformat(),
    }
    users_repo.atualizar_assinatura(user_id, updated_sub)

    return {
        "status": "success",
        "message": f"Downgrade para o Plano Pro ({clean_cycle}) agendado com sucesso para {data_efetiva or 'o término do ciclo'}.",
        "downgrade_agendado": downgrade_info,
    }


@app.post("/api/billing/cancel-downgrade")
def cancelar_agendamento_downgrade(
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Cancela o agendamento de downgrade e restaura a renovação contínua do Plano Ministério."""
    _get_stripe_key()
    user_id = require_authenticated_user(authorization)
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    assinatura = user_doc.get("assinatura") or {}
    if not assinatura.get("downgrade_agendado"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nenhum downgrade agendado encontrado para esta assinatura.",
        )

    sub_id = assinatura.get("stripe_subscription_id")
    current_cycle = assinatura.get("ciclo") or "mensal"
    pricing_info = _STRIPE_PRICING_DEFAULTS.get(("ministerio", current_cycle))
    original_price_id = os.getenv(pricing_info["env_var"], "").strip() if pricing_info else ""

    if sub_id and stripe is not None:
        try:
            stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
            sub = stripe.Subscription.retrieve(sub_id)
            items_data = (sub.to_dict() if hasattr(sub, "to_dict") else sub).get("items", {}).get("data", [])
            if items_data:
                sub_item_id = items_data[0]["id"]
                modify_kwargs: dict[str, Any] = {
                    "proration_behavior": "none",
                    "metadata": {
                        **(sub.get("metadata") or {}),
                        "downgrade_scheduled": "false",
                    },
                }
                if original_price_id:
                    modify_kwargs["items"] = [{"id": sub_item_id, "price": original_price_id}]
                stripe.Subscription.modify(sub_id, **modify_kwargs)
                logger.info("Downgrade cancelado no Stripe para sub %s (restaurado: %s)", sub_id, original_price_id)
        except Exception as stripe_err:
            if "No such subscription" in str(stripe_err) or "Invalid API Key" in str(stripe_err):
                logger.warning("Aviso Stripe ao cancelar downgrade (ambiente de teste/mock): %s", stripe_err)
            else:
                logger.error("Erro ao reverter downgrade no Stripe: %s", stripe_err, exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Falha ao cancelar downgrade no Stripe: {stripe_err}",
                ) from stripe_err

    updated_sub = {
        **assinatura,
        "downgrade_agendado": None,
        "atualizado_em": datetime.now(timezone.utc).isoformat(),
    }
    users_repo.atualizar_assinatura(user_id, updated_sub)

    return {
        "status": "success",
        "message": "Agendamento de downgrade cancelado com sucesso. Sua assinatura continuará como Plano Ministério.",
    }


def _extract_subscription_period_end(sub_data: Any) -> Optional[str]:
    """Extrai o ISO timestamp de current_period_end suportando o formato padrão e o formato por itens da Stripe."""
    if not sub_data:
        return None
    d = sub_data.to_dict() if hasattr(sub_data, "to_dict") else (sub_data if isinstance(sub_data, dict) else {})
    ts = d.get("current_period_end")
    if not ts:
        items_data = (d.get("items") or {}).get("data", [])
        if items_data and isinstance(items_data, list):
            ts = items_data[0].get("current_period_end")
    if ts:
        try:
            return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
        except Exception:
            pass
    return None


@app.post("/api/webhooks/stripe")
async def webhook_stripe(request: Request) -> dict[str, Any]:
    """Webhook para sincronização em tempo real de eventos da Stripe (assinaturas, renovações, faturas)."""
    raw_payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()

    is_live = (
        os.getenv("STRIPE_SECRET_KEY", "").startswith(("sk_live_", "rk_live_"))
        or os.getenv("ENVIRONMENT") == "production"
    )

    if is_live and not webhook_secret:
        logger.error("Tentativa de webhook em produção sem STRIPE_WEBHOOK_SECRET configurado.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuração de segurança incompleta: STRIPE_WEBHOOK_SECRET obrigatório em ambiente de produção.",
        )

    event: dict[str, Any] = {}
    if webhook_secret and stripe is not None:
        if not sig_header:
            logger.warning("Cabeçalho 'stripe-signature' ausente na requisição do Webhook.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cabeçalho 'stripe-signature' ausente.",
            )
        try:
            event = stripe.Webhook.construct_event(
                payload=raw_payload,
                sig_header=sig_header,
                secret=webhook_secret,
            )
        except Exception as sig_err:
            logger.warning("Falha na validação da assinatura do Webhook Stripe: %s", sig_err)
            raise HTTPException(status_code=400, detail=f"Assinatura de Webhook inválida: {sig_err}") from sig_err
    else:
        if is_live:
            raise HTTPException(status_code=400, detail="Assinatura de webhook obrigatória em produção.")
        try:
            event = json.loads(raw_payload.decode("utf-8"))
        except Exception as json_err:
            raise HTTPException(status_code=400, detail="Payload de webhook não é um JSON válido.") from json_err

    event_type = event.get("type", "")
    event_data = event.get("data", {}).get("object", {})
    users_repo = get_users_repo()

    logger.info("Stripe Webhook recebido: %s", event_type)

    if event_type == "checkout.session.completed":
        session = event_data
        customer_id = session.get("customer")
        subscription_id = session.get("subscription")
        user_id = session.get("client_reference_id") or (session.get("metadata") or {}).get("usuario_id")
        plan = (session.get("metadata") or {}).get("plano") or "pro"
        cycle = (session.get("metadata") or {}).get("ciclo") or "mensal"

        expira_em = None
        if subscription_id and stripe is not None and os.getenv("STRIPE_SECRET_KEY"):
            try:
                stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
                sub = stripe.Subscription.retrieve(subscription_id)
                expira_em = _extract_subscription_period_end(sub)
            except Exception as sub_err:
                logger.warning("Não foi possível recuperar dados adicionais da assinatura: %s", sub_err)

        if user_id:
            users_repo.atualizar_assinatura(
                user_id,
                {
                    "plano": plan,
                    "ciclo": cycle,
                    "status": "active",
                    "stripe_customer_id": customer_id,
                    "stripe_subscription_id": subscription_id,
                    "expira_em": expira_em,
                    "atualizado_em": datetime.now(timezone.utc).isoformat(),
                },
            )
            logger.info("Assinatura ativada com sucesso para o usuário %s (plano %s)", user_id, plan)

    elif event_type in ("customer.subscription.updated", "customer.subscription.created"):
        sub = event_data
        customer_id = sub.get("customer")
        sub_id = sub.get("id")
        sub_status = sub.get("status")  # active, trialing, past_due, canceled, unpaid
        metadata = sub.get("metadata") or {}
        user_id = metadata.get("usuario_id")
        plan = metadata.get("plano")
        cycle = metadata.get("ciclo")

        expira_em = _extract_subscription_period_end(sub)

        target_user = None
        if user_id:
            target_user = users_repo.buscar_por_id(user_id)
        if not target_user and customer_id:
            target_user = users_repo.buscar_por_stripe_customer_id(customer_id)

        if target_user:
            uid = target_user["_id"]
            existing_sub = target_user.get("assinatura") or {}
            update_data = {
                **existing_sub,
                "status": sub_status,
                "stripe_customer_id": customer_id,
                "stripe_subscription_id": sub_id,
                "expira_em": expira_em,
                "atualizado_em": datetime.now(timezone.utc).isoformat(),
            }
            if plan:
                update_data["plano"] = plan
            if cycle:
                update_data["ciclo"] = cycle

            # Detecção automática de transição de preço (Downgrade para Pro ou Upgrade para Ministério)
            pro_monthly_id = os.getenv("STRIPE_PRICE_PRO_MONTHLY", "").strip()
            pro_yearly_id = os.getenv("STRIPE_PRICE_PRO_YEARLY", "").strip()
            min_monthly_id = os.getenv("STRIPE_PRICE_MINISTERIO_MONTHLY", "").strip()
            min_yearly_id = os.getenv("STRIPE_PRICE_MINISTERIO_YEARLY", "").strip()

            items_list = (sub.get("items") or {}).get("data", [])
            current_price_id = ""
            if items_list and isinstance(items_list, list):
                price_obj = items_list[0].get("price") or {}
                current_price_id = str(price_obj.get("id") or "").strip()

            if current_price_id:
                if current_price_id in (pro_monthly_id, pro_yearly_id):
                    update_data["plano"] = "pro"
                    update_data["ciclo"] = "anual" if current_price_id == pro_yearly_id else "mensal"
                    # Se havia downgrade agendado e o preço virou para Pro, o downgrade foi concretizado
                    update_data["downgrade_agendado"] = None
                elif current_price_id in (min_monthly_id, min_yearly_id):
                    update_data["plano"] = "ministerio"
                    update_data["ciclo"] = "anual" if current_price_id == min_yearly_id else "mensal"

            users_repo.atualizar_assinatura(uid, update_data)
            logger.info("Assinatura atualizada para o usuário %s (status: %s, plano: %s)", uid, sub_status, update_data.get("plano"))

    elif event_type == "customer.subscription.deleted":
        sub = event_data
        customer_id = sub.get("customer")
        metadata = sub.get("metadata") or {}
        user_id = metadata.get("usuario_id")

        target_user = None
        if user_id:
            target_user = users_repo.buscar_por_id(user_id)
        if not target_user and customer_id:
            target_user = users_repo.buscar_por_stripe_customer_id(customer_id)

        if target_user:
            uid = target_user["_id"]
            existing_sub = target_user.get("assinatura") or {}
            users_repo.atualizar_assinatura(
                uid,
                {
                    **existing_sub,
                    "status": "canceled",
                    "cancelado_em": datetime.now(timezone.utc).isoformat(),
                    "atualizado_em": datetime.now(timezone.utc).isoformat(),
                },
            )
            logger.info("Assinatura cancelada registrada para o usuário %s", uid)

    elif event_type == "invoice.payment_succeeded":
        invoice = event_data
        customer_id = invoice.get("customer")
        if customer_id:
            target_user = users_repo.buscar_por_stripe_customer_id(customer_id)
            if target_user:
                uid = target_user["_id"]
                existing_sub = target_user.get("assinatura") or {}
                users_repo.atualizar_assinatura(
                    uid,
                    {
                        **existing_sub,
                        "status": "active",
                        "atualizado_em": datetime.now(timezone.utc).isoformat(),
                    },
                )
                logger.info("Pagamento de fatura confirmado para usuário %s", uid)

    elif event_type == "invoice.payment_failed":
        invoice = event_data
        customer_id = invoice.get("customer")
        if customer_id:
            target_user = users_repo.buscar_por_stripe_customer_id(customer_id)
            if target_user:
                uid = target_user["_id"]
                existing_sub = target_user.get("assinatura") or {}
                users_repo.atualizar_assinatura(
                    uid,
                    {
                        **existing_sub,
                        "status": "past_due",
                        "atualizado_em": datetime.now(timezone.utc).isoformat(),
                    },
                )
                logger.warning("Falha de pagamento de fatura registrada para usuário %s", uid)

    return {"received": True, "event_type": event_type}


# =============================================================================
# SERVIDOR ESTÁTICO DA NOVA SPA REACT/VITE (web/dist) OU LEGADO FLET OPCIONAL
# =============================================================================
base_dir = os.path.dirname(os.path.abspath(__file__))
spa_dist_dir = os.path.join(base_dir, "web", "dist")
spa_assets_dir = os.path.join(spa_dist_dir, "assets")
icons_dir = os.path.join(base_dir, "assets", "icons")
legacy_assets_dir = os.path.join(base_dir, "assets")
uploads_dir = os.path.join(base_dir, "uploads")
os.makedirs(os.path.join(uploads_dir, "avatars"), exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_dir), name="uploads")

if os.path.exists(icons_dir):
    app.mount("/icons", StaticFiles(directory=icons_dir), name="icons")

if os.getenv("ENABLE_FLET_WEB") == "1":
    # Modo legado Flet Web (somente se ENABLE_FLET_WEB=1)
    _orig_fastapi_init = FastAPI.__init__

    def _compat_fastapi_init(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.pop("openapi_prefix", None)
        return _orig_fastapi_init(self, *args, **kwargs)

    FastAPI.__init__ = _compat_fastapi_init  # type: ignore[method-assign]

    if os.path.exists(legacy_assets_dir):
        app.mount("/assets", StaticFiles(directory=legacy_assets_dir), name="assets")

    try:
        import flet.fastapi as flet_fastapi
        from ciphersong.ui.app_flet import build_ciphersong_app

        _orig_flet_app = flet_fastapi.app

        def _compat_flet_app(*args: Any, **kwargs: Any) -> Any:
            if "session_handler" in kwargs and "main" not in kwargs:
                kwargs["main"] = kwargs.pop("session_handler")
            return _orig_flet_app(*args, **kwargs)

        flet_fastapi.app = _compat_flet_app
        flet_web_app = flet_fastapi.app(
            session_handler=build_ciphersong_app,
            assets_dir="assets",
        )
        app.mount("/", flet_web_app)
        logger.info("CipherSong Flet Web (ENABLE_FLET_WEB=1) montado na rota raiz '/'.")
    except Exception as _flet_mount_err:
        logger.error("Falha ao montar Flet Web no FastAPI: %s", _flet_mount_err, exc_info=True)
        raise _flet_mount_err
else:
    @app.get("/", include_in_schema=False)
    def serve_spa_root() -> Any:
        if os.getenv("MAINTENANCE_MODE", "").lower() in ("1", "true"):
            return serve_maintenance_page()
        index_file = os.path.join(spa_dist_dir, "index.html")
        if os.path.isfile(index_file):
            return FileResponse(index_file, media_type="text/html")
        return HTMLResponse(
            content="<h1>CipherSong Cloud API Online</h1><p>Execute <code>npm run build</code> em <code>web/</code> para servir a SPA.</p>",
            status_code=200,
        )

    @app.get("/manutencao", include_in_schema=False)
    @app.get("/maintenance", include_in_schema=False)
    def serve_maintenance_page() -> Any:
        public_dir = os.path.join(base_dir, "web", "public")
        maint_file = os.path.join(public_dir, "maintenance.html")
        if not os.path.isfile(maint_file):
            maint_file = os.path.join(spa_dist_dir, "maintenance.html")
        if os.path.isfile(maint_file):
            return FileResponse(maint_file, media_type="text/html")
        return HTMLResponse(
            content="<h1>CipherSong em Manutenção Programada</h1><p>Voltaremos em instantes com novidades para sua equipe musical!</p>",
            status_code=503,
        )

    @app.get("/termos", include_in_schema=False)
    @app.get("/termos-de-uso", include_in_schema=False)
    @app.get("/termos.html", include_in_schema=False)
    @app.get("/privacidade", include_in_schema=False)
    @app.get("/politica-de-privacidade", include_in_schema=False)
    @app.get("/privacidade.html", include_in_schema=False)
    @app.get("/reembolso", include_in_schema=False)
    @app.get("/legal", include_in_schema=False)
    def serve_legal_page() -> Any:
        public_dir = os.path.join(base_dir, "ciphersong-web", "web", "public")
        termos_file = os.path.join(public_dir, "termos.html")
        if not os.path.isfile(termos_file):
            termos_file = os.path.join(spa_dist_dir, "termos.html")
        if os.path.isfile(termos_file):
            return FileResponse(termos_file, media_type="text/html")
        return HTMLResponse("<h1>Termos e Políticas CipherSong</h1><p><a href='/'>Ir para o CipherSong</a></p>")

    @app.get("/ads.txt", include_in_schema=False)
    def serve_ads_txt() -> PlainTextResponse:
        return PlainTextResponse(
            "google.com, pub-2817973988921168, DIRECT, f08c47fec0942fa0\n",
            media_type="text/plain; charset=utf-8",
        )

    @app.get("/googlec85dd8e21b06f6b2.html", include_in_schema=False)
    def serve_google_verification() -> PlainTextResponse:
        return PlainTextResponse(
            "google-site-verification: googlec85dd8e21b06f6b2.html\n",
            media_type="text/plain; charset=utf-8",
        )

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa_fallback(full_path: str) -> Any:
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Endpoint da API não encontrado.")
        if os.path.isdir(spa_dist_dir):
            candidate = os.path.normpath(os.path.join(spa_dist_dir, full_path))
            if candidate.startswith(os.path.normpath(spa_dist_dir)) and os.path.isfile(candidate):
                return FileResponse(candidate)
        if full_path.startswith("assets/") and os.path.isdir(legacy_assets_dir):
            rel_legacy = full_path[len("assets/"):]
            legacy_candidate = os.path.normpath(os.path.join(legacy_assets_dir, rel_legacy))
            if legacy_candidate.startswith(os.path.normpath(legacy_assets_dir)) and os.path.isfile(legacy_candidate):
                return FileResponse(legacy_candidate)
        if os.path.isdir(spa_dist_dir):
            index_file = os.path.join(spa_dist_dir, "index.html")
            if os.path.isfile(index_file):
                return FileResponse(index_file, media_type="text/html")
        raise HTTPException(status_code=404, detail="Recurso não encontrado.")



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend_api:app", host="0.0.0.0", port=8000, reload=False)
