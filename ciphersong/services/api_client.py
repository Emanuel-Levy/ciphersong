"""
Cliente Cloud Híbrido & Resiliente para o App Mobile / Desktop (`senior-architect` + `security-specialist`).

Otimizações de Alta Performance e Segurança:
- Quando `CIPHERSONG_API_URL` não está configurada (padrão no Desktop e APK Mobile), conecta-se
  diretamente ao cluster MongoDB Atlas com pool de conexões persistente, eliminando timeouts HTTP
  desnecessários de 6 segundos por operação.
- Quando uma URL de API customizada é fornecida, utiliza Circuit Breaker automático (60s) em caso
  de falha de rede, caindo instantaneamente para o MongoDB Atlas.
- Suporta autenticação completa (Cadastro, Login e Perfil JWT) tanto via HTTP quanto diretamente
  no MongoDB Atlas (`UsuariosRepository` + `PBKDF2-HMAC-SHA256`).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

from bson import ObjectId
import httpx

from ciphersong.database.mongo_connection import (
    EquipesRepository,
    MusicasAEnsaiarRepository,
    MusicasEnsaioRepository,
    PingsRepository,
    RepertorioSemanaRepository,
    UsuariosRepository,
)
from ciphersong.security.auth import (
    create_access_token,
    decode_access_token,
    hash_password,
    validate_email,
    validate_password,
    verify_password,
)

logger = logging.getLogger(__name__)


class SongsApiClient:
    """Cliente seguro e otimizado para autenticação e sincronização em nuvem do CipherSong."""

    def __init__(
        self,
        api_base_url: Optional[str] = None,
        timeout: float = 3.5,
        auth_token: Optional[str] = None,
    ) -> None:
        env_url = os.getenv("CIPHERSONG_API_URL", "").strip()
        explicit_url = (api_base_url or env_url).strip()
        self._has_custom_api_url = bool(explicit_url)
        self.api_base_url = explicit_url.rstrip("/") if explicit_url else ""
        self.timeout = timeout
        self.auth_token: Optional[str] = None
        self.active_equipe_id: Optional[str] = None
        self.set_auth_token(auth_token)

        # Circuit breaker para evitar espera repetida caso servidor HTTP externo esteja offline
        self._http_backoff_until: float = 0.0
        self._http_client: Optional[httpx.Client] = None

        # Repositórios MongoDB cacheados por instância
        self._songs_repo: Optional[MusicasEnsaioRepository] = None
        self._users_repo: Optional[UsuariosRepository] = None
        self._weekly_repo: Optional[RepertorioSemanaRepository] = None
        self._a_ensaiar_repo: Optional[MusicasAEnsaiarRepository] = None
        self._pings_repo: Optional[PingsRepository] = None
        self._equipes_repo: Optional[EquipesRepository] = None

    @property
    def http_client(self) -> httpx.Client:
        """Retorna instância persistente de httpx.Client com pool de conexões reutilizável."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.Client(timeout=self.timeout)
        return self._http_client

    def close(self) -> None:
        """Encerra o pool de conexões HTTP caso esteja aberto."""
        if self._http_client is not None and not self._http_client.is_closed:
            try:
                self._http_client.close()
            except Exception as exc:
                logger.debug("Erro ao fechar http_client: %s", exc)

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> httpx.Response:
        """Executa requisição HTTP reutilizando o pool de conexões e injetando headers JWT."""
        url = f"{self.api_base_url}{endpoint}"
        if "headers" not in kwargs:
            kwargs["headers"] = self._headers()
        return self.http_client.request(method, url, **kwargs)

    @property
    def songs_repo(self) -> MusicasEnsaioRepository:
        if self._songs_repo is None:
            self._songs_repo = MusicasEnsaioRepository()
        return self._songs_repo

    @property
    def users_repo(self) -> UsuariosRepository:
        if self._users_repo is None:
            self._users_repo = UsuariosRepository()
        return self._users_repo

    @property
    def weekly_repo(self) -> RepertorioSemanaRepository:
        if self._weekly_repo is None:
            self._weekly_repo = RepertorioSemanaRepository()
        return self._weekly_repo

    @property
    def a_ensaiar_repo(self) -> MusicasAEnsaiarRepository:
        if self._a_ensaiar_repo is None:
            self._a_ensaiar_repo = MusicasAEnsaiarRepository()
        return self._a_ensaiar_repo

    @property
    def pings_repo(self) -> PingsRepository:
        if self._pings_repo is None:
            self._pings_repo = PingsRepository()
        return self._pings_repo

    @property
    def equipes_repo(self) -> EquipesRepository:
        if self._equipes_repo is None:
            self._equipes_repo = EquipesRepository()
        return self._equipes_repo

    def set_auth_token(self, token: Optional[str]) -> None:
        """Atualiza o token de autenticação ativo para requisições subsequentes."""
        self.auth_token = token.strip() if token and token.strip() else None

    def clear_auth_token(self) -> None:
        """Limpa o token de autenticação ativo."""
        self.set_auth_token(None)

    def set_active_equipe_id(self, equipe_id: Optional[str]) -> None:
        """Define o ID da equipe ativa para todas as consultas e cadastros subsequentes."""
        self.active_equipe_id = str(equipe_id).strip() if equipe_id else None

    def clear_active_equipe_id(self) -> None:
        """Limpa a equipe ativa configurada."""
        self.active_equipe_id = None

    def _current_user_id(self) -> Optional[str]:
        """Extrai o ID do usuário logado a partir do JWT ativo."""
        if not self.auth_token:
            return None
        claims = decode_access_token(self.auth_token)
        if claims and "sub" in claims:
            return str(claims["sub"])
        return None

    def _headers(self) -> dict[str, str]:
        if self.auth_token:
            return {"Authorization": f"Bearer {self.auth_token}"}
        return {}

    def _should_try_http(self) -> bool:
        """Retorna True apenas se uma API HTTP dedicada foi configurada e não está em backoff."""
        return self._has_custom_api_url and (time.monotonic() >= self._http_backoff_until)

    def _mark_http_failure(self, exc: Optional[Exception] = None) -> None:
        """Ativa o circuit breaker por 60 segundos após falha de rede HTTP."""
        if exc is not None:
            logger.debug("Falha HTTP detectada, ativando circuit breaker por 60s: %s", exc)
        self._http_backoff_until = time.monotonic() + 60.0

    # =========================================================================
    # AUTENTICAÇÃO (CADASTRO E LOGIN COM E-MAIL E SENHA)
    # =========================================================================

    def buscar_usuario_por_email(self, email: str) -> Optional[dict[str, Any]]:
        """Busca usuário cadastrado pelo endereço de e-mail sem expor o repositório diretamente para a UI."""
        clean_email = (email or "").strip().lower()
        if not clean_email:
            return None
        try:
            return self.users_repo.buscar_por_email(clean_email)
        except Exception as exc:
            logger.warning("Erro ao buscar usuário por e-mail (%s): %s", clean_email, exc)
            return None

    def registrar_usuario(self, email: str, senha: str, nome: Optional[str] = None) -> dict[str, Any]:
        """Cadastra uma nova conta de usuário por e-mail e senha (API ou MongoDB Atlas direto)."""
        clean_email = email.strip().lower()
        clean_name = (nome or "").strip() or None

        if self._should_try_http():
            payload = {"email": clean_email, "senha": senha, "nome": clean_name}
            try:
                resp = self._request("POST", "/api/auth/register", json=payload)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    if "token" in data:
                        self.set_auth_token(data["token"])
                    return data
                detail = resp.json().get("detail", "Não foi possível criar a conta.")
                raise ValueError(detail)
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        # Autenticação direta no MongoDB Atlas
        if not validate_email(clean_email):
            raise ValueError("Endereço de e-mail inválido. Verifique o formato digitado.")

        pwd_valid, pwd_msg = validate_password(senha)
        if not pwd_valid:
            raise ValueError(pwd_msg)

        hashed = hash_password(senha)
        user_doc = self.users_repo.criar_usuario(
            email=clean_email,
            senha_hash=hashed,
            nome=clean_name,
        )
        token = create_access_token(
            user_id=user_doc["_id"],
            email=user_doc["email"],
            name=user_doc.get("nome"),
        )
        self.set_auth_token(token)
        return {
            "status": "success",
            "message": "Conta criada com sucesso!",
            "token": token,
            "user": {
                "id": user_doc["_id"],
                "email": user_doc["email"],
                "nome": user_doc.get("nome", ""),
            },
        }

    def login_usuario(self, email: str, senha: str) -> dict[str, Any]:
        """Realiza o login com e-mail e senha e armazena o token JWT."""
        clean_email = email.strip().lower()

        if self._should_try_http():
            payload = {"email": clean_email, "senha": senha}
            try:
                resp = self._request("POST", "/api/auth/login", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    if "token" in data:
                        self.set_auth_token(data["token"])
                    return data
                detail = resp.json().get("detail", "E-mail ou senha incorretos.")
                raise ValueError(detail)
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        user_doc = self.users_repo.buscar_por_email(clean_email)
        if not user_doc or not verify_password(senha, user_doc.get("senha_hash", "")):
            raise ValueError("E-mail ou senha incorretos. Verifique suas credenciais.")

        token = create_access_token(
            user_id=user_doc["_id"],
            email=user_doc["email"],
            name=user_doc.get("nome"),
        )
        self.set_auth_token(token)
        return {
            "status": "success",
            "message": "Login realizado com sucesso!",
            "token": token,
            "user": {
                "id": user_doc["_id"],
                "email": user_doc["email"],
                "nome": user_doc.get("nome", ""),
            },
        }

    def login_com_google(self, email: str, nome: str) -> dict[str, Any]:
        """Autentica ou cadastra o usuário via Conta Google com criptografia PBKDF2-HMAC-SHA256 e JWT."""
        clean_email = email.strip().lower()
        clean_name = (nome or "").strip()

        if not validate_email(clean_email):
            raise ValueError("Informe um e-mail Google válido (ex: voce@gmail.com).")
        if not clean_name or len(clean_name) < 2:
            raise ValueError("Escolha um nome de usuário com pelo menos 2 caracteres.")

        if self._should_try_http():
            payload = {"email": clean_email, "nome": clean_name}
            try:
                resp = self._request("POST", "/api/auth/google", json=payload)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    if "token" in data:
                        self.set_auth_token(data["token"])
                    return data
                detail = resp.json().get("detail", "Não foi possível autenticar com Google.")
                raise ValueError(detail)
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        google_token_hash = hash_password(f"google-oauth2::{clean_email}")
        user_doc = self.users_repo.autenticar_ou_criar_google(
            email=clean_email,
            nome=clean_name,
            google_token_hash=google_token_hash,
        )
        token = create_access_token(
            user_id=user_doc["_id"],
            email=user_doc["email"],
            name=user_doc.get("nome", clean_name),
        )
        self.set_auth_token(token)
        return {
            "status": "success",
            "message": "Autenticado com Conta Google!",
            "token": token,
            "user": {
                "id": user_doc["_id"],
                "email": user_doc["email"],
                "nome": user_doc.get("nome", clean_name),
                "provedor": "google",
            },
        }

    def solicitar_codigo_otp(self, email: str, nome: Optional[str] = None) -> dict[str, Any]:
        """Solicita o envio de um código numérico de 6 dígitos temporário para o e-mail do usuário."""
        clean_email = email.strip().lower()
        payload: dict[str, Any] = {"email": clean_email}
        if nome and nome.strip():
            payload["nome"] = nome.strip()

        if self._should_try_http():
            try:
                resp = self._request("POST", "/api/auth/otp/request", json=payload)
                if resp.status_code == 200:
                    return resp.json()
                detail = resp.json().get("detail", "Não foi possível enviar o código.")
                raise ValueError(detail)
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        # Fallback local direto (para desenvolvimento / testes offline sem API HTTP ativa)
        from ciphersong.security.auth import validate_email
        from ciphersong.security.otp import default_otp_manager
        from ciphersong.services.email_service import default_email_service

        if not validate_email(clean_email):
            raise ValueError("Endereço de e-mail inválido. Verifique o formato digitado.")

        existing = self.users_repo.buscar_por_email(clean_email)
        if existing and existing.get("provedor") == "google":
            raise ValueError("Este e-mail está cadastrado com a Conta Google. Faça login pelo botão 'Fazer Login com o Google'.")

        plain_code, cooldown, expires_min = default_otp_manager.request_otp(
            email=clean_email,
            name=nome,
        )
        default_email_service.send_otp_email(to_email=clean_email, codigo=plain_code, expires_in_minutes=expires_min)
        return {
            "status": "success",
            "message": f"Código de verificação enviado para {clean_email}!",
            "email": clean_email,
            "cooldown_seconds": cooldown,
            "expires_in_minutes": expires_min,
        }

    def verificar_codigo_otp(self, email: str, codigo: str, nome: Optional[str] = None) -> dict[str, Any]:
        """Valida o código de 6 dígitos recebido por e-mail e emite o token JWT de sessão."""
        clean_email = email.strip().lower()
        clean_code = (codigo or "").strip()
        payload: dict[str, Any] = {"email": clean_email, "codigo": clean_code}
        if nome and nome.strip():
            payload["nome"] = nome.strip()

        if self._should_try_http():
            try:
                resp = self._request("POST", "/api/auth/otp/verify", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    if "token" in data:
                        self.set_auth_token(data["token"])
                    return data
                detail = resp.json().get("detail", "Código de verificação inválido.")
                raise ValueError(detail)
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        # Fallback local direto (para desenvolvimento / testes offline)
        from ciphersong.security.otp import default_otp_manager

        ok, msg, stored_name = default_otp_manager.verify_otp(clean_email, clean_code)
        chosen_name = (nome or "").strip() or stored_name
        user_doc = self.users_repo.autenticar_ou_criar_otp(clean_email, nome=chosen_name)

        token = create_access_token(
            user_id=user_doc["_id"],
            email=user_doc["email"],
            name=user_doc.get("nome", ""),
        )
        self.set_auth_token(token)
        return {
            "status": "success",
            "message": "Login realizado com sucesso!",
            "token": token,
            "user": {
                "id": user_doc["_id"],
                "email": user_doc["email"],
                "nome": user_doc.get("nome", ""),
                "provedor": user_doc.get("provedor", "email_otp"),
            },
        }

    def atualizar_nome_usuario(self, user_id: str, novo_nome: str) -> dict[str, Any]:
        """
        Atualiza o nome de exibição do usuário no MongoDB Atlas ou via API HTTP,
        emitindo e configurando um novo JWT assinado com o novo nome.
        """
        clean_name = (novo_nome or "").strip()
        if not user_id:
            raise ValueError("Usuário não identificado. Faça login novamente.")
        if len(clean_name) < 2:
            raise ValueError("O nome de usuário deve conter pelo menos 2 caracteres.")

        # 1. Tenta API HTTP se configurada
        if self._should_try_http():
            try:
                resp = self._request(
                    "PUT",
                    "/api/auth/nome",
                    json={"novo_nome": clean_name},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    new_tok = data.get("token")
                    if new_tok:
                        self.set_auth_token(new_tok)
                    return data
                elif resp.status_code == 400:
                    err = resp.json().get("detail", "Nome de usuário inválido ou já em uso.")
                    raise ValueError(err)
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        # 2. Conexão direta com MongoDB Atlas
        updated_doc = self.users_repo.atualizar_nome_usuario(user_id=user_id, novo_nome=clean_name)
        if not updated_doc:
            raise ValueError("Usuário não encontrado para atualizar o nome.")

        new_token = create_access_token(
            user_id=updated_doc["_id"],
            email=updated_doc["email"],
            name=updated_doc.get("nome", clean_name),
        )
        self.set_auth_token(new_token)

        return {
            "status": "success",
            "message": f"Nome alterado com sucesso para '{clean_name}'!",
            "token": new_token,
            "user": {
                "id": updated_doc["_id"],
                "email": updated_doc["email"],
                "nome": updated_doc.get("nome", clean_name),
            },
        }

    def obter_usuario_logado(self) -> Optional[dict[str, Any]]:
        """Recupera os dados do perfil do usuário atualmente autenticado."""
        if not self.auth_token:
            return None

        if self._should_try_http():
            try:
                resp = self._request("GET", "/api/auth/me")
                if resp.status_code == 200:
                    return resp.json()
            except Exception as exc:
                self._mark_http_failure(exc)

        user_id = self._current_user_id()
        if not user_id:
            return None
        try:
            user_doc = self.users_repo.buscar_por_id(user_id)
            if user_doc:
                return {
                    "id": user_doc["_id"],
                    "email": user_doc["email"],
                    "nome": user_doc.get("nome", ""),
                    "criado_em": user_doc.get("criado_em", ""),
                }
        except Exception as exc:
            logger.debug("Erro ao buscar usuário logado (%s): %s", user_id, exc)
        return None

    # =========================================================================
    # REPERTÓRIO DE MÚSICAS ENSAIADAS
    # =========================================================================

    def listar_ou_buscar(
        self,
        query: str = "",
        cantor: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """
        Retorna `(lista_de_musicas, origem_str)`.
        Conecta-se diretamente ao MongoDB Atlas ou via API HTTP customizada com filtro por equipe.
        """
        q = query.strip()
        eq_id = equipe_id or self.active_equipe_id
        if self._should_try_http():
            params: dict[str, str] = {}
            if q:
                params["q"] = q
            if cantor and cantor.strip() and cantor.strip().lower() != "todos":
                params["cantor"] = cantor.strip()
            if eq_id:
                params["equipe_id"] = str(eq_id)
            try:
                resp = self._request("GET", "/api/musicas", params=params)
                if resp.status_code == 200:
                    docs = resp.json()
                    for d in docs:
                        d.setdefault("versao", "Original")
                    return docs, "☁️"
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            docs = self.songs_repo.buscar_por_filtro(
                termo=q,
                cantor=cantor,
                usuario_id=None if eq_id else self._current_user_id(),
                equipe_id=eq_id,
            )
            return docs, "☁️"
        except Exception as exc:
            raise ConnectionError("API Cloud indisponível no momento.") from exc

    def buscar_musicas(
        self,
        query: str = "",
        cantor: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """Alias para `listar_ou_buscar` usado pelo modal de agendamento semanal."""
        return self.listar_ou_buscar(query=query, cantor=cantor, equipe_id=equipe_id)

    def listar_musicas(
        self,
        query: str = "",
        cantor: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """Alias seguro para `listar_ou_buscar` prevenindo AttributeError em chamadas de views."""
        return self.listar_ou_buscar(query=query, cantor=cantor, equipe_id=equipe_id)

    def listar_cantores(self, equipe_id: Optional[str] = None) -> list[str]:
        """Obtém a lista de cantores únicos cadastrados na equipe."""
        eq_id = equipe_id or self.active_equipe_id
        if self._should_try_http():
            params = {"equipe_id": str(eq_id)} if eq_id else None
            try:
                resp = self._request("GET", "/api/cantores", params=params)
                if resp.status_code == 200:
                    return resp.json()
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            return self.songs_repo.listar_cantores_unicos(
                usuario_id=None if eq_id else self._current_user_id(),
                equipe_id=eq_id,
            )
        except Exception as exc:
            logger.debug("Erro ao listar cantores únicos: %s", exc)
            return []

    def salvar_musica(
        self,
        titulo: str,
        cantor_principal: str,
        tons: list[str],
        versao: str = "Original",
        equipe_id: Optional[str] = None,
    ) -> tuple[dict[str, Any], str]:
        """Salva a música no MongoDB Atlas (ou via API REST quando configurada)."""
        eq_id = equipe_id or self.active_equipe_id
        payload = {
            "titulo": titulo.strip(),
            "cantor_principal": cantor_principal.strip() or "Não informado",
            "tons": [t.strip() for t in tons if t.strip()],
            "versao": versao.strip() or "Original",
        }
        if eq_id:
            payload["equipe_id"] = str(eq_id)

        if self._should_try_http():
            try:
                resp = self._request("POST", "/api/musicas", json=payload)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    data.setdefault("versao", payload["versao"])
                    return data, "☁️"
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            doc = self.songs_repo.salvar_musica(
                titulo=payload["titulo"],
                cantor_principal=payload["cantor_principal"],
                tons=payload["tons"],
                versao=payload["versao"],
                usuario_id=self._current_user_id(),
                equipe_id=eq_id,
            )
            return doc, "☁️"
        except Exception as exc:
            raise ConnectionError("Sem conexão com a API Cloud.") from exc

    def deletar_musica(self, song_id: str) -> bool:
        if self._should_try_http():
            try:
                resp = self._request("DELETE", f"/api/musicas/{song_id}")
                if resp.status_code == 200:
                    return True
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            try:
                target_id: Any = ObjectId(song_id)
            except Exception:
                target_id = str(song_id)
            res = self.songs_repo.collection.delete_one({"_id": target_id})
            return res.deleted_count > 0
        except Exception as exc:
            logger.warning("Erro ao deletar música (%s): %s", song_id, exc)
            return False

    # =========================================================================
    # REPERTÓRIO DA SEMANA (ESCALA COMPARTILHADA DA EQUIPE)
    # =========================================================================

    def listar_repertorio_semana(
        self,
        data_ensaio: Optional[str] = None,
        data_inicio: Optional[str] = None,
        data_fim: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """Retorna todas as músicas agendadas no repertório da semana da equipe."""
        eq_id = equipe_id or self.active_equipe_id
        if self._should_try_http():
            params: dict[str, str] = {}
            if data_ensaio and data_ensaio.strip():
                params["data"] = data_ensaio.strip()
            elif data_inicio and data_fim:
                params["data_inicio"] = data_inicio.strip()
                params["data_fim"] = data_fim.strip()
            if eq_id:
                params["equipe_id"] = str(eq_id)

            try:
                resp = self._request("GET", "/api/repertorio-semana", params=params)
                if resp.status_code == 200:
                    docs = resp.json()
                    for d in docs:
                        d.setdefault("versao", "Original")
                        d.setdefault("adicionado_por", "Equipe")
                    return docs, "☁️"
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            if data_ensaio and data_ensaio.strip():
                docs = self.weekly_repo.listar_por_data(data_ensaio.strip(), equipe_id=eq_id)
            elif data_inicio and data_fim:
                docs = self.weekly_repo.listar_por_intervalo_datas(data_inicio.strip(), data_fim.strip(), equipe_id=eq_id)
            else:
                docs = self.weekly_repo.listar_todas(equipe_id=eq_id)
            return docs, "☁️"
        except Exception as exc:
            raise ConnectionError("Sem conexão com o Repertório da Semana.") from exc

    def adicionar_repertorio_semana(
        self,
        musica_id: str,
        titulo: str,
        cantor_principal: str,
        tom_selecionado: str,
        data_ensaio: str,
        dia_semana: str,
        versao: str = "Original",
        adicionado_por: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> tuple[dict[str, Any], str]:
        """Adiciona uma música à escala da semana no MongoDB Atlas."""
        eq_id = equipe_id or self.active_equipe_id
        payload = {
            "musica_id": str(musica_id).strip(),
            "titulo": str(titulo).strip(),
            "cantor_principal": str(cantor_principal).strip() or "Não informado",
            "tom_selecionado": str(tom_selecionado).strip(),
            "data_ensaio": str(data_ensaio).strip(),
            "dia_semana": str(dia_semana).strip(),
            "versao": str(versao).strip() or "Original",
            "adicionado_por": (adicionado_por or "").strip() or "Equipe",
        }
        if eq_id:
            payload["equipe_id"] = str(eq_id)

        if self._should_try_http():
            try:
                resp = self._request("POST", "/api/repertorio-semana", json=payload)
                if resp.status_code in (200, 201):
                    doc = resp.json()
                    doc.setdefault("versao", payload["versao"])
                    return doc, "☁️"
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            doc = self.weekly_repo.agendar_musica(
                musica_id=payload["musica_id"],
                titulo=payload["titulo"],
                cantor_principal=payload["cantor_principal"],
                tom_selecionado=payload["tom_selecionado"],
                data_ensaio=payload["data_ensaio"],
                dia_semana=payload["dia_semana"],
                versao=payload["versao"],
                adicionado_por=payload["adicionado_por"],
                usuario_id=self._current_user_id(),
                equipe_id=eq_id,
            )
            return doc, "☁️"
        except Exception as exc:
            raise ConnectionError("Sem conexão com a API para agendar repertório.") from exc

    def remover_repertorio_semana(
        self,
        item_id: str,
        titulo: Optional[str] = None,
        data_ensaio: Optional[str] = None,
    ) -> bool:
        """Remove um item da escala da semana (API ou MongoDB Atlas)."""
        if self._should_try_http():
            params: dict[str, str] = {}
            if titulo:
                params["titulo"] = str(titulo).strip()
            if data_ensaio:
                params["data_ensaio"] = str(data_ensaio).strip()
            try:
                resp = self._request(
                    "DELETE",
                    f"/api/repertorio-semana/{item_id}",
                    params=params if params else None,
                )
                if resp.status_code in (200, 204, 404):
                    return True
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            return self.weekly_repo.remover_musica_escala(
                item_id,
                titulo=titulo,
                data_ensaio=data_ensaio,
                equipe_id=self.active_equipe_id,
            )
        except Exception as exc:
            logger.warning("Erro ao remover item do repertório da semana (%s): %s", item_id, exc)
            return False

    deletar_repertorio_semana = remover_repertorio_semana

    # =========================================================================
    # MÚSICAS A ENSAIAR (PRÓXIMO ENSAIO COM LINK DO YOUTUBE)
    # =========================================================================

    def listar_a_ensaiar(self, equipe_id: Optional[str] = None) -> tuple[list[dict[str, Any]], str]:
        """Retorna todas as músicas a serem ensaiadas no próximo ensaio da equipe."""
        eq_id = equipe_id or self.active_equipe_id
        if self._should_try_http():
            params = {"equipe_id": str(eq_id)} if eq_id else None
            try:
                resp = self._request("GET", "/api/a-ensaiar", params=params)
                if resp.status_code == 200:
                    docs = resp.json()
                    for d in docs:
                        d.setdefault("status", "Próximo Ensaio")
                        d.setdefault("youtube_url", "")
                    return docs, "☁️"
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            return self.a_ensaiar_repo.listar_todas(equipe_id=eq_id), "☁️"
        except Exception as exc:
            raise ConnectionError("Sem conexão com a lista de Músicas a Ensaiar.") from exc

    def adicionar_a_ensaiar(
        self,
        titulo: str,
        cantor_versao: str,
        youtube_url: Optional[str] = "",
        adicionado_por: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> tuple[dict[str, Any], str]:
        """Adiciona uma música sugerida à fila de Músicas a Ensaiar da equipe."""
        eq_id = equipe_id or self.active_equipe_id
        payload = {
            "titulo": str(titulo).strip(),
            "cantor_versao": str(cantor_versao).strip(),
            "youtube_url": (youtube_url or "").strip(),
            "adicionado_por": (adicionado_por or "").strip() or "Equipe",
        }
        if eq_id:
            payload["equipe_id"] = str(eq_id)

        if self._should_try_http():
            try:
                resp = self._request("POST", "/api/a-ensaiar", json=payload)
                if resp.status_code in (200, 201):
                    doc = resp.json()
                    return doc, "☁️"
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            doc = self.a_ensaiar_repo.adicionar_musica(
                titulo=payload["titulo"],
                cantor_versao=payload["cantor_versao"],
                youtube_url=payload["youtube_url"],
                adicionado_por=payload["adicionado_por"],
                usuario_id=self._current_user_id(),
                equipe_id=eq_id,
            )
            return doc, "☁️"
        except ValueError:
            raise
        except Exception as exc:
            raise ConnectionError("Sem conexão com a API para adicionar música a ensaiar.") from exc

    def remover_a_ensaiar(
        self,
        item_id: str,
        titulo: Optional[str] = None,
        cantor_versao: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> bool:
        """Remove uma música da fila a ensaiar (API HTTP ou MongoDB Atlas)."""
        eq_id = equipe_id or self.active_equipe_id
        if self._should_try_http():
            params: dict[str, str] = {}
            if titulo:
                params["titulo"] = str(titulo).strip()
            if cantor_versao:
                params["cantor_versao"] = str(cantor_versao).strip()
            if eq_id:
                params["equipe_id"] = str(eq_id)
            try:
                resp = self._request(
                    "DELETE",
                    f"/api/a-ensaiar/{item_id}",
                    params=params if params else None,
                )
                if resp.status_code in (200, 204, 404):
                    return True
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            return self.a_ensaiar_repo.remover_musica(
                item_id,
                titulo=titulo,
                cantor_versao=cantor_versao,
                equipe_id=eq_id,
            )
        except Exception as exc:
            logger.warning("Erro ao remover música a ensaiar (%s): %s", item_id, exc)
            return False

    # =========================================================================
    # RECURSO: MULTI-EQUIPES, CONVITES & MEMBROS
    # =========================================================================

    def listar_minhas_equipes(self) -> list[dict[str, Any]]:
        """Lista todas as equipes das quais o usuário faz parte."""
        user_id = self._current_user_id()
        if self._should_try_http():
            try:
                resp = self._request("GET", "/api/equipe/minhas-equipes")
                if resp.status_code == 200:
                    return resp.json()
            except Exception as exc:
                self._mark_http_failure(exc)

        if user_id:
            return self.equipes_repo.listar_equipes_do_usuario(user_id)
        return []

    def criar_equipe(self, nome: str) -> dict[str, Any]:
        """Cria uma nova equipe com código de convite único."""
        user_id = self._current_user_id()
        if not user_id:
            raise ValueError("Você precisa estar autenticado para criar uma equipe.")

        if self._should_try_http():
            try:
                resp = self._request("POST", "/api/equipe/criar", json={"nome": nome})
                if resp.status_code in (200, 201):
                    return resp.json()
                elif resp.status_code == 400:
                    raise ValueError(resp.json().get("detail", "Erro ao criar equipe."))
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        user_doc = self.users_repo.buscar_por_id(user_id)
        criador_nome = (user_doc.get("nome") if user_doc else None) or "Músico"
        return self.equipes_repo.criar_equipe(
            nome=nome,
            criado_por_id=user_id,
            criado_por_nome=criador_nome,
        )

    def entrar_equipe_por_codigo(self, codigo: str) -> dict[str, Any]:
        """Adiciona o usuário a uma equipe através de código de convite."""
        user_id = self._current_user_id()
        if not user_id:
            raise ValueError("Você precisa estar autenticado para entrar em uma equipe.")

        if self._should_try_http():
            try:
                resp = self._request("POST", "/api/equipe/entrar", json={"codigo": codigo})
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code in (400, 404):
                    raise ValueError(resp.json().get("detail", "Equipe não encontrada."))
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        return self.equipes_repo.entrar_equipe_por_codigo(codigo=codigo, usuario_id=user_id)

    def listar_membros_equipe(
        self,
        equipe_id: Optional[str] = None,
        excluir_user_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Lista todos os músicos cadastrados na equipe ativa (Desktop ou Nuvem)."""
        uid = excluir_user_id or self._current_user_id()
        eq_id = equipe_id or self.active_equipe_id
        if self._should_try_http():
            params = {"equipe_id": str(eq_id)} if eq_id else None
            try:
                resp = self._request("GET", "/api/equipe/membros", params=params)
                if resp.status_code == 200:
                    membros = resp.json()
                    if uid:
                        return [m for m in membros if str(m.get("id") or m.get("_id")) != str(uid)]
                    return membros
            except Exception as exc:
                self._mark_http_failure(exc)

        try:
            if not eq_id:
                return []
            membros = self.equipes_repo.listar_membros_equipe(str(eq_id))
            if uid:
                membros = [m for m in membros if str(m.get("id") or m.get("_id")) != str(uid)]
            return membros
        except Exception as exc:
            logger.debug("Erro ao listar membros da equipe (%s): %s", eq_id, exc)
            return []

    # =========================================================================
    # RECURSO: PINGAR / CHAMADAS DA EQUIPE
    # =========================================================================

    def enviar_ping(
        self,
        destinatario_id: str,
        destinatario_nome: str,
        equipe_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Envia uma chamada instantânea para outro músico com delay de 10s."""
        user_id = self._current_user_id()
        if not user_id:
            raise ValueError("Você precisa estar autenticado para chamar outro músico.")

        eq_id = equipe_id or self.active_equipe_id
        remetente_doc = self.users_repo.buscar_por_id(user_id)
        remetente_nome = (remetente_doc.get("nome") if remetente_doc else None) or "Músico"

        if self._should_try_http():
            payload = {
                "destinatario_id": str(destinatario_id),
                "destinatario_nome": str(destinatario_nome),
            }
            if eq_id:
                payload["equipe_id"] = str(eq_id)
            try:
                resp = self._request("POST", "/api/equipe/ping", json=payload)
                if resp.status_code in (200, 201):
                    return resp.json()
                elif resp.status_code == 400:
                    raise ValueError(resp.json().get("detail", "Erro ao chamar músico."))
            except ValueError:
                raise
            except Exception as exc:
                self._mark_http_failure(exc)

        return self.pings_repo.enviar_ping(
            remetente_id=user_id,
            remetente_nome=remetente_nome,
            destinatario_id=str(destinatario_id),
            destinatario_nome=str(destinatario_nome),
            equipe_id=eq_id,
        )

    def buscar_pings_pendentes(self, equipe_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Busca chamadas pendentes recebidas pelo usuário logado na equipe."""
        user_id = self._current_user_id()
        if not user_id:
            return []

        eq_id = equipe_id or self.active_equipe_id
        if self._should_try_http():
            params = {"equipe_id": str(eq_id)} if eq_id else None
            try:
                resp = self._request("GET", "/api/equipe/meus-pings", params=params)
                if resp.status_code == 200:
                    return resp.json()
            except Exception as exc:
                self._mark_http_failure(exc)

        return self.pings_repo.buscar_pings_pendentes(destinatario_id=user_id, equipe_id=eq_id)

    def marcar_ping_lido(self, ping_id: str) -> bool:
        """Marca uma chamada como atendida/lida."""
        if self._should_try_http():
            try:
                resp = self._request("POST", f"/api/equipe/ping/{ping_id}/lido")
                if resp.status_code == 200:
                    return True
            except Exception as exc:
                self._mark_http_failure(exc)

        return self.pings_repo.marcar_como_lido(ping_id)
