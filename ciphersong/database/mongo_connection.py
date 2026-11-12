"""
Módulo de conexão e operações com o MongoDB Atlas para o CipherSong.
Gerencia a coleção 'musicas_ensaio' com validação retrocompatível:
- titulo (str, obrigatório)
- cantor_principal (str, obrigatório)
- tons (list[str], obrigatório)
- versao (str, opcional, padrão: 'Original' - indica de quem é a cifra tocada)
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Optional

from bson import ObjectId
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

from ciphersong.security.local_vault import sanitize_youtube_url

logger = logging.getLogger("ciphersong.database")

from pathlib import Path

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

try:
    import certifi
    _where_fn = getattr(certifi, "where", None)
    _CA_FILE: Optional[str] = _where_fn() if callable(_where_fn) else None
except Exception:
    _CA_FILE = None

# Configura fallback de DNS público para o dnspython no Android (onde /etc/resolv.conf não existe)
try:
    import dns.resolver
    try:
        dns.resolver.get_default_resolver()
    except Exception:
        _fallback_resolver = dns.resolver.Resolver(configure=False)
        _fallback_resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
        dns.resolver.default_resolver = _fallback_resolver
except ImportError:
    pass


class MongoDBConnection:
    """Gerenciador singleton para conexão com o cluster MongoDB Atlas."""

    _client: Optional[MongoClient] = None

    @classmethod
    def get_client(cls, uri: Optional[str] = None) -> MongoClient:
        if cls._client is None:
            raw_uri = (
                uri
                or os.getenv("MONGODB_URI")
                or os.getenv("MONGODB_DIRECT_URI")
            )
            if not raw_uri or not str(raw_uri).strip():
                raise RuntimeError(
                    "Configuração ausente: defina a variável de ambiente 'MONGODB_URI' "
                    "(ou 'MONGODB_DIRECT_URI') no arquivo .env antes de conectar ao MongoDB Atlas."
                )

            connection_uri = str(raw_uri).strip()
            direct_seedlist = os.getenv("MONGODB_DIRECT_URI", "").strip()
            if (
                "mongodb+srv://" in connection_uri
                and "ciphersong.rrrlyx2.mongodb.net" in connection_uri
                and direct_seedlist
            ):
                connection_uri = direct_seedlist

            client_kwargs: dict[str, Any] = {
                "connectTimeoutMS": 8000,
                "serverSelectionTimeoutMS": 8000,
                "socketTimeoutMS": 10000,
                "maxPoolSize": 20,
                "appname": "CipherSong",
            }
            if _CA_FILE and (
                "mongodb+srv://" in connection_uri
                or "tls=true" in connection_uri.lower()
                or "ssl=true" in connection_uri.lower()
            ):
                client_kwargs["tlsCAFile"] = _CA_FILE

            cls._client = MongoClient(connection_uri, **client_kwargs)
        return cls._client

    @classmethod
    def get_database(cls, db_name: Optional[str] = None, uri: Optional[str] = None) -> Database:
        client = cls.get_client(uri=uri)
        name = db_name or os.getenv("MONGODB_DB_NAME", "ciphersong_db")
        return client[name]

    @classmethod
    def get_musicas_ensaio_collection(
        cls, db_name: Optional[str] = None, uri: Optional[str] = None
    ) -> Collection:
        """Retorna a coleção 'musicas_ensaio'."""
        db = cls.get_database(db_name=db_name, uri=uri)
        return db["musicas_ensaio"]

    @classmethod
    def get_usuarios_collection(
        cls, db_name: Optional[str] = None, uri: Optional[str] = None
    ) -> Collection:
        """Retorna a coleção 'usuarios'."""
        db = cls.get_database(db_name=db_name, uri=uri)
        return db["usuarios"]

    @classmethod
    def get_repertorio_semana_collection(
        cls, db_name: Optional[str] = None, uri: Optional[str] = None
    ) -> Collection:
        """Retorna a coleção 'repertorio_semana' compartilhada para escala de culto/ensaio."""
        db = cls.get_database(db_name=db_name, uri=uri)
        return db["repertorio_semana"]

    @classmethod
    def get_a_ensaiar_collection(
        cls, db_name: Optional[str] = None, uri: Optional[str] = None
    ) -> Collection:
        """Retorna a coleção 'musicas_a_ensaiar' compartilhada para sugestões do próximo ensaio."""
        db = cls.get_database(db_name=db_name, uri=uri)
        return db["musicas_a_ensaiar"]

    @classmethod
    def get_pings_collection(
        cls, db_name: Optional[str] = None, uri: Optional[str] = None
    ) -> Collection:
        """Retorna a coleção 'pings_equipe' compartilhada para chamadas de músicos."""
        db = cls.get_database(db_name=db_name, uri=uri)
        return db["pings_equipe"]

    @classmethod
    def get_equipes_collection(
        cls, db_name: Optional[str] = None, uri: Optional[str] = None
    ) -> Collection:
        """Retorna a coleção 'equipes' para gerenciamento de multi-equipes."""
        db = cls.get_database(db_name=db_name, uri=uri)
        return db["equipes"]

    @classmethod
    def get_refresh_tokens_collection(
        cls, db_name: Optional[str] = None, uri: Optional[str] = None
    ) -> Collection:
        """Retorna a coleção 'refresh_tokens' para persistência e rotação de sessões."""
        db = cls.get_database(db_name=db_name, uri=uri)
        return db["refresh_tokens"]

    @classmethod
    def close(cls) -> None:
        """Encerra a conexão com o MongoDB Atlas."""
        if cls._client is not None:
            cls._client.close()
            cls._client = None


class UsuariosRepository:
    """Repositório seguro para gerenciamento de contas de usuário na coleção 'usuarios' (`security-specialist`)."""

    def __init__(self, collection: Optional[Collection] = None) -> None:
        self._collection = collection

    @property
    def collection(self) -> Collection:
        if self._collection is None:
            self._collection = MongoDBConnection.get_usuarios_collection()
        return self._collection

    def criar_usuario(
        self,
        email: str,
        senha_hash: str,
        nome: Optional[str] = None,
        provedor: str = "email",
    ) -> dict[str, Any]:
        """Cadastra um novo usuário no MongoDB garantindo e-mail único e nome de usuário único."""
        clean_email = email.strip().lower()
        clean_nome = (nome or "").strip()

        if not clean_nome:
            raise ValueError("Por favor, escolha um Nome de Usuário para sua conta.")

        if self.buscar_por_email(clean_email):
            raise ValueError("Este e-mail já está cadastrado. Não é permitido criar mais de uma conta com o mesmo e-mail.")

        existing_name = self.buscar_por_nome(clean_nome)
        if existing_name:
            raise ValueError(f"O nome de usuário '{clean_nome}' já está em uso por outro músico. Escolha outro nome.")

        now_iso = datetime.now(timezone.utc).isoformat()
        doc = {
            "email": clean_email,
            "senha_hash": senha_hash,
            "nome": clean_nome,
            "provedor": provedor,
            "criado_em": now_iso,
            "termos_aceitos": True,
            "termos_aceitos_em": now_iso,
            "cookies_aceitos": True,
        }
        res = self.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc

    def autenticar_ou_criar_google(
        self,
        email: str,
        nome: str,
        google_token_hash: str,
        foto_url: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Autentica um usuário via Conta Google oficial ou vincula/cria seu cadastro no MongoDB Atlas.
        Garante que usuários pré-existentes criados por e-mail ou OTP possam logar perfeitamente
        com sua Conta Google de mesmo e-mail, preservando dados, repertório e sem falhas de colisão de nome.
        """
        clean_email = email.strip().lower()
        clean_nome = (nome or "").strip()

        existing = self.buscar_por_email(clean_email)
        if existing:
            # Conta existente (criada via e-mail/senha, OTP ou Google anterior):
            # Vincula a conta ao Google com segurança e preserva o histórico de repertório e bandas.
            update_fields: dict[str, Any] = {
                "google_vinculado": True,
                "google_token_hash": google_token_hash,
            }

            # Se a conta ainda não tem avatar/foto de perfil e o Google forneceu uma, salva
            if foto_url and not existing.get("foto_url") and not existing.get("avatar"):
                update_fields["foto_url"] = foto_url
                update_fields["avatar"] = foto_url
                existing["foto_url"] = foto_url
                existing["avatar"] = foto_url

            # Gerenciamento de nome:
            # Se o usuário já tiver um nome no sistema, preserva intacto sem conflitos.
            # Se não tiver nome, tenta usar o nome do Google (resolvendo qualquer colisão com segurança).
            current_name = (existing.get("nome") or "").strip()
            if not current_name:
                base_candidate = clean_nome or clean_email.split("@")[0]
                candidate = base_candidate
                c = 1
                while True:
                    holder = self.buscar_por_nome(candidate)
                    if not holder or str(holder.get("_id")) == str(existing.get("_id")):
                        break
                    candidate = f"{base_candidate}_{c}"
                    c += 1
                update_fields["nome"] = candidate
                existing["nome"] = candidate

            # Aplica atualização atômica de vínculo
            try:
                if hasattr(self.collection, "update_one") and update_fields:
                    self.collection.update_one(
                        {"_id": ObjectId(existing["_id"])},
                        {"$set": update_fields},
                    )
            except Exception as update_err:
                logger.warning("Falha ao atualizar metadados Google na conta existente: %s", update_err)

            existing["google_vinculado"] = True
            return existing

        # Novo usuário criando conta com Google pela primeira vez:
        base_name = clean_nome or clean_email.split("@")[0]
        final_name = base_name
        counter = 1
        while self.buscar_por_nome(final_name):
            final_name = f"{base_name}_{counter}"
            counter += 1

        new_user = self.criar_usuario(
            email=clean_email,
            senha_hash=google_token_hash,
            nome=final_name,
            provedor="google",
        )
        if foto_url:
            try:
                if hasattr(self.collection, "update_one"):
                    self.collection.update_one(
                        {"_id": ObjectId(new_user["_id"])},
                        {"$set": {"foto_url": foto_url, "avatar": foto_url, "google_vinculado": True}},
                    )
                new_user["foto_url"] = foto_url
                new_user["avatar"] = foto_url
                new_user["google_vinculado"] = True
            except Exception:
                pass
        return new_user

    def autenticar_ou_criar_otp(self, email: str, nome: Optional[str] = None) -> dict[str, Any]:
        """
        Autentica o usuário após validação de código OTP enviado por e-mail,
        ou cria uma nova conta passwordless sem exigência de senha.
        Permite login OTP mesmo para contas vinculadas ao Google, pois o código OTP no e-mail comprova posse da conta.
        """
        clean_email = email.strip().lower()
        clean_nome = (nome or "").strip()

        existing = self.buscar_por_email(clean_email)
        if existing:
            if clean_nome and clean_nome != existing.get("nome"):
                name_holder = self.buscar_por_nome(clean_nome)
                if not name_holder or str(name_holder.get("_id")) == str(existing.get("_id")):
                    try:
                        if hasattr(self.collection, "update_one"):
                            self.collection.update_one(
                                {"_id": ObjectId(existing["_id"])},
                                {"$set": {"nome": clean_nome}},
                            )
                        existing["nome"] = clean_nome
                    except Exception:
                        pass
            return existing

        # Usuário novo via código de e-mail (passwordless)
        base_name = clean_nome or clean_email.split("@")[0]
        final_name = base_name
        counter = 1
        while self.buscar_por_nome(final_name):
            final_name = f"{base_name}_{counter}"
            counter += 1

        import secrets
        otp_dummy_hash = f"otp_passwordless${secrets.token_hex(16)}"
        return self.criar_usuario(
            email=clean_email,
            senha_hash=otp_dummy_hash,
            nome=final_name,
            provedor="email_otp",
        )

    def atualizar_nome_usuario(self, user_id: str, novo_nome: str) -> Optional[dict[str, Any]]:
        """Atualiza o nome de exibição do usuário no banco garantindo que nenhum outro usuário tenha o mesmo nome."""
        clean_nome = (novo_nome or "").strip()
        if not clean_nome:
            raise ValueError("O nome de usuário não pode ser vazio.")

        name_holder = self.buscar_por_nome(clean_nome)
        if name_holder and str(name_holder.get("_id")) != str(user_id):
            raise ValueError(f"O nome de usuário '{clean_nome}' já está em uso por outro músico.")

        try:
            target_id = ObjectId(user_id)
        except Exception:
            target_id = str(user_id)

        try:
            if hasattr(self.collection, "update_one"):
                self.collection.update_one(
                    {"_id": target_id},
                    {"$set": {"nome": clean_nome}},
                )
            return self.buscar_por_id(user_id)
        except Exception:
            return None

    def buscar_por_email(self, email: str) -> Optional[dict[str, Any]]:
        clean_email = email.strip().lower()
        doc = self.collection.find_one({"email": clean_email})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def buscar_por_nome(self, nome: str) -> Optional[dict[str, Any]]:
        """Busca usuário pelo nome (case-insensitive para evitar nomes idênticos com maiúsculas/minúsculas)."""
        clean_nome = (nome or "").strip()
        if not clean_nome:
            return None
        # Busca case-insensitive
        try:
            regex_query = {"nome": {"$regex": f"^{re.escape(clean_nome)}$", "$options": "i"}}
            doc = self.collection.find_one(regex_query)
        except Exception:
            doc = self.collection.find_one({"nome": clean_nome})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def buscar_por_id(self, user_id: str) -> Optional[dict[str, Any]]:
        try:
            try:
                target_id = ObjectId(user_id)
            except Exception:
                target_id = str(user_id)
            doc = self.collection.find_one({"_id": target_id})
            if not doc and target_id != str(user_id):
                doc = self.collection.find_one({"_id": str(user_id)})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception:
            return None

    def listar_membros_equipe(self, excluir_user_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Lista todos os membros cadastrados na equipe ordenados por nome."""
        try:
            cursor = self.collection.find({}, {"senha_hash": 0}).sort("nome", 1)
            membros = []
            for doc in cursor:
                doc_id = str(doc.get("_id", ""))
                if excluir_user_id and doc_id == str(excluir_user_id):
                    continue
                membros.append({
                    "id": doc_id,
                    "_id": doc_id,
                    "nome": doc.get("nome") or (doc.get("email", "").split("@")[0] if doc.get("email") else "Músico"),
                    "email": doc.get("email", ""),
                    "criado_em": doc.get("criado_em", ""),
                    "foto_url": doc.get("foto_url") or doc.get("avatar") or "",
                    "avatar": doc.get("avatar") or doc.get("foto_url") or "",
                })
            return membros
        except Exception:
            return []

    def excluir_usuario(self, user_id: str, email: Optional[str] = None) -> bool:
        """
        Exclui permanentemente o documento do usuário na coleção 'usuarios' no MongoDB (LGPD Art. 18, VI).
        Tenta por ObjectId, string _id e fallback por email único, garantindo remoção definitiva.
        """
        deleted = False
        clean_uid = str(user_id).strip()

        # 1. Tenta exclusão por ObjectId
        try:
            res_oid = self.collection.delete_one({"_id": ObjectId(clean_uid)})
            deleted = getattr(res_oid, "deleted_count", 0) > 0
        except Exception:
            pass

        # 2. Tenta exclusão por String ID
        if not deleted:
            try:
                res_str = self.collection.delete_one({"_id": clean_uid})
                deleted = getattr(res_str, "deleted_count", 0) > 0
            except Exception:
                pass

        # 3. Fallback por email único caso _id não tenha casado
        if not deleted and email and str(email).strip():
            clean_email = str(email).strip().lower()
            try:
                res_email = self.collection.delete_one({"email": clean_email})
                deleted = getattr(res_email, "deleted_count", 0) > 0
            except Exception:
                pass

        # 4. Limpeza adicional por garantia estrita: elimina qualquer resquício com esse e-mail no MongoDB
        if email and str(email).strip():
            try:
                self.collection.delete_many({"email": str(email).strip().lower()})
            except Exception:
                pass

        return deleted

    def conceder_cortesia(self, user_id: str, ate_iso: str) -> Optional[dict[str, Any]]:
        """Concede cortesia Premium de 3 dias de forma idempotente (apenas uma vez por usuário)."""
        try:
            try:
                target_id: Any = ObjectId(user_id)
            except Exception:
                target_id = str(user_id)
            res = self.collection.update_one(
                {"_id": target_id, "cortesia_concedida": {"$ne": True}},
                {"$set": {
                    "cortesia_ate": ate_iso,
                    "cortesia_concedida": True,
                    "cortesia_verificada": True,
                }},
            )
            if getattr(res, "matched_count", 0) == 0 and target_id != str(user_id):
                self.collection.update_one(
                    {"_id": str(user_id), "cortesia_concedida": {"$ne": True}},
                    {"$set": {
                        "cortesia_ate": ate_iso,
                        "cortesia_concedida": True,
                        "cortesia_verificada": True,
                    }},
                )
        except Exception:
            pass
        return self.buscar_por_id(user_id)

    def marcar_cortesia_verificada(self, user_id: str) -> None:
        """Marca que a elegibilidade de cortesia legada já foi avaliada para este usuário."""
        try:
            try:
                target_id: Any = ObjectId(user_id)
            except Exception:
                target_id = str(user_id)
            self.collection.update_one(
                {"_id": target_id},
                {"$set": {"cortesia_verificada": True}},
            )
        except Exception:
            pass

    def atualizar_assinatura(
        self,
        user_id: str,
        assinatura_data: dict[str, Any],
    ) -> bool:
        """Atualiza os dados de assinatura (Stripe) do usuário."""
        try:
            try:
                target_id: Any = ObjectId(user_id)
            except Exception:
                target_id = str(user_id)
            res = self.collection.update_one(
                {"_id": target_id},
                {
                    "$set": {
                        "assinatura": assinatura_data,
                        "atualizado_em": datetime.now(timezone.utc).isoformat(),
                    }
                },
            )
            if getattr(res, "matched_count", 0) == 0 and target_id != str(user_id):
                res = self.collection.update_one(
                    {"_id": str(user_id)},
                    {
                        "$set": {
                            "assinatura": assinatura_data,
                            "atualizado_em": datetime.now(timezone.utc).isoformat(),
                        }
                    },
                )
            return getattr(res, "modified_count", 0) > 0
        except Exception:
            return False

    def buscar_por_stripe_customer_id(self, customer_id: str) -> Optional[dict[str, Any]]:
        """Busca usuário pelo ID de cliente da Stripe."""
        if not customer_id:
            return None
        doc = self.collection.find_one({"assinatura.stripe_customer_id": customer_id})
        if not doc:
            doc = self.collection.find_one({"stripe_customer_id": customer_id})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc


class MusicasEnsaioRepository:
    """Repositório de operações para a coleção 'musicas_ensaio' com suporte a Versão, Filtro por Cantor e Usuário."""

    def __init__(self, collection: Optional[Collection] = None) -> None:
        self._collection = collection

    @property
    def collection(self) -> Collection:
        if self._collection is None:
            self._collection = MongoDBConnection.get_musicas_ensaio_collection()
        return self._collection

    @staticmethod
    def validar_documento(
        titulo: str,
        cantor_principal: str,
        tons: list[str],
        versao: Optional[str] = None,
        usuario_id: Optional[str] = None,
        equipe_id: Optional[str] = None,
        cifra: Optional[str] = None,
        tom_original: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Valida se os campos atendem ao formato exigido mantendo 100% de compatibilidade retroativa.
        """
        if not isinstance(titulo, str) or not titulo.strip():
            raise ValueError("O campo 'titulo' é obrigatório e deve ser uma string não vazia.")

        if not isinstance(cantor_principal, str) or not cantor_principal.strip():
            raise ValueError("O campo 'cantor_principal' é obrigatório e deve ser uma string não vazia.")

        if not isinstance(tons, list) or len(tons) == 0:
            raise ValueError("O campo 'tons' é obrigatório e deve ser uma lista não vazia.")

        for tom in tons:
            if not isinstance(tom, str) or not tom.strip():
                raise ValueError("Todos os itens em 'tons' devem ser strings não vazias (ex: 'G', 'Em').")

        clean_versao = (versao or "").strip() or "Original"

        doc: dict[str, Any] = {
            "titulo": titulo.strip(),
            "cantor_principal": cantor_principal.strip(),
            "tons": [t.strip() for t in tons],
            "versao": clean_versao,
        }
        if usuario_id and str(usuario_id).strip():
            doc["usuario_id"] = str(usuario_id).strip()
        if equipe_id and str(equipe_id).strip():
            doc["equipe_id"] = str(equipe_id).strip()
        if cifra is not None:
            doc["cifra"] = str(cifra).strip()
        if tom_original is not None:
            doc["tom_original"] = str(tom_original).strip()

        return doc

    def salvar_musica(
        self,
        titulo: str,
        cantor_principal: str,
        tons: list[str],
        versao: str = "Original",
        usuario_id: Optional[str] = None,
        equipe_id: Optional[str] = None,
        cifra: Optional[str] = None,
        tom_original: Optional[str] = None,
    ) -> dict[str, Any]:
        """Insere ou atualiza uma música na coleção 'musicas_ensaio', prevenindo duplicações na equipe."""
        documento = self.validar_documento(
            titulo=titulo,
            cantor_principal=cantor_principal,
            tons=tons,
            versao=versao,
            usuario_id=usuario_id,
            equipe_id=equipe_id,
            cifra=cifra,
            tom_original=tom_original,
        )

        # Previne duplicatas de mesma música (título + cantor + versão ignorando maiúsculas) na mesma equipe
        existing = None
        if hasattr(self.collection, "find_one"):
            try:
                filter_find: dict[str, Any] = {
                    "titulo": {"$regex": f"^{re.escape(documento['titulo'])}$", "$options": "i"},
                    "cantor_principal": {"$regex": f"^{re.escape(documento['cantor_principal'])}$", "$options": "i"},
                    "versao": {"$regex": f"^{re.escape(documento['versao'])}$", "$options": "i"},
                }
                if equipe_id:
                    filter_find["equipe_id"] = str(equipe_id)
                elif usuario_id:
                    filter_find["usuario_id"] = str(usuario_id)
                    filter_find["equipe_id"] = {"$in": [None, ""]}
                res = self.collection.find_one(filter_find)
                if isinstance(res, dict):
                    existing = res
            except Exception:
                existing = None
        if existing:
            merged_tons = list(dict.fromkeys(existing.get("tons", []) + documento["tons"]))
            update_fields: dict[str, Any] = {
                "tons": merged_tons,
                "atualizado_em": datetime.now(timezone.utc).isoformat(),
            }
            if usuario_id and not existing.get("usuario_id"):
                update_fields["usuario_id"] = usuario_id
            if equipe_id and not existing.get("equipe_id"):
                update_fields["equipe_id"] = str(equipe_id)
            if "cifra" in documento and documento["cifra"]:
                update_fields["cifra"] = documento["cifra"]
            if "tom_original" in documento and documento["tom_original"]:
                update_fields["tom_original"] = documento["tom_original"]

            self.collection.update_one({"_id": existing["_id"]}, {"$set": update_fields})
            existing["_id"] = str(existing["_id"])
            existing["tons"] = merged_tons
            if "cifra" in update_fields:
                existing["cifra"] = update_fields["cifra"]
            if "tom_original" in update_fields:
                existing["tom_original"] = update_fields["tom_original"]
            return existing

        documento["criado_em"] = datetime.now(timezone.utc).isoformat()
        result = self.collection.insert_one(documento)
        documento["_id"] = str(result.inserted_id)
        return documento

    def listar_todas(
        self, usuario_id: Optional[str] = None, equipe_id: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Lista todas as músicas de ensaio cadastradas filtrando estritamente por equipe ou usuário."""
        if not equipe_id and not usuario_id:
            return []
        query: dict[str, Any] = {}
        if equipe_id:
            query["equipe_id"] = str(equipe_id)
        elif usuario_id:
            query["usuario_id"] = str(usuario_id)
            query["equipe_id"] = {"$in": [None, ""]}

        cursor = self.collection.find(query)
        resultado = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc.setdefault("versao", "Original")
            resultado.append(doc)
        return resultado

    def buscar_por_filtro(
        self,
        termo: str = "",
        cantor: Optional[str] = None,
        usuario_id: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Busca músicas por título, versão, cantor ou tom, isoladas estritamente por equipe ou usuário."""
        if not equipe_id and not usuario_id:
            return []
        conditions: list[dict[str, Any]] = []

        if equipe_id:
            conditions.append({"equipe_id": str(equipe_id)})
        elif usuario_id:
            conditions.append({"usuario_id": str(usuario_id)})
            conditions.append({"equipe_id": {"$in": [None, ""]}})

        if cantor and cantor.strip() and cantor.strip().lower() != "todos":
            conditions.append({"cantor_principal": cantor.strip()})

        if termo and termo.strip():
            t = re.escape(termo.strip())
            conditions.append({
                "$or": [
                    {"titulo": {"$regex": t, "$options": "i"}},
                    {"cantor_principal": {"$regex": t, "$options": "i"}},
                    {"versao": {"$regex": t, "$options": "i"}},
                    {"tons": {"$elemMatch": {"$regex": t, "$options": "i"}}},
                ]
            })

        query = {"$and": conditions} if conditions else {}
        cursor = self.collection.find(query)
        resultado = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc.setdefault("versao", "Original")
            resultado.append(doc)
        return resultado

    def listar_cantores_unicos(
        self, usuario_id: Optional[str] = None, equipe_id: Optional[str] = None
    ) -> list[str]:
        """Retorna uma lista ordenada com todos os cantores cadastrados na equipe ou usuário selecionado."""
        if not equipe_id and not usuario_id:
            return []
        try:
            filter_query: dict[str, Any] = {}
            if equipe_id:
                filter_query["equipe_id"] = str(equipe_id)
            elif usuario_id:
                filter_query["usuario_id"] = str(usuario_id)
                filter_query["equipe_id"] = {"$in": [None, ""]}
            cantores = self.collection.distinct("cantor_principal", filter_query)
            return sorted([str(c).strip() for c in cantores if str(c).strip()])
        except Exception:
            return []

    def contar_por_equipe(
        self, equipe_id: Optional[str] = None, usuario_id: Optional[str] = None
    ) -> int:
        """Conta o total de músicas cadastradas na equipe ou usuário."""
        if not equipe_id and not usuario_id:
            return 0
        query: dict[str, Any] = {}
        if equipe_id:
            query["equipe_id"] = str(equipe_id)
        elif usuario_id:
            query["usuario_id"] = str(usuario_id)
            query["equipe_id"] = {"$in": [None, ""]}
        try:
            if hasattr(self.collection, "count_documents"):
                return int(self.collection.count_documents(query))
            return len(list(self.collection.find(query)))
        except Exception:
            return 0

    def existe_duplicata(
        self,
        titulo: str,
        cantor_principal: str,
        versao: str = "Original",
        equipe_id: Optional[str] = None,
        usuario_id: Optional[str] = None,
    ) -> bool:
        """Verifica se a música já existe na equipe (caso em que salvar_musica apenas mescla os tons)."""
        try:
            filter_find: dict[str, Any] = {
                "titulo": {"$regex": f"^{re.escape(str(titulo).strip())}$", "$options": "i"},
                "cantor_principal": {"$regex": f"^{re.escape(str(cantor_principal).strip())}$", "$options": "i"},
                "versao": {"$regex": f"^{re.escape(str(versao or 'Original').strip())}$", "$options": "i"},
            }
            if equipe_id:
                filter_find["equipe_id"] = str(equipe_id)
            elif usuario_id:
                filter_find["usuario_id"] = str(usuario_id)
                filter_find["equipe_id"] = {"$in": [None, ""]}
            if hasattr(self.collection, "find_one"):
                return self.collection.find_one(filter_find) is not None
        except Exception:
            pass
        return False


class RepertorioSemanaRepository:
    """Repositório de operações para o Repertório da Semana (Escala de Músicas Compartilhada)."""

    def __init__(self, collection: Optional[Collection] = None) -> None:
        self._collection = collection

    @property
    def collection(self) -> Collection:
        if self._collection is None:
            self._collection = MongoDBConnection.get_repertorio_semana_collection()
        return self._collection

    def agendar_musica(
        self,
        musica_id: str,
        titulo: str,
        cantor_principal: str,
        tom_selecionado: str,
        data_ensaio: str,  # Formato YYYY-MM-DD
        dia_semana: str,   # Ex: "Sábado"
        versao: str = "Original",
        adicionado_por: Optional[str] = None,
        usuario_id: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Adiciona uma música à escala da semana para uma data/dia específico na equipe, prevenindo duplicações."""
        if not titulo or not str(titulo).strip():
            raise ValueError("O título da música é obrigatório.")
        if not tom_selecionado or not str(tom_selecionado).strip():
            raise ValueError("O tom da música para o ensaio é obrigatório.")
        if not data_ensaio or not str(data_ensaio).strip():
            raise ValueError("A data de ensaio (YYYY-MM-DD) é obrigatória.")

        clean_tit = str(titulo).strip()
        clean_cp = str(cantor_principal).strip() or "Não informado"
        clean_data = str(data_ensaio).strip()

        # Previne duplicatas da mesma música no mesmo dia de ensaio na mesma equipe
        existing = None
        if hasattr(self.collection, "find_one"):
            try:
                find_filter: dict[str, Any] = {
                    "titulo": {"$regex": f"^{re.escape(clean_tit)}$", "$options": "i"},
                    "cantor_principal": {"$regex": f"^{re.escape(clean_cp)}$", "$options": "i"},
                    "data_ensaio": clean_data,
                }
                if equipe_id:
                    find_filter["equipe_id"] = str(equipe_id)
                res = self.collection.find_one(find_filter)
                if isinstance(res, dict):
                    existing = res
            except Exception:
                existing = None
        if existing:
            update_data = {
                "tom_selecionado": str(tom_selecionado).strip(),
                "versao": str(versao).strip() or "Original",
                "adicionado_por": (adicionado_por or "").strip() or existing.get("adicionado_por", "Equipe"),
                "atualizado_em": datetime.now(timezone.utc).isoformat(),
            }
            if usuario_id and not existing.get("usuario_id"):
                update_data["usuario_id"] = usuario_id
            if equipe_id and not existing.get("equipe_id"):
                update_data["equipe_id"] = str(equipe_id)
            self.collection.update_one({"_id": existing["_id"]}, {"$set": update_data})
            existing["_id"] = str(existing["_id"])
            existing.update(update_data)
            return existing

        doc = {
            "musica_id": str(musica_id).strip(),
            "titulo": clean_tit,
            "cantor_principal": clean_cp,
            "tom_selecionado": str(tom_selecionado).strip(),
            "data_ensaio": clean_data,
            "dia_semana": str(dia_semana).strip() or "Ensaio",
            "versao": str(versao).strip() or "Original",
            "adicionado_por": (adicionado_por or "").strip() or "Equipe",
            "usuario_id": usuario_id,
            "equipe_id": str(equipe_id) if equipe_id else None,
            "criado_em": datetime.now(timezone.utc).isoformat(),
        }
        res = self.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc

    def listar_por_data(
        self,
        data_ensaio: str,
        equipe_id: Optional[str] = None,
        usuario_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Lista todas as músicas agendadas para uma data específica (YYYY-MM-DD) na equipe ou usuário."""
        if not equipe_id and not usuario_id:
            return []
        query: dict[str, Any] = {"data_ensaio": str(data_ensaio).strip()}
        if equipe_id:
            query["equipe_id"] = str(equipe_id)
        else:
            query["equipe_id"] = {"$in": [None, ""]}
            query["usuario_id"] = str(usuario_id)
        cursor = self.collection.find(query).sort("criado_em", 1)
        resultado = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc.setdefault("versao", "Original")
            resultado.append(doc)
        return resultado

    def listar_por_intervalo_datas(
        self,
        data_inicio: str,
        data_fim: str,
        equipe_id: Optional[str] = None,
        usuario_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Lista todas as músicas agendadas no intervalo da semana na equipe ou usuário."""
        if not equipe_id and not usuario_id:
            return []
        query: dict[str, Any] = {
            "data_ensaio": {"$gte": str(data_inicio).strip(), "$lte": str(data_fim).strip()}
        }
        if equipe_id:
            query["equipe_id"] = str(equipe_id)
        else:
            query["equipe_id"] = {"$in": [None, ""]}
            query["usuario_id"] = str(usuario_id)
        cursor = self.collection.find(query).sort("data_ensaio", 1)
        resultado = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc.setdefault("versao", "Original")
            resultado.append(doc)
        return resultado

    def listar_todas(
        self,
        equipe_id: Optional[str] = None,
        usuario_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Lista todas as músicas agendadas na escala da equipe ou pessoal do usuário."""
        if not equipe_id and not usuario_id:
            return []
        if equipe_id:
            query: dict[str, Any] = {"equipe_id": str(equipe_id)}
        else:
            query = {"equipe_id": {"$in": [None, ""]}, "usuario_id": str(usuario_id)}
        cursor = self.collection.find(query).sort("data_ensaio", 1)
        resultado = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc.setdefault("versao", "Original")
            resultado.append(doc)
        return resultado

    def remover_musica_escala(
        self,
        item_id: str,
        titulo: Optional[str] = None,
        data_ensaio: Optional[str] = None,
        equipe_id: Optional[str] = None,
        usuario_id: Optional[str] = None,
    ) -> bool:
        """Remove um item da escala da semana garantindo isolamento por equipe_id ou usuario_id (anti-IDOR)."""
        clean_id = str(item_id).strip()
        target_id: Any = None
        try:
            target_id = ObjectId(clean_id)
        except Exception:
            target_id = clean_id

        if not equipe_id and not usuario_id:
            return False

        scope_filter: dict[str, Any] = {}
        if equipe_id:
            scope_filter["equipe_id"] = str(equipe_id)
        elif usuario_id:
            scope_filter["equipe_id"] = {"$in": [None, ""]}
            scope_filter["usuario_id"] = str(usuario_id)

        res = self.collection.delete_one({"_id": target_id, **scope_filter})
        if getattr(res, "deleted_count", 0) > 0:
            return True

        if target_id != clean_id:
            res_str = self.collection.delete_one({"_id": clean_id, **scope_filter})
            if getattr(res_str, "deleted_count", 0) > 0:
                return True

        if titulo and data_ensaio and (equipe_id or usuario_id):
            clean_tit = str(titulo).strip()
            clean_dt = str(data_ensaio).strip()
            fallback_query: dict[str, Any] = {
                "titulo": {"$regex": f"^{re.escape(clean_tit)}$", "$options": "i"},
                "data_ensaio": clean_dt,
                **scope_filter,
            }
            res_fb = self.collection.delete_one(fallback_query)
            return getattr(res_fb, "deleted_count", 0) > 0

        return False


class MusicasAEnsaiarRepository:
    """Repositório de operações para Músicas a Ensaiar (próximo ensaio da equipe/banda)."""

    def __init__(self, collection: Optional[Collection] = None) -> None:
        self._collection = collection

    @property
    def collection(self) -> Collection:
        if self._collection is None:
            self._collection = MongoDBConnection.get_a_ensaiar_collection()
        return self._collection

    def adicionar_musica(
        self,
        titulo: str,
        cantor_versao: str,
        youtube_url: Optional[str] = "",
        status: str = "Próximo Ensaio",
        adicionado_por: Optional[str] = None,
        usuario_id: Optional[str] = None,
        equipe_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Adiciona uma música à lista de Músicas a Ensaiar da equipe prevenindo duplicações."""
        if not titulo or not str(titulo).strip():
            raise ValueError("O nome da música é obrigatório.")
        if not cantor_versao or not str(cantor_versao).strip():
            raise ValueError("O cantor / versão da música é obrigatório.")

        clean_yt = sanitize_youtube_url(youtube_url)
        clean_tit = str(titulo).strip()
        clean_cv = str(cantor_versao).strip()

        # Previne duplicatas de mesma música e versão na lista de próximos ensaios da mesma equipe
        query_exist: dict[str, Any] = {
            "titulo": {"$regex": f"^{re.escape(clean_tit)}$", "$options": "i"},
            "cantor_versao": {"$regex": f"^{re.escape(clean_cv)}$", "$options": "i"},
        }
        if equipe_id:
            query_exist["equipe_id"] = str(equipe_id)

        existing = None
        if hasattr(self.collection, "find_one"):
            try:
                res = self.collection.find_one(query_exist)
                if isinstance(res, dict):
                    existing = res
            except Exception:
                existing = None
        if existing:
            update_data = {
                "youtube_url": clean_yt or existing.get("youtube_url", ""),
                "status": str(status).strip() or existing.get("status", "Próximo Ensaio"),
                "adicionado_por": (adicionado_por or "").strip() or existing.get("adicionado_por", "Equipe"),
                "atualizado_em": datetime.now(timezone.utc).isoformat(),
            }
            if usuario_id and not existing.get("usuario_id"):
                update_data["usuario_id"] = usuario_id
            if equipe_id and not existing.get("equipe_id"):
                update_data["equipe_id"] = str(equipe_id)
            self.collection.update_one({"_id": existing["_id"]}, {"$set": update_data})
            existing["_id"] = str(existing["_id"])
            existing.update(update_data)
            return existing

        doc = {
            "titulo": clean_tit,
            "cantor_versao": clean_cv,
            "youtube_url": clean_yt,
            "status": str(status).strip() or "Próximo Ensaio",
            "adicionado_por": (adicionado_por or "").strip() or "Equipe",
            "usuario_id": usuario_id,
            "equipe_id": str(equipe_id) if equipe_id else None,
            "criado_em": datetime.now(timezone.utc).isoformat(),
        }
        res = self.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc

    def listar_todas(
        self,
        equipe_id: Optional[str] = None,
        usuario_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Lista todas as músicas a serem ensaiadas ordenadas pelas mais recentes na equipe ou usuário."""
        if not equipe_id and not usuario_id:
            return []
        if equipe_id:
            query: dict[str, Any] = {"equipe_id": str(equipe_id)}
        else:
            query = {"equipe_id": {"$in": [None, ""]}, "usuario_id": str(usuario_id)}
        cursor = self.collection.find(query).sort("criado_em", -1)
        resultado = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc.setdefault("status", "Próximo Ensaio")
            doc.setdefault("youtube_url", "")
            resultado.append(doc)
        return resultado

    def remover_musica(
        self,
        item_id: str,
        titulo: Optional[str] = None,
        cantor_versao: Optional[str] = None,
        equipe_id: Optional[str] = None,
        usuario_id: Optional[str] = None,
    ) -> bool:
        """
        Remove uma música da lista a ensaiar pelo seu _id ou pelo fallback de título + cantor_versao,
        estritamente isolada por equipe_id ou usuario_id (prevenção contra IDOR entre equipes).
        """
        clean_id = str(item_id).strip()
        target_id: Any = None
        try:
            target_id = ObjectId(clean_id)
        except Exception:
            target_id = clean_id

        if not equipe_id and not usuario_id:
            return False

        scope_filter: dict[str, Any] = {}
        if equipe_id:
            scope_filter["equipe_id"] = str(equipe_id)
        elif usuario_id:
            scope_filter["equipe_id"] = {"$in": [None, ""]}
            scope_filter["usuario_id"] = str(usuario_id)

        res = self.collection.delete_one({"_id": target_id, **scope_filter})
        if getattr(res, "deleted_count", 0) > 0:
            return True

        if target_id != clean_id:
            res_str = self.collection.delete_one({"_id": clean_id, **scope_filter})
            if getattr(res_str, "deleted_count", 0) > 0:
                return True

        if titulo and str(titulo).strip() and (equipe_id or usuario_id):
            clean_tit = str(titulo).strip()
            fb_query: dict[str, Any] = {
                "titulo": {"$regex": f"^{re.escape(clean_tit)}$", "$options": "i"},
                **scope_filter,
            }
            if cantor_versao and str(cantor_versao).strip():
                fb_query["cantor_versao"] = {"$regex": f"^{re.escape(str(cantor_versao).strip())}$", "$options": "i"}

            res_fb = self.collection.delete_one(fb_query)
            if getattr(res_fb, "deleted_count", 0) > 0:
                return True

        return False


class PingsRepository:
    """Repositório de operações para chamadas/pings instantâneos entre membros da equipe."""

    COOLDOWN_SECONDS: float = 10.0

    def __init__(self, collection: Optional[Collection] = None) -> None:
        self._collection = collection

    @property
    def collection(self) -> Collection:
        if self._collection is None:
            self._collection = MongoDBConnection.get_pings_collection()
        return self._collection

    def enviar_ping(
        self,
        remetente_id: str,
        remetente_nome: str,
        destinatario_id: str,
        destinatario_nome: str,
        equipe_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Registra uma chamada (ping) para um músico da equipe com cooldown de 10s."""
        if not remetente_id or not destinatario_id:
            raise ValueError("Identificadores de remetente e destinatário são obrigatórios.")
        if str(remetente_id).strip() == str(destinatario_id).strip():
            raise ValueError("Você não pode enviar uma chamada para você mesmo.")

        now_ts = time.time()
        # Verifica se houve chamada recente para a mesma pessoa nos últimos 10 segundos
        try:
            if hasattr(self.collection, "find_one"):
                recent = self.collection.find_one({
                    "remetente_id": str(remetente_id).strip(),
                    "destinatario_id": str(destinatario_id).strip(),
                    "criado_em_ts": {"$gte": now_ts - self.COOLDOWN_SECONDS},
                })
                if isinstance(recent, dict):
                    diff = now_ts - recent.get("criado_em_ts", now_ts)
                    restante = int(self.COOLDOWN_SECONDS - diff)
                    restante = max(1, restante)
                    raise ValueError(f"Aguarde {restante}s antes de chamar {destinatario_nome} novamente.")
        except ValueError:
            raise
        except Exception:
            pass

        doc = {
            "remetente_id": str(remetente_id).strip(),
            "remetente_nome": str(remetente_nome).strip() or "Músico",
            "destinatario_id": str(destinatario_id).strip(),
            "destinatario_nome": str(destinatario_nome).strip() or "Músico",
            "equipe_id": str(equipe_id) if equipe_id else None,
            "criado_em": datetime.now(timezone.utc).isoformat(),
            "criado_em_ts": now_ts,
            "lido": False,
        }
        res = self.collection.insert_one(doc)
        doc["_id"] = str(getattr(res, "inserted_id", "ping_id"))
        return doc

    def buscar_pings_pendentes(
        self, destinatario_id: str, equipe_id: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Busca chamadas não lidas recebidas pelo usuário nos últimos 60 segundos."""
        if not destinatario_id:
            return []
        min_ts = time.time() - 60.0
        try:
            q: dict[str, Any] = {
                "destinatario_id": str(destinatario_id).strip(),
                "lido": False,
                "criado_em_ts": {"$gte": min_ts},
            }
            if equipe_id:
                q["equipe_id"] = str(equipe_id)
            cursor = self.collection.find(q)
            if hasattr(cursor, "sort"):
                cursor = cursor.sort("criado_em_ts", -1)
            pings = []
            for d in cursor:
                d["_id"] = str(d["_id"])
                pings.append(d)
            return pings
        except Exception:
            return []

    def marcar_como_lido(self, ping_id: str, destinatario_id: Optional[str] = None) -> bool:
        """Marca uma chamada como visualizada garantindo que pertença ao destinatário autenticado."""
        try:
            try:
                target_id: Any = ObjectId(ping_id)
            except Exception:
                target_id = str(ping_id)
            query: dict[str, Any] = {"_id": target_id}
            if destinatario_id:
                query["destinatario_id"] = str(destinatario_id).strip()
            if hasattr(self.collection, "update_one"):
                res = self.collection.update_one(query, {"$set": {"lido": True}})
                return getattr(res, "modified_count", 0) > 0
            return True
        except Exception:
            return False


class EquipesRepository:
    """Repositório de operações para Multi-Equipes (criação, convites e isolamento de dados)."""

    def __init__(self, collection: Optional[Collection] = None) -> None:
        self._collection = collection

    @property
    def collection(self) -> Collection:
        if self._collection is None:
            self._collection = MongoDBConnection.get_equipes_collection()
        return self._collection

    def obter_ou_criar_equipe_padrao(self, nome: str = "Teste") -> Optional[dict[str, Any]]:
        """Método legado mantido apenas por retrocompatibilidade de assinatura."""
        return None

    def criar_equipe(self, nome: str, criado_por_id: str, criado_por_nome: str) -> dict[str, Any]:
        """Cria uma nova equipe com código de convite único."""
        if not nome or not str(nome).strip():
            raise ValueError("O nome da equipe é obrigatório.")
        clean_nome = str(nome).strip()

        # Gera código de convite amigável de 6 caracteres alfanuméricos
        codigo = f"CS-{secrets.token_hex(3).upper()}"
        doc = {
            "nome": clean_nome,
            "codigo_convite": codigo,
            "criado_por": str(criado_por_id),
            "criador_nome": str(criado_por_nome or "Músico"),
            "membros": [str(criado_por_id)],
            "padrao": False,
            "criado_em": datetime.now(timezone.utc).isoformat(),
        }
        res = self.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc

    def buscar_por_id(self, equipe_id: str) -> Optional[dict[str, Any]]:
        try:
            oid = ObjectId(equipe_id)
        except Exception:
            oid = equipe_id
        doc = self.collection.find_one({"_id": oid})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def buscar_por_codigo(self, codigo: str) -> Optional[dict[str, Any]]:
        clean_cod = str(codigo).strip().upper()
        # Aceita código com ou sem o prefixo CS-
        if not clean_cod.startswith("CS-") and len(clean_cod) == 6:
            query_cond = {"$in": [clean_cod, f"CS-{clean_cod}"]}
        else:
            query_cond = {"$in": [clean_cod, clean_cod.replace("CS-", "")]}
        doc = self.collection.find_one({"codigo_convite": query_cond})
        if not doc:
            doc = self.collection.find_one({"codigo_convite": {"$regex": f"^{re.escape(clean_cod)}$", "$options": "i"}})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def entrar_equipe_por_codigo(self, codigo: str, usuario_id: str) -> dict[str, Any]:
        """Adiciona um usuário à equipe através de seu código de convite."""
        equipe = self.buscar_por_codigo(codigo)
        if not equipe:
            raise ValueError("Equipe não encontrada para o código de convite informado.")

        eq_id = equipe["_id"]
        try:
            oid = ObjectId(eq_id)
        except Exception:
            oid = eq_id

        self.collection.update_one(
            {"_id": oid},
            {"$addToSet": {"membros": str(usuario_id)}},
        )
        equipe_atualizada = self.buscar_por_id(eq_id)
        return equipe_atualizada or equipe

    def listar_equipes_do_usuario(self, usuario_id: str) -> list[dict[str, Any]]:
        """Lista todas as equipes das quais o usuário participa."""
        if not usuario_id:
            return []
        uid = str(usuario_id).strip()
        cursor = self.collection.find({
            "$or": [
                {"membros": uid},
                {"criado_por": uid},
            ]
        }).sort("criado_em", 1)

        equipes = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            equipes.append(doc)
        return equipes

    def usuario_pertence_a_equipe(self, equipe_id: str, usuario_id: str) -> bool:
        """Verifica se o usuário pertence à equipe especificada."""
        if not equipe_id or not usuario_id:
            return False
        equipe = self.buscar_por_id(equipe_id)
        if not equipe:
            return False
        membros = [str(m) for m in equipe.get("membros", [])]
        return str(usuario_id) in membros or str(equipe.get("criado_por")) == str(usuario_id)

    def listar_membros_equipe(self, equipe_id: str) -> list[dict[str, Any]]:
        """Retorna a lista de usuários membros da equipe com dados públicos."""
        equipe = self.buscar_por_id(equipe_id)
        if not equipe:
            return []
        membros_ids = list(equipe.get("membros", []))
        criador = equipe.get("criado_por")
        if criador and str(criador) not in [str(m) for m in membros_ids]:
            membros_ids.append(str(criador))

        usuarios_col = MongoDBConnection.get_usuarios_collection()

        obj_ids = []
        for mid in membros_ids:
            try:
                obj_ids.append(ObjectId(mid))
            except Exception:
                pass

        query: dict[str, Any] = {
            "$or": [
                {"_id": {"$in": obj_ids}},
                {"_id": {"$in": [str(mid) for mid in membros_ids]}},
            ]
        }
        cursor = usuarios_col.find(query, {"senha_hash": 0, "salt": 0})
        membros = []
        for u in cursor:
            u_id = str(u["_id"])
            u["_id"] = u_id
            u["id"] = u_id
            u["foto_url"] = u.get("foto_url") or u.get("avatar") or ""
            u["avatar"] = u.get("avatar") or u.get("foto_url") or ""
            membros.append(u)
        return membros

    def remover_membro_equipe(self, equipe_id: str, membro_id: str) -> dict[str, Any]:
        """Remove um membro da equipe (pelo líder ou por si próprio ao sair)."""
        equipe = self.buscar_por_id(equipe_id)
        if not equipe:
            raise ValueError("Equipe não encontrada.")

        eq_id = equipe["_id"]
        try:
            oid = ObjectId(eq_id)
        except Exception:
            oid = eq_id

        mid = str(membro_id).strip()
        membros_atuais = [str(m) for m in equipe.get("membros", [])]
        if mid not in membros_atuais:
            return equipe

        membros_restantes = [m for m in membros_atuais if m != mid]
        update_doc: dict[str, Any] = {"membros": membros_restantes}

        # Se o membro saindo for o criador e ainda houver membros, passa liderança para o próximo
        if str(equipe.get("criado_por")) == mid and membros_restantes:
            update_doc["criado_por"] = membros_restantes[0]

        self.collection.update_one(
            {"_id": oid},
            {"$set": update_doc},
        )
        return self.buscar_por_id(eq_id) or equipe

    def contar_equipes_criadas_por(self, usuario_id: str) -> int:
        """Conta quantas equipes foram criadas pelo usuário especificado."""
        if not usuario_id:
            return 0
        uid = str(usuario_id).strip()
        try:
            if hasattr(self.collection, "count_documents"):
                return int(self.collection.count_documents({"criado_por": uid}))
            return len(list(self.collection.find({"criado_por": uid})))
        except Exception:
            return 0


class RefreshTokensRepository:
    """Repositório seguro para persistência, rotação e revogação de Refresh Tokens (RFC 6749 / AppSec)."""

    def __init__(self, collection: Optional[Collection] = None) -> None:
        self._collection = collection

    @property
    def collection(self) -> Collection:
        if self._collection is None:
            self._collection = MongoDBConnection.get_refresh_tokens_collection()
        return self._collection

    def criar_token(
        self,
        token_hash: str,
        usuario_id: str,
        expires_seconds: int = 7 * 86400,
        ip: str = "",
        user_agent: str = "",
    ) -> dict[str, Any]:
        """Armazena o hash SHA-256 do refresh token com validade de 7 dias."""
        now_ts = int(time.time())
        doc = {
            "token_hash": token_hash,
            "usuario_id": str(usuario_id),
            "criado_em": now_ts,
            "expira_em": now_ts + expires_seconds,
            "revogado": False,
            "ip": ip,
            "user_agent": user_agent,
        }
        res = self.collection.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc

    def buscar_valido(self, token_hash: str) -> Optional[dict[str, Any]]:
        """Busca o token pelo hash. Retorna None se não existir, se estiver revogado ou se expirado."""
        now_ts = int(time.time())
        doc = self.collection.find_one({"token_hash": token_hash})
        if not doc:
            return None
        if doc.get("revogado"):
            return None
        if now_ts > doc.get("expira_em", 0):
            return None
        doc["_id"] = str(doc["_id"])
        return doc

    def buscar_qualquer(self, token_hash: str) -> Optional[dict[str, Any]]:
        """Busca o token mesmo que revogado para detecção de reuso indevido."""
        doc = self.collection.find_one({"token_hash": token_hash})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def revogar(self, token_hash: str) -> bool:
        """Revoga um refresh token específico."""
        res = self.collection.update_one(
            {"token_hash": token_hash},
            {"$set": {"revogado": True, "revogado_em": int(time.time())}},
        )
        return res.modified_count > 0

    def revogar_todos_usuario(self, usuario_id: str) -> int:
        """Revoga todas as sessões ativas do usuário (usado no logout geral ou alerta de intrusão)."""
        res = self.collection.update_many(
            {"usuario_id": str(usuario_id), "revogado": False},
            {"$set": {"revogado": True, "revogado_em": int(time.time())}},
        )
        return res.modified_count

    def excluir_todos_usuario(self, usuario_id: str) -> int:
        """Exclui permanentemente todos os registros de refresh tokens do usuário na coleção 'refresh_tokens' no MongoDB."""
        try:
            res = self.collection.delete_many({"usuario_id": str(usuario_id).strip()})
            return getattr(res, "deleted_count", 0)
        except Exception:
            return 0





