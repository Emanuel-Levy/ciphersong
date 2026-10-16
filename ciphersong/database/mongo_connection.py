"""
Módulo de conexão e operações com o MongoDB Atlas para o CipherSong.
Gerencia a coleção 'musicas_ensaio' com validação de esquema:
- titulo (str, obrigatório)
- cantor_principal (str, obrigatório)
- tons (list[str], obrigatório)
"""

from __future__ import annotations

import os
from typing import Any, Optional

from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

load_dotenv()


class MongoDBConnection:
    """Gerenciador singleton para conexão com o cluster MongoDB Atlas."""

    _client: Optional[MongoClient] = None

    @classmethod
    def get_client(cls, uri: Optional[str] = None) -> MongoClient:
        if cls._client is None:
            connection_uri = uri or os.getenv("MONGODB_URI")
            if not connection_uri:
                raise ValueError(
                    "A variável de ambiente 'MONGODB_URI' não foi definida no arquivo .env."
                )
            cls._client = MongoClient(
                connection_uri,
                serverSelectionTimeoutMS=5000,
                appname="CipherSong",
            )
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
    def close(cls) -> None:
        """Encerra a conexão com o MongoDB Atlas."""
        if cls._client is not None:
            cls._client.close()
            cls._client = None


class MusicasEnsaioRepository:
    """Repositório de operações para a coleção 'musicas_ensaio'."""

    def __init__(self, collection: Optional[Collection] = None) -> None:
        self._collection = collection

    @property
    def collection(self) -> Collection:
        if self._collection is None:
            self._collection = MongoDBConnection.get_musicas_ensaio_collection()
        return self._collection

    @staticmethod
    def validar_documento(titulo: str, cantor_principal: str, tons: list[str]) -> dict[str, Any]:
        """
        Valida se os campos obrigatórios atendem ao formato exigido:
        - titulo (String, obrigatório)
        - cantor_principal (String, obrigatório)
        - tons (Array de Strings, obrigatório)
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

        return {
            "titulo": titulo.strip(),
            "cantor_principal": cantor_principal.strip(),
            "tons": [t.strip() for t in tons],
        }

    def salvar_musica(self, titulo: str, cantor_principal: str, tons: list[str]) -> dict[str, Any]:
        """Insere uma nova música de ensaio na coleção 'musicas_ensaio'."""
        documento = self.validar_documento(titulo, cantor_principal, tons)
        result = self.collection.insert_one(documento)
        documento["_id"] = str(result.inserted_id)
        return documento

    def listar_todas(self) -> list[dict[str, Any]]:
        """Lista todas as músicas de ensaio cadastradas."""
        cursor = self.collection.find()
        resultado = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            resultado.append(doc)
        return resultado

    def buscar_por_filtro(self, termo: str) -> list[dict[str, Any]]:
        """Busca músicas por título, cantor_principal ou tom."""
        query = {
            "$or": [
                {"titulo": {"$regex": termo, "$options": "i"}},
                {"cantor_principal": {"$regex": termo, "$options": "i"}},
                {"tons": {"$elemMatch": {"$regex": termo, "$options": "i"}}},
            ]
        }
        cursor = self.collection.find(query)
        resultado = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            resultado.append(doc)
        return resultado
