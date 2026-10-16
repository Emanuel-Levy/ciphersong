"""
API Backend Segura em FastAPI para o CipherSong (`senior-architect` + `security-specialist`).

Propósito de Segurança (AppSec):
- O APK Mobile nunca armazena a `MONGODB_URI` nem a senha do banco de dados.
- Esta API roda no servidor (ou localmente durante desenvolvimento na porta 8000),
  lê a `MONGODB_URI` do `.env` seguro do servidor e expõe endpoints REST limpos
  para o APK Android/iOS e o app Desktop consumirem via HTTPS/HTTP.

Endpoints:
- GET  /health                   -> Status da API e conexão com o MongoDB Atlas
- GET  /api/musicas              -> Lista todas ou filtra por `?q=termo`
- POST /api/musicas              -> Cadastra nova música na coleção `musicas_ensaio`
- DELETE /api/musicas/{song_id}  -> Remove música pelo ID do MongoDB
"""

from __future__ import annotations

from typing import Any, Optional

from bson import ObjectId
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ciphersong.database.mongo_connection import MusicasEnsaioRepository

app = FastAPI(
    title="CipherSong Cloud API",
    description="Backend seguro para sincronização de músicas ensaiadas com o MongoDB Atlas sem expor credenciais no APK.",
    version="1.0.0",
)


class MusicaCreatePayload(BaseModel):
    titulo: str = Field(..., min_length=1, description="Nome da música ensaiada")
    cantor_principal: str = Field(..., min_length=1, description="Nome do solista / cantor principal")
    tons: list[str] = Field(..., min_length=1, description="Lista de tons da música (ex: ['G', 'Em'])")


def get_repo() -> MusicasEnsaioRepository:
    return MusicasEnsaioRepository()


@app.get("/health")
def health_check() -> dict[str, Any]:
    return {"status": "ok", "service": "ciphersong-api"}


@app.get("/api/musicas")
def listar_musicas(q: Optional[str] = Query(default=None, description="Termo de busca")) -> list[dict[str, Any]]:
    repo = get_repo()
    try:
        if q and q.strip():
            return repo.buscar_por_filtro(q.strip())
        return repo.listar_todas()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao consultar MongoDB Atlas: {exc}") from exc


@app.post("/api/musicas", status_code=201)
def criar_musica(payload: MusicaCreatePayload) -> dict[str, Any]:
    repo = get_repo()
    try:
        return repo.salvar_musica(
            titulo=payload.titulo,
            cantor_principal=payload.cantor_principal,
            tons=payload.tons,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao salvar no MongoDB Atlas: {exc}") from exc


@app.delete("/api/musicas/{song_id}")
def deletar_musica(song_id: str) -> dict[str, Any]:
    repo = get_repo()
    try:
        res = repo.collection.delete_one({"_id": ObjectId(song_id)})
        return {"deleted": res.deleted_count > 0, "id": song_id}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Não foi possível remover: {exc}") from exc
