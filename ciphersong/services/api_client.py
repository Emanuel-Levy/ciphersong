"""
Cliente HTTP Resiliente para o App Mobile / Desktop (`senior-architect` + `security-specialist`).

- No APK Android, conecta-se apenas ao `CIPHERSONG_API_URL` (ex: https://sua-api.onrender.com ou http://10.0.2.2:8000),
  garantindo que a `MONGODB_URI` nunca precise ser empacotada dentro do APK.
- No ambiente Desktop local (quando a variável `MONGODB_URI` está presente na máquina do desenvolvedor
  e a API HTTP não está aberta), também oferece fallback automático para o repositório local ou cofre AES-GCM.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx


class SongsApiClient:
    """Cliente seguro para sincronizar a coleção `musicas_ensaio` sem expor credenciais no APK."""

    def __init__(self, api_base_url: Optional[str] = None, timeout: float = 4.0) -> None:
        raw_url = api_base_url or os.getenv("CIPHERSONG_API_URL") or "http://127.0.0.1:8000"
        self.api_base_url = raw_url.rstrip("/")
        self.timeout = timeout

    def listar_ou_buscar(self, query: str = "") -> tuple[list[dict[str, Any]], str]:
        """
        Retorna `(lista_de_musicas, origem_str)`.
        1º Tenta via API REST segura (`CIPHERSONG_API_URL`).
        2º Em ambiente Desktop com `.env` local, tenta conexão direta se a API local não estiver rodando.
        """
        q = query.strip()
        params = {"q": q} if q else {}
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(f"{self.api_base_url}/api/musicas", params=params)
                if resp.status_code == 200:
                    return resp.json(), "Cloud API ☁️"
        except Exception:
            pass

        # Fallback para MongoDB direto apenas se estivermos no ambiente com pymongo + MONGODB_URI configurado
        if os.getenv("MONGODB_URI"):
            try:
                from ciphersong.database.mongo_connection import MusicasEnsaioRepository
                repo = MusicasEnsaioRepository()
                docs = repo.buscar_por_filtro(q) if q else repo.listar_todas()
                return docs, "Atlas ☁️"
            except Exception:
                pass

        raise ConnectionError("API Cloud indisponível no momento.")

    def salvar_musica(self, titulo: str, cantor_principal: str, tons: list[str]) -> tuple[dict[str, Any], str]:
        """Salva a música via API REST segura (ou fallback Atlas no Desktop)."""
        payload = {
            "titulo": titulo.strip(),
            "cantor_principal": cantor_principal.strip() or "Não informado",
            "tons": [t.strip() for t in tons if t.strip()],
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.api_base_url}/api/musicas", json=payload)
                if resp.status_code in (200, 201):
                    return resp.json(), "Cloud API ☁️"
        except Exception:
            pass

        if os.getenv("MONGODB_URI"):
            from ciphersong.database.mongo_connection import MusicasEnsaioRepository
            repo = MusicasEnsaioRepository()
            doc = repo.salvar_musica(
                titulo=payload["titulo"],
                cantor_principal=payload["cantor_principal"],
                tons=payload["tons"],
            )
            return doc, "Atlas ☁️"

        raise ConnectionError("Sem conexão com a API Cloud.")

    def deletar_musica(self, song_id: str) -> bool:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.delete(f"{self.api_base_url}/api/musicas/{song_id}")
                if resp.status_code == 200:
                    return True
        except Exception:
            pass

        if os.getenv("MONGODB_URI"):
            try:
                from bson import ObjectId
                from ciphersong.database.mongo_connection import MusicasEnsaioRepository
                repo = MusicasEnsaioRepository()
                repo.collection.delete_one({"_id": ObjectId(song_id)})
                return True
            except Exception:
                pass
        return False
