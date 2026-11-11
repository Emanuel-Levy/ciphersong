"""
Testes unitários para a conexão e validação da coleção 'musicas_ensaio' do MongoDB Atlas.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from ciphersong.database.mongo_connection import MusicasEnsaioRepository


class TestMusicasEnsaioMongo(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_collection = MagicMock()
        self.repo = MusicasEnsaioRepository(collection=self.mock_collection)

    def test_validar_documento_com_sucesso(self) -> None:
        doc = self.repo.validar_documento(
            titulo="Bondade de Deus",
            cantor_principal="Levy",
            tons=["G", "Em"],
        )
        self.assertEqual(doc["titulo"], "Bondade de Deus")
        self.assertEqual(doc["cantor_principal"], "Levy")
        self.assertEqual(doc["tons"], ["G", "Em"])

    def test_validar_documento_sem_titulo(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.repo.validar_documento(
                titulo="",
                cantor_principal="Levy",
                tons=["G"],
            )
        self.assertIn("titulo", str(ctx.exception))

    def test_validar_documento_sem_cantor_principal(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.repo.validar_documento(
                titulo="Oceanos",
                cantor_principal="   ",
                tons=["D"],
            )
        self.assertIn("cantor_principal", str(ctx.exception))

    def test_validar_documento_sem_tons_ou_tons_vazios(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.repo.validar_documento(
                titulo="Oceanos",
                cantor_principal="Ana",
                tons=[],
            )
        self.assertIn("tons", str(ctx.exception))

    def test_salvar_musica_no_mongodb(self) -> None:
        mock_result = MagicMock()
        mock_result.inserted_id = "652d8e4f1a2b3c4d5e6f7a8b"
        self.mock_collection.insert_one.return_value = mock_result

        doc = self.repo.salvar_musica(
            titulo="Graça Infalível",
            cantor_principal="Levy",
            tons=["A", "F#m"],
        )

        self.mock_collection.insert_one.assert_called_once()
        self.assertEqual(doc["_id"], "652d8e4f1a2b3c4d5e6f7a8b")
        self.assertEqual(doc["titulo"], "Graça Infalível")
        self.assertEqual(doc["tons"], ["A", "F#m"])
        self.assertEqual(doc["versao"], "Original")

    def test_salvar_musica_com_versao_personalizada(self) -> None:
        mock_result = MagicMock()
        mock_result.inserted_id = "111122223333444455556666"
        self.mock_collection.insert_one.return_value = mock_result

        doc = self.repo.salvar_musica(
            titulo="Bondade de Deus",
            cantor_principal="Geisa",
            tons=["D (Ré)"],
            versao="Gabriel Guedes",
        )
        self.assertEqual(doc["versao"], "Gabriel Guedes")

    def test_buscar_por_filtro_com_cantor(self) -> None:
        self.mock_collection.find.return_value = [
            {"_id": "1", "titulo": "Bondade de Deus", "cantor_principal": "Geisa", "tons": ["D"], "versao": "Gabriel Guedes"}
        ]
        res = self.repo.buscar_por_filtro(termo="Bondade", cantor="Geisa")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["versao"], "Gabriel Guedes")


if __name__ == "__main__":
    unittest.main()
