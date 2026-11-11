"""
Suíte de Testes Unitários do MVP CipherSong (`senior-architect` + `security-specialist`).
Testa:
1. Conversão de frequência (Hz) para Nota Musical e Cents (`music_theory.py`).
2. Detecção de Pitch Vocal em sinais senoidais/harmônicos e Noise Gate (`pitch_detector.py`).
3. Estimativa de Tonalidade Musical / Escala Maior e Menor (`key_estimator.py`).
4. Criptografia Autenticada AES-256-GCM e proteção contra adulteração (`local_vault.py`).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np

from ciphersong.core.key_estimator import MusicalKeyEstimator
from ciphersong.core.music_theory import frequency_to_note
from ciphersong.core.pitch_detector import VocalPitchDetector
from ciphersong.security.local_vault import EncryptedSessionVault


class TestCipherSongMVPCore(unittest.TestCase):
    def test_frequency_to_note_conversion(self) -> None:
        # A4 = 440 Hz -> Lá4, 0 cents
        note_a4 = frequency_to_note(440.0)
        self.assertEqual(note_a4.note_en, "A")
        self.assertEqual(note_a4.note_pt, "Lá")
        self.assertEqual(note_a4.octave, 4)
        self.assertAlmostEqual(note_a4.cents_offset, 0.0, places=1)

        # C4 (Dó central) ~ 261.63 Hz
        note_c4 = frequency_to_note(261.63)
        self.assertEqual(note_c4.full_name_en, "C4")
        self.assertEqual(note_c4.full_name_pt, "Dó4")

    def test_vocal_pitch_detector_extracts_fundamental_frequency(self) -> None:
        sample_rate = 44100
        detector = VocalPitchDetector(sample_rate=sample_rate)

        # Simula voz cantando Sol3 (G3 = 196.0 Hz) com 2º harmônico
        t = np.arange(4096, dtype=np.float64) / sample_rate
        target_hz = 196.0
        signal = (
            0.6 * np.sin(2.0 * np.pi * target_hz * t)
            + 0.2 * np.sin(2.0 * np.pi * (2.0 * target_hz) * t)
        ).astype(np.float32)

        result = detector.analyze_frame(signal)
        self.assertTrue(result.is_singing)
        self.assertIsNotNone(result.note)
        assert result.note is not None
        self.assertEqual(result.note.note_en, "G")
        self.assertEqual(result.note.note_pt, "Sol")
        self.assertEqual(result.note.octave, 3)
        self.assertAlmostEqual(result.note.frequency_hz, target_hz, delta=1.5)

    def test_vocal_pitch_detector_ignores_silence(self) -> None:
        detector = VocalPitchDetector(sample_rate=44100)
        silence = np.zeros(4096, dtype=np.float32)
        result = detector.analyze_frame(silence)
        self.assertFalse(result.is_singing)
        self.assertIsNone(result.note)

    def test_musical_key_estimator_identifies_g_major(self) -> None:
        estimator = MusicalKeyEstimator(min_samples_for_estimation=6)
        # Notas da escala de Sol Maior (G, A, B, C, D, E, F#, G) com ênfase na tônica (G) e dominante (D)
        g_major_freqs = [196.0, 196.0, 220.0, 246.94, 261.63, 293.66, 293.66, 329.63, 369.99, 392.0, 392.0]

        last_estimation = None
        for hz in g_major_freqs:
            last_estimation = estimator.add_note(frequency_to_note(hz))

        self.assertIsNotNone(last_estimation)
        assert last_estimation is not None
        self.assertEqual(last_estimation.key_en, "G")
        self.assertEqual(last_estimation.key_pt, "Sol Maior")
        self.assertEqual(last_estimation.relative_key_en, "Em")
        self.assertGreaterEqual(last_estimation.confidence, 0.70)

    def test_encrypted_session_vault_aes_gcm_roundtrip_and_tamper_protection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_file = Path(tmp_dir) / "test_vault.enc"
            vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="strong-secret-key")

            rec = vault.create_record(
                key_pt="Sol Maior",
                key_en="G",
                relative_pt="Mi Menor",
                confidence=0.92,
                last_note="Sol3",
                last_freq_hz=196.0,
            )
            vault.save_record(rec)

            # Garante que o arquivo em disco não contém texto aberto ("Sol Maior")
            raw_content = vault_file.read_text(encoding="utf-8")
            self.assertNotIn("Sol Maior", raw_content)
            self.assertIn("AES-256-GCM", raw_content)

            # Descriptografa com a chave correta
            loaded = vault.load_records()
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].detected_key_pt, "Sol Maior")
            self.assertEqual(loaded[0].confidence_pct, 92)

            # Tenta ler com senha incorreta -> deve retornar lista vazia (proteção GCM)
            wrong_vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="wrong-password")
            self.assertEqual(wrong_vault.load_records(), [])

    def test_rehearsed_songs_multiple_keys_and_search(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_file = Path(tmp_dir) / "songs_vault.enc"
            vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="secret")

            vault.save_song(
                title="Bondade de Deus",
                keys=["G (Sol)", "A (Lá)"],
                soloist="Levy",
            )
            vault.save_song(
                title="Oceanos",
                keys=["D (Ré)", "Bm (Sim)"],
                soloist="Ana",
            )

            all_songs = vault.load_songs()
            self.assertEqual(len(all_songs), 2)
            self.assertEqual(all_songs[0].title, "Oceanos")
            self.assertEqual(all_songs[1].keys, ["G (Sol)", "A (Lá)"])

            # Pesquisa por nome da música
            res_title = vault.search_songs("Bondade")
            self.assertEqual(len(res_title), 1)
            self.assertEqual(res_title[0].soloist, "Levy")

            # Pesquisa por solista
            res_soloist = vault.search_songs("ana")
            self.assertEqual(len(res_soloist), 1)
            self.assertEqual(res_soloist[0].title, "Oceanos")

            # Pesquisa por tom
            res_key = vault.search_songs("A (Lá)")
            self.assertEqual(len(res_key), 1)
            self.assertEqual(res_key[0].title, "Bondade de Deus")

    def test_key_estimator_top_three_keys(self) -> None:
        """Garante que o estimador calcula o 1º, 2º e 3º tons mais prováveis."""
        estimator = MusicalKeyEstimator(min_samples_for_estimation=5)
        # Frequências da escala de Sol Maior (G, B, D, C, E, F#)
        g_notes_hz = [196.0, 246.94, 293.66, 196.0, 261.63, 329.63, 369.99]
        for hz in g_notes_hz:
            estimator.add_note(frequency_to_note(hz))

        estimation = estimator.estimate_current_key()
        self.assertIsNotNone(estimation)
        assert estimation is not None
        self.assertEqual(estimation.key_en, "G")
        self.assertTrue(estimation.second_key_en != "")
        self.assertTrue(estimation.third_key_en != "")
        self.assertGreaterEqual(estimation.confidence, estimation.second_confidence)
        self.assertGreaterEqual(estimation.second_confidence, estimation.third_confidence)

    def test_vault_offline_sync_and_filter(self) -> None:
        """Testa o ciclo de sincronização offline e marcação de sincronizado."""
        with tempfile.TemporaryDirectory() as temp_dir:
            vault_file = Path(temp_dir) / "test_sync_vault.enc"
            vault = EncryptedSessionVault(vault_path=vault_file, secret_passphrase="test-sync-key")

            # Salva música offline
            s1 = vault.save_song(
                title="Música Offline",
                keys=["C (Dó)"],
                soloist="Gabriel",
                versao="Acústico",
                synced=False,
            )
            s2 = vault.save_song(
                title="Música Online",
                keys=["D (Ré)"],
                soloist="Mariana",
                synced=True,
            )

            unsynced = vault.get_unsynced_songs()
            self.assertEqual(len(unsynced), 1)
            self.assertEqual(unsynced[0].id, s1.id)

            # Marca como sincronizado
            vault.mark_song_as_synced(s1.id)
            self.assertEqual(len(vault.get_unsynced_songs()), 0)

            # Filtro estrito por solista
            res_gabriel = vault.search_songs(soloist="Gabriel")
            self.assertEqual(len(res_gabriel), 1)
            self.assertEqual(res_gabriel[0].title, "Música Offline")

            res_mariana = vault.search_songs(soloist="Mariana")
            self.assertEqual(len(res_mariana), 1)
            self.assertEqual(res_mariana[0].title, "Música Online")

    def test_key_estimator_eu_navegarei_identifies_a_minor(self) -> None:
        """
        Simula o canto de 'Eu Navegarei', onde a nota Mi (5ª de Am) é atacada e sustentada,
        mas o desenvolvimento da melodia (Lá, Si, Dó, Ré, Fá, Sol#) resolve inequivocamente em Lá Menor (Am).
        """
        estimator = MusicalKeyEstimator(min_samples_for_estimation=5)
        # Mi sustentado (329.63 Hz)
        for _ in range(4):
            estimator.add_note(frequency_to_note(329.63))

        # Frase melódica desenvolvida: Lá (440), Si (493.88), Dó (523.25), Ré (587.33), Fá (349.23), Sol# (415.30), Lá (440)
        melodic_phrase_hz = [440.0, 493.88, 523.25, 493.88, 587.33, 349.23, 415.30, 440.0, 440.0]
        final_est = None
        for hz in melodic_phrase_hz:
            final_est = estimator.add_note(frequency_to_note(hz))

        self.assertIsNotNone(final_est)
        assert final_est is not None
        self.assertEqual(final_est.key_en, "Am")
        self.assertEqual(final_est.key_pt, "Lá Menor")
        self.assertEqual(final_est.relative_key_en, "C")

    def test_all_application_modules_import_cleanly(self) -> None:
        """Garante que todos os módulos, serviços, views e submódulos importam sem ModuleNotFoundError."""
        import importlib
        modules = [
            "ciphersong.core",
            "ciphersong.core.music_theory",
            "ciphersong.core.key_estimator",
            "ciphersong.core.pitch_detector",
            "ciphersong.core.encrypted_vault",
            "ciphersong.database",
            "ciphersong.security",
            "ciphersong.security.local_vault",
            "ciphersong.services",
            "ciphersong.services.api_client",
            "ciphersong.services.email_service",
            "ciphersong.services.microphone_stream",
            "ciphersong.services.microphone",
            "ciphersong.ui",
            "ciphersong.ui.views.auth_view",
            "ciphersong.ui.views.detector_view",
            "ciphersong.ui.views.repertoire_view",
            "ciphersong.ui.views.team_view",
            "ciphersong.ui.views.to_rehearse_view",
            "ciphersong.ui.views.weekly_view",
            "ciphersong.ui.app_flet",
            "main",
        ]
        for m in modules:
            with self.subTest(module=m):
                mod = importlib.import_module(m)
                self.assertIsNotNone(mod)

    def test_ciphersong_app_and_views_instantiation(self) -> None:
        """Garante que todas as views modulares e build_ciphersong_app instanciam controles Flet sem erro de kwargs."""
        import asyncio
        from unittest.mock import MagicMock
        from ciphersong.ui.app_flet import build_ciphersong_app
        mock_page = MagicMock()
        mock_page.overlay = []
        res = build_ciphersong_app(mock_page)
        if asyncio.iscoroutine(res):
            asyncio.run(res)


if __name__ == "__main__":
    unittest.main()
