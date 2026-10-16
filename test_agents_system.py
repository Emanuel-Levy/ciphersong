"""
Testes unitários para o sistema de agentes do CipherSong (`agents_system.py`).
Valida os 4 agentes (Simples, Complexo/Arquiteto, UI/UX e Segurança),
o roteamento automático e o mecanismo de perguntas ao usuário em caso de dúvida.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import Any

from agents_system import (
    AgentRole,
    CipherSongAgentTeam,
)


@dataclass
class FakeUsage:
    prompt_token_count: int = 150
    candidates_token_count: int = 60
    total_token_count: int = 210


@dataclass
class FakeInteraction:
    id: str
    output_text: str
    usage: Any = field(default_factory=FakeUsage)


class MockInteractionsClient:
    """Mock da API `client.interactions` do SDK `google-genai`."""

    def __init__(self, responses: list[FakeInteraction]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> FakeInteraction:
        self.calls.append(kwargs)
        if not self.responses:
            return FakeInteraction(id="int-default", output_text="Resposta padrão concluída.")
        return self.responses.pop(0)


class TestCipherSongAgents(unittest.TestCase):
    def test_automatic_routing_for_all_four_roles(self) -> None:
        team = CipherSongAgentTeam(interactions_api=MockInteractionsClient([]))

        self.assertEqual(
            team.route_task("Formate esta string JSON simples"),
            AgentRole.SIMPLE,
        )
        self.assertEqual(
            team.route_task("Defina a arquitetura POO e banco de dados do MVP"),
            AgentRole.COMPLEX,
        )
        self.assertEqual(
            team.route_task("Crie o layout responsivo e dark mode para a tela inicial"),
            AgentRole.UI_UX,
        )
        self.assertEqual(
            team.route_task("Implemente criptografia AES e proteção de senha no app"),
            AgentRole.SECURITY,
        )

    def test_agent_asks_user_when_in_doubt_and_continues(self) -> None:
        mock_api = MockInteractionsClient(
            responses=[
                FakeInteraction(
                    id="int-1",
                    output_text=(
                        "[PERGUNTA_AO_USUARIO]\n"
                        "- Qual framework de UI você prefere para o MVP Desktop (Flet ou PySide6)?\n"
                        "- Prefere tema escuro (Dark Mode) por padrão?"
                    ),
                ),
                FakeInteraction(
                    id="int-2",
                    output_text="Layout configurado com Flet e Dark Mode ativado por padrão!",
                ),
            ]
        )
        team = CipherSongAgentTeam(interactions_api=mock_api)

        asked_questions: list[str] = []

        def fake_user_callback(questions: list[str]) -> str:
            asked_questions.extend(questions)
            return "1. Flet. 2. Sim, Dark Mode por padrão."

        response = team.ask_agent(
            prompt="Crie a tela principal do app",
            role=AgentRole.UI_UX,
            ask_user_callback=fake_user_callback,
        )

        self.assertEqual(len(asked_questions), 2)
        self.assertIn("Flet", asked_questions[0])
        self.assertFalse(response.needs_clarification)
        self.assertEqual(response.interaction_id, "int-2")
        self.assertIn("Flet e Dark Mode", response.output_text)
        # Verifica que a segunda chamada enviou o previous_interaction_id="int-1"
        self.assertEqual(mock_api.calls[1].get("previous_interaction_id"), "int-1")

    def test_security_agent_uses_gemini_4_argon(self) -> None:
        mock_api = MockInteractionsClient(
            responses=[
                FakeInteraction(
                    id="int-sec-1",
                    output_text="Use Argon2id para hash de senhas e AES-256-GCM para dados locais.",
                )
            ]
        )
        team = CipherSongAgentTeam(interactions_api=mock_api)
        res = team.ask_agent("Como proteger senhas localmente?", role=AgentRole.SECURITY)

        self.assertEqual(res.role, AgentRole.SECURITY)
        self.assertEqual(res.model_or_agent, "gemini-4-argon")
        self.assertIn("Argon2id", res.output_text)

    def test_agent_response_metadata_and_tokens(self) -> None:
        mock_api = MockInteractionsClient(
            responses=[
                FakeInteraction(
                    id="int-token-test",
                    output_text="Validação de regex concluída com sucesso.",
                    usage=FakeUsage(prompt_token_count=120, candidates_token_count=45, total_token_count=165),
                )
            ]
        )
        team = CipherSongAgentTeam(interactions_api=mock_api)
        res = team.ask_agent(
            prompt="Valide regex",
            role=AgentRole.SIMPLE,
            action_description="Criando e validando expressão regular",
        )

        self.assertEqual(res.role, AgentRole.SIMPLE)
        self.assertEqual(res.action_description, "Criando e validando expressão regular")
        self.assertEqual(res.input_tokens, 120)
        self.assertEqual(res.output_tokens, 45)
        self.assertEqual(res.total_tokens, 165)
        summary = res.format_summary()
        self.assertIn("fast-helper", summary)
        self.assertIn("165", summary)
        self.assertIn("Criando e validando expressão regular", summary)


if __name__ == "__main__":
    unittest.main()
