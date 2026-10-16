"""
Sistema Multi-Agente para o projeto CipherSong (MVP Desktop -> App Mobile).

Utiliza a Interactions API oficial do Google Gemini (`google-genai >= 2.30.1`)
com suporte a:
- Agente de Tarefas Simples (`fast-helper`) -> `gemini-3.8-flash`
- Agente de Tarefas Complexas / Arquitetura (`senior-architect`) -> `gemini-4-argon` ou `antigravity-preview-09-2026`
- Agente de Layout & UI/UX (`ui-ux-designer`) -> `gemini-4-argon`
- Agente de Segurança / AppSec (`security-specialist`) -> `gemini-4-argon`

Todos os agentes seguem a diretriz de perguntar ao usuário caso haja dúvidas
ou ambiguidades antes de tomar decisões críticas.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Protocol

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class AgentRole(str, Enum):
    """Papéis disponíveis na equipe de agentes do CipherSong."""
    SIMPLE = "fast-helper"
    COMPLEX = "senior-architect"
    UI_UX = "ui-ux-designer"
    SECURITY = "security-specialist"


@dataclass
class AgentResponse:
    """Representa o retorno padronizado de um agente de IA com rastreamento de tokens."""
    role: AgentRole
    model_or_agent: str
    action_description: str
    output_text: str
    interaction_id: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    needs_clarification: bool = False
    questions: list[str] = field(default_factory=list)

    def format_summary(self) -> str:
        """Retorna cabeçalho formatado exibindo quem é o agente, o que está fazendo e os tokens gastos."""
        return (
            f"┌─────────────────────────────────────────────────────────────┐\n"
            f"│ 🤖 AGENTE: [{self.role.value}] ({self.model_or_agent})\n"
            f"│ 🎯 AÇÃO:   {self.action_description}\n"
            f"│ 📊 TOKENS: {self.total_tokens} (Entrada: {self.input_tokens} | Saída: {self.output_tokens})\n"
            f"└─────────────────────────────────────────────────────────────┘"
        )


class InteractionsClientProtocol(Protocol):
    """Protocolo para facilitar injeção de dependência e testes unitários."""
    def create(self, **kwargs: Any) -> Any:
        ...


class BaseSpecialistAgent:
    """Classe base para os agentes especialistas do CipherSong."""

    QUESTION_MARKER = "[PERGUNTA_AO_USUARIO]"

    def __init__(
        self,
        role: AgentRole,
        model: str,
        system_instruction: str,
        default_action: str = "Executando análise especializada",
        interactions_api: Optional[InteractionsClientProtocol] = None,
    ) -> None:
        self.role = role
        self.model = model
        self.default_action = default_action
        self.system_instruction = (
            f"{system_instruction.strip()}\n\n"
            "DIRETRIZ DE TRANSPARÊNCIA E IDENTIDADE OBRIGATÓRIA:\n"
            f"Sempre inicie sua resposta se identificando como o agente '{self.role.value}' "
            "e descrevendo resumidamente o que você analisou ou executou.\n\n"
            "DIRETRIZ INTERATIVA OBRIGATÓRIA:\n"
            "Se o pedido do usuário estiver incompleto, ambíguo ou exigir uma escolha importante "
            "(sobre layout, arquitetura, regra de negócio ou nível de segurança), "
            f"inicie sua resposta com a tag {self.QUESTION_MARKER} e liste perguntas diretas e claras "
            "para o usuário antes de gerar a solução final."
        )
        self._interactions_api = interactions_api
        self.last_interaction_id: Optional[str] = None

    def _get_interactions_api(self) -> InteractionsClientProtocol:
        if self._interactions_api is not None:
            return self._interactions_api

        from google import genai
        api_key = os.getenv("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key) if api_key else genai.Client()
        self._interactions_api = client.interactions
        return self._interactions_api

    def run(
        self,
        prompt: str,
        action_description: Optional[str] = None,
        previous_interaction_id: Optional[str] = None,
        ask_user_callback: Optional[Callable[[list[str]], str]] = None,
    ) -> AgentResponse:
        """
        Executa uma interação com o agente, colhendo o uso de tokens e registrando quem e o que está fazendo.
        """
        api = self._get_interactions_api()
        prev_id = previous_interaction_id or self.last_interaction_id
        action = action_description or self.default_action

        kwargs: dict[str, Any] = {
            "model": self.model,
            "input": prompt,
            "system_instruction": self.system_instruction,
        }
        if prev_id:
            kwargs["previous_interaction_id"] = prev_id

        interaction = api.create(**kwargs)
        self.last_interaction_id = getattr(interaction, "id", None)
        text = getattr(interaction, "output_text", "") or ""

        # Extração de métricas de tokens da resposta da API
        usage = getattr(interaction, "usage", None)
        input_tokens = getattr(usage, "prompt_token_count", 0) or getattr(usage, "input_tokens", 0) or 0
        output_tokens = getattr(usage, "candidates_token_count", 0) or getattr(usage, "output_tokens", 0) or 0
        total_tokens = getattr(usage, "total_token_count", 0) or getattr(usage, "total_tokens", 0) or (input_tokens + output_tokens)

        needs_clarification, questions = self._extract_questions(text)

        if needs_clarification and ask_user_callback is not None:
            user_answer = ask_user_callback(questions)
            return self.run(
                prompt=f"Respostas do usuário às suas dúvidas:\n{user_answer}",
                action_description=f"Processando respostas do usuário para {action}",
                previous_interaction_id=self.last_interaction_id,
                ask_user_callback=None,
            )

        return AgentResponse(
            role=self.role,
            model_or_agent=self.model,
            action_description=action,
            output_text=text,
            interaction_id=self.last_interaction_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            needs_clarification=needs_clarification,
            questions=questions,
        )

    @classmethod
    def _extract_questions(cls, text: str) -> tuple[bool, list[str]]:
        """Verifica se o agente solicitou esclarecimento ao usuário."""
        if cls.QUESTION_MARKER not in text:
            return False, []

        lines = [
            line.strip("- *•\t ")
            for line in text.splitlines()
            if line.strip().endswith("?")
        ]
        if not lines:
            cleaned = text.replace(cls.QUESTION_MARKER, "").strip()
            lines = [cleaned] if cleaned else ["Poderia fornecer mais detalhes sobre sua solicitação?"]
        return True, lines


class SimpleTaskAgent(BaseSpecialistAgent):
    """Agente rápido (`fast-helper`) para tarefas simples, regex, scripts curtos e formatação."""

    def __init__(self, interactions_api: Optional[InteractionsClientProtocol] = None) -> None:
        super().__init__(
            role=AgentRole.SIMPLE,
            model="gemini-3.8-flash",
            default_action="Processando utilitário rápido / regex / formatação",
            system_instruction=(
                "Você é o Fast Helper do projeto CipherSong (MVP Desktop & App Mobile). "
                "Sua missão é resolver tarefas rápidas, criar expressões regulares, funções utilitárias, "
                "manipulação de JSON/strings e scripts isolados em Python com tipagem estática (type hints). "
                "Seja conciso e direto."
            ),
            interactions_api=interactions_api,
        )


class ComplexTaskAgent(BaseSpecialistAgent):
    """Agente arquiteto (`senior-architect`) para tarefas complexas, POO, banco de dados e testes."""

    def __init__(self, interactions_api: Optional[InteractionsClientProtocol] = None) -> None:
        super().__init__(
            role=AgentRole.COMPLEX,
            model="gemini-4-argon",
            default_action="Planejando arquitetura / banco de dados / lógica complexa",
            system_instruction=(
                "Você é o Senior Architect do projeto CipherSong (um app mobile com MVP inicial no Desktop). "
                "Projete arquiteturas modulares que separem regras de negócio (core/services) da interface (UI), "
                "aplique boas práticas de POO, sugira dependências externas adequadas quando necessário e "
                "escreva testes unitários com pytest."
            ),
            interactions_api=interactions_api,
        )

    def run_in_sandbox(self, prompt: str) -> AgentResponse:
        """
        Executa uma tarefa complexa usando o Agente Gerenciado Antigravity (`antigravity-preview-09-2026`)
        em um ambiente Linux isolado (sandbox remoto).
        """
        api = self._get_interactions_api()
        action = "Executando código e testes em Sandbox Remoto Linux"
        interaction = api.create(
            agent="antigravity-preview-09-2026",
            input=prompt,
            system_instruction=self.system_instruction,
            environment="remote",
        )
        self.last_interaction_id = getattr(interaction, "id", None)
        text = getattr(interaction, "output_text", "") or ""
        usage = getattr(interaction, "usage", None)
        input_tokens = getattr(usage, "prompt_token_count", 0) or getattr(usage, "input_tokens", 0) or 0
        output_tokens = getattr(usage, "candidates_token_count", 0) or getattr(usage, "output_tokens", 0) or 0
        total_tokens = getattr(usage, "total_token_count", 0) or getattr(usage, "total_tokens", 0) or (input_tokens + output_tokens)

        needs_clarification, questions = self._extract_questions(text)

        return AgentResponse(
            role=self.role,
            model_or_agent="antigravity-preview-09-2026",
            action_description=action,
            output_text=text,
            interaction_id=self.last_interaction_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            needs_clarification=needs_clarification,
            questions=questions,
        )


class UIUXLayoutAgent(BaseSpecialistAgent):
    """Agente especialista em UI/UX (`ui-ux-designer`) para o layout do MVP Desktop e futuro App Mobile."""

    def __init__(self, interactions_api: Optional[InteractionsClientProtocol] = None) -> None:
        super().__init__(
            role=AgentRole.UI_UX,
            model="gemini-4-argon",
            default_action="Desenhando layout responsivo / temas / componentes visuais",
            system_instruction=(
                "Você é o Especialista em UI/UX e Layout do projeto CipherSong (MVP Desktop com foco em Mobile). "
                "Sua missão é criar interfaces modernas, responsivas e intuitivas, definir paletas de cores, "
                "tipografia, temas (Dark/Light mode) e componentes reutilizáveis (ex: usando Flet/Flutter em Python, "
                "CustomTkinter ou PySide6). Garanta que o layout funcione bem na janela Desktop do MVP e possa "
                "ser facilmente adaptado para telas verticais Mobile."
            ),
            interactions_api=interactions_api,
        )


class SecuritySpecialistAgent(BaseSpecialistAgent):
    """Agente especialista em Segurança (`security-specialist`) para proteção do app, criptografia e autenticação."""

    def __init__(self, interactions_api: Optional[InteractionsClientProtocol] = None) -> None:
        super().__init__(
            role=AgentRole.SECURITY,
            model="gemini-4-argon",
            default_action="Auditando segurança / criptografia AES-GCM / proteção de dados",
            system_instruction=(
                "Você é o Especialista em Segurança da Informação (AppSec) do projeto CipherSong (MVP Desktop & Mobile). "
                "Sua missão é proteger os dados do aplicativo, implementar criptografia forte (ex: AES-GCM, ChaCha20, "
                "Argon2 via biblioteca `cryptography` e `argon2-cffi`), gerenciar segredos e variáveis de ambiente com "
                "segurança, validar entradas de usuários e prevenir vulnerabilidades (OWASP Top 10 Desktop/Mobile)."
            ),
            interactions_api=interactions_api,
        )


class CipherSongAgentTeam:
    """
    Orquestrador central que reúne os 4 agentes do projeto CipherSong
    e roteia tarefas automaticamente ou sob demanda.
    """

    def __init__(self, interactions_api: Optional[InteractionsClientProtocol] = None) -> None:
        self.fast_helper = SimpleTaskAgent(interactions_api=interactions_api)
        self.senior_architect = ComplexTaskAgent(interactions_api=interactions_api)
        self.ui_ux_designer = UIUXLayoutAgent(interactions_api=interactions_api)
        self.security_specialist = SecuritySpecialistAgent(interactions_api=interactions_api)

        self._agents: dict[AgentRole, BaseSpecialistAgent] = {
            AgentRole.SIMPLE: self.fast_helper,
            AgentRole.COMPLEX: self.senior_architect,
            AgentRole.UI_UX: self.ui_ux_designer,
            AgentRole.SECURITY: self.security_specialist,
        }

    def route_task(self, task_description: str) -> AgentRole:
        """
        Analisa palavras-chave completas da tarefa para selecionar automaticamente o agente ideal.
        """
        import re

        text = task_description.lower()

        def count_matches(keywords: tuple[str, ...]) -> int:
            return sum(
                1 for kw in keywords
                if re.search(rf"\b{re.escape(kw)}\b", text)
            )

        security_keywords = (
            "segurança", "seguranca", "criptografia", "criptografar", "senha",
            "senhas", "hash", "token", "jwt", "autenticação", "autenticacao",
            "vulnerabilidade", "chave", "aes", "rsa", "argon2", "proteger",
            "vazamento", "permissão",
        )
        ui_keywords = (
            "layout", "tela", "telas", "visual", "ui", "ux", "botão", "botao",
            "tema", "dark mode", "responsivo", "interface", "flet", "janela",
            "menu", "ícone", "icone", "design", "estilo",
        )
        complex_keywords = (
            "arquitetura", "banco de dados", "sqlite", "refatorar", "refatoração",
            "poo", "classe", "integração", "api", "concorrência", "assíncrono",
            "estrutura", "pipeline", "módulo", "camadas", "sincronizar", "pytest",
        )
        simple_keywords = (
            "regex", "expressão regular", "validar", "formate", "formatar",
            "script", "função simples", "json", "string",
        )

        scores = {
            AgentRole.SECURITY: count_matches(security_keywords),
            AgentRole.UI_UX: count_matches(ui_keywords),
            AgentRole.COMPLEX: count_matches(complex_keywords),
            AgentRole.SIMPLE: count_matches(simple_keywords),
        }

        best_role = max(scores, key=lambda r: scores[r])
        if scores[best_role] == 0:
            return AgentRole.SIMPLE
        return best_role

    def ask_agent(
        self,
        prompt: str,
        role: Optional[AgentRole] = None,
        action_description: Optional[str] = None,
        ask_user_callback: Optional[Callable[[list[str]], str]] = None,
    ) -> AgentResponse:
        """
        Envia uma tarefa para um agente específico (ou roteia automaticamente se `role` for None).
        Exibe no console quem é o agente, o que está fazendo e os tokens gastos.
        """
        selected_role = role or self.route_task(prompt)
        agent = self._agents[selected_role]
        response = agent.run(
            prompt=prompt,
            action_description=action_description,
            ask_user_callback=ask_user_callback,
        )
        print(response.format_summary())
        return response


def cli_question_handler(questions: list[str]) -> str:
    """Callback padrão de terminal para quando um agente tem dúvidas e pergunta ao usuário."""
    print("\n[?] O Agente precisa esclarecer algumas dúvidas antes de continuar:")
    answers: list[str] = []
    for idx, q in enumerate(questions, start=1):
        print(f"  {idx}. {q}")
        ans = input("  Sua resposta: ").strip()
        answers.append(f"Pergunta {idx} ({q}): {ans}")
    return "\n".join(answers)


if __name__ == "__main__":
    team = CipherSongAgentTeam()
    exemplos = [
        "Crie uma regex para validar código hexadecimal de cor.",
        "Desenhe o layout da tela inicial do player/cifras com tema escuro para o MVP Desktop pensando no Mobile.",
        "Como devemos criptografar os arquivos de música/cifras salvos localmente no dispositivo?",
        "Defina a arquitetura de camadas para sincronizar dados locais SQLite entre o MVP Desktop e o futuro app Mobile.",
    ]
    print("=== Simulação de Roteamento da Equipe de Agentes CipherSong ===")
    for ex in exemplos:
        papel = team.route_task(ex)
        agente = team._agents[papel]
        print(f"🤖 Agente: [{papel.value}] ({agente.model})")
        print(f"🎯 Ação:   {agente.default_action}")
        print(f"📝 Tarefa: {ex!r}\n")
