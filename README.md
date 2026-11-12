# 🎸 CipherSong — Sistema Completo de Gestão de Cifras & Equipes de Louvor

Bem-vindo ao workspace oficial do **CipherSong**!  
Este documento é o guia definitivo de arquitetura, funcionamento técnico e manutenção do projeto. Ele foi estruturado para que qualquer desenvolvedor entenda **todas as conexões do sistema**, onde cada arquivo vive e **onde mexer para alterar algo específico**.

---

## 📑 Sumário
1. [Visão Geral do Produto](#-1-visão-geral-do-produto)
2. [Arquitetura & Ligações Ponta a Ponta](#-2-arquitetura--ligações-ponta-a-ponta)
3. [Stack Tecnológica Completa](#-3-stack-tecnológica-completa)
4. [Estrutura de Pastas e Arquivos](#-4-estrutura-de-pastas-e-arquivos)
5. [Catálogo de APIs e Endpoints](#-5-catálogo-de-apis-e-endpoints)
6. [Guia Prático: Onde Mexer para Alterar Algo Específico](#-6-guia-prático-onde-mexer-para-alterar-algo-específico)
7. [Como Executar Localmente](#-7-como-executar-localmente)
8. [Fluxo de Deploy e Sincronização](#-8-fluxo-de-deploy-e-sincronização)

---

## 🎯 1. Visão Geral do Produto

O **CipherSong** é uma plataforma SaaS (Software as a Service) voltada para músicos, ministérios de louvor, bandas e igrejas. Suas principais capacidades incluem:
* **Transposição Inteligente de Tom:** Recálculo harmônico automático de acordes e acidentes musicais em tempo real.
* **Sincronização em Banda (WebSockets):** O líder altera o tom ou adiciona uma música e toda a equipe vê a atualização instantaneamente.
* **Auto-Scroll com Aceleração Suave:** Rolagem contínua para tocar com as mãos 100% livres nos instrumentos.
* **Ferramentas Integradas:** Afinador cromático via microfone e metrônomo visual/sonoro.
* **PWA & Modo Offline:** Aplicativo instalável no PC ou celular, com funcionamento local mesmo sem sinal de internet.
* **Planos & Faturamento (SaaS):** Gestão de planos Free (Essencial), Pro e Ministério com limites de integrantes, músicas e equipes.

---

## 🌐 2. Arquitetura & Ligações Ponta a Ponta

O sistema adota uma arquitetura desacoplada e moderna:

```mermaid
flowchart TD
    subgraph Client["Cliente (Navegador & PWA / Mobile)"]
        SPA["React 19 + TypeScript (Vercel CDN)"]
        LocalStore["Armazenamento Seguro: Token 24h & Cache"]
    end

    subgraph CDN["Infraestrutura de Borda (Vercel)"]
        VercelEdge["Vercel Edge Network"]
        Analytics["Speed Insights & Vercel Analytics"]
        AdSense["Google AdSense (ads.txt) & Search Console"]
    end

    subgraph Backend["API & Tempo Real (Render Cloud)"]
        FastAPI["FastAPI + Uvicorn (backend_api.py)"]
        WS["WebSockets Hub (/api/ws/events)"]
        AuthJWT["Cofre Auth (JWT 24h + Refresh 7d)"]
    end

    subgraph Database["Persistência em Nuvem"]
        MongoDB["MongoDB Atlas (Cluster pymongo)"]
    end

    subgraph Automation["Automações & Terceiros"]
        GitHubActions["GitHub Actions (Keep-Alive Cron 12m)"]
        GoogleOAuth["Google OAuth 2.0 (SSO)"]
    end

    SPA -->|Requisições REST & JSON| FastAPI
    SPA <-->|Conexão Bidirecional Tempo Real| WS
    SPA -->|Lê/Grava Sessão Imediata (F5)| LocalStore
    SPA -->|Métricas e Desempenho| Analytics

    FastAPI -->|Consultas e Mutações| MongoDB
    FastAPI -->|Autenticação Social| GoogleOAuth
    GitHubActions -->|Ping /api/health| FastAPI
    VercelEdge -->|Serve SPA & Static 404/ads.txt| Client
```

### 🔗 Como as partes se conversam:
1. **Frontend na Vercel:** O usuário acessa `https://ciphersong.vercel.app`. A Vercel entrega os arquivos compilados (HTML/CSS/JS) globalmente via CDN em milissegundos.
2. **Backend no Render:** O frontend faz requisições HTTPS para `https://ciphersong-web-j0a6.onrender.com/api/...`.
3. **Persistência de Sessão (Zero Logout no F5):** O Access Token JWT (validade de 24h) é salvo no `localStorage`. Ao recarregar a página (F5), o app lê o token instantaneamente (0ms de espera) e valida a expiração sem precisar bater no servidor.
4. **WebSockets ao Vivo:** Ao selecionar uma equipe, o frontend abre conexão em `wss://ciphersong-web-j0a6.onrender.com/api/ws/events?token=...`. Qualquer alteração de repertório ou ping dispara um broadcast para todos os músicos daquela equipe.
5. **Keep-Alive do Render:** Como o plano gratuito do Render hiberna após 15 minutos, um workflow no GitHub Actions (`.github/workflows/keep-alive.yml`) e/ou UptimeRobot pinga `/api/health` periodicamente para manter a API sempre acordada.
6. **Overlay de Cold Start:** Se a API estiver acordando, o frontend exibe suavemente uma tela de aquecimento com um **carrossel interativo** de recursos, aguardando a API sem exibir telas de erro ao usuário.

---

## 🛠️ 3. Stack Tecnológica Completa

| Camada | Tecnologia | Finalidade |
| :--- | :--- | :--- |
| **Frontend UI** | [React 19](https://react.dev) + [TypeScript](https://www.typescriptlang.org) | Componentização reativa, tipagem estrita e alta performance |
| **Build Tool** | [Vite 8](https://vite.dev) | Compilador ultrarrápido com Hot Module Replacement (HMR) |
| **Estilização** | [Tailwind CSS v4](https://tailwindcss.com) | Design system moderno com `@tailwindcss/vite`, temas claro/escuro |
| **Ícones** | [Lucide React](https://lucide.dev) | Conjunto consistente de ícones vetoriais em SVG |
| **Mobile Wrapper** | [Capacitor 7](https://capacitorjs.com) | Empacotamento nativo Android / iOS (PWA para APK/IPA) |
| **Observabilidade** | `@vercel/speed-insights` & `@vercel/analytics` | Métricas reais de Core Web Vitals e uso dos usuários |
| **Backend API** | [Python 3.12](https://python.org) + [FastAPI](https://fastapi.tiangolo.com) | API assíncrona, robusta, tipada e com documentação Swagger |
| **Servidor ASGI** | [Uvicorn](https://www.uvicorn.org) | Servidor de alta velocidade para Python assíncrono |
| **Banco de Dados** | [MongoDB Atlas](https://www.mongodb.com/atlas) (`pymongo`) | Banco NoSQL flexível na nuvem com índices otimizados |
| **Autenticação** | JWT (HS256) + PBKDF2-HMAC-SHA256 | Tokens de 24h, senhas com 600.000 iterações e Refresh seguro |
| **CI/CD & Deploy** | Vercel (Front) + Render (Back) + GitHub Actions | Deploy contínuo e sincronizado a cada push na branch `main` |

---

## 📂 4. Estrutura de Pastas e Arquivos

```text
ciphersong-web/
├── .github/
│   └── workflows/
│       └── keep-alive.yml         # Robô que pinga o Render a cada 12m para evitar hibernação
│
├── ciphersong/                    # Módulos Python Core do CipherSong
│   ├── database/
│   │   └── mongo_connection.py   # Repositórios MongoDB (Usuários, Equipes, Cifras, Pings)
│   ├── security/
│   │   ├── auth.py               # Funções de JWT, hash de senha, validação de tokens
│   │   └── otp.py                # Gerenciador de códigos de verificação de e-mail (6 dígitos)
│   ├── services/
│   │   └── email_service.py      # Envio de e-mails de confirmação e recuperação
│   └── ...
│
├── tests/                         # Suíte de testes automatizados (pytest)
│   ├── test_chords_and_import.py # Testes de importação de cifras e transposição
│   ├── test_plans.py             # Testes de limites de planos (Free, Pro, Ministério)
│   ├── test_refresh_token.py     # Testes do fluxo de renovação de sessão e JWT de 24h
│   └── test_security_audit.py    # Testes de auditoria OWASP e proteção da API
│
├── web/                           # Aplicação Frontend (React 19 + Vite)
│   ├── public/
│   │   ├── 404.html              # Página estática 404 personalizada para Vercel
│   │   ├── ads.txt               # Arquivo oficial do Google AdSense
│   │   ├── favicon.svg           # Ícone oficial CipherSong
│   │   └── google...html         # Arquivo de verificação do Google Search Console
│   ├── src/
│   │   ├── components/
│   │   │   ├── billing/          # Telas e modais de Assinatura, Planos e Quotas
│   │   │   │   ├── BillingSection.tsx   # Aba completa de Faturamento, CDC e LGPD
│   │   │   │   ├── CourtesyBanner.tsx   # Banner de cortesia de 3 dias do Ministério
│   │   │   │   ├── PlanBadge.tsx        # Selo visual do plano no header/perfil
│   │   │   │   ├── UpgradeModal.tsx     # Modal comparativo com gatilhos de limites
│   │   │   │   └── UsageMeter.tsx       # Barras de progresso de consumo de quotas
│   │   │   ├── common/           # Componentes utilitários
│   │   │   │   ├── ServerColdStartOverlay.tsx # Tela de boot com Carrossel de Recursos
│   │   │   │   ├── TunerModal.tsx       # Modal do Afinador Cromático & Metrônomo
│   │   │   │   └── UserAvatar.tsx       # Avatar com suporte a fotos personalizadas
│   │   │   ├── layout/           # Componentes estruturais (Header, Sidebars, Bottom Dock)
│   │   │   │   ├── TopHeader.tsx        # Barra superior com equipe ativa, pings e perfil
│   │   │   │   ├── SidebarDesktop.tsx   # Barra lateral fixa para telas médias e grandes
│   │   │   │   └── BottomDockMobile.tsx # Barra de navegação inferior estilo app nativo
│   │   │   ├── legal/            # Privacidade, Termos e Conformidade LGPD
│   │   │   │   ├── CookieConsentBanner.tsx # Banner de aceite de cookies
│   │   │   │   ├── MandatoryTermsModal.tsx # Bloqueio obrigatório no primeiro login
│   │   │   │   └── LegalModal.tsx          # Textos completos de Termos e Privacidade
│   │   │   └── views/            # As Telas Principais do Aplicativo
│   │   │       ├── RepertoireView.tsx   # Repertório Geral (busca, filtros, cifras)
│   │       │   ├── WeeklyView.tsx       # Músicas escaladas para o culto/semana
│   │       │   ├── ToRehearseView.tsx   # Músicas na fila de ensaio da equipe
│   │       │   ├── TeamView.tsx         # Gestão de equipes, membros e código de convite
│   │       │   ├── SettingsView.tsx     # Configurações de Perfil, Tema e Faturamento
│   │       │   ├── ChordViewModal.tsx   # Visualizador de Cifra com Auto-Scroll e Tom
│   │       │   ├── AuthView.tsx         # Tela de Login, Cadastro, OTP e Google OAuth
│   │       │   └── NotFoundView.tsx     # Tela 404 "Nota Fora do Tom" da SPA
│   │   ├── hooks/                # Custom React Hooks
│   │   │   ├── useTheme.ts       # Gestão de tema claro / escuro
│   │   │   └── useConsent.ts     # Gestão de preferências de consentimento LGPD
│   │   ├── services/
│   │   │   └── api.ts            # Cliente HTTP padronizado, interceptores e endpoints
│   │   ├── types/
│   │   │   └── navigation.ts     # Definição das abas ('repertoire', 'team', etc.)
│   │   ├── App.tsx               # Componente Raiz com roteamento e restauração de sessão
│   │   └── main.tsx              # Ponto de entrada React com Speed Insights e Analytics
│   ├── package.json              # Dependências do frontend
│   ├── vercel.json               # Configurações de rewrite SPA e rotas da Vercel
│   └── vite.config.ts            # Configurações de compilação do Vite e Tailwind
│
├── backend_api.py                 # SERVIDOR PRINCIPAL FASTAPI (Todos os endpoints REST e WS)
├── Dockerfile                     # Imagem Docker de produção para o Render
├── requirements.txt               # Dependências Python do backend
├── vercel.json                    # Configuração Vercel na raiz do repositório
└── README.md                      # Esta documentação
```

---

## 📡 5. Catálogo de APIs e Endpoints

Todas as chamadas REST utilizam prefixo `/api` e esperam/retornam dados em JSON.

### 🔐 Autenticação & Usuários
* `POST /api/auth/register` — Cria conta com nome, e-mail, senha e código OTP.
* `POST /api/auth/register/send-code` — Envia código de 6 dígitos para o e-mail do usuário.
* `POST /api/auth/login` — Autentica com e-mail/senha, emite Access Token (24h) e Refresh Token (7d).
* `POST /api/auth/refresh` — Renova o Access Token (suporta Cookie HttpOnly e JSON body).
* `POST /api/auth/logout` — Revoga a sessão no MongoDB e invalida cookies.
* `GET /api/auth/google/login` — Inicia fluxo de login social OAuth 2.0 com Google.
* `GET /api/auth/google/callback` — Trata o retorno do Google e redireciona com o token.
* `GET /api/auth/me` — Retorna os dados do perfil do usuário autenticado.
* `PUT /api/auth/perfil` — Atualiza nome, avatar ou foto de perfil.
* `POST /api/auth/avatar/upload` — Upload seguro de foto de perfil (máx. 5 MB; JPG, PNG, WEBP).
* `DELETE /api/auth/conta` — Exclui definitivamente a conta (Direito ao esquecimento LGPD).

### 🎵 Cifras & Repertório
* `GET /api/musicas` — Lista músicas do repertório da equipe ativa (com busca e paginação).
* `POST /api/musicas` — Cadastra nova música com cifra, tom original e tags.
* `PUT /api/musicas/{id}` — Atualiza letra, cifra, tom ou observações da música.
* `DELETE /api/musicas/{id}` — Remove uma música do repertório.
* `POST /api/musicas/importar-url` — Importa cifras automaticamente a partir de links externos.

### 📅 Semana & Músicas a Ensaiar
* `GET /api/semana` — Lista as músicas escaladas para a escala do culto atual.
* `POST /api/semana` — Adiciona música à escala da semana.
* `DELETE /api/semana/{id}` — Remove música da escala da semana.
* `GET /api/a-ensaiar` — Lista músicas na fila de estudo/ensaio da equipe.
* `POST /api/a-ensaiar` — Adiciona música à lista de ensaio.
* `DELETE /api/a-ensaiar/{id}` — Remove música da lista de ensaio.

### 👥 Equipes & Pings em Tempo Real
* `GET /api/equipes` — Lista todas as equipes das quais o usuário é dono ou participante.
* `POST /api/equipes` — Cria uma nova equipe de louvor.
* `POST /api/equipes/entrar` — Entra em uma equipe através de código de convite (ex: `LOUVOR-2026`).
* `GET /api/equipes/{id}/membros` — Lista integrantes da equipe.
* `POST /api/pings` — Envia um chamado rápido para músicos da equipe ("Afinar instrumento", etc.).
* `GET /api/pings` — Lista pings não lidos recebidos pelo usuário.
* `GET /api/ws/events` — **Canal WebSocket** para sincronização instantânea de mudanças e pings.

### 💳 Planos & Faturamento (SaaS)
* `GET /api/plano` — Retorna plano atual (`free`, `pro`, `ministerio`), consumo de quotas e status de cortesia.
* `POST /api/plano/cortesia/ativar` — Ativa 3 dias gratuitos do Plano Ministério sem precisar de cartão.

### 🩺 Saúde do Servidor
* `GET /api/health` — Endpoint de Health Check (utilizado pelo UptimeRobot e GitHub Actions).

---

## 🛠️ 6. Guia Prático: Onde Mexer para Alterar Algo Específico

| O que você quer fazer? | Onde você deve mexer? | Arquivos envolvidos |
| :--- | :--- | :--- |
| **Mudar cores, fontes ou tema** | No Tailwind CSS e classes CSS globais | [`ciphersong-web/web/src/index.css`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/index.css), [`ciphersong-web/web/src/hooks/useTheme.ts`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/hooks/useTheme.ts) |
| **Adicionar uma nova tela ou aba** | Crie a view em `components/views/`, registre o tipo em `navigation.ts` e inclua no `App.tsx` | [`ciphersong-web/web/src/types/navigation.ts`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/types/navigation.ts), [`ciphersong-web/web/src/App.tsx`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/App.tsx) |
| **Ajustar rolagem suave (Auto-Scroll)** | Na lógica de intervalo e velocidade do visualizador de cifras | [`ciphersong-web/web/src/components/views/ChordViewModal.tsx`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/components/views/ChordViewModal.tsx) |
| **Alterar a tela de Faturamento / Planos** | No componente da aba de Billing e no Modal de Planos | [`ciphersong-web/web/src/components/billing/BillingSection.tsx`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/components/billing/BillingSection.tsx), [`ciphersong-web/web/src/components/billing/UpgradeModal.tsx`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/components/billing/UpgradeModal.tsx) |
| **Alterar limites de planos (Músicas/Membros)** | No dicionário de limites do backend | [`ciphersong-web/backend_api.py`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/backend_api.py) (procure por `PLAN_LIMITS`) |
| **Criar uma nova rota na API** | No servidor FastAPI | [`ciphersong-web/backend_api.py`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/backend_api.py) |
| **Adicionar uma nova chamada no Frontend** | No cliente HTTP da SPA | [`ciphersong-web/web/src/services/api.ts`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/services/api.ts) |
| **Alterar coleções do MongoDB** | Nos repositórios de banco de dados | [`ciphersong-web/ciphersong/database/mongo_connection.py`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/ciphersong/database/mongo_connection.py) |
| **Mudar tempo de expiração do Token** | Na constante de expiração do JWT | [`ciphersong-web/backend_api.py`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/backend_api.py) (`ACCESS_TOKEN_EXPIRE_SECONDS`) |
| **Alterar mensagens do Cold Start** | No carrossel de recursos do overlay | [`ciphersong-web/web/src/components/common/ServerColdStartOverlay.tsx`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/components/common/ServerColdStartOverlay.tsx) |
| **Modificar a tela 404** | No componente da SPA ou no HTML estático da Vercel | [`ciphersong-web/web/src/components/views/NotFoundView.tsx`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/src/components/views/NotFoundView.tsx), [`ciphersong-web/web/public/404.html`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/public/404.html) |
| **Ajustar regras do Google AdSense ou SEO** | No `ads.txt`, `sitemap.xml` ou nas tags do `index.html` | [`ciphersong-web/web/public/ads.txt`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/public/ads.txt), [`ciphersong-web/web/index.html`](file:///c:/Users/Levy/Documents/CipherSong/ciphersong-web/web/index.html) |

---

## 💻 7. Como Executar Localmente

### Pré-requisitos
* **Python 3.10+** instalado
* **Node.js 18+** e **npm** instalados

### Passo 1: Iniciar o Backend (FastAPI)
```bash
# Navegue até a raiz do projeto ciphersong-web
cd ciphersong-web

# Crie e ative um ambiente virtual (opcional, recomendado)
python -m venv venv
# No Windows:
.\venv\Scripts\activate
# No Linux/Mac:
source venv/bin/activate

# Instale as dependências Python
pip install -r requirements.txt

# Inicie o servidor FastAPI na porta 8000
python -m uvicorn backend_api:app --host 0.0.0.0 --port 8000 --reload
```
A API estará disponível em: `http://localhost:8000`  
Documentação Swagger interativa: `http://localhost:8000/docs`

### Passo 2: Iniciar o Frontend (React + Vite)
Em outro terminal:
```bash
cd ciphersong-web/web

# Instale os pacotes npm
npm install

# Inicie o servidor de desenvolvimento Vite
npm run dev
```
O frontend abrirá em: `http://localhost:5173`

### Passo 3: Executar Testes Automatizados
```bash
cd ciphersong-web
python -m pytest tests
```

---

## 🚀 8. Fluxo de Deploy e Sincronização

O projeto possui **Deploy Contínuo (CI/CD)**:

1. A **Vercel** monitora a branch `main`. Qualquer commit enviado para `origin main` dispara a compilação do React e atualiza o site no ar em segundos.
2. O **Render** monitora o repositório do GitHub e reconstrói o container Docker com a API FastAPI automaticamente.
3. Para garantir que ambas as plataformas recebam as atualizações, sempre enviamos os commits para ambas as branches:

```bash
# 1. Commita as alterações na branch de trabalho
git add .
git commit -m "feat(exemplo): sua melhoria aqui"
git push origin ciphersong-web

# 2. Mescla e envia para a main (dispara deploy da Vercel e Render)
git checkout main
git merge ciphersong-web
git push origin main

# 3. Retorna para a branch de trabalho
git checkout ciphersong-web
```

---

## 🔒 9. Segurança & Boas Práticas

* **Repositório Privado:** Mantenha o repositório como **Private** no GitHub para proteger as regras de negócio, estrutura do MongoDB e algoritmos de cifra. Vercel e Render funcionam perfeitamente com repositórios privados.
* **Segredos e `.env`:** Nunca comite arquivos `.env` ou senhas no Git. Configure variáveis sensíveis como `MONGODB_URI` e `JWT_SECRET` diretamente nos painéis da Vercel e do Render.
* **Keep-Alive:** Para evitar que o Render hiberne no plano gratuito, mantenha o robô do GitHub Actions ativo ou cadastre o endpoint `/api/health` em serviços gratuitos como o [UptimeRobot](https://uptimerobot.com).

---

> Desenvolvido com carinho para músicos e ministérios de louvor. 🎶  
> **CipherSong &bull; A afinação perfeita para a sua equipe.**
