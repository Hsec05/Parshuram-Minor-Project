# 🛡️ Parshuram 2.0 — SIEM Platform

<div align="center">

![SIEM](https://img.shields.io/badge/SIEM-Active-brightgreen?style=for-the-badge&logo=shield)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?style=for-the-badge&logo=node.js)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react)
![MongoDB](https://img.shields.io/badge/MongoDB-7%2B-47A248?style=for-the-badge&logo=mongodb)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=for-the-badge&logo=typescript)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python)
![Redis](https://img.shields.io/badge/Redis-7%2B-DC382D?style=for-the-badge&logo=redis)

**A full-stack, production-grade Security Information and Event Management (SIEM) platform with a real-time SOC Dashboard.**

Collect, analyze, and respond to Windows security events in real time — powered by a custom rule engine, MongoDB persistence, Redis pub/sub, and a rich React UI.

</div>

---

## 📖 Table of Contents

- [What Is This Project?](#-what-is-this-project)
- [Architecture Overview](#-architecture-overview)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
  - [Step 1 — Clone the Repository](#step-1--clone-the-repository)
  - [Step 2 — Set Up MongoDB & Redis](#step-2--set-up-mongodb--redis)
  - [Step 3 — Configure Environment Variables](#step-3--configure-environment-variables)
  - [Step 4 — Install Dependencies](#step-4--install-dependencies)
  - [Step 5 — Start All Services](#step-5--start-all-services)
  - [Step 6 — Deploy the Windows Agent](#step-6--deploy-the-windows-agent)
- [Default Login Credentials](#-default-login-credentials)
- [Port Reference](#-port-reference)
- [How It Works — Under the Hood](#-how-it-works--under-the-hood)
  - [Windows Agent](#the-windows-agent)
  - [Threat Detection Service](#threat-detection-service)
  - [Rule Engine](#rule-engine)
  - [SOC Backend](#soc-backend)
  - [Ticket Escalation](#ticket-escalation)
- [Dashboard Pages](#-dashboard-pages)
- [API Reference](#-api-reference)
- [Database Schema](#-database-schema)
- [User Roles & Permissions](#-user-roles--permissions)
- [Environment Variables Reference](#-environment-variables-reference)
- [Troubleshooting](#-troubleshooting)
- [Tech Stack](#-tech-stack)

---

## 🔍 What Is This Project?

Parshuram 2.0 is a **four-tier security monitoring platform** that simulates a real-world SIEM deployment:

```
[ Windows Endpoint ]
         ↓  (Windows Event Logs — System / Security / Application)
[ Threat Detection Service ]  ← Port 3000  — log ingestion & rule engine
         ↓  (detected threats → MongoDB, alerts → Redis pub/sub)
[ SOC Backend ]               ← Port 3001  — users, tickets, dashboard, GeoIP
         ↑
[ SOC Dashboard UI ]          ← Port 5173  — React real-time monitoring & management
```

- The **Windows Agent** runs on monitored endpoints. It fingerprints the host hardware, authenticates itself to the Threat Detection Service, and streams Windows Event Logs every 10 seconds.
- The **Threat Detection Service** receives those logs, runs every entry through the rule engine, and persists detected threats to MongoDB while publishing real-time alerts to Redis.
- The **SOC Backend** powers the SOC analyst workflow — authentication, ticketing, geolocation, dashboard aggregations, and user management.
- The **SOC Dashboard** gives analysts a full-featured React UI to monitor threats, manage tickets, track agents, view geolocation maps, and administer the platform.

---

## 🏗️ Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│               SOC Dashboard (React + Vite)           │
│  Dashboard | Agents | Logs | Threats | Alerts        │
│  Tickets | Policies | Geolocation | Admin            │
│              http://localhost:5173                   │
└───────────────────────┬──────────────────────────────┘
                        │ REST API (JSON)
                        ▼
┌──────────────────────────────────────────────────────┐
│             SOC Backend (Express.js)                 │
│                                                      │
│  ┌────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │    Auth    │  │   Ticketing   │  │  Dashboard  │ │
│  │ Controller │  │   Controller  │  │  Controller │ │
│  └────────────┘  └───────────────┘  └─────────────┘ │
│  ┌────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │   GeoIP    │  │     Admin     │  │   Log View  │ │
│  │  Resolver  │  │   Controller  │  │  Controller │ │
│  └────────────┘  └───────────────┘  └─────────────┘ │
│              http://localhost:3001                   │
└───────────────────────┬──────────────────────────────┘
                        │ Mongoose / Redis
                        ▼
┌──────────────────────────────────────────────────────┐
│   MongoDB — localhost:27017/Parshuram2               │
│   users | tickets | windows_logs | windows_threats   │
│                                                      │
│   Redis — localhost:6379                             │
│   sessions | threat_alerts pub/sub channel           │
└──────────────────────────────────────────────────────┘
                        ▲
                        │ Mongoose / Redis
┌──────────────────────────────────────────────────────┐
│        Threat Detection Service (Express.js)         │
│                                                      │
│  ┌────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │  Windows   │  │  Rule Engine  │  │   Stateful  │ │
│  │  Decoder   │→ │ (windowsRules)│  │ Brute Force │ │
│  └────────────┘  └───────────────┘  └─────────────┘ │
│  ┌────────────┐  ┌───────────────┐                  │
│  │   Policy   │  │  Agent Auth   │                  │
│  │  Manager   │  │  Controller   │                  │
│  └────────────┘  └───────────────┘                  │
│              http://localhost:3000                   │
└───────────────────────▲──────────────────────────────┘
                        │ HTTP (logs every 10 s)
┌──────────────────────────────────────────────────────┐
│          Windows Agent (Python)                      │
│   Reads: System | Security | Application channels    │
│   Hardware fingerprint → Agent ID                    │
│              monitored Windows endpoint              │
└──────────────────────────────────────────────────────┘
```

---

## ✨ Features

### 🖥️ Windows Agent
- **Hardware fingerprinting** — identifies each agent by CPU ID, motherboard serial, and disk serial (no user configuration needed)
- **Self-registration** — first-run auto-registers with the Threat Detection Service and stores its assigned Agent ID locally
- **Session authentication** — logs in before every run; retries automatically on failure
- **Multi-channel log collection** — reads from `System`, `Security`, and `Application` Windows Event Log channels
- **Incremental shipping** — tracks the last sent Record Number per channel to avoid duplicate or missed events
- **10-second polling loop** — continuously streams new events with no manual intervention

### 🔍 Threat Detection Service
- **Custom Rule Engine** — evaluates every incoming log against a comprehensive `windowsRules.js` ruleset using PCRE-style pattern matching
- **Stateful Brute-Force Detection** — `windowsStatefulRules.js` maintains sliding-window counters (default: 5 failures in 300 s) to detect credential-stuffing and brute-force attacks
- **Windows Event Decoder** — normalises raw Windows Event Log fields into a canonical schema before rule evaluation
- **Policy Management** — REST API to create, read, update, and delete detection policies; rules are tied to active policies
- **Agent Auth API** — agents register and log in with their hardware fingerprint; sessions are validated per-request
- **Redis alert broker** — detected threats are published to the `threat_alerts` Redis channel for real-time downstream consumption
- **MongoDB persistence** — every matched threat is stored in `windows_threats` for historical analysis

### 📊 SOC Backend & Dashboard
- **Real-time Dashboard** — metric cards (total threats, critical threats, open tickets, resolved tickets), a time-series threat/resolved chart, and threats-by-OS breakdown
- **Attack Logs** — searchable, filterable view of all ingested Windows Event Log entries
- **Threat Summary** — list of all rule-matched threats with severity badges and ticket-creation shortcuts
- **Agents Page** — inventory of all registered agents with status, hardware info, and last-seen timestamps
- **Device Requests** — approval workflow for new agent registrations (admin must approve before an agent can submit logs)
- **Geolocation** — GeoIP-based map (Leaflet) plotting the geographic origin of threats and agents
- **Alerts Page** — consolidated alert feed from the threat store
- **Ticketing System** — full CRUD tickets with L1/L2/L3/L4 assignment, file attachments, threaded updates, severity lifecycle management, and auto-incrementing Ticket IDs
- **Policies** — manage detection policies from the UI
- **Admin Panel** — user management, member addition, and platform-wide settings

### 🔐 Authentication & Security
- **Session-based auth** — session tokens stored in Redis with configurable expiry (default: 6 hours)
- **Bcrypt password hashing** — work factor 15
- **OTP verification** — new user registration requires OTP confirmation
- **Approval workflow** — newly registered users land on a "Waiting for Approval" page until an admin activates the account
- **Rate limiting** — `authLimiter` on all login/register endpoints; `addMemberLimiter` on member-creation routes
- **Role-Based Access Control** — six distinct roles enforced on both frontend (navbar filtering, private routes) and backend middleware

---

## 📁 Project Structure

```
Parshuram2.0/
│
├── Parshuram Frontend 2.1/          # React Frontend (TypeScript + Vite)
│   ├── src/
│   │   ├── api/
│   │   │   └── axios.js             # Axios instance with auth headers
│   │   ├── components/
│   │   │   ├── Admin/
│   │   │   │   └── AdminPage.tsx    # User & platform administration
│   │   │   ├── Agents/
│   │   │   │   ├── AgentsPage.tsx   # Registered agent inventory
│   │   │   │   └── AgentDetailsModal.tsx
│   │   │   ├── Alerts/
│   │   │   │   └── AlertsPage.tsx   # Consolidated alert feed
│   │   │   ├── Auth/
│   │   │   │   ├── LoginPage.tsx
│   │   │   │   ├── RegisterPage.tsx
│   │   │   │   ├── OTPPage.tsx
│   │   │   │   ├── ForgotPasswordPage.tsx
│   │   │   │   ├── NewPasswordPage.tsx
│   │   │   │   └── WaitingPage.tsx  # Post-registration approval screen
│   │   │   ├── Dashboard/
│   │   │   │   ├── Dashboard.tsx    # Main SOC overview
│   │   │   │   ├── NotificationPanel.tsx
│   │   │   │   └── NotificationDetailModal.tsx
│   │   │   ├── DeviceRequests/
│   │   │   │   └── DeviceRequestsPage.tsx  # New agent approval queue
│   │   │   ├── Geolocation/
│   │   │   │   └── GeolocationPage.tsx     # Leaflet IP-origin map
│   │   │   ├── Layout/
│   │   │   │   ├── Layout.tsx
│   │   │   │   └── Navbar.tsx       # Role-filtered sidebar navigation
│   │   │   ├── Logs/
│   │   │   │   ├── LogSummaryPage.tsx
│   │   │   │   └── LogViewModal.tsx
│   │   │   ├── Policies/
│   │   │   │   ├── PoliciesPage.tsx
│   │   │   │   └── PolicyModal.tsx
│   │   │   ├── Threats/
│   │   │   │   └── ThreatSummaryPage.tsx
│   │   │   └── Tickets/
│   │   │       ├── TicketingPage.tsx
│   │   │       ├── TicketDetailsPage.tsx
│   │   │       ├── CreateTicketPage.tsx
│   │   │       └── TicketModal.tsx
│   │   ├── context/
│   │   │   └── AuthContext.tsx      # JWT / session state management
│   │   ├── hooks/
│   │   │   └── useOnClickOutside.ts
│   │   ├── types/
│   │   │   └── index.ts             # TypeScript type definitions
│   │   ├── App.tsx                  # Route declarations
│   │   └── main.tsx
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
│
└── Updated SIEM Backend/
    │
    ├── Agents/                       # Windows Log Agent (Python)
    │   ├── Agent.py                  # Main agent script
    │   └── agent_id.txt              # Persisted Agent ID (auto-generated)
    │
    ├── SOC/                          # SOC Backend (Node.js / Express)
    │   ├── index.js                  # App entry point & route wiring
    │   ├── controllers/
    │   │   ├── auth-controller.js    # Login, logout, user management
    │   │   ├── admin-controller.js   # Admin operations
    │   │   ├── dashboard-controller.js  # Metrics, graphs, notifications
    │   │   ├── log-controller.js     # Log retrieval & filtering
    │   │   ├── ticket-controller.js  # Full ticket CRUD & escalation
    │   │   └── agent-controller.js   # Agent inventory
    │   ├── models/
    │   │   ├── user-model.js         # User schema (bcrypt helpers)
    │   │   ├── ticket-model.js       # Ticket schema (auto-increment IDs)
    │   │   ├── agent.js              # Agent schema
    │   │   ├── windows_logs.js       # Raw Windows event schema
    │   │   └── windows_threats.js    # Detected threat schema
    │   ├── middlewares/
    │   │   ├── auth-middleware.js    # Session validation
    │   │   └── rate-limiter.js       # Auth & member-add rate limiting
    │   ├── routes/
    │   │   ├── auth-router.js
    │   │   ├── admin-router.js
    │   │   ├── dashboard-router.js
    │   │   ├── log-router.js
    │   │   ├── ticket-router.js
    │   │   └── agent-router.js
    │   └── util/
    │       ├── mongoConnect.js       # Mongoose connection
    │       ├── redisConnect.js       # Redis session client
    │       ├── redisBroker.js        # Redis pub/sub broker client
    │       └── sqlConnect.js         # MySQL connection (optional)
    │
    └── Threat Detection Service/     # Log Ingestion & Rule Engine (Node.js)
        ├── index.js                  # App entry point & route wiring
        ├── controllers/
        │   └── agent-auth-controller.js  # Agent register / login
        ├── decoders/
        │   └── windowsDecoder.js     # Raw event → canonical schema
        ├── models/
        │   ├── agent.js
        │   ├── policy.js
        │   ├── windows_logs.js
        │   └── windows_threats.js
        ├── middlewares/
        │   └── auth-middleware.js    # Agent session validation
        ├── routes/
        │   ├── agent-auth-routes.js
        │   ├── windows.js            # Log ingestion endpoints
        │   └── policy-route.js
        ├── rules/
        │   ├── windowsRules.js       # Static detection rules (Event IDs, patterns)
        │   └── windowsStatefulRules.js  # Stateful brute-force detection
        └── utils/
            ├── ruleEngine.js         # analyzeWindowsLog() — core matcher
            └── bruteForceDetector.js # Sliding-window counter logic
```

---

## 🔧 Prerequisites

Before you start, make sure you have the following installed:

| Tool | Version | Purpose |
|------|---------|---------|
| Node.js | 18+ | SOC Backend & Threat Detection Service |
| npm | 8+ | Package management |
| Python | 3.8+ | Windows Agent |
| MongoDB | 6+ | Primary database |
| Redis | 6+ | Session store & alert broker |
| Git | Any | Clone the repository |
| Windows OS | 10/11 or Server | Required to run the Agent (`pywin32`) |

> **Note:** MongoDB and Redis must both be running locally (or update the `.env` files to point at remote instances) before starting any backend service.

---

## 🚀 Installation & Setup

### Step 1 — Clone the Repository

```bash
git clone https://github.com/your-username/Parshuram2.0.git
cd Parshuram2.0
```

### Step 2 — Set Up MongoDB & Redis

**MongoDB** (local):
```bash
# macOS
brew services start mongodb-community

# Ubuntu/Debian
sudo systemctl start mongod

# Windows
net start MongoDB
```

**Redis** (local):
```bash
# macOS
brew services start redis

# Ubuntu/Debian
sudo systemctl start redis

# Windows (using Redis for Windows or WSL)
redis-server
```

Verify both are running:
```bash
# MongoDB
mongosh --eval "db.adminCommand('ping')"

# Redis
redis-cli ping   # should return PONG
```

No manual database or collection setup is required — Mongoose auto-creates all collections on first launch.

---

### Step 3 — Configure Environment Variables

**Threat Detection Service** (`Updated SIEM Backend/Threat Detection Service/.env`):

```env
PORT=3000
MONGO_URI=mongodb://localhost:27017/Parshuram2
NODE_ENV=development

# Brute-force detection window
BRUTE_FORCE_WINDOW_MS=300000
BRUTE_FORCE_THRESHOLD=5

REDIS_HOST=127.0.0.1
REDIS_PORT=6379

REDIS_BROKER_HOST=127.0.0.1
REDIS_BROKER_PORT=6379

SESSION_SECRET=change_this_in_production
```

**SOC Backend** (`Updated SIEM Backend/SOC/.env`):

```env
PORT=3001
MONGO_URI=mongodb://localhost:27017/Parshuram2

REDIS_HOST=127.0.0.1
REDIS_PORT=6379

SESSION_SECRET=change_this_in_production
```

**Frontend** (`Parshuram Frontend 2.1/.env`):

```env
VITE_API_URL=http://localhost:3001
```

---

### Step 4 — Install Dependencies

Install dependencies for each Node.js service separately:

```bash
# Threat Detection Service
cd "Updated SIEM Backend/Threat Detection Service"
npm install

# SOC Backend
cd ../SOC
npm install

# Frontend
cd "../../Parshuram Frontend 2.1"
npm install
```

For the Python Agent (on a **Windows** machine only):

```bash
pip install requests pywin32
```

---

### Step 5 — Start All Services

Open three separate terminals and start each service:

**Terminal 1 — Threat Detection Service:**
```bash
cd "Updated SIEM Backend/Threat Detection Service"
node index.js
# Expected: SIEM server listening on port 3000
```

**Terminal 2 — SOC Backend:**
```bash
cd "Updated SIEM Backend/SOC"
node index.js
# Expected: Server running on port 3001
```

**Terminal 3 — Frontend Dev Server:**
```bash
cd "Parshuram Frontend 2.1"
npm run dev
# Expected: Local: http://localhost:5173/
```

---

### Step 6 — Deploy the Windows Agent

> ⚠️ The agent runs on **Windows only** — it uses the `pywin32` library to read Windows Event Logs.

On the Windows machine you want to monitor:

1. Copy the `Updated SIEM Backend/Agents/` folder to the target machine.
2. Edit the `SERVER_HOST` constant in `Agent.py` to point to your Threat Detection Service IP/hostname:
   ```python
   SERVER_HOST = "http://<threat-detection-service-ip>:3000/"
   ```
3. Run the agent:
   ```bash
   python Agent.py
   ```
4. On **first run**, the agent registers itself and stores the assigned `agentId` in `agent_id.txt`. An admin must approve the device request in the SOC Dashboard before log shipping begins.
5. On subsequent runs, the agent loads the existing `agent_id.txt` and proceeds directly to login.

---

## 🔑 Default Login Credentials

No default admin account is pre-seeded. Create the first admin account by calling the add-admin endpoint directly:

```bash
curl -X POST http://localhost:3001/api/auth/add-admin \
  -H "Content-Type: application/json" \
  -d '{"name": "Admin", "email": "admin@example.com", "role": "superadmin"}'
```

This creates an account with the default password `admin`. **Change the password immediately after first login.**

---

## 🔌 Port Reference

| Service | Port | Description |
|---------|------|-------------|
| Threat Detection Service | `3000` | Receives logs from agents, runs rule engine |
| SOC Backend | `3001` | Powers the SOC analyst API |
| Frontend Dev Server | `5173` | React SOC Dashboard |
| MongoDB | `27017` | Primary database |
| Redis | `6379` | Sessions & alert pub/sub |

---

## 🧠 How It Works — Under the Hood

### The Windows Agent

The agent starts by collecting **hardware fingerprint** data — CPU Processor ID, motherboard serial number, and disk drive serial number — using `wmic` shell commands. This fingerprint uniquely identifies the host machine without relying on network addresses that can change.

On first run, the fingerprint is sent to the `/api/auth/register` endpoint of the Threat Detection Service, which returns a UUID-based `agentId` that is saved to `agent_id.txt`. On every subsequent run, the agent loads that file, skipping registration.

Before log shipping begins, the agent calls `/api/auth/login` with its `agentId` and hardware fingerprint to obtain a session token. This token is sent as the `x-session` request header with every batch of logs.

Once authenticated, the agent enters a continuous loop: every 10 seconds it reads up to 11 new events from each of the three Windows Event Log channels (`System`, `Security`, `Application`) using the `pywin32` API. It tracks the last sent `RecordNumber` per channel to ensure only new events are forwarded, then POSTs each batch to `POST /api/windows/{channel}`.

---

### Threat Detection Service

The Threat Detection Service receives batched event logs from agents. Each batch flows through the **Windows Decoder** (`windowsDecoder.js`), which normalises raw `win32evtlog` fields into a canonical document:

```
EventID | Level | TimeCreated | Source | Task | Computer | Description | AgentID | Channel
```

The normalised events are stored in the `windows_logs` collection and immediately passed to the **Rule Engine**.

---

### Rule Engine

`analyzeWindowsLog()` in `ruleEngine.js` evaluates each normalised event against two rulebooks:

**`windowsRules.js`** — a static, Event-ID-driven ruleset. Each rule specifies a set of Windows Event IDs, an optional pattern match on the `Description` or `Source` field, a severity level (`low`, `medium`, `high`, `critical`), and a human-readable name and message.

**`windowsStatefulRules.js`** — stateful rules that aggregate events over a sliding time window. For example, the brute-force rule (`bruteForceDetector.js`) maintains per-agent counters: if the same agent produces more than `BRUTE_FORCE_THRESHOLD` matching events within `BRUTE_FORCE_WINDOW_MS` milliseconds, a threat is raised. Counters are reset after the window expires.

When a rule matches, the engine writes a **Threat** document to the `windows_threats` MongoDB collection and publishes a JSON alert to the `threat_alerts` Redis channel for downstream real-time consumers.

---

### SOC Backend

The SOC Backend is the analyst-facing API server. It connects to the same MongoDB instance and exposes the following functional areas:

**Authentication** — session-based login with Redis-backed session storage. Sessions expire after 6 hours. All protected routes go through the `auth-middleware.js` which validates the `x-session` header or session cookie against Redis.

**Dashboard** — the `dashboard-controller.js` exposes aggregation queries against `windows_threats` and `tickets`: total threats, critical threats, open/working tickets, resolved (closed) tickets, a time-series graph grouped by configurable intervals (5-minute, 30-minute, hourly, daily, monthly, yearly), and threats broken down by OS.

**Ticket System** — a full CRUD ticket lifecycle with auto-incrementing Ticket IDs, multi-level assignment (L1–L4), threaded `updates` with per-update status changes, file attachments via `multer`, and linked `log_refs` that reference source Windows log documents.

**Geolocation** — `geoip-lite` resolves source IP addresses to country/city coordinates, surfaced to the frontend's Leaflet map.

---

### Ticket Escalation

Tickets support a tiered SOC response model:

| Level | Role | Typical Responsibility |
|-------|------|----------------------|
| L1 | First-responder | Triage, initial investigation, basic remediation |
| L2 | Mid-tier analyst | Deeper analysis, forensics, escalation decision |
| L3 | Senior analyst | Complex incident handling, threat hunting |
| L4 | Lead / IR | Crisis management, executive reporting |

A ticket is created in `open` status. Analysts update it with threaded messages (each update records its author, timestamp, and optional attachments). The ticket moves through `open → working → closed` states. Multiple contributors can be assigned to a single ticket, and each ticket maintains an immutable history of all updates.

---

## 🖥️ Dashboard Pages

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/dashboard` | Metric cards, threat graph, OS distribution, recent threat feed, notifications |
| Agents | `/agents` | Registered agent inventory with hardware info and status |
| Device Requests | `/device-requests` | Queue of new agent registrations awaiting admin approval |
| Logs | `/logs` | Full searchable log viewer with modal detail view |
| Threats | `/threats` | Rule-matched threat summary; create tickets directly from threats |
| Alerts | `/alerts` | Consolidated alert feed across all agents |
| Tickets | `/tickets` | Full ticket list with filtering by status/severity/assignee |
| Ticket Detail | `/tickets/:id` | Threaded update view, contributor list, file attachments |
| Create Ticket | `/tickets/create` | New ticket form with log reference linking |
| Policies | `/policies` | Detection policy management |
| Geolocation | `/geolocation` | Leaflet map of agent and threat IP origins |
| Admin | `/admin` | User management, member addition, platform settings |

---

## 🔗 API Reference

### SOC Backend — `http://localhost:3001`

#### Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/auth/login` | ❌ | Authenticate a SOC user |
| `POST` | `/api/auth/logout` | ✅ | Invalidate current session |
| `GET` | `/api/auth/user` | ✅ | Get current user details |
| `POST` | `/api/auth/add-admin` | ❌ | Create the first superadmin account |
| `POST` | `/api/auth/add-member` | ✅ Admin | Add a new SOC user |

#### Dashboard
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/threats/counts` | ✅ | Threat & ticket metric cards |
| `GET` | `/api/threats/graph` | ✅ | Time-series threat/resolved data |
| `GET` | `/api/threats/by-os` | ✅ | Threats grouped by OS |
| `GET` | `/api/threats/recent` | ✅ | 10 most recent threats |
| `GET` | `/api/threats/notifications` | ✅ | 15 most recent notifications |

#### Logs & Threats
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/logs` | ✅ | Paginated Windows event log view |
| `GET` | `/api/logs/:id` | ✅ | Single log entry detail |

#### Tickets
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/tickets` | ✅ | List all tickets (filterable) |
| `POST` | `/api/tickets` | ✅ | Create a new ticket |
| `GET` | `/api/tickets/:id` | ✅ | Get single ticket with full update history |
| `PUT` | `/api/tickets/:id` | ✅ | Update ticket (status, severity, assignees) |
| `DELETE` | `/api/tickets/:id` | ✅ Admin | Delete ticket |

#### Agents
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/agents` | ✅ | List all registered agents |
| `GET` | `/api/agents/:id` | ✅ | Single agent detail |

---

### Threat Detection Service — `http://localhost:3000`

#### Agent Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/auth/register` | ❌ | Register a new agent (hardware fingerprint) |
| `POST` | `/api/auth/login` | ❌ | Authenticate an agent; returns session token |

#### Log Ingestion
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/windows/system` | ✅ Agent | Submit System channel log batch |
| `POST` | `/api/windows/security` | ✅ Agent | Submit Security channel log batch |
| `POST` | `/api/windows/application` | ✅ Agent | Submit Application channel log batch |
| `POST` | `/api/logs/analyze` | ❌ | Test endpoint — analyze a single log against rules |

#### Policies
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/policies` | ✅ | List detection policies |
| `POST` | `/api/policies` | ✅ | Create a detection policy |
| `PUT` | `/api/policies/:id` | ✅ | Update a policy |
| `DELETE` | `/api/policies/:id` | ✅ | Delete a policy |

---

## 🗃️ Database Schema

### `users` (MongoDB)
| Field | Type | Notes |
|-------|------|-------|
| `name` | String | Required |
| `email` | String | Unique, required |
| `password_hash` | String | bcrypt, work factor 15 |
| `role` | Enum | `superadmin`, `admin`, `L1`, `L2`, `L3`, `L4` |
| `createdAt` | Date | Auto (timestamps) |
| `updatedAt` | Date | Auto (timestamps) |

### `windows_threats` (MongoDB)
| Field | Type | Notes |
|-------|------|-------|
| `agentId` | String | Originating agent |
| `eventId` | Number | Windows Event ID |
| `severity` | Enum | `low`, `medium`, `high`, `critical` |
| `ruleMatched` | String | Name of the matched rule |
| `message` | String | Human-readable rule message |
| `channel` | String | `system`, `security`, or `application` |
| `os` | String | OS of originating host |
| `status` | Enum | `open`, `resolved` |
| `timestamp` | Date | Event timestamp |

### `tickets` (MongoDB)
| Field | Type | Notes |
|-------|------|-------|
| `ticketID` | Number | Auto-incrementing, unique |
| `title` | String | Required |
| `description` | String | Required |
| `createdBy` | String | Employee email |
| `log_refs` | ObjectId[] | References to `windows_logs` |
| `logModel` | Enum | `windows_logs`, `linux_logs` |
| `status` | Enum | `open`, `working`, `closed` |
| `severity` | Enum | `low`, `medium`, `high`, `critical`, `urgent` |
| `levels` | Enum[] | `L1`, `L2`, `L3`, `L4` |
| `contributors` | String[] | Assigned analyst emails |
| `updates` | Array | Threaded update documents |
| `files` | String[] | Attachment file paths |

### Redis Keys
| Pattern | Purpose |
|---------|---------|
| `session:<uuid>` | SOC user session hash (email, role) |
| `sessionsByEmail:<email>` | Set of active session IDs per user |
| `threat_alerts` | Pub/sub channel for real-time threat events |

---

## 👥 User Roles & Permissions

| Role | Create Tickets | Manage Users | Approve Agents | Manage Policies | Delete Tickets |
|------|:--------------:|:------------:|:--------------:|:---------------:|:--------------:|
| `superadmin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `L1` | ✅ | ❌ | ❌ | ❌ | ❌ |
| `L2` | ✅ | ❌ | ❌ | ❌ | ❌ |
| `L3` | ✅ | ❌ | ❌ | ✅ | ❌ |
| `L4` | ✅ | ❌ | ✅ | ✅ | ❌ |

---

## 🌐 Environment Variables Reference

### Threat Detection Service

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3000` | Service port |
| `MONGO_URI` | ✅ Yes | — | MongoDB connection string |
| `NODE_ENV` | No | `development` | Environment mode |
| `BRUTE_FORCE_WINDOW_MS` | No | `300000` | Sliding window for brute-force detection (ms) |
| `BRUTE_FORCE_THRESHOLD` | No | `5` | Max failures before threat is raised |
| `REDIS_HOST` | No | `127.0.0.1` | Redis host for sessions |
| `REDIS_PORT` | No | `6379` | Redis port for sessions |
| `REDIS_BROKER_HOST` | No | `127.0.0.1` | Redis host for pub/sub broker |
| `REDIS_BROKER_PORT` | No | `6379` | Redis port for pub/sub broker |
| `SESSION_SECRET` | No | `SIEM` | ⚠️ **Change in production!** |

### SOC Backend

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3001` | Service port |
| `MONGO_URI` | ✅ Yes | — | MongoDB connection string |
| `REDIS_HOST` | No | `127.0.0.1` | Redis host |
| `REDIS_PORT` | No | `6379` | Redis port |
| `SESSION_SECRET` | No | `SIEM` | ⚠️ **Change in production!** |

### Frontend

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_URL` | ✅ Yes | `http://localhost:3001` | SOC Backend base URL |

---

## 🔧 Troubleshooting

### `MongoServerError: connect ECONNREFUSED 127.0.0.1:27017`
MongoDB is not running. Start it:
- **Windows:** Open Services → find `MongoDB` → Start
- **macOS:** `brew services start mongodb-community`
- **Linux:** `sudo systemctl start mongod`

### `Error: connect ECONNREFUSED 127.0.0.1:6379`
Redis is not running. Start it:
- **Windows:** Run `redis-server.exe` or use WSL
- **macOS:** `brew services start redis`
- **Linux:** `sudo systemctl start redis`

### Agent registration returns `400` or `500`
Make sure the Threat Detection Service is running on port 3000 **before** starting the agent. Also verify that `SERVER_HOST` in `Agent.py` matches the actual host/port.

### Agent shows "Awaiting approval" and never ships logs
An admin must approve the device request in the SOC Dashboard under `/device-requests` before the agent can submit logs.

### Frontend shows "Network Error" or blank dashboard
Check that the SOC Backend is running on port 3001 and that `VITE_API_URL` in the frontend `.env` is set to `http://localhost:3001`.

### `Error: Not allowed by CORS`
Your frontend origin is not in the `allowedOrigins` array in `SOC/index.js`. Add your dev server origin (e.g., `http://localhost:5173`) to the array and restart the backend.

### Port already in use
```bash
# Find and kill the process on a given port (Linux/macOS)
lsof -ti:<PORT> | xargs kill

# Windows
netstat -ano | findstr :<PORT>
taskkill /PID <PID> /F
```

### `pywin32` import error on the Agent
Install the dependency:
```bash
pip install pywin32
python -m pywin32_postinstall -install
```
The agent only runs on Windows. Do not attempt to run `Agent.py` on macOS or Linux.

---

## 🧰 Tech Stack

### Frontend
| Technology | Purpose |
|-----------|---------|
| React 18 | UI framework |
| TypeScript 5 | Type-safe JavaScript |
| Vite 5 | Build tool & dev server |
| Tailwind CSS 3 | Utility-first styling |
| React Router v7 | Client-side routing |
| Axios | HTTP client with auth interceptors |
| Recharts | Charts & data visualisation |
| React Leaflet | 2D geolocation map |
| Lucide React | Icon library |

### Backend (SOC & Threat Detection Service)
| Technology | Purpose |
|-----------|---------|
| Node.js + Express 5 | HTTP servers & REST APIs |
| MongoDB + Mongoose | Primary document database |
| Redis (`@redis/client`) | Session storage & pub/sub alerting |
| bcrypt | Password hashing (work factor 15) |
| geoip-lite | Offline IP → country/city resolution |
| multer | File upload handling (ticket attachments) |
| socket.io | Real-time event delivery (ready to enable) |
| express-rate-limit | Brute-force protection on auth routes |
| express-session | Server-side session management |
| uuid | Unique ID generation |
| mysql2 | Optional SQL database connectivity |

### Agent
| Technology | Purpose |
|-----------|---------|
| Python 3 | Agent runtime |
| pywin32 (`win32evtlog`) | Windows Event Log API access |
| requests | HTTP log shipping to Threat Detection Service |

---

<div align="center">

Built with ❤️ for security education and SOC simulation.

**[⬆ Back to Top](#️-parshuram-20--siem-platform)**

</div>
