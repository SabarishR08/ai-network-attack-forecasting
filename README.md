# SIH26153 AI Network Attack Forecasting

![License](https://img.shields.io/badge/license-MIT-green) ![Language](https://img.shields.io/badge/language-Python-informational) ![Docker](https://img.shields.io/badge/docker-ready-2496ed) ![Deploy](https://img.shields.io/badge/deploy-Render-46e3b7)


## Overview

AI-Based Network Attack Forecasting from Network Traffic Data — SIH26153 (NTRO)

## Architecture

```text
Browser / UI
     │   HTTP
     ▼
Flask app
     │
     ├──▶ Database — SQLite
     └──▶ ML models — scikit-learn, XGBoost
```

## Tech Stack

- **Language:** Python
- **Backend:** Flask
- **Frontend:** Web frontend (frontend)
- **Database:** SQLite
- **ML:** scikit-learn, XGBoost
- **Deployment:** Docker container / Render (render.yaml)

## Getting Started

### Prerequisites

- Python 3.10+
- Docker (optional, for container runs)

### 1. Clone

```bash
git clone https://github.com/SabarishR08/SIH26153-AI-Network-Attack-Forecasting.git
cd SIH26153-AI-Network-Attack-Forecasting
```

### 2. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env   # then fill in values
```

Environment variables used: `FLASK_SECRET_KEY`, `FLASK_DEBUG`, `PORT`, `ENABLE_FORECASTING_MODEL`, `ENABLE_KILLCHAIN`.

Most features work without keys; integrations activate when keys are set.

### 4. Run

```bash
python integration/app.py
```

```bash
python run.py
```

### (Alternative) Run with Docker

```bash
docker compose up --build
```

## Deployment

Defined in `render.yaml` (web service `netwatch-sih26153-api`) with `autoDeploy` enabled — pushes to the default branch trigger a Render deploy.


---

![License](https://img.shields.io/badge/license-MIT-green) ![Language](https://img.shields.io/badge/language-Python-informational) ![Docker](https://img.shields.io/badge/docker-ready-2496ed) ![Deploy](https://img.shields.io/badge/deploy-Render-46e3b7)


## Overview

AI-Based Network Attack Forecasting from Network Traffic Data — SIH26153 (NTRO)

## Architecture

```text
Browser / UI
     │   HTTP
     ▼
Flask app
     │
     ├──▶ Database — SQLite
     └──▶ ML models — scikit-learn, XGBoost
```

## Tech Stack

- **Language:** Python
- **Backend:** Flask
- **Frontend:** Web frontend (frontend)
- **Database:** SQLite
- **ML:** scikit-learn, XGBoost
- **Deployment:** Docker container / Render (render.yaml)

## Getting Started

### Prerequisites

- Python 3.10+
- Docker (optional, for container runs)

### 1. Clone

```bash
git clone https://github.com/SabarishR08/SIH26153-AI-Network-Attack-Forecasting.git
cd SIH26153-AI-Network-Attack-Forecasting
```

### 2. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env   # then fill in values
```

Environment variables used: `FLASK_SECRET_KEY`, `FLASK_DEBUG`, `PORT`, `ENABLE_FORECASTING_MODEL`, `ENABLE_KILLCHAIN`.

Most features work without keys; integrations activate when keys are set.

### 4. Run

```bash
python integration/app.py
```

```bash
python run.py
```

### (Alternative) Run with Docker

```bash
docker compose up --build
```

## Deployment

Defined in `render.yaml` (web service `netwatch-sih26153-api`) with `autoDeploy` enabled — pushes to the default branch trigger a Render deploy.


---

**Problem statement:** AI Based Network Attack Forecasting from Network Traffic Data
**Problem owner:** NTRO
**Team:** Sabarish R et al.

---

## What is this?

An integrated threat detection and forecasting system that:

1. **Captures** network traffic (real or synthetic)
2. **Detects** anomalies (port scans, brute force, SYN floods, etc.)
3. **Forecasts** escalation probability before attacks fully execute
4. **Enriches** incidents with MITRE ATT&CK kill chain context
5. **Visualizes** everything in a real-time Flask dashboard

---

## Quick Start

### Prerequisites

- Python 3.10+
- Git
- **Npcap** (Windows only) — download from https://npcap.com

### Setup

```bash
git clone --recurse-submodules https://github.com/SabarishR08/SIH26153-AI-Network-Attack-Forecasting.git
cd SIH26153-AI-Network-Attack-Forecasting

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate    # macOS/Linux

pip install -r requirements.txt
copy .env.example .env         # Windows
# cp .env.example .env        # macOS/Linux
```

### Run

```bash
python run.py                  # Full pipeline + dashboard
# Open http://localhost:5000
```

### Live Monitoring (needs admin)

```bash
python run.py --monitor        # Windows (run as admin)
# sudo python run.py --monitor  # macOS/Linux
```

---

## Full Setup Guide

**For detailed step-by-step instructions (including Npcap, 3-terminal testing, troubleshooting), see:**

### [SETUP.md](SETUP.md)

---

## Testing the IDS (3 Terminals)

```bash
# Terminal 1 — Start the IDS
python run.py --monitor

# Terminal 2 — Scan your machine (triggers detection)
python scan_self.py

# Terminal 3 — Watch the dashboard
# Open http://localhost:5000
```

---

## Architecture

```
Network Traffic → Anomaly Detection → Feature Extraction → ML Forecasting → Kill Chain → Dashboard
       ↑                  ↑                   ↑                  ↑              ↑
   NTAV repo         NTAV repo          NEW (ours)         NEW (ours)    Killchain repo
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full technical architecture.

---

## Project Structure

| File | Purpose |
|---|---|
| `run.py` | Main entry point |
| `integration/` | Core pipeline (detection, forecasting, dashboard) |
| `repos/` | Original source repositories |
| `data/` | Runtime data (packets, anomalies, features) |
| `docs/` | Architecture, demo script, results |
| `SETUP.md` | **Full setup & testing guide** |
| `simulate_attack.py` | Generate synthetic attack data |
| `validate_detection.py` | Automated detection validation |
| `scan_self.py` | Quick self-scan test |

---

## Run Commands Cheat Sheet

| Command | Description |
|---|---|
| `python run.py` | Full pipeline + dashboard |
| `python run.py --no-pipeline` | Dashboard only |
| `python run.py --pipeline-only` | Pipeline only, then exit |
| `python run.py --live` | Capture 30s of real traffic |
| `python run.py --monitor` | Continuous live monitoring |
| `python validate_detection.py` | Run all 6 detection tests |
| `python simulate_attack.py` | Generate synthetic data |
| `python scan_self.py` | Scan your own machine |

---

## Test Tool: network-port-scanner

The project includes [PowerScan](https://github.com/SabarishR08/network-port-scanner) as a test traffic generator in `repos/network-port-scanner/`.

```bash
cd repos/network-port-scanner
pip install -r requirements.txt
python portscanergui.py
# Open http://127.0.0.1:5000
```

See [SETUP.md](SETUP.md#6-using-the-port-scanner-test-tool) for full instructions.

---

---

## License

[MIT](LICENSE) — © 2026 Sabarish R.

---

## License

[MIT](LICENSE) — © 2026 Sabarish R.
