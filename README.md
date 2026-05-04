# Multi-Agent Code Review & Bug Repair System

**Tech:** Python, LangGraph, LLM APIs, ChromaDB, Docker, GitHub Actions

---

## Overview

An autonomous multi-agent LLM pipeline that reviews code, detects bugs semantically, and generates patch suggestions — triggered automatically on every pull request via GitHub Actions CI/CD.

---

## Key Features

- Built a multi-agent LLM pipeline using LangGraph with specialized agents for static analysis, semantic bug detection, and automated patch generation — orchestrated via a ReAct loop with shared state across agents.
- Reduced redundant LLM inference calls by ~40% by integrating ChromaDB as a semantic cache for known error patterns, directly cutting operational cost at scale.
- Containerized the full pipeline with Docker and wired into GitHub Actions CI/CD, enabling automated code review on every pull request without manual intervention.

---

## Tech Stack

- **Agent Orchestration:** LangGraph (ReAct loop)
- **LLM APIs:** OpenAI / Anthropic
- **Semantic Cache:** ChromaDB
- **Containerization:** Docker
- **CI/CD:** GitHub Actions
- **Language:** Python 3.11

---

## Getting Started

### Prerequisites

- Python 3.11+
- Docker
- OpenAI or Anthropic API key

### Installation

```bash
git clone https://github.com/MadhavKalletla/multi-agent-code-review
cd multi-agent-code-review
pip install -r requirements.txt
```

### Run locally

```bash
docker build -t code-review-agent .
docker run -e OPENAI_API_KEY=your_key code-review-agent
```

### GitHub Actions setup

Add your API key to repo secrets as `OPENAI_API_KEY`. The workflow in `.github/workflows/review.yml` triggers automatically on every PR.

---

## Project Structure

```
├── agents/
│   ├── static_analysis.py
│   ├── semantic_detection.py
│   └── patch_generation.py
├── graph/
│   └── pipeline.py
├── cache/
│   └── chroma_store.py
├── .github/workflows/
│   └── review.yml
├── Dockerfile
└── main.py
```

---

## Results

- ~40% reduction in LLM inference calls via ChromaDB semantic caching
- Fully automated code review on every PR with zero manual intervention
