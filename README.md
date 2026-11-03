# Ghost Data Still Exists — Data Deletion Audit Agent

A solo project built for **HackerRank Orchestrate — October 2026**.

The challenge was to determine whether a user's data had actually been deleted across multiple sources, identities, records, and evidence — rather than trusting a simple deletion confirmation.

## 🧩 The Problem

When a user requests data deletion, a system may report that the deletion is complete while data still exists somewhere else.

Examples include:

- Historical user identities
- Old records and snapshots
- Linked resources
- Synchronization or restoration paths
- Evidence recorded at different points in time

The goal was to audit the available evidence and determine the **actual deletion status** of each case.

---

## 🚀 What I Built

I built a local deletion-audit system that:

1. Resolves current and historical user identities
2. Parses evidence from multiple data formats
3. Checks records against deletion rules
4. Identifies remaining user data
5. Detects possible restoration/recreation paths
6. Determines the resulting deletion status
7. Generates ordered remediation and verification steps
8. Validates the final output automatically

The implementation is designed to work deterministically on the supplied challenge dataset without requiring external APIs or model credentials.

---

## 🏗️ Architecture

```text
Input Evidence
      │
      ▼
┌──────────────────────┐
│ Evidence Parser      │
│ CSV / JSON / SQL /   │
│ Logs / TXT / PDF     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Identity Resolution  │
│ Current + Historical │
│ Identifiers          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Evidence Linking     │
│ IDs / Resources /    │
│ Activity Records     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Deletion Rule Engine │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Status Determination │
│ COMPLETE /           │
│ INCOMPLETE /         │
│ NOT_APPLICABLE       │
└──────────┬───────────┘
           │
           ▼
      output.csv
```

---

## 🛠️ Technical Approach

- **JavaScript / Node.js**
- Python launcher
- Deterministic evidence analysis
- Identity resolution
- Rule-based deletion validation
- Multi-format evidence parsing
- Timestamp-aware evidence handling
- Automated output validation
- Public-sample evaluation
- Custom generalization tests

Supported evidence includes formats such as:

- CSV
- JSON
- SQL INSERT snapshots
- Key/value and JSON logs
- Pipe-delimited records
- TXT
- Basic PDF text

---

## 📊 Evaluation

My final implementation was tested against the public evaluation cases and additional custom/generalization checks.

### Results

| Metric | Result |
|---|---:|
| Public status accuracy | **32 / 32** |
| Custom/generalization checks | **11 / 11** |
| Full dataset processed | **518 cases** |
| Exact sequence accuracy | **21.88%** |
| Exact-step precision | **65.19%** |
| Exact-step recall | **53.37%** |
| Field accuracy | **70.91%** |

Full-dataset result:

- **123 COMPLETE**
- **359 INCOMPLETE**
- **36 NOT_APPLICABLE**

These results reflect the final validated implementation.

---

## 🏆 HackerRank Orchestrate — October 2026

**Challenge:** Ghost Data Still Exists  
**Participation:** Solo  
**Final Rank:** **#2579 / 4,094**

### Component Scores

- Chat Transcript: **8.5 / 10**
- Output CSV: **21.0 / 30**
- AI Judge Interview: **7.8 / 30**
- Code ZIP: **2.7 / 30**
- Total: **40.0**

The experience highlighted an important lesson: producing correct outputs is only one part of building an effective agent system. Architecture, tool usage, observability, evaluation strategy, and communication of the agent's decision process matter as well.

---

## 💡 What I Learned

### 1. Architecture matters as much as the final answer

I initially focused heavily on getting the correct result.

The challenge showed me that a strong agent system also needs clear architecture, evidence retrieval, tool usage, and observable decision-making.

### 2. Real-world data is messy

Deletion auditing requires dealing with:

- Multiple identifiers
- Historical records
- Conflicting evidence
- Different timestamps
- Linked resources
- Possible data recreation paths

Correctly connecting evidence is often harder than writing the final decision logic.

### 3. Iteration beats trying to get everything right initially

The project went through multiple rounds of testing, debugging, evaluation, and refinement.

Each evaluation exposed weaknesses that weren't obvious from individual test cases.

---

## 🔭 What I Would Improve

If I rebuilt this project, I would focus more on:

- Stronger agent/tool orchestration
- Better evidence retrieval
- More explicit reasoning and decision traces
- Evaluation-driven architecture
- Better separation between reasoning and deterministic validation
- More robust handling of edge cases
- Improving sequence and step-level accuracy

The biggest lesson for me was that **an AI-powered solution and a well-designed AI agent are not necessarily the same thing.**

---

## 📁 Project Structure

```text
hackerrank-orchestrate-october26/
│
├── code/
│   ├── main.js
│   ├── main.py
│   │
│   └── evaluation/
│       ├── main.js
│       ├── evaluation_report.md
│       └── usage_report.md
│
├── .gitignore
└── README.md
```

Challenge datasets, generated outputs, logs, submission archives, and other challenge-only files are intentionally excluded from the public repository.

---

## ▶️ Running the Project

### Requirements

- Node.js 18+
- Python 3.x (optional)

### Generate output

```bash
node code/main.js
```

### Run evaluation

```bash
node code/evaluation/main.js
```

The evaluator reports status accuracy, step/field comparisons, sequence accuracy, and additional validation checks.

---

## 👨‍💻 About

**Ayush Nishad**  
BTech CSE — 2nd Year

This was my first solo AI-agent competition project after previously working mainly on team-based hackathons.

The project helped me understand the difference between simply producing an AI-powered result and designing a system that can be evaluated as an agent.

---

## 🔗 Links

**GitHub:**  
https://github.com/codewithdamon/hackerrank-orchestrate-october26

**Competition:**  
HackerRank Orchestrate — October 2026
