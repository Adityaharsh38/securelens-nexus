# SecureLens Nexus

### Graph-Native Security Investigation Agent

SecureLens Nexus is a security investigation platform that combines heuristic code analysis with FalkorDB graph storage to organize vulnerability findings, inspect connected evidence, and recommend remediation.

Instead of presenting a vulnerability alert in isolation, SecureLens Nexus uses graph relationships and an investigation workflow to explain what evidence is available, which relationships have been inspected, and whether an attack path has been established.

## The Problem

Traditional vulnerability reports can identify suspicious code but often leave developers with questions:

- What evidence supports the finding?
- What related entities are represented in the security graph?
- Can a path to a potentially affected asset be established?
- What remediation should be prioritized?

SecureLens Nexus explores how graph-native investigation can help answer these questions transparently.

## Key Features

- **Code analysis:** Submit JavaScript for heuristic SQL-injection pattern detection.
- **Graph-backed findings:** Store scans and findings in FalkorDB.
- **Investigation agent:** Retrieve scan-specific evidence and inspect finding relationships.
- **Graph-path investigation:** Attempt to establish a source-to-sink-to-asset path using scan-scoped graph relationships.
- **Explainable results:** Display findings, evidence, remediation recommendations, and an investigation tool trace.
- **Authentication:** Protect user-facing analysis and investigation workflows.
- **Investigation history:** Retrieve previously saved investigations associated with the authenticated user.
- **Synthetic demo:** Explore explicitly modeled security relationships separately from evidence discovered in submitted code.

## Architecture

```text
React + Vite Frontend
        |
        v
Node.js + Express Backend
        |
        +---- Authentication
        |
        +---- Python Heuristic Analyzer
        |
        +---- Investigation Agent
        |
        v
      FalkorDB
        |
        +---- Repositories and Files
        +---- Findings and Security Rules
        +---- Modeled Sinks and Assets
        +---- Investigation Records
```

### Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, JavaScript, Vite |
| Backend | Node.js, Express |
| Analysis engine | Python |
| Graph database | FalkorDB |
| Authentication | JWT and bcrypt |
| Local development | Node.js, npm, Python |

## Graph Model

The graph represents security evidence through nodes and relationships.

### Core nodes

- `Repository` — groups analyzed files.
- `File` — represents a submitted source file or demo file.
- `Finding` — represents a potential vulnerability reported by the analyzer.
- `SecurityRule` — identifies the detection rule associated with a finding.
- `Sink` — represents a modeled potentially dangerous operation.
- `Asset` — represents a modeled resource that may be affected.
- `Investigation` — represents a saved investigation record.

### Core relationships

```text
Repository -[:CONTAINS]-> File
File -[:HAS_FINDING]-> Finding
Finding -[:DETECTED_BY]-> SecurityRule

Finding -[:INDICATES]-> Sink
Sink -[:AFFECTS]-> Asset
```

The last two relationships are used for explicitly modeled synthetic demo scenarios. They are not automatically established for every submitted-code finding.

## Investigation Workflow

1. An authenticated user submits JavaScript.
2. The backend validates the input and invokes the Python analyzer.
3. The analyzer returns structured findings.
4. The backend stores the scan and findings in FalkorDB.
5. The investigation agent retrieves evidence belonging to the requested scan.
6. The agent inspects connected finding relationships and attempts a graph-path query.
7. The result presents the evidence, investigation steps, and recommended remediation.
8. If a complete path is not established, the application reports that limitation instead of substituting synthetic relationships.

## Current Detection Scope

The current analyzer implements heuristic JavaScript SQL-injection detection.

For a detected pattern, the application can recommend parameterized queries and separate user-controlled values from SQL statements.

A heuristic finding indicates a potentially vulnerable pattern; it does not independently prove runtime exploitability.

### Known Limitations

- Detection coverage is limited and can produce false positives or false negatives.
- The current analyzer is not a complete multi-language static analysis engine.
- Submitted-code scans do not yet establish a complete source-to-sink-to-asset path.
- Synthetic graph relationships are demonstration data and must not be interpreted as findings discovered in submitted code.
- The application does not independently prove that a reported vulnerability is exploitable in a running application.

These limitations define the current prototype's scope and guide future development.

## Getting Started

### Prerequisites

- Node.js and npm
- Python 3
- A reachable FalkorDB instance
- Git

### 1. Clone the repository

```bash
git clone https://github.com/Adityaharsh38/securelens-nexus.git
cd securelens-nexus
```

### 2. Configure environment variables

Create local environment files using the variable names expected by the backend and frontend. Consult the source code and existing configuration before setting them.

Configure the FalkorDB connection, authentication secret, and any required service URLs locally.

**Never commit real credentials, tokens, or environment files.**

### 3. Install dependencies

Install backend and frontend dependencies in their respective directories:

```bash
cd backend
npm install
```

```bash
cd ../frontend
npm install
```

Install Python dependencies according to the security engine's dependency files, if present.

### 4. Start the services

Use the scripts defined in each `package.json` to start the backend and frontend. Configure the Python interpreter and FalkorDB connection as required.

The current development setup uses the backend on port `4000` and the Vite frontend on port `5173`.

## Security Considerations

- Submitted code is written to a temporary file for analysis and the temporary directory is cleaned up afterward.
- Source code is not intentionally persisted as a graph property by the current submission flow.
- User-facing scan and investigation access should be authenticated and scoped to the relevant owner.
- Secrets should be supplied through environment variables and excluded from version control.
- The heuristic analyzer should not be treated as a replacement for comprehensive security testing.

## Project Status

SecureLens Nexus is a working prototype demonstrating graph-backed security findings and evidence-driven investigation workflows.

Future work includes broader detection coverage, richer verified source-to-sink relationships, dependency analysis, stronger graph-based prioritization, and expanded automated testing.

## Hackathon Track

**Track:** Agents That Act on Connected Data

SecureLens Nexus explores how an agent can use FalkorDB as an evidence store, inspect connected security entities, and produce explainable investigation results instead of relying exclusively on isolated vulnerability alerts.

## AI Assistance Disclosure

AI coding assistance was used during development. The submitted implementation, its limitations, and its demonstrated behavior should be evaluated based on the actual source code and working application.
