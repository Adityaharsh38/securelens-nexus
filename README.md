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
- **Explainable results:** Display findings, source evidence, remediation recommendations, and an investigation tool trace.
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

The `INDICATES` and `AFFECTS` relationships are used in explicitly modeled synthetic demo scenarios. They are not automatically established for every submitted-code finding.

## Investigation Workflow

1. An authenticated user submits JavaScript.
2. The backend validates the input and invokes the Python analyzer.
3. The analyzer returns structured findings.
4. The backend stores the scan and findings in FalkorDB.
5. The investigation agent retrieves evidence belonging to the requested scan.
6. The agent inspects connected finding relationships and attempts a graph-path query.
7. The result presents the evidence, investigation steps, and recommended remediation.
8. If a complete path is not established, the application reports that limitation instead of substituting synthetic relationships.

## FalkorDB Queries and Investigation Tools

SecureLens Nexus uses Cypher queries to retrieve graph evidence and inspect relationships. Its investigation workflow includes evidence retrieval, relationship inspection, and attack-path investigation.

### 1. Retrieve scan evidence

The `retrieveEvidence` tool retrieves file and finding information, with an optional relationship to a security rule.

Illustrative query shape:

```cypher
MATCH (file:File)-[:HAS_FINDING]->(finding:Finding)
OPTIONAL MATCH (finding)-[:DETECTED_BY]->(rule:SecurityRule)
RETURN file, finding, rule
```

**Purpose:** Retrieve stored findings and their associated detection rules. The submitted-scan implementation applies ownership and scan filters; consult the source code for the exact query and parameters.

### 2. Inspect finding relationships

The `inspectFindingRelationships` tool examines relationships connected to findings and returns information about connected nodes.

Illustrative query shape:

```cypher
MATCH (file:File)-[:HAS_FINDING]->(finding:Finding)
OPTIONAL MATCH (finding)-[rel]-(connected)
RETURN finding, type(rel), labels(connected), connected.id, connected.name
```

**Purpose:** Inspect stored graph relationships and distinguish a finding linked to a security rule from a finding linked to a modeled sink or asset. The actual implementation scopes this operation to the relevant scan.

### 3. Trace a possible attack path

The investigation workflow attempts to find a path from a finding through a sink to an affected asset.

Illustrative query shape:

```cypher
MATCH (finding:Finding)-[:INDICATES]->(sink:Sink)
      -[:AFFECTS]->(asset:Asset)
RETURN finding, sink, asset
```

**Purpose:** Determine whether the expected relationships exist in the graph. The actual submitted-scan query uses scan-specific evidence and ownership filters.

A query returning zero results means the requested path was not established by that query. It does not prove that the code is safe or that no vulnerability exists.

### Evidence integrity

Submitted-code findings currently use the relationships `HAS_FINDING` and `DETECTED_BY`. The `INDICATES` and `AFFECTS` relationships are used by explicitly modeled synthetic demo scenarios.

The investigation interface distinguishes these cases rather than treating synthetic relationships as evidence discovered in submitted code.

The illustrative query shapes above explain the investigation logic; `backend/src/agents/investigationAgent.js` contains the actual implementation and its parameters.

## Current Detection Scope

The current analyzer implements heuristic JavaScript SQL-injection detection.

For a detected pattern, the application can recommend parameterized queries and passing user-controlled values separately from SQL statements.

A heuristic finding indicates a potentially vulnerable pattern; it does not independently prove runtime exploitability.

### Known Limitations

- Detection coverage is limited and can produce false positives or false negatives.
- The analyzer is not a complete multi-language static analysis engine.
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

Create local environment files using the variable names expected by the backend and frontend. Check the source code and existing configuration for the required names.

Configure the FalkorDB connection, authentication secret, and any required service URLs locally.

**Never commit real credentials, tokens, or environment files.**

### 3. Install Node.js dependencies

```bash
cd backend
npm install
```

In a second terminal, install frontend dependencies:

```bash
cd securelens-nexus/frontend
npm install
```

Replace `securelens-nexus` in the second command with the absolute project path if needed, or navigate to the project root before running `cd frontend`.

Install Python dependencies using the security engine's dependency file, if one is present.

### 4. Start the services

Use the scripts defined in `backend/package.json` and `frontend/package.json` to start the backend and frontend. Configure the Python interpreter and FalkorDB connection as required.

The current development setup uses:

- Backend: port `4000`
- Frontend: port `5173`

The application requires a reachable FalkorDB instance for graph-backed features.

## Security Considerations

- Submitted code is written to a temporary file for analysis, and the temporary directory is cleaned up afterward.
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
