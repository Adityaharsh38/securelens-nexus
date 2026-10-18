
const express = require("express");
const path = require("path");
const os = require("os");
const fs = require("fs/promises");
const { randomUUID } = require("crypto");
const { execFile } = require("child_process");
const { promisify } = require("util");

const { getGraph } = require("../graph/client");
const authenticate = require("../middleware/authenticate");

const router = express.Router();
const execFileAsync = promisify(execFile);

const projectRoot = path.resolve(__dirname, "../../../");
const analyzerPath = path.join(
  projectRoot,
  "security-engine",
  "analyzer.py"
);

const MAX_CODE_CHARS = 20000;
const MAX_FINDINGS = 100;

async function runAnalyzerOnFile(filePath) {
  const { stdout } = await execFileAsync(
    process.env.PYTHON_BIN || "python3",
    [analyzerPath, "--file", filePath],
    {
      timeout: 10000,
      maxBuffer: 1024 * 1024,
    }
  );

  return JSON.parse(stdout);
}

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

function normalizeFindings(findings) {
  if (!Array.isArray(findings)) {
    throw new Error("Analyzer returned an invalid findings list.");
  }

  return findings.slice(0, MAX_FINDINGS).map((finding, index) => ({
    id:
      String(finding.ruleId || "UNKNOWN") +
      ":" +
      String(Number.isInteger(finding.line) ? finding.line : 0) +
      ":" +
      String(index + 1),
    ruleId: String(finding.ruleId || "UNKNOWN").slice(0, 100),
    type: String(finding.type || "SECURITY_FINDING").slice(0, 100),
    severity: String(finding.severity || "unknown").slice(0, 30),
    line: Number.isInteger(finding.line) ? finding.line : 0,
    message: String(finding.message || "").slice(0, 1000),
    evidence: String(finding.evidence || "").slice(0, 300),
    recommendation: String(finding.recommendation || "").slice(0, 1500),
    confidence: String(finding.confidence || "heuristic").slice(0, 50),
  }));
}

async function storeFindings({
  graph,
  fileId,
  userId,
  scanId,
  findings,
  synthetic = false,
  demoRepositoryId = null,
}) {
  if (findings.length === 0) return 0;

  const items = findings.map((finding, index) => ({
    ...finding,
    id: synthetic
      ? `${fileId}:${finding.ruleId}:${finding.line}`
      : `${fileId}:finding:${index + 1}`,
    sinkId: synthetic
      ? `${demoRepositoryId}:sql-sink`
      : null,
    assetId: synthetic
      ? `${demoRepositoryId}:demo-customer-asset`
      : null,
  }));

  const result = await graph.query(
    `
      MATCH (file:File {id: $fileId})
      WHERE $synthetic = true
         OR (
           file.ownerId = $userId
           AND file.scanId = $scanId
           AND file.synthetic = false
         )

      UNWIND $findings AS item

      CREATE (finding:Finding {
        id: item.id,
        ruleId: item.ruleId,
        type: item.type,
        severity: item.severity,
        line: item.line,
        message: item.message,
        evidence: item.evidence,
        recommendation: item.recommendation,
        confidence: item.confidence,
        source: 'python-heuristic-analyzer',
        ownerId: $userId,
        scanId: $scanId,
        synthetic: $synthetic
      })

      MERGE (file)-[:HAS_FINDING]->(finding)

      MERGE (rule:SecurityRule {id: item.ruleId})
      SET rule.name = item.type,
          rule.analysisType = 'heuristic'

      MERGE (finding)-[:DETECTED_BY]->(rule)

      WITH finding, item

      FOREACH (_ IN CASE WHEN $synthetic THEN [1] ELSE [] END |
        MERGE (sink:Sink {id: item.sinkId})
        SET sink.name = 'SQL query execution',
            sink.type = 'sql',
            sink.synthetic = true

        MERGE (asset:Asset {id: item.assetId})
        SET asset.name = 'Demo customer database',
            asset.sensitivity = 'high',
            asset.synthetic = true

        MERGE (finding)-[:INDICATES]->(sink)
        MERGE (sink)-[:AFFECTS]->(asset)
      )

      RETURN count(finding) AS storedFindings
    `,
    {
      params: {
        fileId,
        userId: userId || "synthetic-demo",
        scanId: scanId || "synthetic-demo",
        findings: items,
        synthetic,
      },
    }
  );

  const storedCount = Number(
    result.data?.[0]?.storedFindings ?? 0
  );

  if (storedCount !== findings.length) {
    throw new Error(
      `Finding storage mismatch: expected ${findings.length}, stored ${storedCount}.`
    );
  }

  return storedCount;
}

// -----------------------------------------------------------------------------
// Synthetic demo analysis
// -----------------------------------------------------------------------------

router.post("/demo", async (req, res) => {
  try {
    const fixture = req.body?.fixture || "vulnerable";

    if (!["vulnerable", "safe"].includes(fixture)) {
      return res.status(400).json({
        error: 'fixture must be "vulnerable" or "safe".',
      });
    }

    const fixturePath = path.join(
      projectRoot,
      "security-engine",
      "tests",
      fixture === "safe" ? "safe-demo.js" : "vulnerable-demo.js"
    );

    const analysis = await runAnalyzerOnFile(fixturePath);
    const { graph } = await getGraph();

    const repositoryId = "securelens-demo-repository";
    const fileId = `demo-${fixture}-file`;
    const scanId = `demo-${fixture}`;

    await graph.query(
      `
        MERGE (repo:Repository {id: $repositoryId})
        SET repo.name = 'SecureLens Demo Repository',
            repo.synthetic = true

        MERGE (file:File {id: $fileId})
        SET file.name = $fileName,
            file.language = $language,
            file.analysis = $analysisType,
            file.findingsCount = $findingsCount,
            file.analyzedAt = $analyzedAt,
            file.synthetic = true,
            file.scanId = $scanId

        MERGE (repo)-[:CONTAINS]->(file)
        RETURN file.id AS fileId
      `,
      {
        params: {
          repositoryId,
          fileId,
          scanId,
          fileName: analysis.file,
          language: analysis.language,
          analysisType: analysis.analysis,
          findingsCount: analysis.findings.length,
          analyzedAt: new Date().toISOString(),
        },
      }
    );

    const findings = normalizeFindings(analysis.findings);

    const storedFindings = await storeFindings({
      graph,
      fileId,
      scanId,
      findings,
      synthetic: true,
      demoRepositoryId: repositoryId,
    });

    return res.json({
      status: "analyzed",
      fixture,
      analysis,
      graph: {
        repositoryId,
        fileId,
        findingsStored: storedFindings,
      },
      limitation:
        "Heuristic analysis of synthetic demo code. Findings require review; no matching pattern does not prove code is safe.",
    });
  } catch (error) {
    console.error("Analyzer demo failed:", error.message);

    return res.status(500).json({
      error: "Demo analysis or graph ingestion failed.",
      details: "Check the backend logs for diagnostic information.",
    });
  }
});

// -----------------------------------------------------------------------------
// Authenticated pasted-code analysis
// Submitted JavaScript is analyzed statically, never executed.
// The full source is not persisted.
// -----------------------------------------------------------------------------

router.post("/code", authenticate, async (req, res) => {
  const code = req.body?.code;

  if (typeof code !== "string" || !code.trim()) {
    return res.status(400).json({
      error: "Paste JavaScript code to analyze.",
    });
  }

  if (code.length > MAX_CODE_CHARS) {
    return res.status(413).json({
      error: `Code exceeds the ${MAX_CODE_CHARS.toLocaleString()} character limit.`,
    });
  }

  let tempDir;

  try {
    tempDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "securelens-")
    );

    const tempFile = path.join(tempDir, "pasted-code.js");

    await fs.writeFile(tempFile, code, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });

    const analysis = await runAnalyzerOnFile(tempFile);
    const findings = normalizeFindings(analysis.findings);

    const { graph } = await getGraph();

    const scanId = randomUUID();
    const userId = String(req.user.id);
    const repositoryId = `user-${userId}-submitted-code`;
    const fileId = `scan-${scanId}-file`;
    const analyzedAt = new Date().toISOString();

    await graph.query(
      `
        MERGE (repo:Repository {id: $repositoryId})
        SET repo.name = 'Submitted Code Scans',
            repo.ownerId = $userId,
            repo.synthetic = false

        CREATE (file:File {
          id: $fileId,
          name: 'pasted-code.js',
          language: $language,
          analysis: $analysisType,
          findingsCount: $findingsCount,
          analyzedAt: $analyzedAt,
          ownerId: $userId,
          scanId: $scanId,
          sourceStored: false,
          synthetic: false
        })

        MERGE (repo)-[:CONTAINS]->(file)
        RETURN file.id AS fileId
      `,
      {
        params: {
          repositoryId,
          userId,
          scanId,
          fileId,
          language: analysis.language,
          analysisType: analysis.analysis,
          findingsCount: findings.length,
          analyzedAt,
        },
      }
    );

    const storedFindings = await storeFindings({
      graph,
      fileId,
      userId,
      scanId,
      findings,
      synthetic: false,
    });

    return res.json({
      status: "analyzed",
      analysis: {
        ...analysis,
        file: "pasted-code.js",
        findings,
        findingsCount: findings.length,
      },
      graph: {
        scanId,
        repositoryId,
        fileId,
        findingsStored: storedFindings,
        sourceStored: false,
        relationships: [
          "Repository-[:CONTAINS]->File",
          "File-[:HAS_FINDING]->Finding",
          "Finding-[:DETECTED_BY]->SecurityRule",
        ],
      },
      limitation:
        "JavaScript pattern-based SQL-injection analysis only. Findings are heuristic and require review. No finding does not prove code is safe. The graph stores findings and bounded evidence, not the full submitted source. No source-to-sink-to-asset reachability is inferred for submitted code.",
    });
  } catch (error) {
    console.error("Pasted-code analysis failed:", error.message);

    return res.status(500).json({
      error: "Source analysis or graph ingestion failed.",
      details: "Check the backend logs for diagnostic information.",
    });
  } finally {
    if (tempDir) {
      await fs.rm(tempDir, {
        recursive: true,
        force: true,
      }).catch((cleanupError) => {
        console.error(
          "Temporary analysis cleanup failed:",
          cleanupError.message
        );
      });
    }
  }
});

module.exports = router;
