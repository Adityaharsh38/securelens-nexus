
const express = require("express");
const { getGraph } = require("../graph/client");

const router = express.Router();

// Check the FalkorDB connection.
router.get("/test", async (req, res) => {
  try {
    const { graph } = await getGraph();

    const result = await graph.query(
      "MATCH (s:Service {id: $id}) RETURN s.name AS service",
      { params: { id: "svc-demo" } }
    );

    res.json({
      status: "connected",
      graph: process.env.FALKORDB_GRAPH,
      result: result.data || [],
    });
  } catch (error) {
    console.error("FalkorDB query failed:", error.message);
    res.status(503).json({
      status: "error",
      message: "FalkorDB query failed. Check server logs and connection settings.",
    });
  }
});

// Retrieve analyzer findings and their connected graph evidence.
router.get("/evidence", async (req, res) => {
  try {
    const { graph } = await getGraph();

    const result = await graph.query(`
      MATCH (f:File)-[:HAS_FINDING]->(finding:Finding)
      OPTIONAL MATCH (finding)-[:INDICATES]->(sink:Sink)
      OPTIONAL MATCH (sink)-[:AFFECTS]->(asset:Asset)
      RETURN
        f.name AS file,
        finding.ruleId AS ruleId,
        finding.type AS type,
        finding.severity AS severity,
        finding.line AS line,
        finding.message AS message,
        finding.evidence AS evidence,
        finding.recommendation AS recommendation,
        sink.name AS sink,
        asset.name AS asset,
        asset.sensitivity AS sensitivity
      ORDER BY finding.severity, f.name
    `);

    res.json({
      status: "ok",
      count: (result.data || []).length,
      findings: result.data || [],
      limitation:
        "Pattern-based analyzer results and modeled graph paths require review; they do not prove runtime exploitability.",
    });
  } catch (error) {
    console.error("Graph evidence lookup failed:", error.message);
    res.status(503).json({
      error: "Could not retrieve graph evidence",
    });
  }
});

module.exports = router;
