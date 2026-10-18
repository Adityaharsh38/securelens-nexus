
const MAX_RESULTS = 20;

async function traceAttackPath(graph, inputId = "input-demo") {
  const result = await graph.query(
    `
      MATCH p =
        (i:Input {id: $inputId})
        -[:FLOWS_TO*1..3]->(sink:Sink)
        -[:AFFECTS]->(asset:Asset)
      RETURN
        i.name AS input,
        i.trust AS trust,
        [n IN nodes(p) | labels(n)[0]] AS nodeTypes,
        [n IN nodes(p) | coalesce(n.name, n.id)] AS path,
        sink.name AS sink,
        asset.id AS assetId,
        asset.name AS asset,
        asset.sensitivity AS sensitivity
      LIMIT $limit
    `,
    { params: { inputId, limit: MAX_RESULTS } }
  );

  return result.data || [];
}

async function assessBlastRadius(graph, inputId = "input-demo") {
  const result = await graph.query(
    `
      MATCH (i:Input {id: $inputId})
        -[:FLOWS_TO*1..6]->(sink:Sink)
        -[:AFFECTS]->(asset:Asset)
      RETURN DISTINCT
        asset.id AS assetId,
        asset.name AS asset,
        asset.sensitivity AS sensitivity,
        sink.name AS sink
      ORDER BY asset.name
      LIMIT $limit
    `,
    { params: { inputId, limit: MAX_RESULTS } }
  );

  return result.data || [];
}

function makeStep(
  tool,
  purpose,
  resultCount,
  decision,
  status = "completed"
) {
  return { tool, purpose, resultCount, decision, status };
}

async function retrieveEvidence(graph, options = {}) {
  const { scanId, userId, fileId } = options;

  // Retrieve evidence only for the authenticated user's specific scan.
  if (scanId && userId && fileId) {
    const result = await graph.query(
      `
        MATCH (file:File {
          id: $fileId,
          ownerId: $userId,
          scanId: $scanId
        })
        OPTIONAL MATCH (file)-[:HAS_FINDING]->(finding:Finding {
          ownerId: $userId,
          scanId: $scanId
        })
        OPTIONAL MATCH (finding)-[:DETECTED_BY]->(rule:SecurityRule)
        RETURN
          file.name AS file,
          file.id AS fileId,
          finding.id AS findingId,
          finding.ruleId AS ruleId,
          finding.type AS type,
          finding.severity AS severity,
          finding.line AS line,
          finding.message AS message,
          finding.evidence AS evidence,
          finding.recommendation AS recommendation,
          finding.confidence AS confidence,
          rule.name AS detectedBy,
          null AS sink,
          null AS asset
        ORDER BY finding.line
        LIMIT $limit
      `,
      {
        params: { fileId, userId, scanId, limit: MAX_RESULTS },
      }
    );

    return (result.data || []).filter(
      (item) => item.findingId != null
    );
  }

  // Preserve the existing synthetic demo evidence query.
  const result = await graph.query(
    `
      MATCH (file:File)-[:HAS_FINDING]->(finding:Finding)
      OPTIONAL MATCH (finding)-[:INDICATES]->(sink:Sink)
      OPTIONAL MATCH (sink)-[:AFFECTS]->(asset:Asset)
      RETURN
        file.name AS file,
        finding.ruleId AS ruleId,
        finding.type AS type,
        finding.severity AS severity,
        finding.line AS line,
        finding.message AS message,
        finding.evidence AS evidence,
        finding.recommendation AS recommendation,
        finding.confidence AS confidence,
        sink.name AS sink,
        asset.name AS asset
      ORDER BY file.name
      LIMIT $limit
    `,
    { params: { limit: MAX_RESULTS } }
  );

  return result.data || [];
}

// Inspect only relationships connected to findings belonging to this scan.
// This query does not assume that a sink or asset exists.
async function inspectFindingRelationships(graph, options) {
  const { scanId, userId, fileId } = options;

  const result = await graph.query(
    `
      MATCH (file:File {
        id: $fileId,
        ownerId: $userId,
        scanId: $scanId
      })-[:HAS_FINDING]->(finding:Finding {
        ownerId: $userId,
        scanId: $scanId
      })
      OPTIONAL MATCH (finding)-[rel]-(connected)
      RETURN
        finding.id AS findingId,
        finding.ruleId AS ruleId,
        type(rel) AS relationship,
        labels(connected) AS connectedNodeTypes,
        connected.id AS connectedNodeId,
        connected.name AS connectedNodeName
      LIMIT $limit
    `,
    {
      params: {
        scanId,
        userId,
        fileId,
        limit: MAX_RESULTS,
      },
    }
  );

  return result.data || [];
}

function selectRecommendation(findings, attackPaths) {
  const finding = findings.find(
    (item) =>
      typeof item.recommendation === "string" &&
      item.recommendation.trim().length > 0
  );

  if (finding) {
    return {
      text: finding.recommendation,
      source: "finding",
      ruleId: finding.ruleId || null,
    };
  }

  if (attackPaths.length > 0) {
    return {
      text:
        "Review the modeled source-to-sink path and verify that user-controlled values are passed separately through parameterized SQL queries. Confirm the fix with tests.",
      source: "graph-path-guidance",
      ruleId: null,
    };
  }

  return {
    text:
      "A missing graph path does not establish safety. Verify graph coverage, source-analysis results, and relevant data flows before drawing a conclusion.",
    source: "general-guidance",
    ruleId: null,
  };
}

async function runScanInvestigation(graph, options) {
  const { scanId, userId, fileId } = options;
  const steps = [];

  // Step 1: retrieve findings for the requested scan.
  const findings = await retrieveEvidence(graph, {
    scanId,
    userId,
    fileId,
  });

  steps.push(
    makeStep(
      "retrieve_scan_evidence",
      "Retrieve findings belonging to the authenticated user's scan.",
      findings.length,
      findings.length
        ? "Findings were returned; inspect their graph relationships next."
        : "No findings were returned. Check analyzer coverage and graph ingestion."
    )
  );

  // Step 2: inspect actual edges attached to the scan's findings.
  const relationships = await inspectFindingRelationships(graph, {
    scanId,
    userId,
    fileId,
  });

  const hasRuleRelationship = relationships.some(
    (item) => item.relationship === "DETECTED_BY"
  );

  const hasSinkAssetRelationship = relationships.some(
    (item) =>
      item.connectedNodeTypes?.includes("Sink") ||
      item.connectedNodeTypes?.includes("Asset")
  );

  steps.push(
    makeStep(
      "inspect_finding_relationships",
      "Inspect relationships connected to this scan's findings.",
      relationships.length,
      relationships.length
        ? `FalkorDB returned ${relationships.length} relationship record(s). ${
            hasRuleRelationship
              ? "A security-rule relationship was found. "
              : "No security-rule relationship was returned. "
          }${
            hasSinkAssetRelationship
              ? "A sink or asset node is connected to a finding."
              : "No connected sink or asset node was found."
          }`
        : "No connected relationships were returned for these findings."
    )
  );

  // Step 3: only trace a path if the graph actually supports it.
  // Never borrow relationships from the shared synthetic demo.
  let attackPaths = [];
  let assets = [];

  const pathResult = await graph.query(
    `
      MATCH p =
        (file:File {
          id: $fileId,
          ownerId: $userId,
          scanId: $scanId
        })-[:HAS_FINDING]->(finding:Finding {
          ownerId: $userId,
          scanId: $scanId
        })-[:INDICATES]->(sink:Sink)-[:AFFECTS]->(asset:Asset)
      RETURN
        finding.ruleId AS ruleId,
        [n IN nodes(p) | labels(n)[0]] AS nodeTypes,
        [n IN nodes(p) | coalesce(n.name, n.id)] AS path,
        sink.name AS sink,
        asset.id AS assetId,
        asset.name AS asset,
        asset.sensitivity AS sensitivity
      LIMIT $limit
    `,
    {
      params: {
        fileId,
        userId,
        scanId,
        limit: MAX_RESULTS,
      },
    }
  );

  attackPaths = pathResult.data || [];

  assets = [
    ...new Map(
      attackPaths
        .filter((item) => item.assetId)
        .map((item) => [item.assetId, item])
    ).values(),
  ];

  steps.push(
    makeStep(
      "trace_scan_graph_path",
      "Trace a source-to-sink-to-asset path using relationships belonging to this scan.",
      attackPaths.length,
      attackPaths.length
        ? "A complete scan-scoped path was returned by FalkorDB."
        : "No complete scan-scoped path was found. The synthetic demo graph was not used as evidence.",
      attackPaths.length ? "completed" : "not-modeled"
    )
  );

  // Step 4: select a recommendation based on stored evidence.
  const recommendation = selectRecommendation(findings, attackPaths);

  steps.push(
    makeStep(
      "select_remediation",
      "Select a recommendation from the stored finding or explain the evidence gap.",
      recommendation.ruleId ? 1 : 0,
      recommendation.ruleId
        ? `Recommendation sourced from rule ${recommendation.ruleId}.`
        : "No rule-specific recommendation was available; general guidance is provided."
    )
  );

  return {
    status: findings.length ? "potential-risk" : "no-findings",
    summary: findings.length
      ? `The submitted scan contains ${findings.length} potential finding(s).`
      : "No findings were retrieved for this scan. This does not prove the code is safe.",
    scanId,
    fileId,
    attackPaths,
    assets,
    findings,
    relationships,
    steps,
    recommendation: recommendation.text,
    recommendationSource: recommendation.source,
    recommendationRuleId: recommendation.ruleId,
    decision: attackPaths.length
      ? "A scan-scoped source-to-sink-to-asset path was returned. Review the modeled relationships and source-analysis evidence."
      : "No complete scan-scoped source-to-sink-to-asset path was established.",
    limitation:
      "The analyzer uses heuristic JavaScript SQL-injection patterns. Graph paths reflect stored relationships and do not independently prove runtime exploitability.",
  };
}

async function runInvestigation(graph, options = {}) {
  // Submitted-code investigation.
  if (options.scanId && options.userId && options.fileId) {
    return runScanInvestigation(graph, options);
  }

  // Existing synthetic demo investigation.
  const inputId = options.inputId || "input-demo";
  const attackPaths = await traceAttackPath(graph, inputId);

  const steps = [
    makeStep(
      "trace_attack_path",
      "Trace modeled untrusted input to a sink and affected asset.",
      attackPaths.length,
      attackPaths.length
        ? "A modeled path was found; assess its reachable assets."
        : "No modeled path was found. Check graph coverage before drawing conclusions."
    ),
  ];

  let assets = [];

  if (attackPaths.length > 0) {
    assets = await assessBlastRadius(graph, inputId);

    steps.push(
      makeStep(
        "assess_blast_radius",
        "Identify sensitive assets reachable through the modeled flow.",
        assets.length,
        assets.length
          ? "The graph returned reachable assets."
          : "No reachable assets were returned."
      )
    );
  } else {
    steps.push(
      makeStep(
        "assess_blast_radius",
        "Identify sensitive assets reachable through the modeled flow.",
        0,
        "Skipped because no modeled path was found.",
        "skipped"
      )
    );
  }

  const findings = await retrieveEvidence(graph);

  steps.push(
    makeStep(
      "retrieve_graph_evidence",
      "Retrieve stored source-analysis findings.",
      findings.length,
      findings.length
        ? "Stored findings are available to support the investigation."
        : "No stored findings were returned."
    )
  );

  const recommendation = selectRecommendation(findings, attackPaths);

  return {
    status: attackPaths.length ? "potential-risk" : "no-matching-path",
    summary: attackPaths.length
      ? "A modeled input-to-sink path reaches a sensitive asset."
      : "No matching input-to-sink path was found in the analyzed graph.",
    attackPaths,
    assets,
    findings,
    steps,
    recommendation: recommendation.text,
    recommendationSource: recommendation.source,
    recommendationRuleId: recommendation.ruleId,
    decision: attackPaths.length
      ? "A modeled path was found. Review affected assets and source-analysis evidence."
      : "No matching path was found. Verify graph completeness and analyzer coverage.",
    limitation:
      "Results depend on the modeled graph and available source-analysis records. They do not prove runtime exploitability or comprehensive source-code safety.",
  };
}

module.exports = {
  runInvestigation,
  retrieveEvidence,
  inspectFindingRelationships,
};
