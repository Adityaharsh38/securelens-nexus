const express = require("express");
const cors = require("cors");
require("dotenv").config();
const analyzerRoutes = require("./routes/analyzer.routes");
const authRoutes = require("./routes/auth.routes");

const graphRoutes = require("./routes/graph.routes");
const investigationRoutes = require("./routes/investigations.routes");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors({ origin: "http://localhost:5173" }));

app.use(express.json());

app.use("/api/analyzer", analyzerRoutes);
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "SecureLens Nexus API" });
});

app.use("/api/graph", graphRoutes);
app.use("/api/investigations", investigationRoutes);

app.use("/api/auth", authRoutes);

app.listen(PORT, () => {
  console.log(`SecureLens API running at http://localhost:${PORT}`);
});
