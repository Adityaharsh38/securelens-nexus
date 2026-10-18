
const { FalkorDB } = require("falkordb");

let connectionPromise;

async function getGraph() {
  if (!connectionPromise) {
    connectionPromise = FalkorDB.connect({
      socket: {
        host: process.env.FALKORDB_HOST,
        port: Number(process.env.FALKORDB_PORT),
        tls: process.env.FALKORDB_TLS === "true",
        connectTimeout: 10000,
      },
      username: process.env.FALKORDB_USERNAME,
      password: process.env.FALKORDB_PASSWORD,
    })
      .then((db) => ({
        db,
        graph: db.selectGraph(process.env.FALKORDB_GRAPH),
      }))
      .catch((error) => {
        connectionPromise = undefined;
        throw error;
      });
  }

  return connectionPromise;
}

module.exports = { getGraph };
