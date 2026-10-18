app.get("/customer", (req, res) => {
  const query = `SELECT * FROM customers WHERE id = ${req.query.id}`;
  db.query(query);
});
