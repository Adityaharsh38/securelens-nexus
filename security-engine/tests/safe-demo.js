app.get("/customer", (req, res) => {
  db.query("SELECT * FROM customers WHERE id = ?", [req.query.id]);
});