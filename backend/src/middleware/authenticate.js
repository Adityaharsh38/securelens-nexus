const jwt = require("jsonwebtoken");

function authenticate(req, res, next) {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  if (!process.env.JWT_SECRET ||
      process.env.JWT_SECRET === "paste_your_generated_secret_here") {
    return res.status(500).json({
      error: "Authentication is not configured"
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    req.user = {
      id: payload.sub,
      email: payload.email
    };

    next();
  } catch {
    return res.status(401).json({
      error: "Session is invalid or expired. Please sign in again."
    });
  }
}

module.exports = authenticate;