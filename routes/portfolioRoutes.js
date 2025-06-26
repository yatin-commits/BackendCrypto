const express = require("express");
const router = express.Router();
const connection = require("../config/database");

// Get portfolio
router.get("/portfolio/:user_id", async (req, res) => {
  try {
    const [results] = await connection.query(
      "SELECT * FROM portfolio WHERE user_id = ?",
      [req.params.user_id]
    );
    // Always return an array, even if empty, to match client expectation
    res.status(200).json(results.length > 0 ? results : []);
  } catch (err) {
    console.error("Error fetching portfolio:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;