const express = require("express");
const router = express.Router();
const connection = require("../config/database");

// Get wishlist
router.get("/wishlist/:user_id", async (req, res) => {
  try {
    const [results] = await connection.query(
      "SELECT coin_name, symbol FROM wishlist WHERE user_id = ?",
      [req.params.user_id]
    );
    res.json(results);
  } catch (err) {
    console.log(err);
    
    return res.status(500).json({ message: "Error fetching wishlist" });
  }
});

// Add to wishlist
router.post("/wishlist/add/:user_id", async (req, res) => {
  const { coin_name, symbol } = req.body;

  if (!coin_name || !symbol) {
    return res.status(400).json({ message: "coin_name and symbol are required" });
  }

  try {
    await connection.query(
      "INSERT INTO wishlist (user_id, coin_name, symbol) VALUES (?, ?, ?)",
      [req.params.user_id, coin_name, symbol]
    );
    res.status(200).json({ message: "Added to wishlist successfully" });
  } catch (err) {
    return res.status(500).json({ message: "Database error" });
  }
});

// Remove from wishlist
router.delete("/wishlist/remove/:userId/:symbol", async (req, res) => {
  try {
    const [results] = await connection.query(
      "DELETE FROM wishlist WHERE user_id = ? AND symbol = ?",
      [req.params.userId, req.params.symbol]
    );
    if (results.affectedRows > 0) {
      return res.status(200).json({ message: "Coin removed from watchlist" });
    } else {
      return res.status(404).json({ message: "Coin not found in watchlist" });
    }
  } catch (err) {
    return res.status(500).json({ message: "Error removing coin from watchlist" });
  }
});

module.exports = router;