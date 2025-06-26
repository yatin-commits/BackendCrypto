const express = require("express");
const router = express.Router();
const connection = require("../config/database");

// Get wallet balance
router.get("/wallet/:user_id", async (req, res) => {
  try {
    const [results] = await connection.query(
      "SELECT wallet_balance FROM users WHERE user_id = ?",
      [req.params.user_id]
    );
    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    // Ensure wallet_balance is a number, default to 0 if null/undefined
    const walletBalance = parseFloat(results[0].wallet_balance) || 0;
    res.status(200).json({ wallet_balance: walletBalance });
  } catch (err) {
    console.error("Error fetching wallet balance:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Update wallet balance
router.put("/wallet/:user_id", async (req, res) => {
  const { new_balance } = req.body;
  const parsedBalance = parseFloat(new_balance);

  if (isNaN(parsedBalance) || parsedBalance < 0) {
    return res.status(400).json({ error: "Invalid balance value. Must be a non-negative number." });
  }

  try {
    const [result] = await connection.query(
      "UPDATE users SET wallet_balance = ? WHERE user_id = ?",
      [parsedBalance, req.params.user_id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.status(200).json({ message: "Wallet balance updated successfully", new_balance: parsedBalance });
  } catch (err) {
    console.error("Error updating wallet balance:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;