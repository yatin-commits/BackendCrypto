const express = require("express");
const router = express.Router();
const pool = require("../config/database");

// Hardcoded list of admin emails
const adminEmails = [
  "admin1@example.com",
  "admin2@example.com",
  // Add more admin emails as needed
];

// Middleware to check if user is an admin
const isAdmin = async (req, res, next) => {
  const { admin_email } = req.body;
  if (!admin_email || !adminEmails.includes(admin_email)) {
    return res.status(403).json({ message: "Unauthorized: Admin access required" });
  }
  next();
};


// Get all users
router.get('/users/:user_id', async (req, res) => {
  const { user_id } = req.params;
  try {
    const [rows] = await pool.query('SELECT current_level, wallet_balance FROM users WHERE user_id = ?', [user_id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({
      level: rows[0].current_level, // Return current_level as 'level' for frontend compatibility
      wallet_balance: Number(rows[0].wallet_balance) || 0
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


router.get("/users", async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT user_id, username, email, is_blocked, created_at, " +
      "(SELECT COUNT(*) FROM comments WHERE comments.user_id = users.user_id) AS comment_count " +
      "FROM users"
    );
    res.status(200).json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Error fetching users", error: err.message });
  }
});

// Block a user
router.put("/:userId/block", isAdmin, async (req, res) => {
  const { userId } = req.params;
  try {
    const [result] = await pool.query("UPDATE users SET is_blocked = 1 WHERE id = ?", [userId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ message: "User blocked" });
  } catch (err) {
    console.error("Error blocking user:", err);
    res.status(500).json({ message: "Error blocking user", error: err.message });
  }
});

// Unblock a user
router.put("/:userId/unblock", isAdmin, async (req, res) => {
  const { userId } = req.params;
  try {
    const [result] = await pool.query("UPDATE users SET is_blocked = 0 WHERE id = ?", [userId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ message: "User unblocked" });
  } catch (err) {
    console.error("Error unblocking user:", err);
    res.status(500).json({ message: "Error unblocking user", error: err.message });
  }
});

module.exports = router;