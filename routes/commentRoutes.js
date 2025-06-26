const express = require("express");
const router = express.Router();
const pool = require("../config/database");

// Middleware to check if the comment exists
const checkCommentExists = async (commentId, res) => {
  const [comment] = await pool.query("SELECT * FROM comments WHERE id = ?", [commentId]);
  if (!comment.length) {
    res.status(404).json({ message: "Comment not found" });
    return false;
  }
  return true;
};

// Fetch comments for a specific symbol
router.get("/comments/:symbol", async (req, res) => {
  const { symbol } = req.params;

  try {
    const [comments] = await pool.query(
      `SELECT c.id, c.user_id, c.symbol, c.content, c.created_at, c.likes, c.dislikes, c.reports,
            u.username, GROUP_CONCAT(DISTINCT cl.user_id) AS user_likes,
            GROUP_CONCAT(DISTINCT cd.user_id) AS user_dislikes,
            COUNT(DISTINCT cr.id) AS report_count
      FROM comments c
      LEFT JOIN users u ON c.user_id = u.user_id
      LEFT JOIN comment_likes cl ON c.id = cl.comment_id
      LEFT JOIN comment_dislikes cd ON c.id = cd.comment_id
      LEFT JOIN comment_reports cr ON c.id = cr.comment_id
      WHERE c.symbol = ?
      GROUP BY c.id
      ORDER BY c.created_at DESC`,
      [symbol]
    );
    res.status(200).json(comments);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch comments", error: error.message });
  }
});

// Post a new comment
router.post("/comments/:symbol", async (req, res) => {
  const { symbol } = req.params;
  const { user_id, content } = req.body;

  if (!user_id || !content) {
    return res.status(400).json({ message: "User ID and content are required" });
  }

  try {
    const [result] = await pool.query(
      "INSERT INTO comments (user_id, symbol, content, created_at) VALUES (?, ?, ?, NOW())",
      [user_id, symbol, content]
    );
    res.status(201).json({ id: result.insertId, message: "Comment posted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Failed to post comment", error: error.message });
  }
});

// Delete a comment
router.delete("/comments/:commentId", async (req, res) => {
  const { commentId } = req.params;
  const { user_id } = req.body;

  if (!user_id) {
    return res.status(400).json({ message: "User ID is required" });
  }

  if (!(await checkCommentExists(commentId, res))) return;

  try {
    const [comment] = await pool.query("SELECT user_id FROM comments WHERE id = ?", [commentId]);
    if (comment[0].user_id !== user_id) {
      return res.status(403).json({ message: "Unauthorized to delete this comment" });
    }

    await pool.query("DELETE FROM comments WHERE id = ?", [commentId]);
    res.status(200).json({ message: "Comment deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Failed to delete comment", error: error.message });
  }
});

// Report a comment
router.post("/comments/reports", async (req, res) => {
  const { user_id, commentId } = req.body;

  if (!user_id || !commentId) {
    return res.status(400).json({ message: "User ID and comment ID are required" });
  }

  if (!(await checkCommentExists(commentId, res))) return;

  try {
    await pool.query(
      "INSERT INTO comment_reports (comment_id, user_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE user_id = user_id",
      [commentId, user_id]
    );

    await pool.query("UPDATE comments SET reports = reports + 1 WHERE id = ?", [commentId]);
    res.status(200).json({ message: "Comment reported successfully" });
  } catch (error) {
    res.status(500).json({ message: "Failed to report comment", error: error.message });
  }
});

// Route to handle like, unlike, dislike, undislike actions
router.post("/comments/:commentId/:action", async (req, res) => {
  const { commentId, action } = req.params;
  const { user_id } = req.body;

  if (!user_id) {
    return res.status(400).json({ message: "User ID is required" });
  }

  // Check if the comment exists
  const [commentRows] = await pool.query("SELECT id FROM comments WHERE id = ?", [commentId]);
  if (commentRows.length === 0) {
    return res.status(404).json({ message: "Comment not found" });
  }

  try {
    if (action === "like") {
      // Insert like
      await pool.query(
        "INSERT INTO comment_likes (comment_id, user_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE user_id = user_id",
        [commentId, user_id]
      );
      // Remove from dislikes
      await pool.query("DELETE FROM comment_dislikes WHERE comment_id = ? AND user_id = ?", [commentId, user_id]);
      
    } else if (action === "unlike") {
      await pool.query("DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?", [commentId, user_id]);

    } else if (action === "dislike") {
      // Insert dislike
      await pool.query(
        "INSERT INTO comment_dislikes (comment_id, user_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE user_id = user_id",
        [commentId, user_id]
      );
      // Remove from likes
      await pool.query("DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?", [commentId, user_id]);

    } else if (action === "undislike") {
      await pool.query("DELETE FROM comment_dislikes WHERE comment_id = ? AND user_id = ?", [commentId, user_id]);

    } else {
      return res.status(400).json({ message: "Invalid action" });
    }

    // Recalculate likes and dislikes
    const [likeCountRows] = await pool.query(
      "SELECT COUNT(*) as count FROM comment_likes WHERE comment_id = ?",
      [commentId]
    );
    const [dislikeCountRows] = await pool.query(
      "SELECT COUNT(*) as count FROM comment_dislikes WHERE comment_id = ?",
      [commentId]
    );

    const likeCount = likeCountRows[0].count;
    const dislikeCount = dislikeCountRows[0].count;

    // Update the main comment table
    await pool.query(
      "UPDATE comments SET likes = ?, dislikes = ? WHERE id = ?",
      [likeCount, dislikeCount, commentId]
    );

    return res.status(200).json({ message: `${action} recorded` });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Something went wrong", error: error.message });
  }
});


module.exports = router;