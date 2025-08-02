const express = require("express");
const router = express.Router();
const redis = require("../utils/redisClient"); // ioredis client

const connection = require("../config/database");

// 🔑 Utility to generate cache key per user
const getWishlistCacheKey = (userId) => `wishlist:${userId}`;

// ========================= GET WISHLIST =========================
router.get("/wishlist/:user_id", async (req, res) => {
  const userId = req.params.user_id;
  const cacheKey = getWishlistCacheKey(userId);

  try {
    // 1. Try fetching from Redis cache
    const cached = await redis.get(cacheKey);
    if (cached) {
      console.log("✅ Served from Redis cache");
      return res.json(JSON.parse(cached));
    }

    // 2. If not cached, fetch from DB
    const [results] = await connection.query(
      "SELECT coin_name, symbol FROM wishlist WHERE user_id = ?",
      [userId]
    );

    // 3. Cache the result for 10 minutes (600s)
    await redis.set(cacheKey, JSON.stringify(results), "EX", 600);

    console.log("✅ Fetched from DB and cached");
    res.json(results);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Error fetching wishlist" });
  }
});

// ========================= ADD TO WISHLIST =========================
router.post("/wishlist/add/:user_id", async (req, res) => {
  const { coin_name, symbol } = req.body;
  const userId = req.params.user_id;
  const cacheKey = getWishlistCacheKey(userId);

  if (!coin_name || !symbol) {
    return res.status(400).json({ message: "coin_name and symbol are required" });
  }

  try {
    await connection.query(
      "INSERT INTO wishlist (user_id, coin_name, symbol) VALUES (?, ?, ?)",
      [userId, coin_name, symbol]
    );

    // ❌ Invalidate Redis cache for the user
    await redis.del(cacheKey);

    res.status(200).json({ message: "Added to wishlist successfully" });
  } catch (err) {
    return res.status(500).json({ message: "Database error" });
  }
});

// ========================= REMOVE FROM WISHLIST =========================
router.delete("/wishlist/remove/:userId/:symbol", async (req, res) => {
  const { userId, symbol } = req.params;
  const cacheKey = getWishlistCacheKey(userId);

  try {
    const [results] = await connection.query(
      "DELETE FROM wishlist WHERE user_id = ? AND symbol = ?",
      [userId, symbol]
    );

    if (results.affectedRows > 0) {
      // ❌ Invalidate Redis cache for the user
      await redis.del(cacheKey);
      return res.status(200).json({ message: "Coin removed from watchlist" });
    } else {
      return res.status(404).json({ message: "Coin not found in watchlist" });
    }
  } catch (err) {
    return res.status(500).json({ message: "Error removing coin from watchlist" });
  }
});

module.exports = router;
