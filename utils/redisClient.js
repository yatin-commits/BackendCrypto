const Redis = require("ioredis");

const redisClient = new Redis("redis://default@127.0.0.1:6379"); // Store your Redis URL in .env

redisClient.on("connect", () => {
  console.log("✅ Connected to Redis");
});

redisClient.on("error", (err) => {
  console.error("❌ Redis connection error:", err);
});

module.exports = redisClient;
