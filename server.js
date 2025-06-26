// ```javascript
const express = require("express");
const cors = require("cors");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { setupWebSocketServer } = require("./utils/websocket");
const http = require("http");
const axios = require("axios");

const app = express();
const { PORT = 3000 } = require("./config/env");

const corsOptions = {
  origin: "http://localhost:5173",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

if (process.env.NODE_ENV === "development") {
  app.use((req, res, next) => {
    // console.log("Incoming request:", {
    //   method: req.method,
    //   url: req.url,
    //   body: req.body,
    // });
    next();
  });
}

app.get("/", (req, res) => {
  res.json({ message: "Welcome to the Crypto API!" });
});


app.use("/api", require("./routes/authRoutes"));
app.use("/api", require("./routes/walletRoutes"));
app.use("/api", require("./routes/wishlistRoutes"));
app.use("/api", require("./routes/portfolioRoutes"));
app.use("/api", require("./routes/transactionRoutes"));
app.use("/api", require("./routes/commentRoutes"));
app.use("/api", require("./routes/userRoutes"));
app.use("/api", require("./routes/quizRoutes"));

// Nomics proxy endpoint
const nomicsCache = new Map();
app.get("/api/nomics/currencies/ticker", async (req, res) => {
  const cacheKey = JSON.stringify(req.query);
  const cached = nomicsCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < 5 * 60 * 1000) {
    return res.json(cached.data);
  }

  try {
    const response = await axios.get("https://api.nomics.com/v1/currencies/ticker", {
      params: req.query,
    });
    nomicsCache.set(cacheKey, { data: response.data, timestamp: Date.now() });
    res.json(response.data);
  } catch (err) {
    console.error("Nomics proxy error:", err.message);
    res.status(err.response?.status || 500).json({ error: "Failed to fetch Nomics data" });
  }
});

const genAI = new GoogleGenerativeAI("AIzaSyB-2bhc_UYCa-tfOIv5y5SEcE_p-sZibAA");

app.post("/api/crypto-query", async (req, res) => {
  const { query } = req.body;

  try {
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro" });
    const prompt = `
      You are a cryptocurrency expert. Provide a concise answer (1-2 sentences) for: "${query}".
      Focus on theoretical or general crypto topics, avoiding real-time data, comparisons, or tables.
    `;
    const result = await model.generateContent(prompt);
    const answer = result.response.text();
    res.json({ answer });
  } catch (error) {
    console.error("Error in crypto-query:", error.message);
    res.status(500).json({ answer: "Sorry, something went wrong. Please try again." });
  }
});

module.exports = app;

app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("Error:", err.stack);
  res.status(500).json({ message: "Internal server error" });
});

const server = http.createServer(app);
setupWebSocketServer(server);

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

process.on("SIGTERM", () => {
  console.log("SIGTERM received. Shutting down gracefully...");
  server.close(() => {
    console.log("Server closed.");
    process.exit(0);
  });
});
