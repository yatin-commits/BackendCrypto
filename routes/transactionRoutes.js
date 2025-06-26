const express = require("express");
const router = express.Router();
const connection = require("../config/database");

router.get("/transactions/:user_id", async (req, res) => {
  try {
    const [results] = await connection.query(
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY transaction_time DESC",
      [req.params.user_id]
    );
    res.status(200).json(results);
  } catch (err) {
    console.error("Error in /transactions:", err.message, err.stack);
    return res.status(500).json({ error: "Internal server error", details: err.message });
  }
});

router.post("/buy", async (req, res) => {
  const { user_id, coin_symbol, quantity, price } = req.body;
  if (!user_id || !coin_symbol || isNaN(quantity) || isNaN(price) || quantity <= 0 || price <= 0) {
    return res.status(400).json({ error: "Invalid or missing input data" });
  }
  const normalizedSymbol = coin_symbol.toUpperCase();
  const totalCost = price * quantity;

  try {
    // await connection.beginTransaction();

    const [walletResults] = await connection.query(
      "SELECT wallet_balance FROM users WHERE user_id = ?",
      [user_id]
    );
    if (walletResults.length === 0) {
      throw new Error("User not found");
    }

    const walletBalance = parseFloat(walletResults[0].wallet_balance);
    if (isNaN(walletBalance) || walletBalance < totalCost) {
      throw new Error("Insufficient funds");
    }

    const newBalance = walletBalance - totalCost;

    await connection.query(
      "UPDATE users SET wallet_balance = ? WHERE user_id = ?",
      [newBalance, user_id]
    );

    await connection.query(
      "INSERT INTO transactions (user_id, coin_symbol, quantity, price, total, transaction_type) VALUES (?, ?, ?, ?, ?, ?)",
      [user_id, normalizedSymbol, quantity, price, totalCost, "Buy"]
    );

    const [portfolioResults] = await connection.query(
      "SELECT * FROM portfolio WHERE user_id = ? AND crypto_symbol = ?",
      [user_id, normalizedSymbol]
    );

    if (portfolioResults.length > 0) {
      const oldQuantity = parseFloat(portfolioResults[0].quantity) || 0;
      const oldAvgPrice = parseFloat(portfolioResults[0].average_buy_price) || price;
      if (isNaN(oldQuantity) || isNaN(oldAvgPrice)) {
        throw new Error("Invalid portfolio data");
      }
      const newQuantity = parseFloat(quantity);
      const totalValue = oldQuantity * oldAvgPrice + newQuantity * price;
      const updatedQuantity = oldQuantity + newQuantity;
      const newAvgPrice = updatedQuantity > 0 ? totalValue / updatedQuantity : 0;

      await connection.query(
        "UPDATE portfolio SET quantity = ?, average_buy_price = ? WHERE user_id = ? AND crypto_symbol = ?",
        [updatedQuantity, newAvgPrice, user_id, normalizedSymbol]
      );
    } else {
      await connection.query(
        "INSERT INTO portfolio (user_id, crypto_symbol, quantity, average_buy_price) VALUES (?, ?, ?, ?)",
        [user_id, normalizedSymbol, quantity, price]
      );
    }

    // await connection.commit();
    res.status(200).json({
      message: "Transaction successful and portfolio updated.",
      wallet_balance: newBalance,
    });
  } catch (err) {
    // await connection.rollback();
    console.error("Error in /buy:", err.message, err.stack);
    if (err.message === "Insufficient funds") {
      return res.status(400).json({ error: err.message });
    } else if (err.message === "User not found" || err.message === "Invalid portfolio data") {
      return res.status(404).json({ error: err.message });
    }
    return res.status(500).json({ error: "Internal server error", details: err.message });
  }
});

router.post("/sell", async (req, res) => {
  const { user_id, crypto_symbol, quantity, price } = req.body;
  if (!user_id || !crypto_symbol || isNaN(quantity) || isNaN(price) || quantity <= 0 || price <= 0) {
    return res.status(400).json({ error: "Invalid or missing input data" });
  }
  const normalizedSymbol = crypto_symbol.toUpperCase();
  const totalRevenue = price * quantity;

  try {
    // await connection.beginTransaction();

    const [portfolioResults] = await connection.query(
      "SELECT * FROM portfolio WHERE user_id = ? AND crypto_symbol = ?",
      [user_id, normalizedSymbol]
    );
    if (portfolioResults.length === 0) {
      throw new Error("Portfolio entry not found");
    }

    const oldQuantity = parseFloat(portfolioResults[0].quantity);
    const averageBuyPrice = parseFloat(portfolioResults[0].average_buy_price);
    if (isNaN(oldQuantity) || isNaN(averageBuyPrice)) {
      throw new Error("Invalid portfolio data");
    }

    if (oldQuantity < quantity) {
      throw new Error("Insufficient quantity in portfolio");
    }

    const remainingQuantity = oldQuantity - quantity;
    const profitLoss = (price - averageBuyPrice) * quantity;
    const profitLossType = profitLoss >= 0 ? "Profit" : "Loss";

    const [userResults] = await connection.query(
      "SELECT wallet_balance FROM users WHERE user_id = ?",
      [user_id]
    );
    if (userResults.length === 0) {
      throw new Error("User not found");
    }

    const currentBalance = parseFloat(userResults[0].wallet_balance);
    const newBalance = currentBalance + totalRevenue;

    await connection.query(
      "UPDATE users SET wallet_balance = ? WHERE user_id = ?",
      [newBalance, user_id]
    );

    await connection.query(
      "INSERT INTO transactions (user_id, coin_symbol, quantity, transaction_type, profit_loss_type, price, total, profit_loss) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [user_id, normalizedSymbol, -quantity, "Sell", profitLossType, price, totalRevenue, profitLoss.toFixed(2)]
    );

    if (remainingQuantity > 0) {
      await connection.query(
        "UPDATE portfolio SET quantity = ? WHERE user_id = ? AND crypto_symbol = ?",
        [remainingQuantity, user_id, normalizedSymbol]
      );
    } else {
      await connection.query(
        "DELETE FROM portfolio WHERE user_id = ? AND crypto_symbol = ?",
        [user_id, normalizedSymbol]
      );
    }

    // await connection.commit();
    res.status(200).json({
      message: remainingQuantity > 0 ? "Transaction successful and portfolio updated." : "Transaction successful, portfolio entry removed.",
      wallet_balance: newBalance,
    });
  } catch (err) {
    // await connection.rollback();
    console.error("Error in /sell:", err.message, err.stack);
    if (err.message === "Insufficient quantity in portfolio" || err.message === "Insufficient funds") {
      return res.status(400).json({ error: err.message });
    } else if (err.message === "Portfolio entry not found" || err.message === "User not found") {
      return res.status(404).json({ error: err.message });
    }
    return res.status(500).json({ error: "Internal server error", details: err.message });
  }
});

module.exports = router;