const socketIo = require("socket.io");
const WebSocket = require("ws");

let latestPrices = {};
let activeCoins = new Set();
let clientSubscriptions = new Map();
let binanceSocket = null;

function setupWebSocketServer(server) {
const io = socketIo(server, {
  cors: {
    origin: [
      "http://localhost:5173",
      "https://crypto-frontend-khaki.vercel.app"
    ],
    methods: ["GET", "POST"],
    credentials: true
  }
});


  function connectToBinance() {
    if (binanceSocket && binanceSocket.readyState === WebSocket.OPEN) {
      updateBinanceSubscriptions(binanceSocket);
      return;
    }

    binanceSocket = new WebSocket("wss://stream.binance.com:9443/ws");

    binanceSocket.on("open", () => {
      console.log("Connected to Binance WebSocket");
      updateBinanceSubscriptions(binanceSocket);
    });

    binanceSocket.on("message", (data) => {
      try {
        const parsedData = JSON.parse(data);
        // console.log("Binance data:", parsedData);

        if (parsedData.s && parsedData.c && parsedData.P) {
          const coin = parsedData.s.replace("USDT", "").toUpperCase();
          latestPrices[coin] = {
            usd: parseFloat(parsedData.c),
            change: parseFloat(parsedData.P),
            timestamp: new Date().toISOString()
          };
          sendToSubscribedClients(io, coin);
        } else {
          console.log("parsedData",parsedData)
          console.warn("Invalid Binance data format:", parsedData);
        }
      } catch (error) {
        console.error("Error parsing Binance data:", error.message);
      }
    });

    binanceSocket.on("error", (error) => {
      console.error("Binance WebSocket error:", error.message);
    });

    binanceSocket.on("close", () => {
      console.log("Binance WebSocket closed. Reconnecting...");
      setTimeout(connectToBinance, 5000);
    });
  }

  function updateBinanceSubscriptions(binanceSocket) {
    if (binanceSocket.readyState !== WebSocket.OPEN) {
      console.warn("Binance WebSocket not open, cannot update subscriptions");
      return;
    }
    const streams = [...activeCoins].map(coin => `${coin.toLowerCase()}usdt@ticker`);
    if (streams.length > 0) {
      binanceSocket.send(JSON.stringify({
        method: "SUBSCRIBE",
        params: streams,
        id: 1
      }));
      // console.log("Subscribed to Binance streams:", streams);
    }
  }

  function sendToSubscribedClients(io, coin) {
    io.sockets.sockets.forEach((socket) => {
      const subscribedCoins = clientSubscriptions.get(socket.id) || [];
      if (subscribedCoins.includes(coin)) {
        socket.emit("priceUpdate", {
          timestamp: new Date().toISOString(),
          prices: { [coin.toLowerCase()]: latestPrices[coin] }
        });
      }
    });
  }

  io.on("connection", (socket) => {
    // console.log("New client connected:", socket.id);

    socket.on("subscribe", (coinList) => {
      if (Array.isArray(coinList)) {
        const subscribedCoins = coinList.map(coin => coin.toUpperCase());
        clientSubscriptions.set(socket.id, subscribedCoins);
        subscribedCoins.forEach(coin => activeCoins.add(coin));
        updateBinanceSubscriptions(binanceSocket);

        const clientPrices = {};
        subscribedCoins.forEach(coin => {
          if (latestPrices[coin]) {
            clientPrices[coin.toLowerCase()] = latestPrices[coin];
          }
        });
        socket.emit("priceUpdate", {
          timestamp: new Date().toISOString(),
          prices: clientPrices
        });
      } else {
        console.warn("Invalid coinList received:", coinList);
        socket.emit("error", { message: "Invalid coin list provided" });
      }
    });

    socket.on("disconnect", () => {
      console.log("Client disconnected:", socket.id);
      clientSubscriptions.delete(socket.id);
      activeCoins = new Set();
      clientSubscriptions.forEach(coins => {
        coins.forEach(coin => activeCoins.add(coin));
      });
      updateBinanceSubscriptions(binanceSocket);
    });
  });

  connectToBinance();
  return io;
}

module.exports = { setupWebSocketServer };