const mysql = require('mysql2/promise');
const fs = require('fs');

// Create pool configuration
const pool = mysql.createPool({
    host: 'mysql-1d3067fc-cryptotrade.k.aivencloud.com',
    user: 'avnadmin',
    password: 'AVNS_RWpVe1VrKkpYw2D3H4Z',
    database: 'defaultdb', // Update to match your database name
    port: 11848, // Confirm port in Aiven dashboard
    ssl: {
        ca: fs.readFileSync('./config/ca.pem'), // Replace with actual path
        rejectUnauthorized: true
    },
    connectionLimit: 10,
    connectTimeout: 30000 // 30 seconds timeout
});

module.exports = pool;