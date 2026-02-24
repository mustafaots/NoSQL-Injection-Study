/**
 * ============================================================
 * WARNING: INTENTIONALLY VULNERABLE APPLICATION
 * ============================================================
 *
 * This application is designed for NoSQL Injection case study.
 * It contains INTENTIONAL security vulnerabilities including:
 *
 * 1. No input sanitization on login (allows operator injection)
 * 2. Plain text password storage (no bcrypt hashing)
 * 3. Unsanitized regex search (allows ReDoS)
 * 4. Direct user input in MongoDB queries
 *
 * DO NOT deploy this application in production.
 * For educational and research purposes ONLY.
 * ============================================================
 */

require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors());

// VULNERABLE: express.json() without limiting or sanitizing input
// This allows MongoDB operators in JSON body (e.g., {"$gt": ""})
// to be parsed and passed directly to Mongoose queries
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/notes', notesRoutes);

// Serve frontend for any non-API routes
app.get('*path', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`\n============================================================`);
    console.log(`NoSQL Injection Study Server`);
    console.log(`============================================================`);
    console.log(`Server running on: http://localhost:${PORT}`);
    console.log(`MongoDB URI: ${process.env.MONGODB_URI}`);
    console.log(`\nWARNING: This app is intentionally vulnerable.`);
    console.log(`For educational purposes ONLY.`);
    console.log(`============================================================\n`);
});

module.exports = app;

