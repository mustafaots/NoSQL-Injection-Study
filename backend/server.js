/**
 * ============================================================
 * WARNING: INTENTIONALLY VULNERABLE APPLICATION
 * ============================================================
 *
 * This application is designed for NoSQL Injection case study.
 * It still contains intentionally vulnerable areas for educational testing,
 * while authentication endpoints now include blue-team defenses.
 *
 * DO NOT deploy this application in production.
 * For educational and research purposes ONLY.
 * ============================================================
 */

require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(mongoSanitize());

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { message: 'Too many attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false
});

const loginSecurityLogger = (req, res, next) => {
    const { username, password } = req.body || {};

    const payloadShape = {
        usernameType: Array.isArray(username) ? 'array' : typeof username,
        passwordType: Array.isArray(password) ? 'array' : typeof password
    };

    const suspicious = typeof username !== 'string' || typeof password !== 'string';

    if (suspicious) {
        console.warn('[ALERT] Suspicious login attempt', {
            timestamp: new Date().toISOString(),
            ip: req.ip,
            payloadShape
        });
    }

    res.on('finish', () => {
        if (res.statusCode >= 400) {
            console.warn('[AUTH-FAIL] Login request failed', {
                timestamp: new Date().toISOString(),
                ip: req.ip,
                statusCode: res.statusCode,
                payloadShape
            });
        }
    });

    next();
};

app.use('/api/auth/login', loginSecurityLogger);
app.use('/api/auth/login', loginLimiter);

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
    console.log(`\nBlue Team defenses are enabled for auth routes.`);
    console.log(`============================================================\n`);
});

module.exports = app;

