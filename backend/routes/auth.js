const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const Session = require('../models/Session');

const router = express.Router();

function logFailedLogin(req, reason) {
    const { username, password } = req.body || {};

    const payloadShape = {
        usernameType: Array.isArray(username) ? 'array' : typeof username,
        passwordType: Array.isArray(password) ? 'array' : typeof password
    };

    console.warn('[AUTH-FAIL] Invalid login attempt', {
        timestamp: new Date().toISOString(),
        ip: req.ip,
        reason,
        payloadShape
    });
}

/**
 * POST /api/auth/signup
 * Register a new user
 *
 * Secure signup with type validation and bcrypt password hashing.
 */
router.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body || {};

        if (typeof username !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ message: 'Invalid input' });
        }

        const normalizedUsername = username.trim();

        if (!normalizedUsername || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        if (normalizedUsername.length < 3 || normalizedUsername.length > 20) {
            return res.status(400).json({ message: 'Username must be 3-20 characters' });
        }

        if (typeof password !== 'string' || password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }

        const existingUser = await User.findOne({ username: normalizedUsername });

        if (existingUser) {
            return res.status(409).json({ message: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = new User({
            username: normalizedUsername,
            password: hashedPassword
        });

        await user.save();

        res.status(201).json({ message: 'Account created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'An error occurred during signup' });
    }
});

/**
 * POST /api/auth/login
 * Authenticate a user
 *
 * Secure login with strict type checks, generic errors, and bcrypt verification.
 */
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body || {};

        if (typeof username !== 'string' || typeof password !== 'string') {
            logFailedLogin(req, 'invalid_input_type');
            return res.status(400).json({ message: 'Invalid input' });
        }

        const normalizedUsername = username.trim();

        if (!normalizedUsername || !password) {
            logFailedLogin(req, 'missing_credentials');
            return res.status(400).json({ message: 'Username and password are required' });
        }

        const user = await User.findOne({ username: normalizedUsername });

        if (!user) {
            logFailedLogin(req, 'invalid_credentials');
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            logFailedLogin(req, 'invalid_credentials');
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate a session token
        const token = crypto.randomBytes(32).toString('hex');
        const session = new Session({
            userId: user._id,
            token: token,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
        });

        await session.save();

        res.json({
            message: 'Login successful',
            token: token,
            username: user.username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

/**
 * POST /api/auth/logout
 * Destroy user session
 */
router.post('/logout', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader) {
            const token = authHeader.replace('Bearer ', '');
            await Session.deleteOne({ token: token });
        }
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'An error occurred during logout' });
    }
});

module.exports = router;

