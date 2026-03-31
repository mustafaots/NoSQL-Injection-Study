const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const Session = require('../models/Session');

const router = express.Router();

/**
 * POST /api/auth/signup
 * Register a new user
 *
 * Secure signup with type validation and bcrypt password hashing.
 */
router.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Basic validation only - no sanitization (intentionally vulnerable)
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        if (typeof username !== 'string' || username.length < 3 || username.length > 20) {
            return res.status(400).json({ message: 'Username must be 3-20 characters' });
        }

        if (typeof password !== 'string' || password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }

        // Check if username already exists
        // VULNERABLE: username is passed directly without sanitization
        const existingUser = await User.findOne({ username: username });

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
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        // VULNERABLE: Directly passing user input to MongoDB query
        // No sanitization, no type checking - allows operator injection
        // An attacker can send { "username": {"$gt": ""}, "password": {"$gt": ""} }
        // which would match any user with a non-empty username and password
        const user = await User.findOne({
            username: username,
            password: password
        });

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

