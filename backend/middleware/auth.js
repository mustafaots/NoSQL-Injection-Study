const Session = require('../models/Session');

/**
 * Authentication middleware
 *
 * VULNERABLE: Passes the token directly from the request to the database query
 * without sanitization. This allows NoSQL injection via the Authorization header.
 *
 * Example attack: An attacker could manipulate the token parameter to inject
 * MongoDB operators like $gt, $ne, $exists, etc.
 */
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({ message: 'No authorization token provided' });
        }

        const token = authHeader.replace('Bearer ', '');

        // VULNERABLE: Token is passed directly to the query without sanitization
        // An attacker could potentially inject operators here
        const session = await Session.findOne({ token: token });

        if (!session) {
            return res.status(401).json({ message: 'Invalid or expired session' });
        }

        // Check if session has expired
        if (new Date() > session.expiresAt) {
            await Session.deleteOne({ _id: session._id });
            return res.status(401).json({ message: 'Session expired' });
        }

        // Attach userId to request for use in route handlers
        req.userId = session.userId;
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

module.exports = authenticate;

