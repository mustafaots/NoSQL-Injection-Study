const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 20
    },
    password: {
        // VULNERABLE: Password stored in plain text (no hashing)
        // This is intentional for NoSQL injection study purposes.
        // In a secure app, you would use bcrypt to hash passwords.
        type: String,
        required: true,
        minlength: 6
    }
}, {
    timestamps: true  // adds createdAt and updatedAt
});

module.exports = mongoose.model('User', userSchema);

