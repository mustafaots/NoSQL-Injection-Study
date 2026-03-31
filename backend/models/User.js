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
        // Passwords are stored as bcrypt hashes.
        type: String,
        required: true,
        minlength: 6
    }
}, {
    timestamps: true  // adds createdAt and updatedAt
});

module.exports = mongoose.model('User', userSchema);

