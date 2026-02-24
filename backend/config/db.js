const mongoose = require('mongoose');

const connectDB = async () => {
    const MAX_RETRIES = 5;
    const RETRY_DELAY = 5000; // 5 seconds

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        try {
            const conn = await mongoose.connect(process.env.MONGODB_URI);
            console.log(`MongoDB Connected: ${conn.connection.host}`);
            return;
        } catch (error) {
            console.error(`MongoDB Connection Error (attempt ${attempt}/${MAX_RETRIES}): ${error.message}`);
            if (attempt < MAX_RETRIES) {
                console.log(`Retrying in ${RETRY_DELAY / 1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
            } else {
                console.error('All connection attempts failed. Make sure MongoDB is running.');
                console.error('Install & start MongoDB: https://www.mongodb.com/docs/manual/installation/');
                process.exit(1);
            }
        }
    }
};

module.exports = connectDB;

