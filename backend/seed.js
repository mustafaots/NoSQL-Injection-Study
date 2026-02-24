/**
 * Database Seed Script
 * 
 * Populates the MongoDB database with sample users and notes
 * for testing NoSQL injection vulnerabilities.
 * 
 * Usage: node seed.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');
const Note = require('./models/Note');
const Session = require('./models/Session');

const seedUsers = [
    { username: 'admin', password: 'admin123' },
    { username: 'student1', password: 'pass1234' },
    { username: 'student2', password: 'mypassword' },
    { username: 'demo', password: 'demo123' },
    { username: 'testuser', password: 'test1234' }
];

const seedNotes = [
    // Admin notes
    { title: 'System Configuration', content: 'MongoDB running on default port 27017. Admin credentials stored in .env file. Remember to update firewall rules.' },
    { title: 'Database Backup Schedule', content: 'Weekly backups every Sunday at 2 AM. Backup stored in /backups directory. Retention policy: 30 days.' },
    // Student1 notes
    { title: 'Math Notes - Calculus', content: 'Integration formulas: ∫x^n dx = x^(n+1)/(n+1) + C. Remember the chain rule for derivatives.' },
    { title: 'Physics - Quantum Mechanics', content: 'Wave-particle duality: Light exhibits both wave and particle properties. Heisenberg uncertainty principle.' },
    // Student2 notes
    { title: 'History Essay Outline', content: 'Topic: Industrial Revolution. Key points: Origins in Britain, Technological innovations, Social impact.' },
    { title: 'Chemistry Lab Report', content: 'Experiment: Titration of HCl with NaOH. Objective: Determine the concentration of unknown acid solution.' },
    // Demo notes
    { title: 'Welcome to TrackNotes!', content: 'This is your personal note-taking space. Create, edit, and organize your study notes all in one place.' },
    { title: 'Study Tips', content: '1. Break study sessions into 25-minute intervals. 2. Review notes within 24 hours. 3. Use active recall.' },
    // Testuser notes
    { title: 'Project Ideas', content: 'Build a weather app using React. Create a REST API with Express. Design a portfolio website.' },
    { title: 'Interview Prep', content: 'Common questions: Tell me about yourself. What are your strengths? Describe a challenging project.' }
];

async function seedDatabase() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to MongoDB');

        // Clear existing data
        await User.deleteMany({});
        await Note.deleteMany({});
        await Session.deleteMany({});
        console.log('Cleared existing data');

        // Create users (passwords stored in plain text - intentionally insecure)
        const createdUsers = await User.insertMany(seedUsers);
        console.log(`Created ${createdUsers.length} users:`);
        createdUsers.forEach(user => {
            const originalPassword = seedUsers.find(u => u.username === user.username).password;
            console.log(`  - ${user.username} / ${originalPassword}`);
        });

        // Create notes and assign to users
        const notesWithUsers = [
            // Admin gets first 2 notes
            { ...seedNotes[0], userId: createdUsers[0]._id },
            { ...seedNotes[1], userId: createdUsers[0]._id },
            // Student1 gets next 2
            { ...seedNotes[2], userId: createdUsers[1]._id },
            { ...seedNotes[3], userId: createdUsers[1]._id },
            // Student2 gets next 2
            { ...seedNotes[4], userId: createdUsers[2]._id },
            { ...seedNotes[5], userId: createdUsers[2]._id },
            // Demo gets next 2
            { ...seedNotes[6], userId: createdUsers[3]._id },
            { ...seedNotes[7], userId: createdUsers[3]._id },
            // Testuser gets last 2
            { ...seedNotes[8], userId: createdUsers[4]._id },
            { ...seedNotes[9], userId: createdUsers[4]._id }
        ];

        const createdNotes = await Note.insertMany(notesWithUsers);
        console.log(`Created ${createdNotes.length} notes`);

        console.log('\n============================================================');
        console.log('Database seeded successfully!');
        console.log('============================================================');
        console.log('\nTest Accounts (username / password):');
        console.log('  admin    / admin123');
        console.log('  student1 / pass1234');
        console.log('  student2 / mypassword');
        console.log('  demo     / demo123');
        console.log('  testuser / test1234');
        console.log('\nPasswords are stored in plain text (intentionally vulnerable)');
        console.log('============================================================\n');

        process.exit(0);
    } catch (error) {
        console.error('Seeding error:', error);
        process.exit(1);
    }
}

seedDatabase();

