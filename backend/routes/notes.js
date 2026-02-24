const express = require('express');
const Note = require('../models/Note');
const authenticate = require('../middleware/auth');

const router = express.Router();

// All notes routes require authentication
router.use(authenticate);

/**
 * GET /api/notes
 * Get all notes for the authenticated user
 *
 * VULNERABLE: The search query parameter is passed directly into a MongoDB
 * $where clause or regex without sanitization, allowing NoSQL injection.
 */
router.get('/', async (req, res) => {
    try {
        const { search } = req.query;

        let query = { userId: req.userId };

        if (search) {
            // VULNERABLE: User input is directly used in $regex without escaping
            // An attacker could inject regex patterns or use $where for injection
            // Example: search=.*  would match everything
            // This allows ReDoS (Regular Expression Denial of Service) attacks
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { content: { $regex: search, $options: 'i' } }
            ];
        }

        const notes = await Note.find(query).sort({ updatedAt: -1 });
        res.json(notes);
    } catch (error) {
        console.error('Error fetching notes:', error);
        res.status(500).json({ message: 'Error fetching notes' });
    }
});

/**
 * GET /api/notes/:id
 * Get a single note by ID
 *
 * VULNERABLE: The note ID from the URL parameter is not validated
 * before being used in the query.
 */
router.get('/:id', async (req, res) => {
    try {
        // VULNERABLE: No validation on req.params.id
        const note = await Note.findOne({
            _id: req.params.id,
            userId: req.userId
        });

        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }

        res.json(note);
    } catch (error) {
        console.error('Error fetching note:', error);
        res.status(500).json({ message: 'Error fetching note' });
    }
});

/**
 * POST /api/notes
 * Create a new note
 *
 * VULNERABLE: No input sanitization on title/content fields.
 * User input is stored directly in MongoDB.
 */
router.post('/', async (req, res) => {
    try {
        const { title, content } = req.body;

        if (!title || !content) {
            return res.status(400).json({ message: 'Title and content are required' });
        }

        // VULNERABLE: No sanitization - data stored as-is
        const note = new Note({
            userId: req.userId,
            title: title,
            content: content
        });

        await note.save();
        res.status(201).json(note);
    } catch (error) {
        console.error('Error creating note:', error);
        res.status(500).json({ message: 'Error creating note' });
    }
});

/**
 * PUT /api/notes/:id
 * Update a note
 *
 * VULNERABLE: No input sanitization. The update object is constructed
 * from user input without validation.
 */
router.put('/:id', async (req, res) => {
    try {
        const { title, content } = req.body;

        if (!title || !content) {
            return res.status(400).json({ message: 'Title and content are required' });
        }

        // VULNERABLE: req.body fields passed directly without sanitization
        const note = await Note.findOneAndUpdate(
            { _id: req.params.id, userId: req.userId },
            { title: title, content: content },
            { new: true }
        );

        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }

        res.json(note);
    } catch (error) {
        console.error('Error updating note:', error);
        res.status(500).json({ message: 'Error updating note' });
    }
});

/**
 * DELETE /api/notes/:id
 * Delete a note
 */
router.delete('/:id', async (req, res) => {
    try {
        const note = await Note.findOneAndDelete({
            _id: req.params.id,
            userId: req.userId
        });

        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }

        res.json({ message: 'Note deleted successfully' });
    } catch (error) {
        console.error('Error deleting note:', error);
        res.status(500).json({ message: 'Error deleting note' });
    }
});

module.exports = router;

