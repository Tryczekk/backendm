const express = require('express');
const router = express.Router();
const Card = require('../models/Card');
const { optionalAuth } = require('../middleware/auth');

// Prosty middleware dla card routes
const simpleAuth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1] || req.query.token || req.params.token;
    if (!token) {
        return res.status(401).json({ success: false, error: 'Brak tokenu' });
    }
    req.userToken = token;
    next();
};

// GET /api/card/:token - Pobierz dane karty
router.get('/:token', simpleAuth, async (req, res) => {
    try {
        let card = await Card.findOne({ token: req.params.token });
        if (!card) {
            card = new Card({ token: req.params.token });
            await card.save();
        }
        res.json({
            success: true,
            data: card
        });
    } catch (error) {
        console.error('Błąd podczas pobierania karty:', error);
        res.status(500).json({
            success: false,
            error: 'Błąd serwera'
        });
    }
});

// GET /api/card/:token/image - Pobierz zdjęcie karty
router.get('/:token/image', simpleAuth, async (req, res) => {
    try {
        const card = await Card.findOne({ token: req.params.token });
        if (!card || !card.image) {
            return res.status(404).json({
                success: false,
                error: 'Zdjęcie nie zostało znalezione'
            });
        }
        
        // Sprawdź czy zdjęcie jest w formacie base64
        if (card.image.startsWith('data:image')) {
            const base64Data = card.image.split(',')[1];
            const imageBuffer = Buffer.from(base64Data, 'base64');
            res.type('image/jpeg').send(imageBuffer);
        } else {
            res.type('image/jpeg').send(card.image);
        }
    } catch (error) {
        console.error('Błąd podczas pobierania zdjęcia:', error);
        res.status(500).json({
            success: false,
            error: 'Błąd serwera'
        });
    }
});

// POST /api/card/:token/image - Zapisz zdjęcie karty
router.post('/:token/image', simpleAuth, async (req, res) => {
    try {
        const { image } = req.body;
        if (!image) {
            return res.status(400).json({
                success: false,
                error: 'Brak zdjęcia w żądaniu'
            });
        }

        let card = await Card.findOne({ token: req.params.token });
        if (!card) {
            card = new Card({ token: req.params.token, image });
        } else {
            card.image = image;
        }
        await card.save();

        res.json({
            success: true,
            message: 'Zdjęcie zostało zapisane'
        });
    } catch (error) {
        console.error('Błąd podczas zapisywania zdjęcia:', error);
        res.status(500).json({
            success: false,
            error: 'Błąd serwera'
        });
    }
});

module.exports = router;