const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');

// Model karty
const Card = require('../models/Card');

// GET /api/card/:token - Pobierz dane karty
router.get('/:token', authenticateToken, async (req, res) => {
    try {
        const card = await Card.findOne({ token: req.params.token });
        if (!card) {
            return res.status(404).json({
                success: false,
                error: 'Karta nie została znaleziona'
            });
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
router.get('/:token/image', authenticateToken, async (req, res) => {
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
router.post('/:token/image', authenticateToken, async (req, res) => {
    try {
        const { image } = req.body;
        if (!image) {
            return res.status(400).json({
                success: false,
                error: 'Brak zdjęcia w żądaniu'
            });
        }

        const card = await Card.findOne({ token: req.params.token });
        if (!card) {
            return res.status(404).json({
                success: false,
                error: 'Karta nie została znaleziona'
            });
        }

        // Zapisz zdjęcie
        card.image = image;
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