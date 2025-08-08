const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// This single route will work for both patients and doctors
router.get('/me', authController.protect, authController.getCurrentUser);

module.exports = router;