const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');

// Admin login route
router.post('/login', adminController.authenticateAdmin, (req, res) => {
    res.json({ message: 'Admin login successful' });
});

// Get dashboard data route (protected by admin authentication)
router.get('/dashboard-data', adminController.authenticateAdmin, adminController.getDashboardData);

module.exports = router; 