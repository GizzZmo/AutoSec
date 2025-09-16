const express = require('express');
const { body } = require('express-validator');
const { authenticate } = require('../middleware/auth');
const mfaController = require('../controllers/mfaController');

const router = express.Router();

// MFA setup routes
router.post('/setup', authenticate, mfaController.setupMFA);

router.post('/verify-setup', 
  authenticate,
  [
    body('token')
      .isLength({ min: 6, max: 6 })
      .isNumeric()
      .withMessage('Token must be a 6-digit number'),
  ],
  mfaController.verifyAndEnableMFA
);

router.post('/disable',
  authenticate,
  [
    body('token')
      .isLength({ min: 6, max: 6 })
      .isNumeric()
      .withMessage('Token must be a 6-digit number'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password is required'),
  ],
  mfaController.disableMFA
);

// MFA verification during login
router.post('/verify',
  [
    body('token')
      .isLength({ min: 6, max: 8 })
      .withMessage('Invalid token format'),
    body('useBackupCode')
      .optional()
      .isBoolean()
      .withMessage('useBackupCode must be a boolean'),
  ],
  mfaController.verifyMFA
);

// Backup codes management
router.post('/regenerate-backup-codes',
  authenticate,
  [
    body('token')
      .isLength({ min: 6, max: 6 })
      .isNumeric()
      .withMessage('Token must be a 6-digit number'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password is required'),
  ],
  mfaController.regenerateBackupCodes
);

module.exports = router;