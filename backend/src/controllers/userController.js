const { validationResult } = require('express-validator');
const { Op } = require('sequelize');
const User = require('../models/User');
const logger = require('../config/logger');

// Get all users (admin only)
exports.getAllUsers = async (req, res) => {
  try {
    const { page = 1, limit = 20, search, role, isActive } = req.query;
    
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const whereClause = {};

    // Apply filters
    if (search) {
      whereClause[Op.or] = [
        { username: { [Op.iLike]: `%${search}%` } },
        { email: { [Op.iLike]: `%${search}%` } },
        { firstName: { [Op.iLike]: `%${search}%` } },
        { lastName: { [Op.iLike]: `%${search}%` } },
      ];
    }

    if (role) {
      whereClause.role = role;
    }

    if (isActive !== undefined) {
      whereClause.isActive = isActive === 'true';
    }

    const { count, rows: users } = await User.findAndCountAll({
      where: whereClause,
      order: [['createdAt', 'DESC']],
      limit: parseInt(limit),
      offset,
      attributes: { exclude: ['password', 'mfaSecret', 'passwordResetToken'] },
    });

    res.json({
      success: true,
      data: {
        users,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(count / parseInt(limit)),
          totalUsers: count,
          limit: parseInt(limit),
        },
      },
    });
  } catch (error) {
    logger.error('Get all users error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get user by ID (admin only)
exports.getUserById = async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findByPk(id, {
      attributes: { exclude: ['password', 'mfaSecret', 'passwordResetToken'] },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    res.json({
      success: true,
      data: {
        user: user.getPublicProfile(),
      },
    });
  } catch (error) {
    logger.error('Get user by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Create new user (admin only)
exports.createUser = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { username, email, password, firstName, lastName, role, isActive } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      where: {
        [Op.or]: [{ email }, { username }],
      },
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User with this email or username already exists',
      });
    }

    // Create user
    const user = await User.create({
      username,
      email,
      password,
      firstName,
      lastName,
      role: role || 'viewer',
      isActive: isActive !== undefined ? isActive : true,
      emailVerified: true, // Admin created users are pre-verified
    });

    logger.info(`User created by admin: ${user.username}`, {
      userId: user.id,
      createdBy: req.user.id,
      createdByUsername: req.user.username,
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        user: user.getPublicProfile(),
      },
    });
  } catch (error) {
    logger.error('Create user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Update user (admin only)
exports.updateUser = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { id } = req.params;
    const { username, email, firstName, lastName, role, isActive } = req.body;

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Prevent admin from deactivating themselves
    if (id === req.user.id && isActive === false) {
      return res.status(400).json({
        success: false,
        message: 'You cannot deactivate your own account',
      });
    }

    // Check for unique constraints if changing username or email
    if ((username && username !== user.username) || (email && email !== user.email)) {
      const existingUser = await User.findOne({
        where: {
          [Op.and]: [
            { id: { [Op.ne]: id } },
            {
              [Op.or]: [
                username ? { username } : {},
                email ? { email } : {},
              ],
            },
          ],
        },
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: 'Username or email already exists',
        });
      }
    }

    // Update user
    await user.update({
      username: username || user.username,
      email: email || user.email,
      firstName: firstName || user.firstName,
      lastName: lastName || user.lastName,
      role: role || user.role,
      isActive: isActive !== undefined ? isActive : user.isActive,
    });

    logger.info(`User updated by admin: ${user.username}`, {
      userId: user.id,
      updatedBy: req.user.id,
      updatedByUsername: req.user.username,
      changes: req.body,
    });

    res.json({
      success: true,
      message: 'User updated successfully',
      data: {
        user: user.getPublicProfile(),
      },
    });
  } catch (error) {
    logger.error('Update user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Delete user (admin only)
exports.deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent admin from deleting themselves
    if (id === req.user.id) {
      return res.status(400).json({
        success: false,
        message: 'You cannot delete your own account',
      });
    }

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    await user.destroy();

    logger.info(`User deleted by admin: ${user.username}`, {
      userId: user.id,
      deletedBy: req.user.id,
      deletedByUsername: req.user.username,
    });

    res.status(204).send();
  } catch (error) {
    logger.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Reset user password (admin only)
exports.resetUserPassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { id } = req.params;
    const { newPassword } = req.body;

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    await user.update({
      password: newPassword,
      failedLoginAttempts: 0,
      lockoutUntil: null,
    });

    logger.info(`Password reset by admin for user: ${user.username}`, {
      userId: user.id,
      resetBy: req.user.id,
      resetByUsername: req.user.username,
    });

    res.json({
      success: true,
      message: 'Password reset successfully',
    });
  } catch (error) {
    logger.error('Reset user password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Unlock user account (admin only)
exports.unlockUser = async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    await user.update({
      failedLoginAttempts: 0,
      lockoutUntil: null,
    });

    logger.info(`User account unlocked by admin: ${user.username}`, {
      userId: user.id,
      unlockedBy: req.user.id,
      unlockedByUsername: req.user.username,
    });

    res.json({
      success: true,
      message: 'User account unlocked successfully',
    });
  } catch (error) {
    logger.error('Unlock user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get user statistics (admin only)
exports.getUserStats = async (req, res) => {
  try {
    const totalUsers = await User.count();
    const activeUsers = await User.count({ where: { isActive: true } });
    const lockedUsers = await User.count({
      where: {
        lockoutUntil: {
          [Op.gt]: new Date(),
        },
      },
    });

    const usersByRole = await User.findAll({
      attributes: ['role', [User.sequelize.fn('COUNT', User.sequelize.col('role')), 'count']],
      group: ['role'],
      raw: true,
    });

    const recentUsers = await User.findAll({
      where: {
        createdAt: {
          [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
        },
      },
      attributes: ['createdAt'],
      order: [['createdAt', 'ASC']],
      raw: true,
    });

    res.json({
      success: true,
      data: {
        totalUsers,
        activeUsers,
        inactiveUsers: totalUsers - activeUsers,
        lockedUsers,
        usersByRole: usersByRole.reduce((acc, curr) => {
          acc[curr.role] = parseInt(curr.count);
          return acc;
        }, {}),
        recentUsers,
      },
    });
  } catch (error) {
    logger.error('Get user stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

module.exports = exports;