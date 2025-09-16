const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const bcrypt = require('bcryptjs');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      len: [3, 50],
      notEmpty: true,
    },
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
      notEmpty: true,
    },
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [8, 255],
      notEmpty: true,
    },
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [1, 50],
      notEmpty: true,
    },
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [1, 50],
      notEmpty: true,
    },
  },
  role: {
    type: DataTypes.ENUM('admin', 'analyst', 'operator', 'viewer'),
    defaultValue: 'viewer',
    allowNull: false,
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
    allowNull: false,
  },
  lastLogin: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  failedLoginAttempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false,
  },
  lockoutUntil: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  mfaEnabled: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
  },
  mfaSecret: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  emailVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
  },
  emailVerificationToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  passwordResetToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  passwordResetExpires: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  preferences: {
    type: DataTypes.JSON,
    defaultValue: {},
    allowNull: true,
  },
}, {
  tableName: 'users',
  timestamps: true,
  hooks: {
    beforeCreate: async (user) => {
      if (user.password) {
        const salt = await bcrypt.genSalt(12);
        user.password = await bcrypt.hash(user.password, salt);
      }
    },
    beforeUpdate: async (user) => {
      if (user.changed('password')) {
        const salt = await bcrypt.genSalt(12);
        user.password = await bcrypt.hash(user.password, salt);
      }
    },
  },
});

// Instance methods
User.prototype.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

User.prototype.isLocked = function() {
  return !!(this.lockoutUntil && this.lockoutUntil > Date.now());
};

User.prototype.incFailedLoginAttempts = async function() {
  const maxAttempts = 5;
  const lockoutTime = 2 * 60 * 60 * 1000; // 2 hours

  if (this.lockoutUntil && this.lockoutUntil < Date.now()) {
    return this.update({
      failedLoginAttempts: 1,
      lockoutUntil: null,
    });
  }

  const updates = { failedLoginAttempts: this.failedLoginAttempts + 1 };

  if (updates.failedLoginAttempts >= maxAttempts && !this.isLocked()) {
    updates.lockoutUntil = Date.now() + lockoutTime;
  }

  return this.update(updates);
};

User.prototype.resetFailedLoginAttempts = async function() {
  return this.update({
    failedLoginAttempts: 0,
    lockoutUntil: null,
  });
};

User.prototype.getPublicProfile = function() {
  return {
    id: this.id,
    username: this.username,
    email: this.email,
    firstName: this.firstName,
    lastName: this.lastName,
    role: this.role,
    isActive: this.isActive,
    lastLogin: this.lastLogin,
    mfaEnabled: this.mfaEnabled,
    emailVerified: this.emailVerified,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

module.exports = User;