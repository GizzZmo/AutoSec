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
  mfaTempSecret: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  mfaBackupCodes: {
    type: DataTypes.JSON,
    allowNull: true,
  },
  mfaRecoveryCode: {
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
  knownIPs: {
    type: DataTypes.JSON,
    defaultValue: [],
    allowNull: true,
  },
  knownDevices: {
    type: DataTypes.JSON,
    defaultValue: [],
    allowNull: true,
  },
  typicalLoginHours: {
    type: DataTypes.JSON,
    defaultValue: [],
    allowNull: true,
  },
  loginSessions: {
    type: DataTypes.JSON,
    defaultValue: [],
    allowNull: true,
  },
  permissions: {
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
    permissions: this.permissions,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

User.prototype.enableMFA = async function(secret, backupCodes) {
  return this.update({
    mfaEnabled: true,
    mfaSecret: secret,
    mfaTempSecret: null,
    mfaBackupCodes: backupCodes,
  });
};

User.prototype.disableMFA = async function() {
  return this.update({
    mfaEnabled: false,
    mfaSecret: null,
    mfaTempSecret: null,
    mfaBackupCodes: null,
    mfaRecoveryCode: null,
  });
};

User.prototype.updateLoginContext = async function(ip, userAgent) {
  const knownIPs = this.knownIPs || [];
  const knownDevices = this.knownDevices || [];
  const currentHour = new Date().getHours();
  const typicalHours = this.typicalLoginHours || [];

  // Add IP if not known (keep last 10)
  if (ip && !knownIPs.includes(ip)) {
    knownIPs.push(ip);
    if (knownIPs.length > 10) {
      knownIPs.shift();
    }
  }

  // Add device if not known (keep last 5)
  if (userAgent && !knownDevices.includes(userAgent)) {
    knownDevices.push(userAgent);
    if (knownDevices.length > 5) {
      knownDevices.shift();
    }
  }

  // Track typical login hours
  if (!typicalHours.includes(currentHour)) {
    typicalHours.push(currentHour);
  }

  return this.update({
    knownIPs,
    knownDevices,
    typicalLoginHours: typicalHours,
    lastLogin: new Date(),
  });
};

User.prototype.hasPermission = function(permission) {
  if (!this.permissions) return false;
  
  // Admin has all permissions
  if (this.role === 'admin') return true;
  
  // Check specific permission
  return this.permissions[permission] === true;
};

User.prototype.addSession = async function(sessionId, deviceInfo) {
  const sessions = this.loginSessions || [];
  sessions.push({
    id: sessionId,
    deviceInfo,
    createdAt: new Date(),
    lastActivity: new Date(),
  });

  // Keep only last 5 sessions
  if (sessions.length > 5) {
    sessions.shift();
  }

  return this.update({ loginSessions: sessions });
};

User.prototype.removeSession = async function(sessionId) {
  const sessions = (this.loginSessions || []).filter(s => s.id !== sessionId);
  return this.update({ loginSessions: sessions });
};

module.exports = User;