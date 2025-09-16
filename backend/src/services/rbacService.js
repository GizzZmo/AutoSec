/**
 * Role-Based Access Control (RBAC) Service
 * Manages permissions, roles, and access control throughout the system
 */

class RBACService {
  constructor() {
    this.permissions = this.initializePermissions();
    this.roleHierarchy = this.initializeRoleHierarchy();
    this.defaultRolePermissions = this.initializeDefaultRolePermissions();
  }

  /**
   * Initialize all available permissions in the system
   */
  initializePermissions() {
    return {
      // User Management
      'users.view': 'View user profiles and information',
      'users.create': 'Create new user accounts',
      'users.edit': 'Edit user profiles and settings',
      'users.delete': 'Delete user accounts',
      'users.activate': 'Activate/deactivate user accounts',
      'users.roles': 'Manage user roles and permissions',

      // Authentication & Security
      'auth.mfa.manage': 'Manage MFA settings for users',
      'auth.sessions.view': 'View active user sessions',
      'auth.sessions.terminate': 'Terminate user sessions',
      'auth.audit': 'View authentication audit logs',

      // Network & Firewall Management
      'network.rules.view': 'View network security rules',
      'network.rules.create': 'Create network security rules',
      'network.rules.edit': 'Edit network security rules',
      'network.rules.delete': 'Delete network security rules',
      'network.rules.enforce': 'Enforce/deploy network rules',
      'network.monitoring': 'Monitor network traffic and events',

      // Threat Intelligence
      'threats.view': 'View threat intelligence data',
      'threats.feeds.manage': 'Manage threat intelligence feeds',
      'threats.indicators.create': 'Create threat indicators',
      'threats.indicators.edit': 'Edit threat indicators',
      'threats.hunt': 'Perform threat hunting activities',
      'threats.correlation': 'Correlate threat data',

      // Incident Response
      'incidents.view': 'View security incidents',
      'incidents.create': 'Create new incidents',
      'incidents.edit': 'Edit incident details',
      'incidents.assign': 'Assign incidents to users',
      'incidents.escalate': 'Escalate incidents',
      'incidents.close': 'Close resolved incidents',
      'incidents.playbooks': 'Manage incident response playbooks',

      // Behavioral Analysis
      'behavior.view': 'View behavioral analysis data',
      'behavior.models.manage': 'Manage ML models for behavior analysis',
      'behavior.baselines': 'Manage behavioral baselines',
      'behavior.alerts': 'Manage behavioral alerts and thresholds',

      // Asset Management
      'assets.view': 'View asset inventory',
      'assets.discovery': 'Perform asset discovery',
      'assets.scan': 'Initiate vulnerability scans',
      'assets.risk.assess': 'Perform risk assessments',

      // Reports & Analytics
      'reports.view': 'View security reports',
      'reports.create': 'Create custom reports',
      'reports.schedule': 'Schedule automated reports',
      'reports.export': 'Export report data',
      'analytics.dashboard': 'Access analytics dashboards',

      // System Administration
      'system.config': 'Manage system configuration',
      'system.integrations': 'Manage third-party integrations',
      'system.logs': 'View system logs',
      'system.backup': 'Manage system backups',
      'system.maintenance': 'Perform system maintenance',

      // Compliance & Audit
      'compliance.view': 'View compliance reports',
      'compliance.manage': 'Manage compliance frameworks',
      'audit.view': 'View audit trails',
      'audit.export': 'Export audit data',
    };
  }

  /**
   * Initialize role hierarchy (higher numbers have more authority)
   */
  initializeRoleHierarchy() {
    return {
      'viewer': 1,
      'operator': 2,
      'analyst': 3,
      'admin': 4,
    };
  }

  /**
   * Initialize default permissions for each role
   */
  initializeDefaultRolePermissions() {
    return {
      viewer: [
        'network.rules.view',
        'threats.view',
        'incidents.view',
        'behavior.view',
        'assets.view',
        'reports.view',
        'analytics.dashboard',
        'audit.view',
      ],
      operator: [
        // All viewer permissions plus:
        'network.rules.create',
        'network.rules.edit',
        'network.rules.enforce',
        'network.monitoring',
        'threats.indicators.create',
        'threats.indicators.edit',
        'incidents.create',
        'incidents.edit',
        'incidents.assign',
        'behavior.alerts',
        'assets.discovery',
        'assets.scan',
        'reports.create',
        'reports.export',
      ],
      analyst: [
        // All operator permissions plus:
        'network.rules.delete',
        'threats.feeds.manage',
        'threats.hunt',
        'threats.correlation',
        'incidents.escalate',
        'incidents.close',
        'incidents.playbooks',
        'behavior.models.manage',
        'behavior.baselines',
        'assets.risk.assess',
        'reports.schedule',
        'compliance.view',
        'audit.export',
      ],
      admin: [
        // All permissions - admins have full access
        ...Object.keys(this.initializePermissions()),
      ],
    };
  }

  /**
   * Check if a user has a specific permission
   * @param {Object} user - User object
   * @param {string} permission - Permission to check
   * @returns {boolean} True if user has permission
   */
  hasPermission(user, permission) {
    if (!user || !user.isActive) {
      return false;
    }

    // Admin role has all permissions
    if (user.role === 'admin') {
      return true;
    }

    // Check custom user permissions
    if (user.permissions && user.permissions[permission]) {
      return user.permissions[permission];
    }

    // Check default role permissions
    const rolePermissions = this.defaultRolePermissions[user.role] || [];
    const hasRolePermission = rolePermissions.includes(permission);

    // Check inherited permissions from role hierarchy
    const userRoleLevel = this.roleHierarchy[user.role] || 0;
    const inheritedPermissions = this.getInheritedPermissions(userRoleLevel);
    const hasInheritedPermission = inheritedPermissions.includes(permission);

    return hasRolePermission || hasInheritedPermission;
  }

  /**
   * Get permissions inherited from lower-level roles
   * @param {number} roleLevel - Current role level
   * @returns {Array} Array of inherited permissions
   */
  getInheritedPermissions(roleLevel) {
    const inheritedPermissions = [];
    
    Object.entries(this.roleHierarchy).forEach(([role, level]) => {
      if (level < roleLevel) {
        inheritedPermissions.push(...(this.defaultRolePermissions[role] || []));
      }
    });

    return [...new Set(inheritedPermissions)]; // Remove duplicates
  }

  /**
   * Check if user has minimum required role level
   * @param {Object} user - User object
   * @param {string} minRole - Minimum required role
   * @returns {boolean} True if user meets minimum role requirement
   */
  hasMinimumRole(user, minRole) {
    if (!user || !user.isActive) {
      return false;
    }

    const userRoleLevel = this.roleHierarchy[user.role] || 0;
    const requiredRoleLevel = this.roleHierarchy[minRole] || 0;

    return userRoleLevel >= requiredRoleLevel;
  }

  /**
   * Get all permissions for a user
   * @param {Object} user - User object
   * @returns {Array} Array of permissions
   */
  getUserPermissions(user) {
    if (!user || !user.isActive) {
      return [];
    }

    if (user.role === 'admin') {
      return Object.keys(this.permissions);
    }

    const rolePermissions = this.defaultRolePermissions[user.role] || [];
    const userRoleLevel = this.roleHierarchy[user.role] || 0;
    const inheritedPermissions = this.getInheritedPermissions(userRoleLevel);
    const customPermissions = Object.entries(user.permissions || {})
      .filter(([, granted]) => granted)
      .map(([permission]) => permission);

    return [...new Set([...rolePermissions, ...inheritedPermissions, ...customPermissions])];
  }

  /**
   * Grant specific permission to user
   * @param {Object} user - User object
   * @param {string} permission - Permission to grant
   * @returns {Object} Updated permissions object
   */
  grantPermission(user, permission) {
    if (!this.permissions[permission]) {
      throw new Error(`Unknown permission: ${permission}`);
    }

    const permissions = user.permissions || {};
    permissions[permission] = true;
    return permissions;
  }

  /**
   * Revoke specific permission from user
   * @param {Object} user - User object
   * @param {string} permission - Permission to revoke
   * @returns {Object} Updated permissions object
   */
  revokePermission(user, permission) {
    const permissions = user.permissions || {};
    permissions[permission] = false;
    return permissions;
  }

  /**
   * Get available roles
   * @returns {Array} Array of role objects
   */
  getAvailableRoles() {
    return Object.entries(this.roleHierarchy).map(([role, level]) => ({
      role,
      level,
      permissions: this.defaultRolePermissions[role] || [],
    }));
  }

  /**
   * Validate permission name
   * @param {string} permission - Permission to validate
   * @returns {boolean} True if permission exists
   */
  isValidPermission(permission) {
    return this.permissions.hasOwnProperty(permission);
  }

  /**
   * Get permission description
   * @param {string} permission - Permission name
   * @returns {string} Permission description
   */
  getPermissionDescription(permission) {
    return this.permissions[permission] || 'Unknown permission';
  }

  /**
   * Check if user can manage another user (based on role hierarchy)
   * @param {Object} manager - Manager user object
   * @param {Object} target - Target user object
   * @returns {boolean} True if manager can manage target
   */
  canManageUser(manager, target) {
    if (!manager || !target) {
      return false;
    }

    // Users can manage themselves
    if (manager.id === target.id) {
      return true;
    }

    const managerLevel = this.roleHierarchy[manager.role] || 0;
    const targetLevel = this.roleHierarchy[target.role] || 0;

    // Can only manage users with lower or equal role level
    return managerLevel >= targetLevel;
  }
}

module.exports = new RBACService();