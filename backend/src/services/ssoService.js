/**
 * Single Sign-On (SSO) Integration Service
 * Supports multiple SSO providers including SAML, OAuth2, and OpenID Connect
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const logger = require('../config/logger');

class SSOService {
  constructor() {
    this.providers = this.initializeProviders();
    this.ssoSessions = new Map(); // In production, use Redis
  }

  /**
   * Initialize supported SSO providers
   */
  initializeProviders() {
    return {
      saml: {
        name: 'SAML 2.0',
        type: 'saml',
        enabled: process.env.SAML_ENABLED === 'true',
        config: {
          entryPoint: process.env.SAML_ENTRY_POINT,
          issuer: process.env.SAML_ISSUER || 'autosec',
          cert: process.env.SAML_CERT,
          signatureAlgorithm: 'sha256',
        },
      },
      oidc: {
        name: 'OpenID Connect',
        type: 'oidc',
        enabled: process.env.OIDC_ENABLED === 'true',
        config: {
          issuer: process.env.OIDC_ISSUER,
          clientId: process.env.OIDC_CLIENT_ID,
          clientSecret: process.env.OIDC_CLIENT_SECRET,
          redirectUri: process.env.OIDC_REDIRECT_URI,
          scope: 'openid profile email',
        },
      },
      oauth2: {
        name: 'OAuth 2.0',
        type: 'oauth2',
        enabled: process.env.OAUTH2_ENABLED === 'true',
        config: {
          authorizationURL: process.env.OAUTH2_AUTH_URL,
          tokenURL: process.env.OAUTH2_TOKEN_URL,
          userInfoURL: process.env.OAUTH2_USERINFO_URL,
          clientId: process.env.OAUTH2_CLIENT_ID,
          clientSecret: process.env.OAUTH2_CLIENT_SECRET,
          scope: 'profile email',
        },
      },
      ldap: {
        name: 'LDAP/Active Directory',
        type: 'ldap',
        enabled: process.env.LDAP_ENABLED === 'true',
        config: {
          url: process.env.LDAP_URL,
          bindDN: process.env.LDAP_BIND_DN,
          bindCredentials: process.env.LDAP_BIND_PASSWORD,
          searchBase: process.env.LDAP_SEARCH_BASE,
          searchFilter: process.env.LDAP_SEARCH_FILTER || '(uid={{username}})',
        },
      },
    };
  }

  /**
   * Get available SSO providers
   * @returns {Array} List of enabled providers
   */
  getAvailableProviders() {
    return Object.entries(this.providers)
      .filter(([, provider]) => provider.enabled)
      .map(([key, provider]) => ({
        id: key,
        name: provider.name,
        type: provider.type,
        loginUrl: `/api/auth/sso/${key}/login`,
      }));
  }

  /**
   * Initiate SSO login
   * @param {string} providerId - SSO provider ID
   * @param {string} returnUrl - URL to return to after authentication
   * @returns {Object} SSO initiation response
   */
  async initiateSSOLogin(providerId, returnUrl = '/') {
    const provider = this.providers[providerId];
    if (!provider || !provider.enabled) {
      throw new Error('Invalid or disabled SSO provider');
    }

    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');

    // Store SSO session
    this.ssoSessions.set(state, {
      providerId,
      returnUrl,
      nonce,
      timestamp: Date.now(),
    });

    switch (provider.type) {
      case 'oidc':
        return this.initiateOIDCLogin(provider, state, nonce);
      case 'oauth2':
        return this.initiateOAuth2Login(provider, state);
      case 'saml':
        return this.initiateSAMLLogin(provider, state);
      default:
        throw new Error('Unsupported SSO provider type');
    }
  }

  /**
   * Initiate OpenID Connect login
   */
  initiateOIDCLogin(provider, state, nonce) {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: provider.config.clientId,
      redirect_uri: provider.config.redirectUri,
      scope: provider.config.scope,
      state,
      nonce,
    });

    const authUrl = `${provider.config.issuer}/auth?${params.toString()}`;

    return {
      authUrl,
      state,
      method: 'redirect',
    };
  }

  /**
   * Initiate OAuth 2.0 login
   */
  initiateOAuth2Login(provider, state) {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: provider.config.clientId,
      redirect_uri: provider.config.redirectUri || `${process.env.API_BASE_URL}/auth/sso/oauth2/callback`,
      scope: provider.config.scope,
      state,
    });

    const authUrl = `${provider.config.authorizationURL}?${params.toString()}`;

    return {
      authUrl,
      state,
      method: 'redirect',
    };
  }

  /**
   * Initiate SAML login
   */
  initiateSAMLLogin(provider, state) {
    const samlRequest = this.generateSAMLRequest(provider);
    const encodedRequest = Buffer.from(samlRequest).toString('base64');

    const params = new URLSearchParams({
      SAMLRequest: encodedRequest,
      RelayState: state,
    });

    return {
      authUrl: `${provider.config.entryPoint}?${params.toString()}`,
      state,
      method: 'redirect',
      samlRequest: encodedRequest,
    };
  }

  /**
   * Handle SSO callback
   * @param {string} providerId - SSO provider ID
   * @param {Object} callbackData - Callback data from provider
   * @returns {Object} Authentication result
   */
  async handleSSOCallback(providerId, callbackData) {
    const provider = this.providers[providerId];
    if (!provider || !provider.enabled) {
      throw new Error('Invalid or disabled SSO provider');
    }

    const ssoSession = this.ssoSessions.get(callbackData.state);
    if (!ssoSession || ssoSession.providerId !== providerId) {
      throw new Error('Invalid SSO session');
    }

    // Check session timeout (10 minutes)
    if (Date.now() - ssoSession.timestamp > 10 * 60 * 1000) {
      this.ssoSessions.delete(callbackData.state);
      throw new Error('SSO session expired');
    }

    let userInfo;
    switch (provider.type) {
      case 'oidc':
        userInfo = await this.handleOIDCCallback(provider, callbackData, ssoSession);
        break;
      case 'oauth2':
        userInfo = await this.handleOAuth2Callback(provider, callbackData);
        break;
      case 'saml':
        userInfo = await this.handleSAMLCallback(provider, callbackData);
        break;
      default:
        throw new Error('Unsupported SSO provider type');
    }

    // Clean up SSO session
    this.ssoSessions.delete(callbackData.state);

    return {
      userInfo,
      returnUrl: ssoSession.returnUrl,
      providerId,
    };
  }

  /**
   * Handle OpenID Connect callback
   */
  async handleOIDCCallback(provider, callbackData, ssoSession) {
    const { code } = callbackData;
    
    // Exchange code for tokens
    const tokenResponse = await this.exchangeCodeForTokens(
      provider.config.issuer + '/token',
      {
        grant_type: 'authorization_code',
        client_id: provider.config.clientId,
        client_secret: provider.config.clientSecret,
        code,
        redirect_uri: provider.config.redirectUri,
      }
    );

    // Verify ID token
    const idToken = jwt.decode(tokenResponse.id_token);
    if (idToken.nonce !== ssoSession.nonce) {
      throw new Error('Invalid nonce in ID token');
    }

    return {
      sub: idToken.sub,
      email: idToken.email,
      name: idToken.name,
      given_name: idToken.given_name,
      family_name: idToken.family_name,
      groups: idToken.groups || [],
      provider: 'oidc',
    };
  }

  /**
   * Handle OAuth 2.0 callback
   */
  async handleOAuth2Callback(provider, callbackData) {
    const { code } = callbackData;
    
    // Exchange code for access token
    const tokenResponse = await this.exchangeCodeForTokens(
      provider.config.tokenURL,
      {
        grant_type: 'authorization_code',
        client_id: provider.config.clientId,
        client_secret: provider.config.clientSecret,
        code,
      }
    );

    // Get user info
    const userInfoResponse = await fetch(provider.config.userInfoURL, {
      headers: {
        Authorization: `Bearer ${tokenResponse.access_token}`,
      },
    });

    const userInfo = await userInfoResponse.json();

    return {
      sub: userInfo.id || userInfo.sub,
      email: userInfo.email,
      name: userInfo.name,
      given_name: userInfo.given_name || userInfo.first_name,
      family_name: userInfo.family_name || userInfo.last_name,
      provider: 'oauth2',
    };
  }

  /**
   * Handle SAML callback
   */
  async handleSAMLCallback(provider, callbackData) {
    const { SAMLResponse } = callbackData;
    
    // Decode and parse SAML response
    const decodedResponse = Buffer.from(SAMLResponse, 'base64').toString();
    const userInfo = this.parseSAMLResponse(decodedResponse);

    return {
      ...userInfo,
      provider: 'saml',
    };
  }

  /**
   * Generate SAML authentication request
   */
  generateSAMLRequest(provider) {
    const id = crypto.randomBytes(16).toString('hex');
    const timestamp = new Date().toISOString();

    return `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="${id}"
                    Version="2.0"
                    IssueInstant="${timestamp}"
                    Destination="${provider.config.entryPoint}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    AssertionConsumerServiceURL="${process.env.API_BASE_URL}/auth/sso/saml/callback">
  <saml:Issuer>${provider.config.issuer}</saml:Issuer>
</samlp:AuthnRequest>`;
  }

  /**
   * Parse SAML response
   */
  parseSAMLResponse(samlResponse) {
    // In production, use a proper SAML library like saml2-js
    // This is a simplified example
    const emailMatch = samlResponse.match(/<saml:Attribute Name="email".*?<saml:AttributeValue>(.*?)<\/saml:AttributeValue>/);
    const nameMatch = samlResponse.match(/<saml:Attribute Name="name".*?<saml:AttributeValue>(.*?)<\/saml:AttributeValue>/);
    const subMatch = samlResponse.match(/<saml:NameID.*?>(.*?)<\/saml:NameID>/);

    return {
      sub: subMatch ? subMatch[1] : null,
      email: emailMatch ? emailMatch[1] : null,
      name: nameMatch ? nameMatch[1] : null,
    };
  }

  /**
   * Exchange authorization code for tokens
   */
  async exchangeCodeForTokens(tokenUrl, params) {
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(params),
    });

    if (!response.ok) {
      throw new Error('Failed to exchange code for tokens');
    }

    return response.json();
  }

  /**
   * Map SSO user to local user account
   * @param {Object} ssoUserInfo - User info from SSO provider
   * @returns {Object} Mapped user data
   */
  mapSSOUserToLocal(ssoUserInfo) {
    return {
      email: ssoUserInfo.email,
      username: ssoUserInfo.email?.split('@')[0] || ssoUserInfo.sub,
      firstName: ssoUserInfo.given_name || ssoUserInfo.name?.split(' ')[0] || 'Unknown',
      lastName: ssoUserInfo.family_name || ssoUserInfo.name?.split(' ').slice(1).join(' ') || 'User',
      ssoProvider: ssoUserInfo.provider,
      ssoSubject: ssoUserInfo.sub,
      groups: ssoUserInfo.groups || [],
      isActive: true,
      emailVerified: true, // Assume SSO providers verify emails
    };
  }

  /**
   * Determine user role based on SSO groups
   * @param {Array} groups - User groups from SSO
   * @returns {string} Mapped role
   */
  mapGroupsToRole(groups = []) {
    const roleMapping = {
      'autosec-admin': 'admin',
      'autosec-analyst': 'analyst',
      'autosec-operator': 'operator',
      'autosec-viewer': 'viewer',
      'admin': 'admin',
      'analyst': 'analyst',
      'operator': 'operator',
    };

    // Find the highest privilege role
    const mappedRoles = groups
      .map(group => roleMapping[group.toLowerCase()])
      .filter(role => role);

    const roleHierarchy = { admin: 4, analyst: 3, operator: 2, viewer: 1 };
    
    if (mappedRoles.length === 0) {
      return 'viewer'; // Default role
    }

    return mappedRoles.reduce((highest, current) => {
      return roleHierarchy[current] > roleHierarchy[highest] ? current : highest;
    });
  }

  /**
   * Validate SSO configuration
   * @param {string} providerId - Provider ID to validate
   * @returns {Object} Validation result
   */
  validateSSOConfig(providerId) {
    const provider = this.providers[providerId];
    if (!provider) {
      return { valid: false, errors: ['Provider not found'] };
    }

    const errors = [];
    const config = provider.config;

    switch (provider.type) {
      case 'oidc':
        if (!config.issuer) errors.push('OIDC issuer is required');
        if (!config.clientId) errors.push('OIDC client ID is required');
        if (!config.clientSecret) errors.push('OIDC client secret is required');
        break;
      case 'oauth2':
        if (!config.authorizationURL) errors.push('OAuth2 authorization URL is required');
        if (!config.tokenURL) errors.push('OAuth2 token URL is required');
        if (!config.clientId) errors.push('OAuth2 client ID is required');
        break;
      case 'saml':
        if (!config.entryPoint) errors.push('SAML entry point is required');
        if (!config.cert) errors.push('SAML certificate is required');
        break;
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

module.exports = new SSOService();