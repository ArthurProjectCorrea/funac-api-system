export default () => ({
  port: parseInt(process.env.PORT || '3000', 10),

  database: {
    url: process.env.DATABASE_URL,
  },

  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
    accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
  },

  security: {
    password: {
      minLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '12', 10),
      maxLength: parseInt(process.env.PASSWORD_MAX_LENGTH || '128', 10),
      minScore: parseInt(process.env.PASSWORD_MIN_SCORE || '3', 10),
      pepper: process.env.PASSWORD_PEPPER || '',
      requireMixedCase: process.env.PASSWORD_REQUIRE_MIXED_CASE !== 'false',
      requireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== 'false',
      requireSpecialChars:
        process.env.PASSWORD_REQUIRE_SPECIAL_CHARS !== 'false',
    },

    mfa: {
      required: (
        process.env.MFA_REQUIRED_ROLES || 'system_admin,department_manager'
      ).split(','),
      optional: (
        process.env.MFA_OPTIONAL_ROLES || 'social_worker,external_user'
      ).split(','),
      totpWindow: parseInt(process.env.MFA_TOTP_WINDOW || '2', 10),
    },

    session: {
      inactivityTimeout: process.env.SESSION_INACTIVITY_TIMEOUT || '15m',
      maxConcurrentSessions: parseInt(
        process.env.MAX_CONCURRENT_SESSIONS || '5',
        10,
      ),
      refreshTokenExpirationDays: parseInt(
        process.env.REFRESH_TOKEN_EXPIRATION_DAYS || '14',
        10,
      ),
      sessionInactiveExpirationDays: parseInt(
        process.env.SESSION_INACTIVE_EXPIRATION_DAYS || '7',
        10,
      ),
    },

    rateLimit: {
      login: {
        ttl: parseInt(process.env.RATE_LIMIT_LOGIN_TTL || '900', 10), // 15 minutes
        limit: parseInt(process.env.RATE_LIMIT_LOGIN_LIMIT || '5', 10),
      },
      passwordReset: {
        ttl: parseInt(process.env.RATE_LIMIT_RESET_TTL || '3600', 10), // 1 hour
        limit: parseInt(process.env.RATE_LIMIT_RESET_LIMIT || '3', 10),
      },
      emailVerification: {
        ttl: parseInt(process.env.RATE_LIMIT_EMAIL_TTL || '3600', 10), // 1 hour
        limit: parseInt(process.env.RATE_LIMIT_EMAIL_LIMIT || '3', 10),
      },
    },

    riskAssessment: {
      enableGeolocation: process.env.ENABLE_IP_GEOLOCATION !== 'false',
      suspiciousThreshold: parseInt(
        process.env.SUSPICIOUS_LOGIN_THRESHOLD || '3',
        10,
      ),
      blockThreshold: parseInt(process.env.BLOCK_LOGIN_THRESHOLD || '5', 10),
    },
  },

  tokens: {
    accessToken: process.env.TOKEN_ACCESS_EXPIRY || '15m',
    refreshToken: process.env.TOKEN_REFRESH_EXPIRY || '7d',
    emailVerification: process.env.TOKEN_EMAIL_EXPIRY || '1h',
    passwordReset: process.env.TOKEN_RESET_EXPIRY || '20m',
    invitation: process.env.TOKEN_INVITATION_EXPIRY || '7d',
    emailVerifyExpirationMinutes: parseInt(
      process.env.EMAIL_VERIFY_EXPIRATION_MINUTES || '60',
      10,
    ),
    passwordResetExpirationMinutes: parseInt(
      process.env.PASSWORD_RESET_EXPIRATION_MINUTES || '20',
      10,
    ),
    invitationExpirationDays: parseInt(
      process.env.INVITATION_EXPIRATION_DAYS || '7',
      10,
    ),
  },

  email: {
    from: process.env.EMAIL_FROM || 'noreply@funac.gov.br',
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT || '587', 10),
    secure: process.env.EMAIL_SECURE === 'true',
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
