export default () => ({
  port: parseInt(process.env.PORT || '3000', 10),

  database: {
    url: process.env.DATABASE_URL,
  },

  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
  },

  security: {
    password: {
      minLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '12', 10),
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
  },

  tokens: {
    accessToken: process.env.TOKEN_ACCESS_EXPIRY || '15m',
    refreshToken: process.env.TOKEN_REFRESH_EXPIRY || '7d',
    emailVerification: process.env.TOKEN_EMAIL_EXPIRY || '1h',
    passwordReset: process.env.TOKEN_RESET_EXPIRY || '30m',
    invitation: process.env.TOKEN_INVITATION_EXPIRY || '72h',
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
