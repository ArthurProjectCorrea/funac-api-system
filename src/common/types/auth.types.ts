export enum UserRole {
  SYSTEM_ADMIN = 'system_admin',
  DEPARTMENT_MANAGER = 'department_manager',
  SOCIAL_WORKER = 'social_worker',
  EXTERNAL_USER = 'external_user',
}

export enum Permission {
  // Usuários
  USER_CREATE = 'user:create',
  USER_READ = 'user:read',
  USER_UPDATE = 'user:update',
  USER_DELETE = 'user:delete',

  // Departamentos
  DEPARTMENT_MANAGE = 'department:manage',
  DEPARTMENT_VIEW = 'department:view',

  // Relatórios
  REPORT_GENERATE = 'report:generate',
  REPORT_VIEW_ALL = 'report:view_all',
  REPORT_VIEW_OWN = 'report:view_own',

  // Sistema
  SYSTEM_CONFIG = 'system:config',
  AUDIT_VIEW = 'audit:view',
}

export enum UserStatus {
  INVITED = 'INVITED',
  PENDING_EMAIL_VERIFICATION = 'PENDING_EMAIL_VERIFICATION',
  ACTIVE = 'ACTIVE',
  SUSPENDED = 'SUSPENDED',
  DISABLED = 'DISABLED',
}

export enum TokenType {
  EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
  PASSWORD_RESET = 'PASSWORD_RESET',
  INVITATION = 'INVITATION',
  MFA_BACKUP = 'MFA_BACKUP',
}

export enum AuditAction {
  LOGIN_SUCCESS = 'login:success',
  LOGIN_FAILURE = 'login:failure',
  LOGOUT = 'logout',
  PASSWORD_RESET_REQUEST = 'password:reset_request',
  PASSWORD_RESET_SUCCESS = 'password:reset_success',
  EMAIL_VERIFICATION = 'email:verification',
  MFA_ENABLE = 'mfa:enable',
  MFA_DISABLE = 'mfa:disable',
  USER_CREATE = 'user:create',
  USER_UPDATE = 'user:update',
  USER_SUSPEND = 'user:suspend',
  USER_ACTIVATE = 'user:activate',
  ROLE_ASSIGN = 'role:assign',
  ROLE_REVOKE = 'role:revoke',
}

export interface JwtPayload {
  sub: string; // user id
  email: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  sub: string; // user id
  sessionId: string;
  tokenVersion: number;
  iat?: number;
  exp?: number;
}

export interface AuthUser {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  status: UserStatus;
  roles: string[];
  permissions: string[];
  mfaEnabled: boolean;
  emailVerified: boolean;
}
