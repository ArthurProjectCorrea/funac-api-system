import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerModule } from '@nestjs/throttler';
import { ScheduleModule } from '@nestjs/schedule';
import { CacheModule } from '@nestjs/cache-manager';

// Services
import { AuthService } from './services/auth.service';
import { TokenService } from './services/token.service';
import { SessionService } from './services/session.service';
import { RiskAssessmentService } from './services/risk-assessment.service';
import { TokenBlacklistService } from './services/token-blacklist.service';
import { TokenCleanupService } from './services/token-cleanup.service';
import { DeviceManagementService } from './services/device-management.service';

// Controllers
import { AuthController } from './controllers/auth.controller';
import { SessionManagementController } from './controllers/session-management.controller';
import { MfaController } from './controllers/mfa.controller';

// Strategies
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';

// Guards
import { JwtAuthGuard, LocalAuthGuard } from './guards/auth.guards';

// Shared modules
import { DatabaseModule } from '../database/database.module';
import { SecurityModule } from '../security/security.module';
import { AuditModule } from '../audit/audit.module';
import { NotificationModule } from '../notifications/notification.module';

@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
    SecurityModule,
    AuditModule,
    NotificationModule,
    ScheduleModule.forRoot(),
    CacheModule.register({
      ttl: 15 * 60 * 1000, // 15 minutos (TTL do access token)
      max: 10000, // máximo de itens no cache
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_ACCESS_EXPIRATION', '15m'),
        },
      }),
      inject: [ConfigService],
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => [
        {
          name: 'login',
          ttl: 60000, // 1 minuto
          limit: configService.get<number>('LOGIN_RATE_LIMIT', 5),
        },
        {
          name: 'general',
          ttl: 60000,
          limit: configService.get<number>('GENERAL_RATE_LIMIT', 100),
        },
      ],
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController, SessionManagementController, MfaController],
  providers: [
    // Core Services
    AuthService,
    TokenService,
    SessionService,
    RiskAssessmentService,

    // New Services (Etapas 5-6)
    TokenBlacklistService,
    TokenCleanupService,
    DeviceManagementService,

    // Strategies
    LocalStrategy,
    JwtStrategy,

    // Guards
    JwtAuthGuard,
    LocalAuthGuard,
  ],
  exports: [
    AuthService,
    TokenService,
    SessionService,
    TokenBlacklistService,
    DeviceManagementService,
    JwtAuthGuard,
    LocalAuthGuard,
  ],
})
export class AuthModule {}
