import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerModule } from '@nestjs/throttler';

// Services
import { AuthService } from './services/auth.service';
import { TokenService } from './services/token.service';
import { SessionService } from './services/session.service';
import { RiskAssessmentService } from './services/risk-assessment.service';

// Controllers
import { AuthController } from './controllers/auth.controller';

// Strategies
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';

// Guards
import { JwtAuthGuard, LocalAuthGuard } from './guards/auth.guards';

// Shared modules
import { DatabaseModule } from '../database/database.module';
import { SecurityModule } from '../security/security.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
    SecurityModule,
    AuditModule,
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
  controllers: [AuthController],
  providers: [
    // Services
    AuthService,
    TokenService,
    SessionService,
    RiskAssessmentService,

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
    JwtAuthGuard,
    LocalAuthGuard,
  ],
})
export class AuthModule {}
