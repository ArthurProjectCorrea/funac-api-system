import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Request,
  Get,
  UnauthorizedException,
} from '@nestjs/common';
import { Request as ExpressRequest } from 'express';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AuthService } from '../services/auth.service';
import { TokenService } from '../services/token.service';
import {
  MfaVerifyDto,
  RefreshTokenDto,
  LogoutDto,
  PasswordResetDto,
  EmailVerifyDto,
} from '../dto/auth.dto';
import { LocalAuthGuard, JwtAuthGuard } from '../guards/auth.guards';
import { TokenType } from '@prisma/client';

interface AuthenticatedRequest extends ExpressRequest {
  user: {
    userId: string;
    email: string;
    status: string;
    mfaEnabled: boolean;
    roles: string[];
    permissions: string[];
  };
}

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(
    private authService: AuthService,
    private tokenService: TokenService,
  ) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(LocalAuthGuard)
  login(@Request() req: AuthenticatedRequest) {
    // O LocalAuthGuard já processou o login
    return req.user;
  }

  @Post('mfa/verify')
  @HttpCode(HttpStatus.OK)
  async verifyMfa(
    @Body() mfaDto: MfaVerifyDto,
    @Request() req: ExpressRequest,
  ) {
    const ipAddress = (req.ip as string) || 'unknown';
    const userAgent = (req.get('User-Agent') as string) || 'unknown';

    return await this.authService.verifyMfa(mfaDto, ipAddress, userAgent);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(
    @Body() refreshDto: RefreshTokenDto,
    @Request() req: ExpressRequest,
  ) {
    const ipAddress = (req.ip as string) || 'unknown';
    const userAgent = (req.get('User-Agent') as string) || 'unknown';

    return await this.authService.refreshTokens(
      refreshDto.refreshToken,
      ipAddress,
      userAgent,
    );
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Body() logoutDto: LogoutDto) {
    await this.authService.logout(logoutDto.refreshToken);
    return { message: 'Logout realizado com sucesso' };
  }

  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async logoutAll(@Request() req: AuthenticatedRequest) {
    const userId = req.user.userId;
    const revokedCount = await this.authService.logoutAll(userId);

    return {
      message: 'Logout de todos os dispositivos realizado com sucesso',
      revokedSessions: revokedCount,
    };
  }

  @Post('password/forgot')
  @HttpCode(HttpStatus.OK)
  forgotPassword() {
    // Implementar envio de email de reset
    // Por enquanto, apenas retornar sucesso
    return {
      message:
        'Se o email existir, você receberá instruções para redefinir sua senha',
    };
  }

  @Post('password/reset')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetDto: PasswordResetDto) {
    const tokenValidation = await this.tokenService.validateAndConsumeToken(
      resetDto.token,
      TokenType.PASSWORD_RESET,
    );

    if (!tokenValidation.isValid || !tokenValidation.userId) {
      throw new UnauthorizedException('Token de reset inválido ou expirado');
    }

    // Implementar reset de senha
    return { message: 'Senha redefinida com sucesso' };
  }

  @Post('email/verify')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() verifyDto: EmailVerifyDto) {
    const tokenValidation = await this.tokenService.validateAndConsumeToken(
      verifyDto.token,
      TokenType.EMAIL_VERIFICATION,
    );

    if (!tokenValidation.isValid || !tokenValidation.userId) {
      throw new UnauthorizedException(
        'Token de verificação inválido ou expirado',
      );
    }

    // Implementar verificação de email
    return { message: 'Email verificado com sucesso' };
  }

  @Post('email/resend')
  @HttpCode(HttpStatus.OK)
  resendVerification() {
    // Implementar reenvio de verificação
    return {
      message: 'Se o email existir, você receberá um novo link de verificação',
    };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  getProfile(@Request() req: AuthenticatedRequest) {
    return {
      id: req.user.userId,
      email: req.user.email,
      status: req.user.status,
      mfaEnabled: req.user.mfaEnabled,
      roles: req.user.roles,
      permissions: req.user.permissions,
    };
  }
}
