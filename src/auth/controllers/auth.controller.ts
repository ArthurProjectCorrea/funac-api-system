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
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
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
  ResendVerificationDto,
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
    tokenId?: string; // JTI do token atual
  };
}

@ApiTags('Auth')
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
  @ApiOperation({
    summary: 'Fazer login',
    description:
      'Autentica o usuário com email e senha. Retorna tokens de acesso e refresh.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'admin@funac.gov.br' },
        password: { type: 'string', example: 'Admin123!@#' },
      },
      required: ['email', 'password'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Login realizado com sucesso',
    schema: {
      type: 'object',
      properties: {
        accessToken: { type: 'string' },
        refreshToken: { type: 'string' },
        user: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            email: { type: 'string' },
            status: { type: 'string' },
            mfaEnabled: { type: 'boolean' },
            roles: { type: 'array', items: { type: 'string' } },
            permissions: { type: 'array', items: { type: 'string' } },
          },
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Credenciais inválidas' })
  @ApiResponse({ status: 429, description: 'Muitas tentativas de login' })
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
  @ApiOperation({
    summary: 'Renovar tokens',
    description: 'Renova o access token usando o refresh token',
  })
  @ApiResponse({ status: 200, description: 'Tokens renovados com sucesso' })
  @ApiResponse({ status: 401, description: 'Refresh token inválido' })
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
  @UseGuards(JwtAuthGuard)
  async logout(
    @Body() logoutDto: LogoutDto,
    @Request() req: AuthenticatedRequest,
  ) {
    await this.authService.logout(logoutDto.refreshToken, req.user.tokenId);
    return { message: 'Logout realizado com sucesso' };
  }

  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async logoutAll(@Request() req: AuthenticatedRequest) {
    const userId = req.user.userId;
    const revokedCount = await this.authService.logoutAll(
      userId,
      undefined, // não temos sessionId no token JWT
      req.user.tokenId,
    );

    return {
      message: 'Logout de todos os dispositivos realizado com sucesso',
      revokedSessions: revokedCount,
    };
  }

  @Post('password/forgot')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Solicitar reset de senha',
    description: 'Envia email com token para reset de senha',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'user@funac.gov.br' },
      },
      required: ['email'],
    },
  })
  async forgotPassword(@Body() forgotDto: { email: string }) {
    await this.authService.forgotPassword(forgotDto.email);
    return {
      message:
        'Se o email existir, você receberá instruções para redefinir sua senha',
    };
  }

  @Post('password/reset')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Redefinir senha',
    description: 'Redefine a senha usando token válido',
  })
  async resetPassword(@Body() resetDto: PasswordResetDto) {
    const tokenValidation = await this.tokenService.validateAndConsumeToken(
      resetDto.token,
      TokenType.PASSWORD_RESET,
    );

    if (!tokenValidation.isValid || !tokenValidation.userId) {
      throw new UnauthorizedException('Token de reset inválido ou expirado');
    }

    await this.authService.resetPassword(
      tokenValidation.userId,
      resetDto.newPassword,
    );
    return { message: 'Senha redefinida com sucesso' };
  }

  @Post('email/verify')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verificar email',
    description: 'Verifica o email usando token enviado',
  })
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

    await this.authService.verifyEmail(tokenValidation.userId);
    return { message: 'Email verificado com sucesso' };
  }

  @Post('email/resend')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reenviar verificação de email',
    description: 'Reenvia email de verificação',
  })
  async resendVerification(@Body() resendDto: ResendVerificationDto) {
    await this.authService.resendEmailVerification(resendDto.email);
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
