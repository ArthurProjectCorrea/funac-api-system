import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Email deve ter um formato válido' })
  email: string;

  @IsString({ message: 'Senha é obrigatória' })
  @MinLength(1, { message: 'Senha não pode estar vazia' })
  password: string;
}

export class MfaVerifyDto {
  @IsString({ message: 'Código MFA é obrigatório' })
  @MinLength(6, { message: 'Código MFA deve ter pelo menos 6 caracteres' })
  code: string;

  @IsString({ message: 'Session ID é obrigatório' })
  sessionId: string;
}

export class RefreshTokenDto {
  @IsString({ message: 'Refresh token é obrigatório' })
  refreshToken: string;
}

export class LogoutDto {
  @IsString({ message: 'Refresh token é obrigatório' })
  refreshToken: string;
}

export class PasswordResetRequestDto {
  @IsEmail({}, { message: 'Email deve ter um formato válido' })
  email: string;
}

export class PasswordResetDto {
  @IsString({ message: 'Token é obrigatório' })
  token: string;

  @IsString({ message: 'Nova senha é obrigatória' })
  @MinLength(12, { message: 'Senha deve ter pelo menos 12 caracteres' })
  newPassword: string;
}

export class EmailVerifyDto {
  @IsString({ message: 'Token é obrigatório' })
  token: string;
}

export class ResendVerificationDto {
  @IsEmail({}, { message: 'Email deve ter um formato válido' })
  email: string;
}
