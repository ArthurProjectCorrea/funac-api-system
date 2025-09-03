import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}

@Injectable()
export class RefreshJwtAuthGuard extends AuthGuard('refresh-jwt') {}
