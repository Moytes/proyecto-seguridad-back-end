import { Controller, Post, Body, Res, HttpStatus, UseGuards } from '@nestjs/common';
import type { Response } from 'express'; 
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(
    @Body() signInDto: { email: string; password: string }, 
    @Res({ passthrough: true }) response: Response 
  ) {
    const user = await this.authService.validateUser(signInDto.email, signInDto.password);
    if (!user) {
        response.status(HttpStatus.UNAUTHORIZED).send({ message: 'Credenciales incorrectas' });
        return;
    }

    const { accessToken, user: userData } = await this.authService.login(user);

    response.setHeader('Set-Cookie', this.authService.getCookieForJwt(accessToken));

    return {
      message: 'Login exitoso',
      user: userData
    };
  }

  @Post('logout')
  async logout(@Res({ passthrough: true }) response: Response) {
    response.setHeader('Set-Cookie', this.authService.getCookieForLogout());
    return { message: 'Sesión cerrada correctamente' };
  }
}