import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.usersService.findOneByEmail(email);
    if (user && (await user.validatePassword(pass))) {
      const { password, sensitiveData, currentRefreshToken, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user.id };
    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      user
    };
  }

  getCookieForJwt(token: string) {

    return `Authentication=${token}; HttpOnly; Path=/; Max-Age=900; SameSite=Strict`; 
  }
  
  getCookieForLogout() {
    return `Authentication=; HttpOnly; Path=/; Max-Age=0`;
  }
}