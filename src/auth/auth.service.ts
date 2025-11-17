import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { User, UserDocument } from './models/users.schema';

@Injectable()
export class AuthService {
  private privateKey = fs.readFileSync('private.key');
  private publicKey = fs.readFileSync('public.key');

  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async register(login: string, password: string) {
    const existing = await this.userModel.findOne({ login });
    if (existing) throw new Error('Користувач вже існує');

    const user = new this.userModel({ login, password });
    await user.save();

    return this.createTokens(user);
  }

  async login(login: string, password: string) {
    const user = await this.userModel.findOne({ login });
    if (!user) throw new UnauthorizedException('Невірний логін або пароль');

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new UnauthorizedException('Невірний логін або пароль');

    return this.createTokens(user);
  }

  refresh(refreshToken: string) {
    try {
      const payload = this.verifyToken(refreshToken);
      const accessToken = this.createAccessToken(payload);
      return { refreshToken, accessToken };
    } catch (e) {
      throw new UnauthorizedException('Невірний refresh token');
    }
  }

  private createAccessToken(payload: any) {
    const accessToken = jwt.sign(
      { sub: payload.sub, login: payload.login, roles: payload.roles },
      this.privateKey,
      { algorithm: 'RS256', expiresIn: '15m' },
    );
    return accessToken;
  }
  private createTokens(user: UserDocument) {
    const payload = { sub: user._id, login: user.login, roles: user.roles };

    const accessToken = jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: '15m',
    });

    const refreshToken = jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: '30d',
    });

    return { accessToken, refreshToken };
  }

  verifyToken(token: string) {
    return jwt.verify(token, this.publicKey, { algorithms: ['RS256'] });
  }
}
