import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { CreateUserDto } from '../dto/create-user.dto';



export interface RefreshTokenStore {
  get(token: string): RefreshTokenData | undefined;
  set(token: string, data: RefreshTokenData): void;
  delete(token: string): void;
}

export interface RefreshTokenData {
  userId: string;
  expiresAt: Date;
}

export interface UserPayload {
  userId: string;
  username: string;
  sub?: string;
}

@Injectable()
export class AuthService {
  
  private refreshTokenStore: Map<string, RefreshTokenData> = new Map();

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async register(createUserDto: CreateUserDto) {
    try {
      const user = await this.usersService.create(createUserDto);
      return {
        message: 'User registered successfully',
        user
      };
    } catch (error) {
      if (error.code === 11000) {
        throw new ConflictException('Username or email already exists');
      }
      throw error;
    }
  }

  async getProfile(user: UserPayload) {
    return this.usersService.findOne(user.userId);
  }


  async refreshToken(refreshToken: string) {
    
    const storedToken = this.refreshTokenStore.get(refreshToken);
    
    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    
    if (storedToken.expiresAt < new Date()) {
      this.refreshTokenStore.delete(refreshToken);
      throw new UnauthorizedException('Refresh token expired');
    }
    
    
    const user = await this.usersService.findOne(storedToken.userId);
    const payload = { username: user.username, userId: storedToken.userId };
    
    
    const newRefreshToken = this.generateRefreshToken(storedToken.userId);
    
  
    this.refreshTokenStore.delete(refreshToken);
    
    return {
      access_token: this.jwtService.sign(payload),
      refresh_token: newRefreshToken,
    };
  }

  generateRefreshToken(userId: string): string {
    const token = Math.random().toString(36).substring(2, 15) + 
                 Math.random().toString(36).substring(2, 15);
    
    this.refreshTokenStore.set(token, {
      userId,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 dias
    });
    
    return token;
  }

 

  async validateUser(username: string, password: string) {
    return this.usersService.validateUser(username, password);
  }

  async login(user: any) {
    const payload = { username: user.username, userId: user._id };
    
    return {
      access_token: this.jwtService.sign(payload),
      refresh_token: this.generateRefreshToken(user._id),
    };
  }
}