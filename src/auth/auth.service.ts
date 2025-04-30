// src/auth/auth.service.ts
import { Injectable, UnauthorizedException, ConflictException, InternalServerErrorException } from '@nestjs/common';
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
      // Validar datos de entrada
      if (!createUserDto.username || !createUserDto.email || !createUserDto.password) {
        throw new ConflictException('Username, email y password son requeridos');
      }
      
      // Verificar si el usuario ya existe
      const existingUser = await this.usersService.findByUsername(createUserDto.username);
      if (existingUser) {
        throw new ConflictException('El nombre de usuario ya existe');
      }
      
      // Verificar si el email ya existe
      const existingEmail = await this.usersService.findByEmail(createUserDto.email);
      if (existingEmail) {
        throw new ConflictException('El email ya está registrado');
      }
      
      // Crear el usuario
      const user = await this.usersService.create(createUserDto);
      
      return {
        message: 'Usuario registrado exitosamente',
        user
      };
    } catch (error) {
      // Si ya es un error de NestJS, lo propagamos
      if (error.status) {
        throw error;
      }
      
      // Si es un error de MongoDB de duplicación (código 11000)
      if (error.code === 11000) {
        throw new ConflictException('El nombre de usuario o email ya existe');
      }
      
      // Para cualquier otro error
      console.error('Error en registro:', error);
      throw new InternalServerErrorException('Error al registrar el usuario: ' + error.message);
    }
  }
  
  async getProfile(user: UserPayload) {
    try {
      return await this.usersService.findOne(user.userId);
    } catch (error) {
      console.error('Error al obtener perfil:', error);
      throw error;
    }
  }
  
  async refreshToken(refreshToken: string) {
    try {
      const storedToken = this.refreshTokenStore.get(refreshToken);
      
      if (!storedToken) {
        throw new UnauthorizedException('Token de actualización inválido');
      }
      
      if (storedToken.expiresAt < new Date()) {
        this.refreshTokenStore.delete(refreshToken);
        throw new UnauthorizedException('Token de actualización expirado');
      }
      
      const user = await this.usersService.findOne(storedToken.userId);
      const payload = { username: user.username, userId: storedToken.userId };
      
      const newRefreshToken = this.generateRefreshToken(storedToken.userId);
      
      this.refreshTokenStore.delete(refreshToken);
      
      return {
        access_token: this.jwtService.sign(payload),
        refresh_token: newRefreshToken,
      };
    } catch (error) {
      console.error('Error en refreshToken:', error);
      throw error;
    }
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
    try {
      return await this.usersService.validateUser(username, password);
    } catch (error) {
      console.error('Error en validateUser:', error);
      throw new UnauthorizedException('Credenciales inválidas');
    }
  }
  
  async login(user: any) {
    try {
      const payload = { username: user.username, userId: user._id };
      
      return {
        access_token: this.jwtService.sign(payload),
        refresh_token: this.generateRefreshToken(user._id),
      };
    } catch (error) {
      console.error('Error en login:', error);
      throw new InternalServerErrorException('Error al iniciar sesión: ' + error.message);
    }
  }
}