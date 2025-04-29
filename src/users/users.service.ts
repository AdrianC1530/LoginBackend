import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from '../dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
  ) {}

  async findAll(page: number = 1, limit: number = 10): Promise<Partial<User>[]> {
    const skip = (page - 1) * limit;
    const users = await this.userModel.find().skip(skip).limit(limit).exec();
    
    // Return users without passwords
    return users.map(user => {
      const userObj = user.toObject();
      const { password, ...result } = userObj;
      return result;
    });
  }

  async findOne(id: string): Promise<Partial<User>> {
    const user = await this.userModel.findById(id).exec();
    if (!user) {
      throw new NotFoundException(`User with id ${id} not found`);
    }
    
    // Return user without password
    const userObj = user.toObject();
    const { password, ...result } = userObj;
    return result;
  }

  async findOneWithPassword(id: string): Promise<UserDocument> {
    const user = await this.userModel.findById(id).exec();
    if (!user) {
      throw new NotFoundException(`User with id ${id} not found`);
    }
    return user;
  }

  async findByUsername(username: string): Promise<User | null> {
    const user = await this.userModel.findOne({ username }).exec();
    if (!user) {
      return null;
    }
    return user.toObject();  // Retorna el objeto completo sin la contraseña
  }
  
  async removeByEmail(email: string): Promise<any> {
    const result = await this.userModel.deleteOne({ email }).exec();
    
    if (result.deletedCount === 0) {
      throw new NotFoundException(`User with email ${email} not found`);
    }
    
    return { message: 'User successfully deleted' };
  }
  
  

  async findByEmail(email: string): Promise<Partial<User> | null> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      return null;
    }
    const userObj = user.toObject();
    const { password, ...result } = userObj;
    return result;
  }

  async create(createUserDto: CreateUserDto): Promise<Partial<User>> {
    // Check if username or email already exists
    const existingUsername = await this.userModel.findOne({ username: createUserDto.username }).exec();
    if (existingUsername) {
      throw new ConflictException('Username already exists');
    }

    const existingEmail = await this.userModel.findOne({ email: createUserDto.email }).exec();
    if (existingEmail) {
      throw new ConflictException('Email already exists');
    }
    
    // Hash the password before storing
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    
    const newUser = new this.userModel({
      ...createUserDto,
      password: hashedPassword
    });
    
    const savedUser = await newUser.save();
    
    // Return user without password
    const userObj = savedUser.toObject();
    const { password, ...result } = userObj;
    return result;
  }

  async updatePassword(id: string, newPassword: string): Promise<void> {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    const updatedUser = await this.userModel
      .findByIdAndUpdate(id, { password: hashedPassword })
      .exec();
      
    if (!updatedUser) {
      throw new NotFoundException(`User with id ${id} not found`);
    }
  }

  async validateUser(username: string, password: string): Promise<any | null> {
    const user = await this.userModel.findOne({ username }).exec();
    
    if (user && await bcrypt.compare(password, user.password)) {
      const userObj = user.toObject();
      return {
        _id: userObj._id,
        username: userObj.username,
        email: userObj.email
      };
    }
    
    return null;
  }
}