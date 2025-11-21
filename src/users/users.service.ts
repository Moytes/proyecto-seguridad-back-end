import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { CryptoService } from '../crypto/crypto.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly cryptoService: CryptoService,
  ) {}

  async create(createUserDto: CreateUserDto) {
    const encryptedSensitiveData = this.cryptoService.encryptDataAtRest(
      createUserDto.sensitiveData,
    );
    const dataToSign = `${createUserDto.email}|${createUserDto.sensitiveData}`;
    const authoritySignature = this.cryptoService.signData(dataToSign);

    const user = this.userRepository.create({
      ...createUserDto,
      sensitiveData: encryptedSensitiveData, 
      authoritySignature: authoritySignature, 
    });

    return await this.userRepository.save(user);
  }

  async verifyIdentity(decryptedData: { email: string; rawSensitiveData: string }) {
    console.log('Verificando identidad para:', decryptedData.email);

    const user = await this.findOneByEmail(decryptedData.email);
    if (!user) {
      throw new NotFoundException('Cédula digital no encontrada en el registro nacional.');
    }

    const dataToVerify = `${decryptedData.email}|${decryptedData.rawSensitiveData}`;

    const isSignatureValid = this.cryptoService.verifySignature(
      dataToVerify,
      user.authoritySignature
    );

    if (!isSignatureValid) {
        return {
            status: 'ALERT',
            message: 'FALSIFICACIÓN DETECTADA: Los datos presentados no coinciden con la firma de la autoridad.',
            isValid: false
        };
    }

    return {
      status: 'SUCCESS',
      message: 'Cédula Auténtica. Verificada por la Autoridad.',
      isValid: true,
      timestamp: new Date().toISOString()
    };
  }

  async findAll() {
    return this.userRepository.find();
  }

  async findOne(id: string) {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    return user;
  }

  async findOneByEmail(email: string) {
    return this.userRepository.findOne({ where: { email } });
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    return this.userRepository.update(id, updateUserDto);
  }

  async remove(id: string) {
    return this.userRepository.delete(id);
  }
}