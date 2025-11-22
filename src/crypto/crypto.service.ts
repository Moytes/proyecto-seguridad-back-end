import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs';

@Injectable()
export class CryptoService {
  private readonly algorithm = 'aes-256-cbc';
  private readonly masterKey: Buffer;
  private readonly serverPrivateKeyPath: string;
  private readonly serverPublicKeyPath: string;

  constructor(private configService: ConfigService) {
    const keyHex = this.configService.get<string>('AES_MASTER_KEY');
    const privateKeyPath = this.configService.get<string>('SERVER_PRIVATE_KEY_PATH');
    const publicKeyPath = this.configService.get<string>('SERVER_PUBLIC_KEY_PATH');

    if (!keyHex || !privateKeyPath || !publicKeyPath) {
      throw new Error('FATAL: Faltan configuraciones de seguridad en .env');
    }

    this.masterKey = Buffer.from(keyHex, 'hex');
    this.serverPrivateKeyPath = privateKeyPath;
    this.serverPublicKeyPath = publicKeyPath;
  }

  encryptDataAtRest(text: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, this.masterKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
  }

  decryptDataAtRest(text: string): string {
    const [ivHex, encryptedHex] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(this.algorithm, this.masterKey, iv);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  signData(data: string): string {
    try {
      const privateKey = fs.readFileSync(this.serverPrivateKeyPath, 'utf8');
      const sign = crypto.createSign('SHA256');
      sign.update(data);
      sign.end();
      const signature = sign.sign(privateKey, 'hex');
      return signature;
    } catch (error) {
      console.error("Error firmando datos:", error);
      throw new InternalServerErrorException('Error al generar firma de autoridad');
    }
  }

  verifySignature(data: string, signature: string): boolean {
    try {
      const publicKey = fs.readFileSync(this.serverPublicKeyPath, 'utf8');
      const verify = crypto.createVerify('SHA256');
      verify.update(data);
      verify.end();
      return verify.verify(publicKey, signature, 'hex');
    } catch (error) {
      return false;
    }
  }

  hybridDecrypt(packageData: { encryptedKey: string; encryptedData: string; iv: string }) {
    try {
      const privateKeyPem = fs.readFileSync(this.serverPrivateKeyPath, 'utf8');
      
      const symmetricKeyBuffer = crypto.privateDecrypt(
        { 
          key: privateKeyPem, 
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        Buffer.from(packageData.encryptedKey, 'base64'),
      );

      const decipher = crypto.createDecipheriv(
        this.algorithm,
        symmetricKeyBuffer,
        Buffer.from(packageData.iv, 'hex'),
      );

      let decrypted = decipher.update(packageData.encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return JSON.parse(decrypted);
    } catch (error) {
      console.error("Error CRÍTICO en descifrado híbrido:", error);
      throw new InternalServerErrorException('Fallo al descifrar paquete híbrido. Revisa los logs del servidor.');
    }
  }
  
}