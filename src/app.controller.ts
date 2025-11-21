import { Controller, Get, Post, Body } from '@nestjs/common';
import { AppService } from './app.service';
import { CryptoService } from './crypto/crypto.service';
import { HybridPayloadDto } from './users/dto/hybrid-payload.dto';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly cryptoService: CryptoService 
  ) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Post('secure-data')
  async receiveSecureData(@Body() payload: HybridPayloadDto) {
    const decryptedJson = this.cryptoService.hybridDecrypt(payload);
    console.log("Datos Híbridos Recibidos y Descifrados:", decryptedJson);
    return { 
      message: 'Datos recibidos correctamente bajo protocolo híbrido',
      verification: 'Descifrado exitoso en servidor'
    };
  }
}