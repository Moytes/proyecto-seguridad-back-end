import { IsString, IsNotEmpty } from 'class-validator';

export class HybridPayloadDto {
  @IsString()
  @IsNotEmpty()
  encryptedKey: string;

  @IsString()
  @IsNotEmpty()
  encryptedData: string;

  @IsString()
  @IsNotEmpty()
  iv: string;
}