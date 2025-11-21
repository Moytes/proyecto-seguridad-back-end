import { Entity, PrimaryGeneratedColumn, Column, BeforeInsert, BeforeUpdate } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { Exclude } from 'class-transformer'; 

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude() 
  password: string;

  @Column({ name: 'sensitive_data', type: 'text' })
  sensitiveData: string;

  @Column({ name: 'authority_signature', type: 'text', nullable: true })
  authoritySignature: string;

  @Column({ name: 'public_key', type: 'text', nullable: true })
  publicKey: string;

  @Column({ default: true })
  isActive: boolean;

  @Column({ name: 'current_refresh_token', nullable: true })
  @Exclude() 
  currentRefreshToken: string;

  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    if (this.password && !this.password.startsWith('$2b$')) {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
    }
  }
  
  async validatePassword(plainPassword: string): Promise<boolean> {
    return await bcrypt.compare(plainPassword, this.password);
  }
}