# Sistema de Identidad Digital y Seguridad Criptográfica (Backend)

Este repositorio contiene la implementación del Backend para el sistema de Gestión de Identidad Digital. El proyecto ha sido diseñado bajo el principio de **Defensa en Profundidad**, implementando cuatro capas de seguridad independientes para garantizar la confidencialidad, integridad y disponibilidad de la información.

## Tabla de Contenidos

- [Arquitectura de Seguridad](#arquitectura-de-seguridad)
- [Stack Tecnológico](#stack-tecnológico)
- [Implementación de Código Crítico](#implementación-de-código-crítico)
- [Instalación y Configuración](#instalación-y-configuración)

## Arquitectura de Seguridad

El sistema cumple rigurosamente con los siguientes estándares criptográficos:

| Capa de Seguridad | Tecnología / Algoritmo | Propósito |
| :--- | :--- | :--- |
| **Autenticación** | Bcrypt (Salt Rounds: 10) | Protección de credenciales ante ataques de fuerza bruta y Rainbow Tables. |
| **Datos en Reposo** | AES-256-CBC | Confidencialidad de datos sensibles (PII) en la base de datos. |
| **Integridad** | RSA-2048 + SHA-256 | Firma digital para garantizar autenticidad y no repudio por parte de la autoridad. |
| **Datos en Tránsito** | Híbrido (RSA + AES) | Tunneling seguro a nivel de aplicación (Application Layer Security). |

## Stack Tecnológico

*   **NestJS**: Framework de Node.js para el backend.
*   **TypeORM**: ORM para la base de datos.
*   **MySQL**: Base de datos relacional.
*   **Passport + JWT**: Manejo de autenticación y sesiones.

## Implementación de Código Crítico

A continuación se documenta la lógica central de seguridad implementada en el `CryptoService` y las Entidades.

### 1. Hashing de Contraseñas (Bcrypt)

**Ubicación:** `src/users/entities/user.entity.ts`

Utilizamos Entity Subscribers (`@BeforeInsert`, `@BeforeUpdate`) para asegurar que la contraseña nunca toque la capa de persistencia en texto plano.

```typescript
@BeforeInsert()
@BeforeUpdate()
async hashPassword() {
  // Verificamos si ya está hasheada para evitar doble hash
  if (this.password && !this.password.startsWith('$2b$')) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
}
```

### 2. Cifrado de Datos en Reposo (AES-256)

**Ubicación:** `src/crypto/crypto.service.ts`

Se utiliza un Vector de Inicialización (IV) aleatorio para cada registro. El IV se concatena al dato cifrado, asegurando alta entropía.

```typescript
encryptDataAtRest(text: string): string {
  const iv = crypto.randomBytes(16); // IV Único por registro
  const cipher = crypto.createCipheriv('aes-256-cbc', this.masterKey, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Formato de almacenamiento: IV:DATOCIFRADO
  return `${iv.toString('hex')}:${encrypted}`;
}
```

### 3. Firma Digital (RSA-SHA256)

**Ubicación:** `src/crypto/crypto.service.ts`

El sistema actúa como Autoridad Certificadora. Firma un hash de los datos del usuario usando la llave privada del servidor.

```typescript
signData(data: string): string {
  // Se carga la llave privada del servidor
  const privateKey = fs.readFileSync(this.serverPrivateKeyPath, 'utf8');
  
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  sign.end();
  
  // Genera la firma en formato Hexadecimal
  return sign.sign(privateKey, 'hex');
}
```

### 4. Descifrado Híbrido (RSA + AES)

**Ubicación:** `src/crypto/crypto.service.ts`

Implementación del protocolo de Defensa en Profundidad. El servidor recibe un paquete con una llave simétrica efímera cifrada asimétricamente.

```typescript
hybridDecrypt(packageData: { encryptedKey: string; encryptedData: string; iv: string }) {
  // PASO 1: Descifrar la Llave Simétrica Efímera usando la Llave Privada (RSA)
  const privateKeyPem = fs.readFileSync(this.serverPrivateKeyPath, 'utf8');
  
  const symmetricKeyBuffer = crypto.privateDecrypt(
    { 
      key: privateKeyPem, 
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Padding seguro OAEP
      oaepHash: 'sha256'
    },
    Buffer.from(packageData.encryptedKey, 'base64'),
  );

  // PASO 2: Descifrar la Data Real usando la Llave Simétrica recuperada (AES)
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    symmetricKeyBuffer,
    Buffer.from(packageData.iv, 'hex'),
  );

  let decrypted = decipher.update(packageData.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return JSON.parse(decrypted);
}
```

## 🛠 Instalación y Configuración

### Prerrequisitos

*   Node.js v18+
*   MySQL 8.0
*   OpenSSL (para generación de llaves)

### Pasos

1.  **Clonar repositorio e instalar dependencias:**

    ```bash
    git clone <URL_DEL_REPO>
    cd proyecto-seguridad-back-end
    npm install
    ```

2.  **Generación de Llaves Asimétricas (RSA):**
    Es necesario generar el par de llaves en la carpeta raíz para las firmas y el cifrado híbrido.

    ```bash
    mkdir keys
    openssl genrsa -out keys/private.pem 2048
    openssl rsa -in keys/private.pem -pubout -out keys/public.pem
    ```

3.  **Configuración de Entorno (.env):**
    Crear un archivo `.env` en la raíz con las siguientes variables:

    ```env
    DB_HOST=localhost
    DB_PORT=3306
    DB_USERNAME=root
    DB_PASSWORD=tu_password
    DB_DATABASE=security_challenge_db

    JWT_SECRET=Secreto_JWT_Para_Sesiones

    # Llave Maestra AES (32 bytes / 64 hex chars)
    AES_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

    SERVER_PRIVATE_KEY_PATH=./keys/private.pem
    SERVER_PUBLIC_KEY_PATH=./keys/public.pem
    ```

4.  **Ejecutar en desarrollo:**

    ```bash
    npm run start:dev
    ```

## Endpoints de la API

*(Documentación de endpoints pendiente)*

## Guía de Verificación (Pruebas)

*(Guía de pruebas pendiente)*
