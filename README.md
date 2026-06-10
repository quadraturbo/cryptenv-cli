# cryptenv-cli

Secrets manager for `.env` files — encrypted at rest with AES-256-GCM, keys bound to the OS keyring. No plaintext ever touches disk after encryption.

---

## Table of Contents

- [Español](#español)
  - [Descripción técnica](#descripción-técnica)
  - [Requisitos](#requisitos)
  - [Instalación](#instalación)
  - [Uso](#uso)
  - [Consideraciones de seguridad](#consideraciones-de-seguridad)
  - [Licencia](#licencia)
- [English](#english)
  - [Technical Description](#technical-description)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Security Considerations](#security-considerations)
  - [License](#license)

---

# Español

## Descripción técnica

`cryptenv-cli` es una herramienta de línea de comandos escrita en Python que cifra archivos `.env` mediante **AES-256-GCM** y vincula las claves maestras al administrador de credenciales nativo del sistema operativo: **Windows Credential Manager** en Windows y **Secret Service** (vía D-Bus) en Linux. El texto plano nunca regresa al disco: en el subcomando `run`, el descifrado ocurre íntegramente en memoria y el buffer se sobreescribe con ceros antes de que el proceso hijo termine.

### Por qué es necesario

Los archivos `.env` concentran los secretos más críticos de un proyecto —tokens de API, cadenas de conexión a bases de datos, claves privadas— y son incluidos accidentalmente en commits con una frecuencia inaceptable. Las mitigaciones habituales trasladan el problema:

- `.gitignore` falla ante un `git add -f` accidental o ante un cambio de directorio.
- Variables de entorno manuales no se versionan y se pierden al cambiar de máquina.
- Cifrado simétrico con clave embebida en el repositorio anula cualquier beneficio de seguridad.

`cryptenv-cli` garantiza que **la clave de cifrado nunca reside en disco en texto plano**: se almacena exclusivamente en el llavero del sistema, protegida por las credenciales del usuario activo. El archivo `.env.{env}.enc` puede incluirse en Git sin riesgo, ya que el ciphertext es inútil sin acceso al llavero del sistema operativo.

### Arquitectura de seguridad

| Capa | Detalle de implementación |
|------|--------------------------|
| Algoritmo de cifrado | AES-256-GCM (AEAD), implementado via `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| Tamaño de clave | 256 bits, generada con `AESGCM.generate_key(bit_length=256)` |
| Nonce / IV | 96 bits (`NONCE_SIZE = 12` bytes), generado con `secrets.token_bytes(12)` para cada operación de cifrado |
| GCM tag | 128 bits; cualquier modificación del ciphertext lanza `InvalidTag` antes del descifrado |
| AAD (datos autenticados) | Constante `b"cryptenv/aes-256-gcm/v1"` vinculada a la versión del formato del contenedor |
| Aislamiento por entorno | La clave del keyring se indexa por `{project_dir_abs}::{env_name}`, haciendo cada entorno (`dev`, `staging`, `prod`) completamente independiente |
| Formato del contenedor | `MAGIC(5B) + NONCE(12B) + CIPHERTEXT+TAG` con cabecera `b"CENV1"` para detección de formato corrupto |
| Almacenamiento de claves | `keyring` con backend nativo: DPAPI en Windows, libsecret/KWallet en Linux |
| Validación de nombre de entorno | Regex `[A-Za-z0-9][A-Za-z0-9._-]*` para prevenir inyección en rutas del keyring |

### Flujo de operación

```
.env (plaintext)
      │
      ▼
  encrypt ──► AES-256-GCM ──► .env.{env}.enc  (puede ir a Git)
                   │
                   └──► clave maestra ──► OS Keyring (nunca en disco)

.env.{env}.enc
      │
      ▼
   run ──► OS Keyring ──► descifrado en memoria ──► subprocess env vars
                                    │
                                    └──► buffer sobreescrito con \x00
```

---

## Requisitos

**Sistema operativo:**
- Windows 10 / 11
- Linux con soporte para Secret Service: GNOME Keyring o KWallet (requiere sesión D-Bus activa)

**Python:**
- Python **3.8** o superior (se requiere `from __future__ import annotations` y `typing.Final`)

**Dependencias de Python:**

| Paquete | Versión mínima recomendada | Uso |
|---------|---------------------------|-----|
| `cryptography` | >= 41.0 | `AESGCM`, `InvalidTag` |
| `keyring` | >= 24.0 | Abstracción del almacén de credenciales nativo |

**Dependencias del sistema (solo Linux):**

```bash
# Debian / Ubuntu
sudo apt install python3-secretstorage

# Fedora / RHEL
sudo dnf install python3-secretstorage

# Arch Linux
sudo pacman -S python-secretstorage
```

---

## Instalación

### Desde PyPI

```bash
pip install cryptenv-cli
```

### Desde el código fuente

```bash
git clone https://github.com/quadraturbo/cryptenv-cli.git
cd cryptenv-cli
pip install -e .
```

### Instalación manual de dependencias únicamente

```bash
pip install cryptography keyring
```

### Verificación de la instalación

```bash
python cryptenv.py --help
```

Salida esperada:

```
usage: cryptenv [-h] {encrypt,run} ...

Secretos .env cifrados en reposo, inyectados solo en memoria.
```

---

## Uso

### Subcomando `encrypt`

Cifra un archivo `.env` existente y elimina el original de forma segura.

```bash
python cryptenv.py encrypt <archivo.env> [--env ENTORNO]
```

**Argumentos:**

| Argumento | Requerido | Descripción |
|-----------|-----------|-------------|
| `file` | Sí | Ruta al archivo `.env` a cifrar |
| `--env` | No | Nombre lógico del entorno (defecto: `dev`) |

**Ejemplos:**

```bash
# Cifrar .env para el entorno de desarrollo (defecto)
python cryptenv.py encrypt .env

# Cifrar .env para producción
python cryptenv.py encrypt .env --env production

# Cifrar un .env ubicado en otra ruta
python cryptenv.py encrypt /srv/myapp/.env --env staging
```

**Resultado:** se genera `.env.{env}.enc` en el mismo directorio. El archivo `.env` original se sobreescribe con bytes aleatorios y se elimina. La clave AES-256 se almacena automáticamente en el keyring del sistema operativo bajo la cuenta `{directorio_absoluto}::{entorno}`.

---

### Subcomando `run`

Descifra el archivo `.env.{env}.enc` en memoria e inyecta las variables como variables de entorno del proceso hijo especificado.

```bash
python cryptenv.py run [--env ENTORNO] [-f ARCHIVO.enc] -- <comando> [args...]
```

**Argumentos:**

| Argumento | Requerido | Descripción |
|-----------|-----------|-------------|
| `--env` | No | Entorno a inyectar (defecto: `dev`). Determina el archivo `.env.{env}.enc` y la clave del keyring |
| `-f`, `--file` | No | Ruta explícita al contenedor cifrado (anula el derivado de `--env`) |
| `command` | Sí | Comando a ejecutar, separado por `--` |

**Ejemplos:**

```bash
# Lanzar la aplicación con variables de producción
python cryptenv.py run --env production -- python app.py

# Ejecutar migraciones con variables de staging
python cryptenv.py run --env staging -- python manage.py migrate

# Usar un archivo cifrado con ruta explícita
python cryptenv.py run -f /secrets/.env.prod.enc --env production -- uvicorn main:app

# Ejecutar un comando npm con variables de desarrollo
python cryptenv.py run --env dev -- npm run start
```

**Notas sobre el separador `--`:** el doble guion es obligatorio para que `argparse` no interprete los argumentos del comando hijo como flags de `cryptenv`.

---

### Formato del archivo `.env` soportado

El parser interno soporta la sintaxis dotenv estándar:

```dotenv
# Comentario ignorado
DATABASE_URL=postgres://user:pass@localhost/db
API_KEY="mi_clave_con_espacios"
TOKEN='otro_valor'
export SECRET=valor_con_export
```

- Comentarios con `#`
- Prefijo `export` (ignorado)
- Valores con comillas simples o dobles (eliminadas al parsear)
- BOM UTF-8 (añadido por editores de Windows) tolerado via `utf-8-sig`

---

## Consideraciones de seguridad

### Borrado seguro en disco

Tras el cifrado, `_secure_delete()` sobreescribe el archivo `.env` original con `secrets.token_bytes(size)` —bytes criptográficamente aleatorios— antes de su eliminación. `os.fsync(fh.fileno())` se invoca explícitamente para forzar el vaciado de los buffers del sistema operativo al soporte físico, reduciendo la ventana de recuperación forense a nivel de bloque.

**Limitaciones conocidas:**
- En **SSD con wear-leveling** (NAND flash), el controlador puede redirigir las escrituras a celdas distintas, haciendo que los datos originales persistan en bloques no asignados hasta el siguiente ciclo de garbage collection del firmware.
- En **sistemas de archivos con journaling** (ext4, NTFS, APFS), el journal puede preservar una copia temporal del contenido original.
- La garantía de seguridad real proviene de no escribir texto plano después del primer cifrado, combinada con cifrado de disco completo (**BitLocker** en Windows, **LUKS** en Linux).

### Limpieza de memoria

El texto plano se mantiene en un `bytearray` mutable (no en `bytes` inmutable) para permitir su sobreescritura explícita:

```python
# Inmediatamente tras cifrar o tras lanzar el proceso hijo:
plaintext[:] = b"\x00" * len(plaintext)
```

En `run()`, los diccionarios de variables secretas también se limpian:

```python
secret_env.clear()
child_env.clear()
secret_env = None
child_env = None
gc.collect()
```

`gc.collect()` fuerza un ciclo completo del recolector de basura de CPython para liberar los objetos desreferenciados lo antes posible. **Limitación:** CPython no ofrece garantías de borrado inmediato e irrecuperable de páginas de memoria; el sistema operativo puede haber paginado los datos a disco si hubo presión de memoria. En entornos de alta sensibilidad, considerar el uso de `mlock(2)` para fijar páginas de memoria (no paginables).

### Gestión de privilegios UAC / root

**Windows:** `check_keyring_privileges()` abre el token de seguridad del proceso via `advapi32.OpenProcessToken` con `TOKEN_QUERY`. Si UAC u otra política de grupo bloquea el acceso, el script aborta antes de cualquier operación criptográfica. No se solicita ni requiere elevación de privilegios en ningún caso.

**Linux:** Se verifica que `os.getuid() == os.geteuid()`. Si difieren (binario con bit `setuid` activo), el script aborta para evitar mezclar almacenes de credenciales de usuarios distintos. Si el proceso se ejecuta como `root` (UID 0), se emite una advertencia y la clave se vincula al keyring de root, que es diferente al keyring del usuario interactivo.

### Validación de formato del contenedor

Antes de intentar el descifrado, se verifica:
1. Que el archivo comience con la cabecera `b"CENV1"` (magic bytes).
2. Que el tamaño mínimo sea `5 + 12 + 16` bytes (MAGIC + NONCE + GCM_TAG mínimo).

Si cualquiera de estas verificaciones falla, el error se comunica antes de acceder al keyring, evitando fugas de información sobre la existencia o no de una clave.

### Recomendaciones de despliegue

- Añadir `*.enc` a `.gitignore` si los archivos cifrados contienen datos de producción con alta criticidad, aunque el ciphertext no expone secretos sin la clave del keyring.
- En entornos CI/CD, usar variables de entorno del sistema del runner para inyectar directamente las variables, en lugar de distribuir archivos `.enc` en el repositorio.
- Rotar claves periódicamente: eliminar la entrada del keyring manualmente y volver a ejecutar `encrypt` para regenerar la clave maestra.

---

## Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulte el archivo [`LICENSE`](./LICENSE) para conocer los términos completos.

---
---

# English

## Technical Description

`cryptenv-cli` is a command-line tool written in Python that encrypts `.env` files using **AES-256-GCM** and binds the master keys to the native OS credential store: **Windows Credential Manager** on Windows and **Secret Service** (via D-Bus) on Linux. Plaintext never returns to disk: in the `run` subcommand, decryption occurs entirely in memory and the buffer is overwritten with zeros before the child process terminates.

### Why It Is Necessary

`.env` files concentrate the most critical project secrets — API tokens, database connection strings, private keys — and are accidentally committed to version control at an unacceptable frequency. Common mitigations shift the problem rather than solving it:

- `.gitignore` fails against an accidental `git add -f` or a directory change.
- Manual environment variables are not versioned and are lost when switching machines.
- Symmetric encryption with an embedded key in the repository nullifies any security benefit.

`cryptenv-cli` ensures that **the encryption key never resides on disk in plaintext**: it is stored exclusively in the system keyring, protected by the active user's credentials. The `.env.{env}.enc` file can be safely included in Git, as the ciphertext is useless without access to the OS keyring.

### Security Architecture

| Layer | Implementation Detail |
|-------|-----------------------|
| Encryption algorithm | AES-256-GCM (AEAD), implemented via `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| Key size | 256 bits, generated with `AESGCM.generate_key(bit_length=256)` |
| Nonce / IV | 96 bits (`NONCE_SIZE = 12` bytes), generated with `secrets.token_bytes(12)` per encryption operation |
| GCM tag | 128 bits; any ciphertext modification raises `InvalidTag` before decryption |
| AAD (authenticated data) | Constant `b"cryptenv/aes-256-gcm/v1"` bound to the container format version |
| Per-environment isolation | Keyring key indexed by `{abs_project_dir}::{env_name}`, making each environment (`dev`, `staging`, `prod`) fully independent |
| Container format | `MAGIC(5B) + NONCE(12B) + CIPHERTEXT+TAG` with header `b"CENV1"` for corrupt format detection |
| Key storage | `keyring` with native backend: DPAPI on Windows, libsecret/KWallet on Linux |
| Environment name validation | Regex `[A-Za-z0-9][A-Za-z0-9._-]*` to prevent injection into keyring paths |

### Operation Flow

```
.env (plaintext)
      │
      ▼
  encrypt ──► AES-256-GCM ──► .env.{env}.enc  (safe to commit)
                   │
                   └──► master key ──► OS Keyring (never on disk)

.env.{env}.enc
      │
      ▼
   run ──► OS Keyring ──► in-memory decryption ──► subprocess env vars
                                    │
                                    └──► buffer overwritten with \x00
```

---

## Requirements

**Operating System:**
- Windows 10 / 11
- Linux with Secret Service support: GNOME Keyring or KWallet (active D-Bus session required)

**Python:**
- Python **3.8** or higher (`from __future__ import annotations` and `typing.Final` required)

**Python dependencies:**

| Package | Minimum recommended version | Purpose |
|---------|----------------------------|---------|
| `cryptography` | >= 41.0 | `AESGCM`, `InvalidTag` |
| `keyring` | >= 24.0 | Native credential store abstraction |

**System dependencies (Linux only):**

```bash
# Debian / Ubuntu
sudo apt install python3-secretstorage

# Fedora / RHEL
sudo dnf install python3-secretstorage

# Arch Linux
sudo pacman -S python-secretstorage
```

---

## Installation

### From PyPI

```bash
pip install cryptenv-cli
```

### From source

```bash
git clone https://github.com/quadraturbo/cryptenv-cli.git
cd cryptenv-cli
pip install -e .
```

### Manual dependency installation only

```bash
pip install cryptography keyring
```

### Verify installation

```bash
python cryptenv.py --help
```

Expected output:

```
usage: cryptenv [-h] {encrypt,run} ...

Secretos .env cifrados en reposo, inyectados solo en memoria.
```

---

## Usage

### Subcommand `encrypt`

Encrypts an existing `.env` file and securely deletes the original.

```bash
python cryptenv.py encrypt <file.env> [--env ENVIRONMENT]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `file` | Yes | Path to the `.env` file to encrypt |
| `--env` | No | Logical environment name (default: `dev`) |

**Examples:**

```bash
# Encrypt .env for the development environment (default)
python cryptenv.py encrypt .env

# Encrypt .env for production
python cryptenv.py encrypt .env --env production

# Encrypt a .env located at a different path
python cryptenv.py encrypt /srv/myapp/.env --env staging
```

**Result:** `.env.{env}.enc` is created in the same directory. The original `.env` file is overwritten with random bytes and deleted. The AES-256 key is automatically stored in the OS keyring under the account `{absolute_directory}::{environment}`.

---

### Subcommand `run`

Decrypts `.env.{env}.enc` in memory and injects the variables as environment variables into the specified child process.

```bash
python cryptenv.py run [--env ENVIRONMENT] [-f FILE.enc] -- <command> [args...]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `--env` | No | Environment to inject (default: `dev`). Determines the `.env.{env}.enc` file and the keyring key |
| `-f`, `--file` | No | Explicit path to the encrypted container (overrides the one derived from `--env`) |
| `command` | Yes | Command to execute, separated by `--` |

**Examples:**

```bash
# Launch the application with production variables
python cryptenv.py run --env production -- python app.py

# Run database migrations with staging variables
python cryptenv.py run --env staging -- python manage.py migrate

# Use an encrypted file with an explicit path
python cryptenv.py run -f /secrets/.env.prod.enc --env production -- uvicorn main:app

# Run an npm command with development variables
python cryptenv.py run --env dev -- npm run start
```

**Note on `--` separator:** the double dash is mandatory so that `argparse` does not interpret child command arguments as `cryptenv` flags.

---

### Supported `.env` file format

The internal parser supports standard dotenv syntax:

```dotenv
# Comment — ignored
DATABASE_URL=postgres://user:pass@localhost/db
API_KEY="value with spaces"
TOKEN='another_value'
export SECRET=value_with_export_prefix
```

- `#` comments
- `export` prefix (stripped during parsing)
- Single or double-quoted values (quotes removed on parse)
- UTF-8 BOM (added by Windows editors) tolerated via `utf-8-sig`

---

## Security Considerations

### Secure disk erasure

After encryption, `_secure_delete()` overwrites the original `.env` file with `secrets.token_bytes(size)` — cryptographically random bytes — before deletion. `os.fsync(fh.fileno())` is explicitly called to flush OS buffers to the physical storage medium, narrowing the forensic recovery window at block level.

**Known limitations:**
- On **SSDs with wear-leveling** (NAND flash), the controller may redirect writes to different cells, leaving original data in unallocated blocks until the next firmware garbage collection cycle.
- On **journaling file systems** (ext4, NTFS, APFS), the journal may preserve a temporary copy of the original content.
- Real security guarantees come from never writing plaintext after the first encryption, combined with full-disk encryption (**BitLocker** on Windows, **LUKS** on Linux).

### Memory cleanup

Plaintext is held in a mutable `bytearray` (not immutable `bytes`) to allow explicit overwriting:

```python
# Immediately after encrypting or after launching the child process:
plaintext[:] = b"\x00" * len(plaintext)
```

In `run()`, secret variable dictionaries are also cleaned:

```python
secret_env.clear()
child_env.clear()
secret_env = None
child_env = None
gc.collect()
```

`gc.collect()` forces a full CPython garbage collector cycle to release dereferenced objects as early as possible. **Limitation:** CPython provides no guarantees of immediate, irrecoverable memory page erasure; the OS may have paged data to disk under memory pressure. In high-sensitivity environments, consider using `mlock(2)` to pin memory pages (non-pageable).

### UAC / root privilege management

**Windows:** `check_keyring_privileges()` opens the process security token via `advapi32.OpenProcessToken` with `TOKEN_QUERY`. If UAC or a Group Policy blocks access, the script aborts before any cryptographic operation. No privilege elevation is requested or required under any circumstances.

**Linux:** Verifies that `os.getuid() == os.geteuid()`. If they differ (binary with active `setuid` bit), the script aborts to avoid mixing credential stores from different users. If the process runs as `root` (UID 0), a warning is emitted and the key is bound to the root keyring, which is distinct from the interactive user's keyring.

### Container format validation

Before attempting decryption, the following is verified:
1. The file begins with the header `b"CENV1"` (magic bytes).
2. The minimum size is `5 + 12 + 16` bytes (MAGIC + NONCE + minimum GCM_TAG).

If either check fails, the error is reported before accessing the keyring, preventing information leakage about whether a key exists.

### Deployment recommendations

- Add `*.enc` to `.gitignore` if encrypted files contain highly critical production data, even though the ciphertext does not expose secrets without the keyring key.
- In CI/CD environments, use the runner system's environment variables to inject variables directly, rather than distributing `.enc` files in the repository.
- Rotate keys periodically: manually delete the keyring entry and re-run `encrypt` to regenerate the master key.

---

## License

This project is distributed under the **MIT** license. See the [`LICENSE`](./LICENSE) file for the full terms.

---

Made with ❤️ by quadraturbo
