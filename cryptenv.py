#!/usr/bin/env python3


from __future__ import annotations

import argparse
import base64
import gc
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Final, NoReturn

try:
    import keyring
    import keyring.errors
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        f"[cryptenv] dependencia faltante: {exc.name}\n"
        "           instala con: pip install cryptography keyring\n"
    )
    sys.exit(2)

# ---------------------------------------------------------------------------

MAGIC: Final[bytes] = b"CENV1"         
NONCE_SIZE: Final[int] = 12             
KEY_SIZE_BITS: Final[int] = 256
KEYRING_SERVICE: Final[str] = "cryptenv"
AAD: Final[bytes] = b"cryptenv/aes-256-gcm/v1" 
ENC_SUFFIX: Final[str] = ".enc"
DEFAULT_ENV: Final[str] = "dev"
ENC_TEMPLATE: Final[str] = ".env.{env}.enc"
_ENV_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

# ---------------------------------------------------------------------------

_USE_COLOR: Final[bool] = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None


def _paint(code: str, text: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if _USE_COLOR else text


def log_ok(msg: str) -> None:
    sys.stderr.write(f"{_paint('32', '  ✔')} {msg}\n")


def log_info(msg: str) -> None:
    sys.stderr.write(f"{_paint('36', '  ·')} {msg}\n")


def log_err(msg: str) -> None:
    sys.stderr.write(f"{_paint('31', '  ✘')} {msg}\n")


# ---------------------------------------------------------------------------


class CryptEnvError(Exception):
    """Error operacional con mensaje apto para el usuario final."""


# ---------------------------------------------------------------------------
# Validación de privilegios (UAC / uid)


def check_keyring_privileges() -> None:
  
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        advapi32 = ctypes.windll.advapi32
        TOKEN_QUERY = 0x0008
        token = ctypes.c_void_p()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
        ):
            raise CryptEnvError(
                "privilegios insuficientes (UAC): no se pudo abrir el token de "
                "seguridad del proceso; el Credential Manager no está disponible"
            )
        kernel32.CloseHandle(token)
    else:
        if os.getuid() != os.geteuid():
            raise CryptEnvError(
                "privilegios inconsistentes: uid real y efectivo difieren (setuid); "
                "se aborta para no mezclar almacenes de credenciales"
            )
        if os.getuid() == 0:
            log_info("ejecutando como root: la clave se vinculará al keyring de root")


# ---------------------------------------------------------------------------


class CryptEnv:

    def __init__(self, env: str = DEFAULT_ENV, project_dir: Path | None = None) -> None:
        if not _ENV_NAME_RE.fullmatch(env):
            raise CryptEnvError(f"nombre de entorno inválido: {env!r}")
        self.env: str = env
        self.project_dir: Path = (project_dir or Path.cwd()).resolve()
        # path::entorno actúa como "cuenta" dentro del servicio del keyring:
        # aísla por completo los secretos de cada entorno del mismo proyecto.
        self._account: str = f"{self.project_dir}::{env}"

    # -- gestión de clave maestra -------------------------------------------

    def _load_key(self) -> bytes:
        """Recupera la clave maestra del keyring. Falla si no existe."""
        try:
            stored = keyring.get_password(KEYRING_SERVICE, self._account)
        except keyring.errors.KeyringError as exc:
            raise CryptEnvError(f"no se pudo acceder al keyring del sistema: {exc}") from exc
        if stored is None:
            raise CryptEnvError(
                f"no hay clave registrada para este proyecto ({self._account}). "
                "Ejecuta primero: cryptenv encrypt <archivo>"
            )
        try:
            key = base64.b64decode(stored, validate=True)
        except (ValueError, TypeError) as exc:
            raise CryptEnvError("la clave almacenada en el keyring está corrupta") from exc
        if len(key) != KEY_SIZE_BITS // 8:
            raise CryptEnvError("la clave almacenada no es AES-256 (longitud inválida)")
        return key

    def _load_or_create_key(self) -> bytes:
        """Devuelve la clave del proyecto, generándola si es la primera vez."""
        try:
            return self._load_key()
        except CryptEnvError:
            pass
        key = AESGCM.generate_key(bit_length=KEY_SIZE_BITS)
        try:
            keyring.set_password(KEYRING_SERVICE, self._account, base64.b64encode(key).decode("ascii"))
        except keyring.errors.KeyringError as exc:
            raise CryptEnvError(f"no se pudo guardar la clave en el keyring: {exc}") from exc
        log_ok(f"clave maestra AES-256 generada y guardada en el almacén del SO ({self._account})")
        return key

    # -- borrado seguro -------------------------------------------------------

    @staticmethod
    def _secure_delete(path: Path) -> None:
      
        size = path.stat().st_size
        with path.open("r+b", buffering=0) as fh:
            fh.write(secrets.token_bytes(size))
            fh.flush()
            os.fsync(fh.fileno())
        path.unlink()

    # -- comandos -------------------------------------------------------------

    def encrypt(self, env_file: Path) -> Path:
        """Cifra `env_file` a `.env.<env>.enc` y elimina el original."""
        env_file = env_file.resolve()
        if not env_file.is_file():
            raise CryptEnvError(f"archivo no encontrado: {env_file}")
        if env_file.suffix == ENC_SUFFIX:
            raise CryptEnvError(f"{env_file.name} ya parece estar cifrado")

        plaintext = bytearray(env_file.read_bytes())
        try:
            key = self._load_or_create_key()
            nonce = secrets.token_bytes(NONCE_SIZE)
            ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), AAD)
        finally:
            # Limpia el buffer de texto plano de la memoria del proceso.
            plaintext[:] = b"\x00" * len(plaintext)

        out_path = env_file.with_name(ENC_TEMPLATE.format(env=self.env))
        out_path.write_bytes(MAGIC + nonce + ciphertext)
        log_ok(
            f"[{self.env}] cifrado → {out_path.name} "
            f"({len(ciphertext)} bytes, AES-256-GCM)"
        )

        self._secure_delete(env_file)
        log_ok(f"original eliminado de forma segura: {env_file.name}")
        return out_path

    def _decrypt(self, enc_file: Path) -> bytearray:
        """Descifra el contenedor binario y devuelve el texto plano en memoria."""
        enc_file = enc_file.resolve()
        if not enc_file.is_file():
            raise CryptEnvError(
                f"archivo cifrado no encontrado: {enc_file}. "
                "Genera uno con: cryptenv encrypt <archivo>"
            )
        blob = enc_file.read_bytes()
        if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + NONCE_SIZE + 16:
            raise CryptEnvError(f"{enc_file.name} no es un contenedor cryptenv válido")

        nonce = blob[len(MAGIC) : len(MAGIC) + NONCE_SIZE]
        ciphertext = blob[len(MAGIC) + NONCE_SIZE :]
        key = self._load_key()
        try:
            return bytearray(AESGCM(key).decrypt(nonce, ciphertext, AAD))
        except InvalidTag as exc:
            raise CryptEnvError(
                "fallo de autenticación: el archivo fue alterado o la clave "
                "del keyring no corresponde a este proyecto"
            ) from exc

    @staticmethod
    def _parse_env(plaintext: bytearray) -> dict[str, str]:
        """Parsea contenido dotenv (KEY=VALUE, comentarios, export, comillas)."""
        env: dict[str, str] = {}
        # utf-8-sig tolera el BOM que editores de Windows suelen añadir.
        for raw_line in plaintext.decode("utf-8-sig", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            name, _, value = line.partition("=")
            name = name.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if name:
                env[name] = value
        return env

    def run(self, command: list[str], enc_file: Path | None = None) -> int:
       
        if not command:
            raise CryptEnvError("no se especificó comando. Uso: cryptenv run -- <comando>")

        target = enc_file or (self.project_dir / ENC_TEMPLATE.format(env=self.env))
        plaintext = self._decrypt(target)
        try:
            secret_env = self._parse_env(plaintext)
        finally:
            plaintext[:] = b"\x00" * len(plaintext)

        child_env: dict[str, str] = {**os.environ, **secret_env}
        log_info(
            f"[{self.env}] {len(secret_env)} variable(s) inyectada(s) "
            f"en memoria → {' '.join(command)}"
        )

        executable = shutil.which(command[0])
        if executable is None:
            raise CryptEnvError(f"comando no encontrado en PATH: {command[0]}")

        try:
            process = subprocess.Popen([executable, *command[1:]], env=child_env)
        finally:
       
            secret_env.clear()
            child_env.clear()
            secret_env = None  
            child_env = None  
            gc.collect()

        try:
            return process.wait()
        except KeyboardInterrupt:
            process.terminate()
            return process.wait()


# ---------------------------------------------------------------------------
# CLI


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptenv",
        description="Secretos .env cifrados en reposo, inyectados solo en memoria.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="cifra un .env y elimina el original")
    p_enc.add_argument("file", type=Path, help="ruta del archivo .env a cifrar")
    p_enc.add_argument(
        "--env", default=DEFAULT_ENV,
        help=f"entorno destino: el resultado será .env.<env>.enc (defecto: {DEFAULT_ENV})",
    )

    p_run = sub.add_parser(
        "run",
        help="ejecuta un comando con las variables descifradas en memoria",
        usage="cryptenv run [--env ENTORNO] [-f ARCHIVO.enc] -- <comando> [args...]",
    )
    p_run.add_argument(
        "--env", default=DEFAULT_ENV,
        help=f"entorno a inyectar: usa .env.<env>.enc y su clave aislada (defecto: {DEFAULT_ENV})",
    )
    p_run.add_argument(
        "-f", "--file", type=Path, default=None,
        help="contenedor cifrado explícito (anula el derivado de --env)",
    )
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="comando a ejecutar tras --")
    return parser


def main(argv: list[str] | None = None) -> NoReturn:
    args = _build_parser().parse_args(argv)
    try:
        check_keyring_privileges()
        app = CryptEnv(env=args.env)
        if args.cmd == "encrypt":
            app.encrypt(args.file)
            sys.exit(0)
        # args.cmd == "run"
        command: list[str] = args.command
        if command and command[0] == "--":
            command = command[1:]
        sys.exit(app.run(command, enc_file=args.file))
    except CryptEnvError as exc:
        log_err(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
    
""" made with ♡ by quadraturbo """
