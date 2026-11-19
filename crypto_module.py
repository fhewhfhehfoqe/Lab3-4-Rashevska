import os
import json
import base64
import secrets
import hashlib
import hmac
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Cryptographic module parameters
SALT_SIZE = 16
KEY_SIZE = 32                  # AES-256: 32 bytes
NONCE_SIZE = 12                # Recommended nonce size for GCM
IV_SIZE = 16                   # IV size for AES-CBC
TAG_SIZE = 16
PBKDF2_ITERATIONS = 600_000


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derive two independent 256-bit keys:
    one for AES-CBC encryption and one for HMAC-SHA-256.
    """

    if not password:
        raise ValueError("Password cannot be empty.")

    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt length.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )

    material = kdf.derive(password.encode("utf-8"))

    return material[:KEY_SIZE], material[KEY_SIZE:]


def _derive_gcm_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key for AES-GCM."""

    if not password:
        raise ValueError("Password cannot be empty.")

    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt length.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    algorithm: str = "AES-GCM",
) -> None:
    """Encrypt a file using AES-GCM or AES-CBC with HMAC."""

    source = Path(input_path)
    destination = Path(output_path)

    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")

    if source.resolve() == destination.resolve():
        raise ValueError("Input and output files must be different.")

    mode_name = algorithm.upper()

    if mode_name not in {"AES-GCM", "AES-CBC"}:
        raise ValueError("Supported modes are AES-GCM and AES-CBC.")

    # Generate a new random salt for every encrypted file.
    salt = secrets.token_bytes(SALT_SIZE)
    plaintext = source.read_bytes()

    if mode_name == "AES-GCM":
        key = _derive_gcm_key(password, salt)
        nonce = secrets.token_bytes(NONCE_SIZE)

        # Authenticate the header together with the encrypted data.
        header = {
            "version": 1,
            "algorithm": "AES-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }

        aad = json.dumps(
            header, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    else:
        encryption_key, mac_key = derive_keys(password, salt)
        iv = secrets.token_bytes(IV_SIZE)

        # Apply PKCS7 padding before AES-CBC encryption.
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(iv),
        )

        encryptor = cipher.encryptor()
        ciphertext = (
            encryptor.update(padded_data) + encryptor.finalize()
        )

        header = {
            "version": 1,
            "algorithm": "AES-CBC-HMAC-SHA256",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
        }

        aad = json.dumps(
            header, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        # Calculate HMAC over the header and ciphertext.
        tag = hmac.new(
            mac_key,
            aad + ciphertext,
            hashlib.sha256,
        ).digest()

        ciphertext += tag

    envelope = {
        "header": header,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

    destination.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temporary file before replacing the destination.
    temporary = destination.with_name(destination.name + ".tmp")

    try:
        with open(temporary, "x", encoding="utf-8") as file:
            json.dump(envelope, file)

        os.replace(temporary, destination)

    finally:
        if temporary.exists():
            temporary.unlink()


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
) -> None:
    """Authenticate and decrypt an encrypted file."""

    source = Path(input_path)
    destination = Path(output_path)

    if not source.is_file():
        raise FileNotFoundError(
            f"Encrypted input file not found: {source}"
        )

    if source.resolve() == destination.resolve():
        raise ValueError("Input and output files must be different.")

    # Read and validate the encrypted container.
    envelope = json.loads(source.read_text(encoding="utf-8"))
    header = envelope["header"]

    if header.get("version") != 1:
        raise ValueError("Unsupported file format version.")

    if header.get("kdf") != "PBKDF2-HMAC-SHA256":
        raise ValueError("Unsupported key derivation algorithm.")

    iterations = header.get("iterations")

    if (
        type(iterations) is not int
        or iterations != PBKDF2_ITERATIONS
    ):
        raise ValueError("Invalid PBKDF2 parameters.")

    salt = base64.b64decode(header["salt"], validate=True)
    ciphertext = base64.b64decode(
        envelope["ciphertext"], validate=True
    )

    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt length.")

    aad = json.dumps(
        header, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    algorithm = header.get("algorithm")

    if algorithm == "AES-GCM":
        nonce = base64.b64decode(header["nonce"], validate=True)

        if len(nonce) != NONCE_SIZE:
            raise ValueError("Invalid nonce length.")

        if len(ciphertext) < TAG_SIZE:
            raise ValueError("Ciphertext is too short.")

        key = _derive_gcm_key(password, salt)

        # Decryption raises InvalidTag if authentication fails.
        plaintext = AESGCM(key).decrypt(
            nonce, ciphertext, aad
        )

    elif algorithm == "AES-CBC-HMAC-SHA256":
        iv = base64.b64decode(header["iv"], validate=True)

        if len(iv) != IV_SIZE:
            raise ValueError("Invalid IV length.")

        if len(ciphertext) < 32 + 16:
            raise ValueError("Ciphertext is too short.")

        encryption_key, mac_key = derive_keys(password, salt)

        encrypted_data = ciphertext[:-32]
        received_tag = ciphertext[-32:]

        expected_tag = hmac.new(
            mac_key,
            aad + encrypted_data,
            hashlib.sha256,
        ).digest()

        # Verify HMAC before decrypting the ciphertext.
        if not hmac.compare_digest(received_tag, expected_tag):
            raise ValueError(
                "Authentication failed: data or MAC was modified."
            )

        if (
            len(encrypted_data) == 0
            or len(encrypted_data) % 16 != 0
        ):
            raise ValueError("Invalid AES-CBC ciphertext length.")

        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(iv),
        )

        decryptor = cipher.decryptor()
        padded_data = (
            decryptor.update(encrypted_data) + decryptor.finalize()
        )

        # Remove PKCS7 padding after successful authentication.
        unpadder = padding.PKCS7(
            algorithms.AES.block_size
        ).unpadder()

        plaintext = (
            unpadder.update(padded_data) + unpadder.finalize()
        )

    else:
        raise ValueError("Unknown encryption algorithm.")

    # Write the plaintext only after successful authentication.
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")

    try:
        with open(temporary, "xb") as file:
            file.write(plaintext)

        os.replace(temporary, destination)

    finally:
        if temporary.exists():
            temporary.unlink()
