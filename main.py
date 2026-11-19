import getpass
import logging
from pathlib import Path

from cryptography.exceptions import InvalidTag
from crypto_module import encrypt_file, decrypt_file


Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    filename="logs/crypto.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("crypto_lab")


def main():
    while True:
        print("\n=== CRYPTO LAB ===")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")

        choice = input("Select an action: ").strip()

        if choice == "3":
            print("Exiting the application.")
            break

        if choice not in {"1", "2"}:
            print("Invalid menu option.")
            continue

        source = input("Enter the input file path: ").strip()
        destination = input("Enter the output file path: ").strip()
        password = getpass.getpass("Enter password: ")

        try:
            if choice == "1":
                print("1. AES-GCM")
                print("2. AES-CBC + HMAC")

                mode = input("Select encryption mode: ").strip()

                if mode not in {"1", "2"}:
                    print("Invalid encryption mode.")
                    continue

                algorithm = "AES-GCM" if mode == "1" else "AES-CBC"

                encrypt_file(source, destination, password, algorithm)

                logger.info(
                    "Encryption successful mode=%s", algorithm
                )
                print(f"File encrypted successfully: {destination}")

            else:
                decrypt_file(source, destination, password)

                logger.info("Decryption successful")
                print(f"File decrypted successfully: {destination}")

        except InvalidTag:
            logger.warning(
                "Decryption failed: authentication failure"
            )
            print("Error: authentication verification failed.")

        except Exception as error:
            logger.warning(
                "Operation failed type=%s", type(error).__name__
            )
            print(f"Operation failed: {error}")


if __name__ == "__main__":
    main()
