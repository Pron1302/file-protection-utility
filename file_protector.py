import os
import hmac
import hashlib
import getpass

MAGIC = b"FPU1"
SALT_SIZE = 16
NONCE_SIZE = 16
MAC_SIZE = 32
ITERATIONS = 200_000


def derive_keys(password, salt):
    """Turn a password into an encryption key and an integrity key."""
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, dklen=64)
    return key[:32], key[32:]


def keystream(key, nonce, length):
    """Generate a pseudo-random byte stream of the required length."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def xor_bytes(data, stream):
    return bytes(a ^ b for a, b in zip(data, stream))


def protect_file(path, password):
    with open(path, "rb") as f:
        data = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    enc_key, mac_key = derive_keys(password, salt)

    cipher = xor_bytes(data, keystream(enc_key, nonce, len(data)))
    mac = hmac.new(mac_key, salt + nonce + cipher, hashlib.sha256).digest()

    out_path = path + ".locked"
    with open(out_path, "wb") as f:
        f.write(MAGIC + salt + nonce + mac + cipher)
    return out_path


def restore_file(path, password):
    with open(path, "rb") as f:
        blob = f.read()

    header = len(MAGIC) + SALT_SIZE + NONCE_SIZE + MAC_SIZE
    if len(blob) < header or blob[:4] != MAGIC:
        raise ValueError("This is not a protected file.")

    salt = blob[4:4 + SALT_SIZE]
    nonce = blob[4 + SALT_SIZE:4 + SALT_SIZE + NONCE_SIZE]
    mac = blob[4 + SALT_SIZE + NONCE_SIZE:header]
    cipher = blob[header:]

    enc_key, mac_key = derive_keys(password, salt)
    expected = hmac.new(mac_key, salt + nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Wrong password or file is corrupted.")

    data = xor_bytes(cipher, keystream(enc_key, nonce, len(cipher)))

    out_path = path[:-7] if path.endswith(".locked") else path + ".restored"
    if os.path.exists(out_path):
        out_path += ".restored"
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


def main():
    print("=== File Protection Utility ===")
    while True:
        print("\n1. Protect (encrypt) a file")
        print("2. Restore (decrypt) a file")
        print("3. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "3":
            print("Goodbye!")
            break
        if choice not in ("1", "2"):
            print("Invalid choice.")
            continue

        path = input("Enter file path: ").strip().strip('"')
        if not os.path.isfile(path):
            print("File not found.")
            continue

        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty.")
            continue

        try:
            if choice == "1":
                out = protect_file(path, password)
                print(f"File protected -> {out}")
            else:
                out = restore_file(path, password)
                print(f"File restored -> {out}")
        except ValueError as e:
            print(f"Error: {e}")
        except OSError as e:
            print(f"File error: {e}")


if __name__ == "__main__":
    main()
