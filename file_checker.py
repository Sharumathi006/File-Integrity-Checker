import hashlib
import os
import json

# Function to calculate the SHA256 hash of a file
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read the file in chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

# Function to save file hashes to a JSON file
def save_hashes(directory, output_file="hashes.json"):
    hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            hash_val = calculate_hash(full_path)
            if hash_val:
                hashes[full_path] = hash_val

    with open(output_file, 'w') as f:
        json.dump(hashes, f, indent=4)
    print(f"[✓] Hashes saved to '{output_file}'")

# Function to verify file integrity
def verify_files(hash_file="hashes.json"):
    try:
        with open(hash_file, 'r') as f:
            saved_hashes = json.load(f)
    except FileNotFoundError:
        print(f"[!] Hash file '{hash_file}' not found.")
        return

    for file_path, original_hash in saved_hashes.items():
        current_hash = calculate_hash(file_path)
        if current_hash is None:
            print(f"[!] Missing file: {file_path}")
        elif current_hash != original_hash:
            print(f"[✗] Modified file: {file_path}")
        else:
            print(f"[✓] File intact: {file_path}")

# Main menu
def main():
    print("========== File Integrity Checker ==========")
    print("1. Save file hashes")
    print("2. Verify file integrity")
    print("============================================")

    choice = input("Choose an option (1 or 2): ").strip()

    if choice == '1':
        directory = input("Enter the folder path to scan: ").strip()
        if os.path.isdir(directory):
            save_hashes(directory)
        else:
            print("[!] Invalid directory path.")
    elif choice == '2':
        verify_files()
    else:
        print("[!] Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()

