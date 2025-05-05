import hashlib
import json
import argparse
import os

HASH_FILE = "hashes.json"

def calculate_hashes(filename):
    """Calculates MD5, SHA1, and SHA256 hashes for a given file."""
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    try:
        with open(filename, 'rb') as f:
            while True:
                chunk = f.read(4096) # Read in chunks to handle large files
                if not chunk:
                    break
                for h in hashes.values():
                    h.update(chunk)
        return {name: h.hexdigest() for name, h in hashes.items()}
    except FileNotFoundError:
        print(f"Error: File not found - {filename}")
        return None
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
        return None

def load_stored_hashes(filename):
    """Loads stored hashes from the JSON file."""
    try:
        if os.path.exists(HASH_FILE):
            with open(HASH_FILE, 'r') as f:
                all_hashes = json.load(f)
                return all_hashes.get(os.path.abspath(filename)) # Use absolute path as key
        return None
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {HASH_FILE}")
        return None
    except Exception as e:
        print(f"Error loading stored hashes: {e}")
        return None

def save_hashes(filename, hashes_to_save):
    """Saves/updates hashes for a given file in the JSON file."""
    all_hashes = {}
    if os.path.exists(HASH_FILE):
        try:
            with open(HASH_FILE, 'r') as f:
                all_hashes = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
             print(f"Warning: Could not read existing {HASH_FILE}. Creating a new one.")
        except Exception as e:
             print(f"Warning: Error reading {HASH_FILE}: {e}. Overwriting.")


    all_hashes[os.path.abspath(filename)] = hashes_to_save # Use absolute path
    try:
        with open(HASH_FILE, 'w') as f:
            json.dump(all_hashes, f, indent=4)
        print(f"Hashes for {filename} saved to {HASH_FILE}")
    except Exception as e:
        print(f"Error saving hashes to {HASH_FILE}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Compute and check file hashes for integrity.")
    parser.add_argument("filename", help="The file to check or store hashes for.")
    parser.add_argument("-u", "--update", action="store_true",
                        help="Calculate and store/update hashes for the file.")
    parser.add_argument("-c", "--check", action="store_true",
                        help="Check file integrity against stored hashes.")

    args = parser.parse_args()

    if not args.update and not args.check:
        print("Please specify an action: --update or --check")
        parser.print_help()
        return

    if args.update:
        print(f"Calculating hashes for {args.filename}...")
        current_hashes = calculate_hashes(args.filename)
        if current_hashes:
            save_hashes(args.filename, current_hashes)
            print("Hashes calculated:")
            for name, h in current_hashes.items():
                print(f"  {name.upper()}: {h}")

    if args.check:
        print(f"\nChecking integrity for {args.filename}...")
        stored_hashes = load_stored_hashes(args.filename)
        if not stored_hashes:
            print(f"No stored hashes found for {args.filename} in {HASH_FILE}. Cannot check integrity.")
            print("Run with --update first to store initial hashes.")
            return

        current_hashes = calculate_hashes(args.filename)
        if not current_hashes:
            print("Could not calculate current hashes. Check failed.")
            return

        print("Comparing current hashes with stored hashes:")
        print(f"  Stored Hashes: {stored_hashes}")
        print(f"  Current Hashes: {current_hashes}")

        match = True
        for name in stored_hashes:
            if name not in current_hashes or stored_hashes[name] != current_hashes[name]:
                match = False
                print(f"  MISMATCH found for {name.upper()}!")

        if match:
            print("\nResult: PASS - File integrity verified. Hashes match.")
        else:
            print("\nResult: FAIL - File has been modified or corrupted! Hashes DO NOT match.")

if __name__ == "__main__":
    main()