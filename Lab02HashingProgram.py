import hashlib
import os
import json


def hash_file(file_path):
  """In the hashlib use sha256 to calculate the sha257 hash files context with security."""
  # hashlib doc https://docs.python.org/3/library/hashlib.html 
  sha256_hash = hashlib.sha256()
  try:
    with open(file_path, "rb") as f:
      #Read file in pieces so as to not overload on large files
      for byte_block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
  except (PermisionError, FileNotFoundError):
    return None
  
def traverse_directory(directory_path):
  """Navigate through the directory path and finds the directory of file_path and hash."""
  # os doc https://docs.python.org/3/library/os.html
  file_hashes = {}
  for root, dirs, files in os.walk(directory_path):
    for names in files:
      filepath = os.path.join(root, names)
      file_hash = hash_file(filepath)
      if file_hash:
        file_hashes[filepath] = file_hash
  return file_hashes

def generate_table():
  """Pulls directory, hashes, files, and puts them in a json table"""
  # json doc https://docs.python.org/3/library/json.html
  path = input("Enter the directory path to hash: ").strip()
  if not os.path.isdir(path):
    print("Invalid directory path.")
    return
  hashes = traverse_directory(path)
  with open("hash_table.json", "w") as f:
    json.dump(hashes, f, indent=4)
  print("\n--- Hash table generated ---")

def validate_hash():
  """Compares current file states against the values in the table"""
  if not os.path.exists("hash_table.json"):
        print("Error: No hash table found. Please generate one first.")
        return
  with open("hash_table.json", "r") as f:
        stored_hashes = json.load(f)
  # get the current directory
  current_files = []
  for filepath, stored_hash in stored_hashes.items():
        if os.path.exists(filepath):
            current_files_found.append(filepath)
            current_hash = hash_file(filepath)
            if current_hash == stored_hash:
                print(# 
                    f"VALID:   {filepath}")
            else:
                print(f"INVALID: {filepath} (Content has changed!)")
        else:
            print(f"DELETED: {filepath} is missing from the directory.")
  # check for the new files 
  if stored_hashes:
        base_dir = os.path.dirname(list(stored_hashes.keys())[0])
        for root, dirs, files in os.walk(base_dir):
            for name in files:
                full_path = os.path.join(root, name)
                if full_path not in stored_hashes:
                    print(f"NEW:     {full_path} was added since last scan.")
          
def main():
  while True: 
    print("1. Generate new hash table")
    print("2. Verify hashes")
    choice = input("Select an option: ")
  
    if choice == '1':
      generate_table()
    elif choic == '2':
      validate_hash()
    else:
      print("Option not available.")

if __name__ == "__main__":
  main()
