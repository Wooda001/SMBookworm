import os
import re
import sys

def is_password(line):
    # Define a regular expression pattern to match a password.
    pattern = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"
    # Match the line against the pattern.
    match = re.match(pattern, line.strip())
    # If the line matches the pattern, return True, else return False.
    return bool(match)

def has_keyword(line):
    # Define a list of keywords to search for.
    keywords = ["pass", "password", "key", "cert", "cred"]
    # Loop over all the keywords.
    for keyword in keywords:
        # If the keyword is found in the line, return True.
        if keyword in line.lower():
            return True
    # If none of the keywords are found in the line, return False.
    return False

def inspect_directory(directory):
    # Loop over all the files and directories in the directory.
    for filename in os.listdir(directory):
        # Get the path of the file or directory.
        path = os.path.join(directory, filename)
        # Check if the path is a directory.
        if os.path.isdir(path):
            # If it is, recursively inspect the directory.
            inspect_directory(path)
        # If the path is a file, open it and read its contents.
        else:
            with open(path, "r") as f:
                contents = f.readlines()
            # Loop over all the lines in the file.
            for line in contents:
                # Check if the line contains a password or keyword.
                if is_password(line) or has_keyword(line):
                    # If it does, print the filename and line number.
                    print(f"Possible password or keyword found in file {path}, line {contents.index(line) + 1}: {line.strip()}")

# Check if the directory argument was provided.
if len(sys.argv) < 2:
    print("Please provide a directory argument.")
    sys.exit(1)

# Get the directory argument.
directory = sys.argv[1]
# Check if the directory exists.
if not os.path.isdir(directory):
    print("Invalid directory argument.")
    sys.exit(1)

# Inspect the directory and its subdirectories for possible passwords or keywords.
inspect_directory(directory)
