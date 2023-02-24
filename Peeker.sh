#!/bin/bash

# Define a regular expression pattern to match a password.
password_pattern="^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"
# Define a list of keywords to search for.
keywords=("pass" "password" "key" "cert" "cred")

# Define a function to check if a line is a password.
function is_password() {
  if [[ "$1" =~ $password_pattern ]]; then
    return 0  # true
  else
    return 1  # false
  fi
}

# Define a function to check if a line contains a keyword.
function has_keyword() {
  for keyword in "${keywords[@]}"; do
    if echo "$1" | grep -qi "$keyword"; then
      return 0  # true
    fi
  done
  return 1  # false
}

# Define a function to inspect a directory for passwords and keywords.
function inspect_directory() {
  for file in "$1"/*; do
    if [ -d "$file" ]; then
      inspect_directory "$file"
    elif [ -f "$file" ]; then
      while read -r line; do
        if is_password "$line" || has_keyword "$line"; then
          echo "Possible password or keyword found in file $file, line $((LINENO-1)): $line"
        fi
      done < "$file"
    fi
  done
}

# Check if a directory argument was provided.
if [ -z "$1" ]; then
  echo "Please provide a directory argument."
  exit 1
fi

# Check if the directory exists.
if [ ! -d "$1" ]; then
  echo "Invalid directory argument."
  exit 1
fi

# Inspect the directory for passwords and keywords.
inspect_directory "$1"
