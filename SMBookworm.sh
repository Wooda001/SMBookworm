#!/bin/bash

# Keywords to match potential passwords and hashes
keywords=("pass" "pw" "creds" "secret" "private" "key" "ntlm" "pfx" "rsa" "ssh")

# Regex to match potential passwords
password_pattern="((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{8,})"

# Regex to match potential NTLM hashes
ntlm_pattern="([0-9a-fA-F]{32})"

# Regex to match potential PFX files
pfx_pattern="(.*\.pfx)"

# Regex to match potential RSA keys
rsa_pattern="(.*\.key)"

# Parse command line arguments
if [[ $# -ne 3 ]]; then
    echo "Usage: $0 ip username password"
    exit 1
fi

ip=$1
username=$2
password=$3

# Get list of IP addresses to scan
if [[ -f $ip ]]; then
    readarray -t ips < $ip
else
    ips=("$ip")
fi

# Iterate through each IP address and check SMB shares for passwords and hashes
for ip in "${ips[@]}"; do
    # Run CrackMapExec to retrieve list of readable SMB shares
    shares=$(crackmapexec smb $ip -u $username -p $password --shares)
    share_names=()

    # Parse share names from the output that have READ permissions
    while IFS= read -r line; do
        if [[ $line == *"(READ)"* ]]; then
            share_names+=("$(echo $line | awk '{print $NF}')")
        fi
    done <<< "$shares"

    # Download contents of each share and check files for passwords and hashes
    for share_name in "${share_names[@]}"; do
        share_path="//$ip/$share_name"
        # Check if the share is accessible
        if smbclient $share_path -c 'prompt off;recurse;lcd /tmp/;mget *' -U $username%$password > /dev/null 2>&1; then
            # Check each file for passwords and hashes
            for file in /tmp/*; do
                while IFS= read -r line; do
                    # Check if line matches password pattern or keywords
                    if [[ $line =~ $password_pattern ]] || [[ "${keywords[@]}" =~ $(echo "$line" | tr '[:upper:]' '[:lower:]') ]]; then
                        echo "Possible password found in file: $file on IP: $ip"
                        break
                    fi
                    # Check if line matches NTLM hash pattern
                    if [[ $line =~ $ntlm_pattern ]]; then
                        echo "Possible NTLM hash found in file: $file on IP: $ip"
                        break
                    fi
                done < "$file"
                # Check if file matches PFX or RSA key pattern
                if [[ $file =~ $pfx_pattern ]] || [[ $file =~ $rsa_pattern ]]; then
                    echo "Possible PFX or RSA key found: $file on IP: $ip"
                fi
                # Delete the file after it has been checked
                rm -f "$file"
            done
        else
            # Unable to access the share
            echo "Unable to access share $share_name"
        fi
    done
done
