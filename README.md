# pls - Automation for when there is no better option
`pls` is a tool for executing elevated commands on remote targets over ssh.  
Combining the utility of `sshpass` and `ansible-vault`; `pls` lets you define the authentication passwords for hosts ahead of time and pass them in securely.  

## Key Features
* Secure password management using libsodium to encrypt and decrypt password vaults.
* Wildcard target matching for authentication credentials.
* Specific fields for login vs. elevation on each target.
* Ability to execute full bash scripts on targets instead of just single line commands.
* Execute commands on a list of targets with only one vault decryption.
* Made for static compilation - build once and copy (mostly) anywhere.
* Full integration with normal OpenSSH configurations.

## Prerequisites
To build `pls` from source you'll need standard C build tools, libsodium development files, and [json.hpp](https://github.com/nlohmann/json).  

## Build
```
git clone https://github.com/Jepebu/pls.git
cd pls
wget https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
g++ -o pls pls.cpp -lutil -lsodium
# Alternatively for static compilation:
# g++ -O2 -static -o pls pls.cpp -lutil -lsodium
./pls -h

Usage:
  Edit Vault:    ./pls -e -v <vault_file>
  Execute SSH:   ./pls -v <vault_file> [-s <script_file>] [-l <target_list>] -- <ssh arguments...>

Examples:
  ./pls -v secure.vault -- ssh -J user@hop1 target_host -t sudo ls -la
  ./pls -v secure.vault -s ./script.sh -- ssh -J hop1 target_host
  ./pls -v secure.vault -l hosts.txt -s ./script.sh -- ssh -J hop1 {TARGET}
```

## The Vault
The vault utility of `pls` is the core of its functionality.  
In your own personal vault you'll define your usernames and passwords for the targets you need to authenticate to in a JSON format.  
```
{
  "prompts": {
    "hop1.example.com": {
      "login": "Hop1Pass",
      "sudo": "Hop1SudoPass"
    },
    "sub-1-*": {
      "login": "Sub1Login",
      "sudo": "Sub1Sudo"
    },
    "target.domain?": {
      "login": "DomainLogin",
      "sudo": "DomainSudo"
    },
    "default": {
      "login": "FallbackLogin",
      "sudo": "FallbackSudo"
    }
  }
}
```
