# HACKPREP — Autoconfigure an Attack Machine
![HACKPREP Banner](https://github.com/mrdanielvelez/hackprep/assets/85040841/ab0b739c-28b6-40c3-9c55-3105af007b03)

HACKPREP automates a myriad of repetitive actions pertaining to configuring an attack machine from scratch.

## Demo GIF
![hackprep_demo](https://github.com/mrdanielvelez/hackprep/assets/85040841/80267c6d-32a8-4c85-9b74-1168b0a7fb70)

## Main Features
- Tests internet connectivity and DNS name resolution immediately after execution
- Downloads, installs, activates, and configures the latest versions of Nessus and Cobalt Strike after securely prompting for license keys
- Initializes the Cobalt Strike team server to run in the background as an enabled service using a complex password and random port to listen on
- Automatically builds the Mimikatz, Resource, and Process_Inject Cobalt Strike kits (CNA output files must be imported manually). Artifact/Sleep Mask/etc. aren't built due to the manual customization they require
- Adds a rule within Nessus to reject the attack machine's IPv4 address by default. Prompts for an optional file containing additional hosts to reject within Nessus
- Automatically creates an admin user within Nessus using a randomly-generated complex password
- Modifies Nessus's SQLite database to only listen on localhost (127.0.0.1) instead of 0.0.0.0
- Automatically disables "Use Vulnerability Groups" and "Use Mixed Vulnerability Groups" within Nessus
- Installs several hacking tools (Impacket, CrackMapExec, Certipy, Coercer, LdapRelayScan, etc.) within isolated virtual environments to prevent dependency conflicts 
- Patches the infamous Libcrypto version Python error by fixing the erroneous regular expressions
- Patches the AttributeError that stems from using Certipy with >= Python3.11
- Builds Kerbrute from source after patching "KDC_ERROR: AS Exchange Error" (credit to Parker for providing me with info on this)
- Updates existing tools within the default tools directory via Git and updates Golang via update-golang.sh
- Automatically installs Python requirements for tools via pip
- Executes package operations via APT and subsequently cleans up leftover/unneeded packages
- Creates a backup of the /etc/resolv.conf file present upon execution
- Configures Responder to utilize the magic challenge 1122334455667788. Disables Responder's SMB/HTTP servers and disables responding to the attack machine's IPv4 address
- Creates two helper functions within ~/.zshrc: rsmbhttp and zippy
- rsmbhttp — Toggle switch for Responder's SMB and HTTP servers (rsmbhttp [on/off/http/smb], without arguments it simply prints the current status)
- zippy — Automatically outputs a ZIP file containing all of your project evidence (including Tmux command logs). If no path is specified it assumes that “$PWD” = project directory

## Helper Functions Demo (*rsmbhttp* and *zippy*)
![helper_functions](https://github.com/mrdanielvelez/hackprep/assets/85040841/d282f4d4-94e3-43ed-9599-ddd49595b1b2)
