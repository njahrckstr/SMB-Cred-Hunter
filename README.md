# SMB-Cred-Hunter
Python script used in internal red team/pen test engagements looking for SMB shares that have hard coded creds.
After coming across hard coded creds in SMB shares throughout various engagements (I know, I know... but I was still finding this mess) I wanted to automate it for quick wins by leveraging impacket and my ugly Python "skills"...
# Goals:
1. Feed it IPs via a static list or an IP range.
2. Attempt authentication using a list of known creds
3. Traverse directories with limits to prevent endless recursion
4. Check file sizes before downloading or flagging.
5. Throttle request rates to avoid network saturation or detection.
6. Log my findings via success, errors, flags, etc.) to a file or syslog.
7. User has a choice to output to a CSV or JSON file.

# Dependencies
Impacket

# ToDo
1. Make it work with Slack, Teams, email etc. so blue teams can run it...?
2. Include file type filters like .docx, .pdf, .odt, and specific keyword search inside files.

# Features.
## For CSV:
```
python smb_scanner.py -i 192.168.1.0/24 -c credentials.txt -r csv
```
## For JSON:
```
python smb_scanner.py -i targets.txt -c credentials.txt -r json
```
## Various options
```
--users | Username list (one per line)
--passwords | Password list (one per line)
--max-attempts | Max username:password attempts per host
--exclude | Skip scanning certain IPs or CIDR ranges
--report-format | Save results as csv or json
```
## Example usage: 
#### Limit attempts to 5 per host and exclude specific IPs while using user and password list of your choice and exporting the results to a .json file
```
python smb_scanner.py -i 192.168.1.0/24 \
    --users users.txt \
    --passwords passwords.txt \
    --max-attempts 5 \
    --exclude 192.168.1.50,192.168.1.100/30 \
    -r json
```


