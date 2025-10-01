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






