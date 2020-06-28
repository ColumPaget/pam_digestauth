# PAM DIGESTAUTH

This is a VERY simple PAM (Pluggable Authentication Modules) that implements a challenge-response login. It sends a random 'nonce' value and the user concatanates this with their password, hashes it using sha256 hashing, and sends the result back. 

The intended use for this module is when dealing with legacy or embedded/iot devices that lack an encrypted communications channel. It is not intended for use in environments or with accounts that need significant security. These accounts that can log in with this system should be low-privilege accounts. This module is intended to be used in environments where the alternative is to send the password in the clear. Using this module the password at least can be sent in a fairly secure manner.

Firstly this module should be installed into '/lib/security' ('make install' will do this).

Secondly it should be configured in the appropriate pam config file as:

```
auth sufficient pam_digestauth.so

```

Finally passwords are set up in the file `/etc/digestauth.auth' (using your favorite text editor) with the format:

```
<username>:<password>
```
The first thing to note here is that your passwords in this file are stored in the clear! 


When authentication happens a line like this is displayed:

```
Challenge: abc843b159810e6bfe9a9bc2a5a57f
```

This random string should have the password concatanted to the end of it, and then by sha256 hashed using 'sha256sum' or 'hashrat -16 -sha256' like so:

```
echo -n abc843b159810e6bfe9a9bc2a5a57fmypassword | sha256sum
```

```
echo -n abc843b159810e6bfe9a9bc2a5a57fmypassword | hashrat -16 -sha256
```

The resulting sha256 has is what is sent as the password.
