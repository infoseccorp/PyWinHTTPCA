# PyWinHTTPCA
Python code to do TLS client authentication using the WinHTTP API and a specified certificate

Some time in 2025 we had someone using Python on Windows to connect to a website requiring TLS client authentication. The twist being that the certificate and private key to be used to authenticate were in Microsoft's key store and not extractable (OK, the credential was in CSPid, but this isn't an ad). The main point is that the private key could not be extracted into a form that most Pything HTTP libraries want. After a LOT of digging we couldn't find a way to actually do this using the normal Python routes. Attempts to use PKCS#11 with requests, urllib, m2crypto, etc. were unsuccessful (possible due to our own issues). Attempts to use win32com were unsuccessful in the case where the user had multiple certificates with the same common name in them (the SetClientCertificate function is...unhelpful).

This sample code directly uses the WinHTTP COM object through the Python ctypes library and the Windows Cryptgoraphic API through the Python win32crypt library. Hopefully, this makes someone's life easier at some point.
