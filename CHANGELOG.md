# IMAPdedup Change Log

## [1.4] - 2026-08-27

* No real functional changes, but the minimum Python version is now 3.10, and the code has been updated to adopt some newer Python conventions.

## [1.3] - 2026-08-10

* Attempt fix for issue #57: 'Too many items to unpack' from some servers which return extraneous lines in the response.

## [1.2] - 2024-11-18

* Add the '-d' (or --delete) option, which will expunge all messages marked for deletion from the server.

## [1.1] - 2024-09-01

* Package the script as a Python package, so you can install it with `pip install imapdedup` and run it from anywhere.
* This means it needs a version number. What do you call something that's been around for 15 years but has never had a version number? Well, 1.1 seems reasonable!
* The code also now includes a Change Log!


## Earlier versions:

For around a decade and a half, IMAPdedup was simply distributed as a standalone Python script, and you can still run `imapdedup.py` that way if you want.
But from version 1.1 onwards, it's also available as a Python package, so you can install it with `pip install imapdedup`, and then run `imapdedup` from anywhere.
