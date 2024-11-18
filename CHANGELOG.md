# IMAPdedup Change Log

## [1.2] - 2024-11-18

* Add the '-d' (or --delete) option, which will expunge all messages marked for deletion from the server.

## [1.1] - 2024-09-01

* Package the script as a Python package, so you can install it with `pip install imapdedup` and run it from anywhere.
* This means it needs a version number. What do you call something that's been around for 15 years but has never had a version number? Well, 1.1 seems reasonable!
* The code also now includes a Change Log!


## Earlier versions:

For around a decade and a half, IMAPdedup was simply distributed as a standalone Python script, and you can still run `imapdedup.py` that way if you want.
But from version 1.1 onwards, it's also available as a Python package, so you can install it with `pip install imapdedup`, and then run `imapdedup` from anywhere.
