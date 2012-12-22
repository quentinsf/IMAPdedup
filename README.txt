IMAPdedup is a python script (imapdedup.py) that looks for duplicate messages in an IMAP mailbox and marks all but the first one for deletion. Although efforts were taken to try to minimize false positives, you may want to do a dry run first with the '-n' parameter.

Note that IMAPdedup will tell the IMAP server to *mark* messages as deleted. Exactly what that does in your environment will depend on your mail server and your mail client.  Sometimes deleted messages appear in a 'Trash' folder.  Sometimes they are hidden and can be displayed and un-deleted if wanted, until they are purged. 

For more information, please see http://qandr.org/quentin/software/imapdedup.

This software is released under the terms of the GPL v2.  See LICENCE.TXT for details.

Quentin Stafford-Fraser
statusq.org
