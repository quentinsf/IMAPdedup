#! /usr/bin/env python
#
#  imapdedup.py
#
#  Looks for duplicate messages in a set of IMAP mailboxes and removes all but the first.
#  Comparison is normally based on the Message-ID header.
#
#  Default behaviour is purely to mark the duplicates as deleted.  Some mail clients
#  will allow you to view these and undelete them if you change your mind.
#
#  Copyright (c) 2013 Quentin Stafford-Fraser.   All rights reserved, subject to the following:
#
#
#   This is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this software; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
#   USA.
#

import os
import sys
import getpass
import re
import imaplib
import hashlib
import socket
import email.parser
from email.header import decode_header

# Increase the rather small limit on result line-length
# imposed in recent imaplib versions.
imaplib._MAXLINE = 200000

class ImapDedupException(Exception): pass

# IMAP responses should normally begin 'OK' - we strip that off
def check_response(resp):
    status, value = resp
    if status != 'OK':
        raise ImapDedupException("Got response: %s from server" % value)
    return value

def get_arguments(args):
    # Get arguments and create link to server
    from optparse import OptionParser
    parser = OptionParser(usage="%prog [options] <mailboxname> [<mailboxname> ...]")
    parser.add_option("-P", "--process",dest='process', help='IMAP process to access mailboxes')
    parser.add_option("-s", "--server",dest='server',help='IMAP server')
    parser.add_option("-p", "--port",  dest='port',  help='IMAP server port', type='int')
    parser.add_option("-x", "--ssl",   dest='ssl',   action="store_true", help='Use SSL')
    parser.add_option("-u", "--user",  dest='user',  help='IMAP user name')
    parser.add_option("-w", "--password", dest='password',  help='IMAP password (Will prompt if not specified)')
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose mode")
    parser.add_option("-n", "--dry-run", dest="dry_run", action="store_true",
                        help="Don't actually do anything, just report what would be done")
    parser.add_option("-c", "--checksum", dest="use_checksum", action="store_true",
                        help="Use a checksum of several mail headers, instead of the Message-ID")
    parser.add_option("-m", "--checksum-with-id", dest="use_id_in_checksum", action="store_true",
                        help="Include the Message-ID (if any) in the -c checksum.")
    parser.add_option("",   "--no-close",  dest='no_close', action="store_true",
                        help='Do not "close" mailbox when done. Some servers will purge deleted messages on a close command.')
    parser.add_option("-l", "--list", dest="just_list", action="store_true",
                                            help="Just list mailboxes")

    parser.set_defaults(verbose=False, ssl=False, dry_run=False, no_close=False, just_list=False)
    (options, mboxes) = parser.parse_args(args)
    if ((not options.server) or (not options.user)) and not options.process:
        sys.stderr.write("\nError: Must specify server, user, and at least one mailbox.\n\n")
        parser.print_help()
        sys.exit(1)
    if not options.password and not options.process:
        # Read from IMAPDEDUP_PASSWORD env variable, or prompt for one.
        options.password = os.getenv("IMAPDEDUP_PASSWORD") or getpass.getpass()

    if options.use_id_in_checksum and not options.use_checksum:
        sys.stderr.write("\nError: If you use -m you must also use -c.\n")
        sys.exit(1)

    return (options, mboxes)

# Thanks to http://www.doughellmann.com/PyMOTW/imaplib/
list_response_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')


def parse_list_response(line):
    flags, delimiter, mailbox_name = list_response_pattern.match(line).groups()
    mailbox_name = mailbox_name.strip('"')
    return (flags, delimiter, mailbox_name)


def utf8_header(parsed_message, name):
    """"
    Return the value (of the first instance, if more than one) of
    the given header, as a UTF-8 encoded string.
    """
    text, encoding = decode_header(parsed_message.get(name,''))[0]
    # Attempt to handle python 2 and 3 here at least
    if sys.version_info < (3,0,0):
        if not isinstance(text, unicode): 
            text = text.decode('utf-8', 'ignore')
    else:
        if isinstance(text, bytes):
            text = text.decode('utf-8', 'ignore')
    return text.encode('utf-8')


def get_message_id(parsed_message,
                   options_use_checksum = False,
                   options_use_id_in_checksum = False):
    """
    If user specified, use md5 hash of several headers as message id.


    For more safety, user should first do a dry run, reviewing them before deletion.
    Problems are extremely unlikely, but md5 is not collision-free.

    Otherwise use the Message-ID header. Print a warning if the Message-ID header does not exist.
    """
    try:
        if options_use_checksum:
            md5 = hashlib.md5()
            md5.update("From:"    + utf8_header(parsed_message,'From'))
            md5.update("To:"      + utf8_header(parsed_message,'To'))
            md5.update("Subject:" + utf8_header(parsed_message,'Subject'))
            md5.update("Date:"    + utf8_header(parsed_message,'Date'))
            md5.update("Cc:"      + utf8_header(parsed_message,'Cc'))
            md5.update("Bcc:"     + utf8_header(parsed_message,'Bcc'))
            if options_use_id_in_checksum:
                md5.update("Message-ID:" + utf8_header(parsed_message,'Message-ID'))
            msg_id = md5.hexdigest()
            # print(msg_id)
        else:
            msg_id = utf8_header(parsed_message,'Message-ID')
            if not msg_id:
                print("Message '%s' dated '%s' has no Message-ID header." % (
                    utf8_header(parsed_message,'Subject'), utf8_header(parsed_message,'Date')))
                print("You might want to use the -c option.")
                return None
        return msg_id
    except ValueError:
        print("WARNING: There was an exception trying to parse the headers of this message.")
        print("It may be corrupt, and you might consider deleting it.")
        print("Subject: %s\nFrom: %s\nDate: %s\n" % (
            parsed_message['Subject'], parsed_message['From'], parsed_message['Date']))
        print("Message skipped.")
        return None



def print_message_info(parsed_message):
    print("From: " +    utf8_header(parsed_message,'From'))
    print("To: " +      utf8_header(parsed_message,'To'))
    print("Cc: " +      utf8_header(parsed_message,'Cc'))
    print("Bcc: " +     utf8_header(parsed_message,'Bcc'))
    print("Subject: " + utf8_header(parsed_message,'Subject'))
    print("Date: " +    utf8_header(parsed_message,'Date'))
    print("")


# This actually does the work
def process(options, mboxes):
    if options.process:
        serverclass = imaplib.IMAP4_stream
    elif options.ssl:
        serverclass = imaplib.IMAP4_SSL
    else:
        serverclass = imaplib.IMAP4

    try:
        if options.process:
            server = serverclass(options.process)
        elif options.port:
            server = serverclass(options.server, options.port)
        else:
            # Use the default, which will be different depending on SSL choice
            server = serverclass(options.server)
    except socket.error as e:
        sys.stderr.write("\nFailed to connect to server. Might be host, port or SSL settings?\n")
        sys.stderr.write("%s\n\n" % e)
        sys.exit(1)

    if ('STARTTLS' in server.capabilities) and hasattr(server, 'starttls'):
        server.starttls()
    elif not options.ssl:
        sys.stderr.write('\nWarning: Unencrypted connection\n')

    try:
        if not options.process:
            server.login(options.user, options.password)
    except:
        sys.stderr.write("\nError: Login failed\n")
        sys.exit(1)

    # List mailboxes option
    if options.just_list:
        for mb in check_response(server.list()):
            mb = mb.decode('utf-7')
            bits = parse_list_response(mb)
            if r'\\Noselect' not in bits[0]:
                print(bits[2])
        sys.exit()

    if len(mboxes) == 0:
        sys.stderr.write("\nError: Must specify mailbox\n")
        sys.exit(1)

    # OK - let's get started.
    # Iterate through a set of named mailboxes and delete the later messages discovered.
    try:
        p = email.parser.Parser() # can be the same for all mailboxes
        # Create a list of previously seen message IDs, in any mailbox
        msg_ids = {}
        for mbox in mboxes:
            msgs_to_delete = [] # should be reset for each mbox
            msg_map = {} # should be reset for each mbox

            # Select the mailbox
            msgs = check_response(server.select(mbox, options.dry_run))[0]
            print("There are %d messages in %s." % (int(msgs), mbox))

            # Check how many messages are already marked 'deleted'...
            deleted = check_response(server.search(None, 'DELETED'))[0];
            numdeleted  = 0
            if deleted != None:
                deleted = check_response(server.search(None, 'DELETED'))[0].split()
                numdeleted = len(deleted)
            print("%s message(s) currently marked as deleted in %s" % (numdeleted or "No", mbox))

            # ...and get a list of the ones that aren't deleted. That's what we'll use.
            msgnums = check_response(server.search(None, 'UNDELETED'))[0].split()
            print("%s others in %s" % (len(msgnums), mbox))

            chunkSize = 100
            if options.verbose: print ("Reading the others... (in batches of %d)" % chunkSize)

            for i in range(0, len(msgnums), chunkSize):
                msgnums_in_chunk = msgnums[i:i + chunkSize]
                message_ids = ','.join(msgnums_in_chunk)
                # Get the header of each message
                ms = check_response(server.fetch(message_ids, '(RFC822.HEADER)'))
                if options.verbose:
                    print ("Batch starting at item %d" % i)

                # and parse them.
                for ci in range(0, len(msgnums_in_chunk)):
                    mnum = msgnums_in_chunk[ci]
                    mp = p.parsestr(ms[ci * 2][1])
                    if options.verbose:
                        print("Checking %s message %s" % (mbox, mnum))

                    # Record the message-ID header (or generate one from other headers)
                    msg_id = get_message_id(mp, options.use_checksum, options.use_id_in_checksum)

                    # Store message only when verbose is enabled (to print it later on)
                    if options.verbose:
                        msg_map[mnum] = mp

                    if msg_id:
                        # If we've seen this message before, record it as one to be
                        # deleted in this mailbox.
                        if msg_id in msg_ids:
                            print ("Message %s_%s is a duplicate of %s and %s be marked as deleted" % (
                                           mbox, mnum, msg_ids[msg_id], options.dry_run and "would" or "will"))
                            if options.verbose:
                                print ("Subject: %s\nFrom: %s\nDate: %s\n" % (mp['Subject'], mp['From'], mp['Date']))
                            msgs_to_delete.append(mnum)
                        # Otherwise record the fact that we've seen it
                        else:
                            msg_ids[msg_id] = mbox + '_' + mnum

                print ("%s message(s) in %s processed" % (min(len(msgnums), i + chunkSize), mbox))

            # OK - we've been through this mailbox, and msgs_to_delete holds
            # a list of the duplicates we've found.

            if len(msgs_to_delete) == 0:
                print("No duplicates were found in %s" % mbox)

            else:
                if options.verbose:
                    print("These are the duplicate messages: ")
                    for mnum in msgs_to_delete:
                        print_message_info(msg_map[mnum])

                if options.dry_run:
                    print("If you had not selected the 'dry-run' option,\n%i messages would now be marked as 'deleted'." % (len(msgs_to_delete)))

                else:
                    print("Marking %i messages as deleted..." % (len(msgs_to_delete)))
                    # Deleting messages one at a time can be slow if there are many, so we batch them up
                    chunkSize = 30
                    if options.verbose: print("(in batches of %d)" % chunkSize)
                    for i in range(0, len(msgs_to_delete), chunkSize):
                        message_ids = ','.join(msgs_to_delete[i:i + chunkSize])
                        check_response(server.store(message_ids, '+FLAGS', r'(\Deleted)'))
                        if options.verbose:
                            print("Batch starting at item %d marked." % i)
                    print("Confirming new numbers...")
                    deleted = check_response(server.search(None, 'DELETED'))[0].split()
                    numdeleted = len(deleted)
                    undeleted = check_response(server.search(None, 'UNDELETED'))[0].split()
                    numundel = len(undeleted)
                    print("There are now %s messages marked as deleted and %s others in %s." % (numdeleted, numundel, mbox))
        if not options.no_close:
            server.close()
    except ImapDedupException as e:
        print >> sys.stderr, "Error:", e
    finally:
        server.logout()

def main(args):
    options, mboxes = get_arguments(args)
    process(options, mboxes)

if __name__ == '__main__':
    main(sys.argv[1:])

