#! /usr/bin/env python3
#
#  imapdedup.py
#
#  Looks for duplicate messages in a set of IMAP mailboxes and removes all but the first.
#  Comparison is normally based on the Message-ID header.
#
#  Default behaviour is purely to mark the duplicates as deleted.  Some mail clients
#  will allow you to view these and undelete them if you change your mind.
#
#  Copyright (c) 2013-2020 Quentin Stafford-Fraser.
#  All rights reserved, subject to the following:
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

import getpass
import hashlib
import imaplib
import os
import optparse
import re
import socket
import sys
from typing import List, Dict, Tuple, Optional, Type, Any

from email.parser import BytesParser
from email.message import Message
from email.errors import HeaderParseError
from email.header import decode_header

# Increase the rather small limit on result line-length
# imposed in certain imaplib versions.
# imaplib._MAXLINE = max(2000000, imaplib._MAXLINE)


class ImapDedupException(Exception):
    pass


# IMAP responses should normally begin 'OK' - we strip that off
def check_response(resp: Tuple[str, List[bytes]]):
    status, value = resp
    if status != "OK":
        raise ImapDedupException("Got response: %s from server" % str(value))
    return value


def get_arguments(args: List[str]) -> Tuple[optparse.Values, List[str]]:
    # Get arguments and create link to server

    parser = optparse.OptionParser(usage="%prog [options] <mailboxname> [<mailboxname> ...]")
    parser.add_option(
        "-P", "--process", dest="process", help="IMAP process to access mailboxes"
    )
    parser.add_option("-s", "--server", dest="server", help="IMAP server")
    parser.add_option("-p", "--port", dest="port", help="IMAP server port", type="int")
    parser.add_option("-x", "--ssl", dest="ssl", action="store_true", help="Use SSL")
    parser.add_option("-X", "--starttls", dest="starttls", action="store_true", help="Require STARTTLS")
    parser.add_option("-u", "--user", dest="user", help="IMAP user name")
    parser.add_option("-K", "--keyring", dest="keyring", help="Keyring name to get password")
    parser.add_option(
        "-w",
        "--password",
        dest="password",
        help="IMAP password (Will prompt if not specified)",
    )
    parser.add_option(
        "-v", "--verbose", dest="verbose", action="store_true", help="Verbose mode"
    )
    parser.add_option(
        "-S", "--show", dest="show", action="store_true", help="Show duplicated messages"
    )
    parser.add_option(
        "-n",
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Don't actually do anything, just report what would be done",
    )
    parser.add_option(
        "-c",
        "--checksum",
        dest="use_checksum",
        action="store_true",
        help="Use a checksum of several mail headers, instead of the Message-ID",
    )
    parser.add_option(
        "-b",
        "--sentbefore",
        dest="sent_before",
        help="Only process messages sent before given date, given as d-m-y, e.g: 1-Feb-2020. Useful when there are many duplicates of each message",
    )
    parser.add_option(
        "-m",
        "--checksum-with-id",
        dest="use_id_in_checksum",
        action="store_true",
        help="Include the Message-ID (if any) in the -c checksum.",
    )
    parser.add_option(
        "",
        "--no-close",
        dest="no_close",
        action="store_true",
        help='Do not "close" mailbox when done. Some servers will purge deleted messages on a close command.',
    )
    parser.add_option(
        "-l",
        "--list",
        dest="just_list",
        action="store_true",
        help="Just list mailboxes",
    )
    parser.add_option(
        "-r",
        "--recursive",
        dest="recursive",
        action="store_true",
        help="Remove duplicates recursively",
    )
    parser.add_option(
        "-R",
        "--reverse",
        dest="reverse",
        action="store_true",
        help="Walk through specified folder inreverse order",
    )

    parser.set_defaults(
        verbose=False,
        show=False,
        ssl=False,
        dry_run=False,
        no_close=False,
        just_list=False,
        reverse=False,
        recursive=False
    )
    (options, mboxes) = parser.parse_args(args)
    if ((not options.server) or (not options.user)) and not options.process:
        sys.stderr.write(
            "\nError: Must specify server, user, and at least one mailbox.\n\n"
        )
        parser.print_help()
        sys.exit(1)

    if options.recursive and len(mboxes) > 1:
        sys.stderr.write("\nError: You can only specify one mailbox if you use -r.\n")
        sys.exit(1)

    if options.use_id_in_checksum and not options.use_checksum:
        sys.stderr.write("\nError: If you use -m you must also use -c.\n")
        sys.exit(1)

    if options.keyring:
        import keyring
        options.password = keyring.get_password(options.keyring, options.user)

    if not options.password and not options.process:
        # Read from IMAPDEDUP_PASSWORD env variable, or prompt for one.
        options.password = os.getenv("IMAPDEDUP_PASSWORD") or getpass.getpass()

    return (options, mboxes)


# Thanks to http://www.doughellmann.com/PyMOTW/imaplib/
list_response_pattern = re.compile(
    rb'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)'
)


def parse_list_response(line: bytes):
    m = list_response_pattern.match(line)
    if m is None:
        sys.stderr.write("\nError: parsing list response '{}'".format(str(line)))
        sys.exit(1)
    flags, delimiter, mailbox_name = m.groups()
    mailbox_name = mailbox_name.strip(b'"')
    return (flags, delimiter, mailbox_name)


def str_header(parsed_message: Message, name: str) -> str:
    """"
    Return the value (of the first instance, if more than one) of
    the given header, as a unicode string.
    """
    hdrlist = decode_header(parsed_message.get(name, ""))
    btext, charset = hdrlist[0]
    if isinstance(btext, str):
        text = btext
    else:
        text = btext.decode("utf-8", "ignore")
    return text


def get_message_id(
    parsed_message: Message, options_use_checksum=False, options_use_id_in_checksum=False
) -> Optional[str]:
    """
    Normally, return the Message-ID header (or print a warning if it doesn't
    exist and return None).

    If options_use_checksum is specified, use md5 hash of several headers
    instead.

    For more safety, user should first do a dry run, reviewing them before
    deletion. Problems are extremely unlikely, but md5 is not collision-free.

    If options_use_id_in_checksum is specified, then the Message-ID will be
    included in the header checksum, otherwise it is excluded.
    """
    try:
        if options_use_checksum:
            md5 = hashlib.md5()
            sha = hashlib.sha256()
            sha3 = hashlib.sha3_256()
            def update(x):
                md5.update(x)
                sha.update(x)
                sha3.update(x)
            update(("From:" + str_header(parsed_message, "From")).encode())
            update(("To:" + str_header(parsed_message, "To")).encode())
            update(("Subject:" + str_header(parsed_message, "Subject")).encode())
            update(("Date:" + str_header(parsed_message, "Date")).encode())
            update(("Cc:" + str_header(parsed_message, "Cc")).encode())
            update(("Bcc:" + str_header(parsed_message, "Bcc")).encode())
            if options_use_id_in_checksum:
                update(("Message-ID:" + str_header(parsed_message, "Message-ID")).encode())
            msg_id = md5.hexdigest() + "|" + sha.hexdigest() + "|" + sha3.hexdigest()
            # print(msg_id)
        else:
            msg_id = str_header(parsed_message, "Message-ID")
            if not msg_id:
                print(
                    (
                        "Message '%s' dated '%s' has no Message-ID header."
                        % (
                            str_header(parsed_message, "Subject"),
                            str_header(parsed_message, "Date"),
                        )
                    )
                )
                print("You might want to use the -c option.")
                return None
        return msg_id
    except (ValueError, HeaderParseError):
        print(
            "WARNING: There was an exception trying to parse the headers of this message."
        )
        print("It may be corrupt, and you might consider deleting it.")
        print(
            (
                "Subject: %s\nFrom: %s\nDate: %s\n"
                % (
                    parsed_message["Subject"],
                    parsed_message["From"],
                    parsed_message["Date"],
                )
            )
        )
        print("Message skipped.")
        return None


def get_mailbox_list(server: imaplib.IMAP4, directory: str = '""', pattern: str = '"*"') -> List[str]:
    """
    Return a list of usable mailbox names which match the pattern.
    """
    resp = []
    for mb in check_response(server.list(directory, pattern)):
        bits = parse_list_response(mb)
        if rb"\\Noselect" not in bits[0]:
            resp.append(bits[2].decode())
    return resp

def get_deleted_msgnums(server: imaplib.IMAP4, sent_before) -> List[int]:
    """
    Return a list of ids of deleted messages in the folder.
    """
    resp = []
    query = "DELETED"
    if (sent_before != None):
        query = query + " SENTBEFORE " + sent_before
        print("Getting deleted messages sent before " + sent_before)
    deleted_info = check_response(server.search(None, query))
    if deleted_info:   
        # If neither None nor empty, then
        # the first item should be a list of msg ids
        resp = [int(n) for n in deleted_info[0].split()]
    return resp

def get_undeleted_msgnums(server: imaplib.IMAP4, sent_before) -> List[int]:
    """
    Return a list of ids of non-deleted messages in the folder.
    """
    resp = []
    query = "UNDELETED"
    if (sent_before != None):
        query = query + " SENTBEFORE " + sent_before
        print("Getting undeleted messages sent before " + sent_before)
    undeleted_info = check_response(server.search(None, query))
    if undeleted_info:   
        # If neither None nor empty, then
        # the first item should be a list of msg ids
        resp = [int(n) for n in undeleted_info[0].split()]
    return resp


def mark_messages_deleted(server: imaplib.IMAP4, msgs_to_delete: List[int]):
    message_ids = ",".join(map(str, msgs_to_delete))
    check_response(
        server.store(message_ids, "+FLAGS", r"(\Deleted)")
    )

def get_msg_headers(server: imaplib.IMAP4, msg_ids: List[int]) -> List[Tuple[int, bytes]]:
    """
    Get the dict of headers for each message in the list of provided IDs.
    Return a list of tuples:  [ (msgid, header_bytes), (msgid, header_bytes)... ]
    The returned header_bytes can be parsed by 
    """
    # Get the header info for each message
    message_ids_str = ",".join(map(str, msg_ids))
    ms = check_response(server.fetch(message_ids_str, "(RFC822.HEADER)"))

    # There are two lines per message in the response
    resp: List[Tuple[int, bytes]] = []
    for ci in range(0, len(ms) // 2):
        mnum = int(msg_ids[ci])
        _, hinfo = ms[ci * 2]
        resp.append((mnum, hinfo))
    return resp


def print_message_info(parsed_message: Message):
    print("From: " + str_header(parsed_message, "From"))
    print("To: " + str_header(parsed_message, "To"))
    print("Cc: " + str_header(parsed_message, "Cc"))
    print("Bcc: " + str_header(parsed_message, "Bcc"))
    print("Subject: " + str_header(parsed_message, "Subject"))
    print("Date: " + str_header(parsed_message, "Date"))
    print("")


def add_quotes(mbox: str) -> str:
    if " " in mbox and (mbox[0] != '"' or mbox[-1] != '"'):
        mbox = '"' + mbox + '"'
    return mbox


# This actually does the work
def process(options, mboxes: List[str]):
    serverclass: Type[Any]
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
        sys.stderr.write(
            "\nFailed to connect to server. Might be host, port or SSL settings?\n"
        )
        sys.stderr.write("%s\n\n" % e)
        sys.exit(1)

    if ("STARTTLS" in server.capabilities) and hasattr(server, "starttls"):
        server.starttls()
    elif options.starttls:
        sys.stderr.write("\nError: Server did not offer TLS\n")
        sys.exit(1)
    elif not options.ssl:
        sys.stderr.write("\nWarning: Unencrypted connection\n")

    try:
        if not options.process:
            server.login(options.user, options.password)
    except:
        sys.stderr.write("\nError: Login failed\n")
        sys.exit(1)

    # List mailboxes option
    # Just do that and then exit
    if options.just_list:
        for mb in get_mailbox_list(server):
            print(mb)
        return

    if len(mboxes) == 0:
        sys.stderr.write("\nError: Must specify mailbox\n")
        sys.exit(1)

    # Recursive option
    # Add child mailboxes to mboxes
    if options.recursive:
        # Make sure mailbox name is surrounded by quotes if it contains a space
        parent = add_quotes(mboxes[0])
        # Fetch the hierarchy delimiter
        bits = parse_list_response(check_response(server.list(parent, '""'))[0])
        delimiter = bits[1].decode()
        pattern='"' + delimiter + '*"'
        for mb in get_mailbox_list(server, parent, pattern):
            mboxes.append(mb)
        print("Working recursively from mailbox %s. There are %d total mailboxes." % (parent, len(mboxes)))

    if options.reverse:
        mboxes.reverse()

    if len(mboxes) > 1:
        print("Working with mailboxes in order: %s" % (", ".join(mboxes)))

    # OK - let's get started.
    # Iterate through a set of named mailboxes and delete the later messages discovered.
    try:
        parser = BytesParser()  # can be the same for all mailboxes
        # Create a list of previously seen message IDs, in any mailbox
        msg_ids: Dict[str, str] = {}
        for mbox in mboxes:
            msgs_to_delete = []  # should be reset for each mbox
            msg_map = {}  # should be reset for each mbox

            # Make sure mailbox name is surrounded by quotes if it contains a space
            mbox = add_quotes(mbox)

            # Select the mailbox
            msgs = check_response(server.select(mailbox=mbox, readonly=options.dry_run))[0]
            print("There are %d messages in %s." % (int(msgs), mbox))

            # Check how many messages are already marked 'deleted'...
            numdeleted = len(get_deleted_msgnums(server, options.sent_before))
            print(
                "%s message(s) currently marked as deleted in %s"
                % (numdeleted or "No", mbox)
            )

            # Now get a list of the ones that aren't deleted. 
            # That's what we'll actually use.
            msgnums = get_undeleted_msgnums(server, options.sent_before)
            print("%s others in %s" % (len(msgnums), mbox))

            chunkSize = 100
            if options.verbose:
                print("Reading the others... (in batches of %d)" % chunkSize)

            for i in range(0, len(msgnums), chunkSize):
                if options.verbose:
                    print("Batch starting at item %d" % i)

                # and parse them.
                for mnum, hinfo in get_msg_headers(server, msgnums[i: i + chunkSize]):
                    # Parse the header info into a Message object
                    mp = parser.parsebytes(hinfo)

                    if options.verbose:
                        print("Checking %s message %s" % (mbox, mnum))
                        # Store message only when verbose is enabled (to print it later on)
                        msg_map[mnum] = mp

                    # Record the message-ID header (or generate one from other headers)
                    msg_id = get_message_id(
                        mp, options.use_checksum, options.use_id_in_checksum
                    )

                    if msg_id:
                        # If we've seen this message before, record it as one to be
                        # deleted in this mailbox.
                        if msg_id in msg_ids:
                            print(
                                "Message %s_%s is a duplicate of %s and %s be marked as deleted"
                                % (
                                    mbox, mnum, msg_ids[msg_id],
                                    options.dry_run and "would" or "will",
                                ) 
                            )
                            if options.show or options.verbose:
                                print(
                                    "Subject: %s\nFrom: %s\nDate: %s\n"
                                    % (mp["Subject"], mp["From"], mp["Date"])
                                )
                            msgs_to_delete.append(mnum)
                        # Otherwise just record the fact that we've seen it
                        else:
                            msg_ids[msg_id] = f"{mbox}_{mnum}"

                print(
                    (
                        "%s message(s) in %s processed"
                        % (min(len(msgnums), i + chunkSize), mbox)
                    )
                )

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
                    print(
                        "If you had NOT selected the 'dry-run' option,\n"
                        "  %i messages would now be marked as 'deleted'."
                        % (len(msgs_to_delete))
                    )

                else:
                    
                    print("Marking %i messages as deleted..." % (len(msgs_to_delete)))
                    # Deleting messages one at a time can be slow if there are many,
                    # so we batch them up.
                    chunkSize = 30
                    if options.verbose:
                        print("(in batches of %d)" % chunkSize)
                    for i in range(0, len(msgs_to_delete), chunkSize):
                        mark_messages_deleted(server, msgs_to_delete[i: i + chunkSize])
                        if options.verbose:
                            print("Batch starting at item %d marked." % i)
                    print("Confirming new numbers...")
                    numdeleted = len(get_deleted_msgnums(server, options.sent_before))
                    numundel = len(get_undeleted_msgnums(server, options.sent_before))
                    print(
                        "There are now %s messages marked as deleted and %s others in %s."
                        % (numdeleted, numundel, mbox)
                    )

        if not options.no_close:
            server.close()

    except ImapDedupException as e:
        print("Error:", e, file=sys.stderr)
    finally:
        server.logout()


def main(args: List[str]):
    options, mboxes = get_arguments(args)
    process(options, mboxes)


if __name__ == "__main__":
    main(sys.argv[1:])
