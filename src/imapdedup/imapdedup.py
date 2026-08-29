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
#  Copyright (c) 2013-2022 Quentin Stafford-Fraser.
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

import argparse
import getpass
import hashlib
import imaplib
import os
import re
import socket
import sys
import time
from email.errors import HeaderParseError
from email.header import decode_header
from email.message import Message
from email.parser import BytesParser
from typing import Any

# Increase the max line length that imaplib expects to get back from the server,
# since we're often dealing with big folders and large numbers of messages.

imaplib._MAXLINE = max(10_000_000, imaplib._MAXLINE)

# Timeout in seconds for IMAP socket operations. Without this, a connection
# that has silently died can hang forever on a read instead of raising, which
# would prevent the reconnect-and-resume logic below from ever kicking in.
SOCKET_TIMEOUT = 300

# How many times to retry connecting/reconnecting to the server before giving up.
MAX_RECONNECT_ATTEMPTS = 10

class ImapDedupException(Exception):
    pass


def check_response(resp: tuple[str, list[bytes]]):
    """
    IMAP responses should normally begin 'OK'. Strip that off, or raise
    an exception if it isn't there.
    """
    status, value = resp
    if status != "OK":
        raise ImapDedupException(f"Got response: {value!s} from server")
    return value


def get_arguments(args: list[str] | None = None) -> tuple[argparse.Namespace, list[str]]:
    """
    Parse the given command-line arguments - defaults to using sys.argv
    """

    parser = argparse.ArgumentParser(
        description="Mark duplicate messages in IMAP mailboxes for deletion"
    )
    parser.add_argument(
        "-P", "--process", dest="process", help="IMAP process to access mailboxes"
    )
    parser.add_argument("-s", "--server", dest="server", help="IMAP server")
    parser.add_argument("-p", "--port", dest="port", help="IMAP server port", type=int)
    parser.add_argument("-x", "--ssl", dest="ssl", action="store_true", help="Use SSL")
    parser.add_argument("-X", "--starttls", dest="starttls", action="store_true", help="Require STARTTLS")
    parser.add_argument("-u", "--user", dest="user", help="IMAP user name")
    parser.add_argument("-a", "--authuser", dest='authuser', help='IMAP admin user')
    parser.add_argument(
        "-K",
        "--keyring",
        dest="keyring",
        nargs='?',
        const='',
        help="Keyring name to get password, no value means to use IMAP server name"
    )
    parser.add_argument(
        "-w",
        "--password",
        dest="password",
        help="IMAP password (Will prompt if not specified)",
    )
    parser.add_argument(
        "-v", "--verbose", dest="verbose", action="store_true", help="Verbose mode"
    )
    parser.add_argument(
        "-S", "--show", dest="show", action="store_true", help="Show duplicated messages"
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Don't actually do anything, just report what would be done",
    )
    parser.add_argument(
        "-c",
        "--checksum",
        dest="use_checksum",
        action="store_true",
        help="Use a checksum of several mail headers, instead of the Message-ID",
    )
    parser.add_argument(
        "-b",
        "--sentbefore",
        dest="sent_before",
        help="Only process messages sent before given date, given as d-m-y, e.g: 1-Feb-2020. Useful when there are many duplicates of each message",
    )
    parser.add_argument(
        "-m",
        "--checksum-with-id",
        dest="use_id_in_checksum",
        action="store_true",
        help="Include the Message-ID (if any) in the -c checksum.",
    )
    parser.add_argument(
        "--no-close",
        dest="no_close",
        action="store_true",
        help='Do not "close" mailbox when done. Some servers will purge deleted messages on a close command.',
    )
    parser.add_argument(
        "-l",
        "--list",
        dest="just_list",
        action="store_true",
        help="Just list mailboxes",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        dest="recursive",
        action="store_true",
        help="Remove duplicates recursively",
    )
    parser.add_argument(
        "-R",
        "--reverse",
        dest="reverse",
        action="store_true",
        help="Walk through the folders in reverse order",
    )
    parser.add_argument(
        "-t", "--only-tag", dest="tag_name", 
        help="Tag duplicates with specified tag instead of deleting them"
    )
    parser.add_argument(
        "-y", "--copy", dest="copy_mailbox", 
        help="Copy messages to specified mailbox before deleting them from current location."
    )
    parser.add_argument(
        "-d",
        "--delete",
        dest="delete_marked_messages",
        action="store_true",
        help="Delete marked messages (expunge)"
    )
    parser.add_argument('mailbox', nargs='*')

    options = parser.parse_args(args)
    mboxes = list(options.mailbox)

    if (not options.server or not options.user) and not options.process:
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

    if options.keyring == '':
        options.keyring = options.server

    if options.keyring:
        # You'll need to install the keyring module if you want to use this option.
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
    if not isinstance(line, bytes):
        return None
    m = list_response_pattern.match(line)
    if m is None:
        sys.stderr.write(f"\nError: parsing list response '{line}'")
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
    btext, _charset = hdrlist[0]
    text = btext if isinstance(btext, str) else btext.decode("utf-8", "ignore")
    return text.lstrip()


def get_message_id(
    parsed_message: Message, options_use_checksum=False, options_use_id_in_checksum=False
) -> str | None:
    """
    Normally, return the Message-ID header (or print a warning if it doesn't
    exist and return None).

    If options_use_checksum is specified, use a hash of several headers
    instead.

    For more safety, user should first do a dry run, reviewing them before
    deletion.

    If options_use_id_in_checksum is specified, then the Message-ID will be
    included in the header checksum, otherwise it is excluded.
    """
    try:
        if options_use_checksum:
            md5 = hashlib.md5(usedforsecurity=False)
            sha = hashlib.sha256(usedforsecurity=False)
            sha3 = hashlib.sha3_256(usedforsecurity=False)
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
                subj, date = str_header(parsed_message, "Subject"), str_header(parsed_message, "Date")
                print(f"Message '{subj}' dated '{date}' has no Message-ID header.")
                print("You might want to use the -c option.")
                return None
        return msg_id.lstrip()

    except (ValueError, HeaderParseError):
        print(
            "WARNING: There was an exception trying to parse the headers of this message."
        )
        print("It may be corrupt, and you might consider deleting it.")
        print("Subject:", parsed_message.get("Subject"))
        print("From:", parsed_message.get("From"))
        print("Date:", parsed_message.get("Date"))
        print("Message skipped.")
        return None


def get_mailbox_list(server: imaplib.IMAP4, directory: str = '""', pattern: str = '"*"') -> list[str]:
    """
    Return a list of usable mailbox names which match the pattern.
    """
    resp = []
    for mb in check_response(server.list(directory, pattern)):
        if mb is None:
            continue
        bits = parse_list_response(mb)
        if rb"\\Noselect" not in bits[0]:
            resp.append(bits[2].decode())
    return resp


def get_matching_uids(server: imaplib.IMAP4, query: str, sent_before: str | None) -> list[int]:
    """
    Return a list of IMAP UIDs of messages matching the given query in the
    selected folder. UIDs (unlike sequence numbers) stay stable for the life
    of a message in a mailbox, so it's safe to hold onto them across the
    fetch/store calls we make later in processing this mailbox.
    """
    resp = []
    if (sent_before is not None):
        query = f"{query} SENTBEFORE {sent_before}"
        print(f"Getting matching messages sent before {sent_before}")
    deleted_info = check_response(server.uid("search", None, query))
    if deleted_info and deleted_info[0]:
        # If neither None nor empty nor [None], then
        # the first item should be a list of UIDs
        resp = [int(n) for n in deleted_info[0].split()]
    return resp

def get_deleted_uids(server: imaplib.IMAP4, sent_before: str | None) -> list[int]:
    """
    Return a list of UIDs of deleted messages in the folder.
    """
    return get_matching_uids(server, "DELETED", sent_before)

def get_undeleted_uids(server: imaplib.IMAP4, sent_before: str | None) -> list[int]:
    """
    Return a list of UIDs of non-deleted messages in the folder.
    """
    return get_matching_uids(server, "UNDELETED", sent_before)

def get_tagged_uids(server: imaplib.IMAP4, tag_name: str, sent_before: str | None) -> list[int]:
    """
    Return a list of UIDs of tagged messages in the folder.
    """
    return get_matching_uids(server, f"KEYWORD {tag_name}", sent_before)


def process_messages(server: imaplib.IMAP4, uids_to_delete: list[int], tag_name: str | None = None, copy_mailbox: str | None = None):
    """
    Actually do whatever we want to do to duplicates.
    Tag them with (\\Deleted) or the specified tag_name.
    Copy them to another mailbox first if copy_mailbox specified.
    """
    uid_string = ",".join(map(str, uids_to_delete))
    action = tag_name or r"(\Deleted)"
    if copy_mailbox:
        check_response(
            server.uid("copy", uid_string, copy_mailbox)
        )
    check_response(
        server.uid("store", uid_string, "+FLAGS", action)
    )


def delete_marked_messages(server: imaplib.IMAP4):
    print("Expunging deleted messages...")
    check_response(server.expunge())


def get_msg_headers(server: imaplib.IMAP4, uids: list[int]) -> list[tuple[int, bytes]]:
    """
    Get the dict of headers for each message in the list of provided UIDs.
    Return a list of tuples:  [ (uid, header_bytes), (uid, header_bytes)... ]
    """
    # Get the header info for each message
    uids_str = ",".join(map(str, uids))
    ms = check_response(server.uid("fetch", uids_str, "(RFC822.HEADER)"))

    # Each message we asked for normally shows up as a (info, header_bytes) tuple,
    # e.g. (b'123 (UID 456 RFC822.HEADER {1234}', b'...headers...'), followed by a
    # plain b')' entry to close the parenthesised list. However, some servers also
    # mark the message \Seen as a side effect of this fetch and send an unsolicited
    # "* 123 FETCH (FLAGS (\Seen))" update, which imaplib lumps into this same
    # list (it only buckets untagged responses by type, not by which command
    # triggered them). That extra entry breaks any assumption of a fixed number
    # of items per message, so we parse the UID out of each tuple's info line
    # instead of relying on position, and ignore anything else. A UID FETCH's
    # response always includes a "UID <n>" data item regardless of what other
    # items were requested (RFC 3501 section 6.4.8).
    resp: list[tuple[int, bytes]] = []
    for item in ms:
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        info, hinfo = item
        match = re.search(rb"UID\s+(\d+)", info)
        if match:
            resp.append((int(match.group(1)), hinfo))
    return resp


def print_message_info(parsed_message: Message):
    print("From: " + str_header(parsed_message, "From"))
    print("To: " + str_header(parsed_message, "To"))
    if cc := str_header(parsed_message, "Cc"):
        print("Cc:", cc)
    if bcc := str_header(parsed_message, "Bcc"):
        print("Bcc:", bcc)
    print("Subject: " + str_header(parsed_message, "Subject"))
    print("Date: " + str_header(parsed_message, "Date"))
    print()


def add_quotes(mbox: str) -> str:
    if " " in mbox and (mbox[0] != '"' or mbox[-1] != '"'):
        mbox = '"' + mbox + '"'
    return mbox


def process_mailbox(
    server: imaplib.IMAP4,
    mbox: str,
    options,
    msg_ids: dict[str, str],
    checkpoints: dict[str, int],
):
    """
    Scan a single mailbox for duplicates against msg_ids (which also holds
    entries from any mailboxes already processed in this run) and mark/tag/
    copy them.

    If checkpoints holds a UID for this mailbox left over from an attempt
    that was interrupted by a connection drop, resume scanning after it
    instead of starting the mailbox over. Duplicates found in each batch are
    marked immediately, and the checkpoint is only advanced once that marking
    has succeeded - so a connection drop can never leave a found duplicate
    unmarked while the checkpoint already considers that batch done.
    """
    parser = BytesParser()
    uids_to_delete: list[int] = []  # accumulated across the mailbox, for reporting only
    msg_map = {}

    # Make sure mailbox name is surrounded by quotes if it contains a space
    mbox = add_quotes(mbox)

    # Select the mailbox
    msgs = check_response(server.select(mailbox=mbox, readonly=options.dry_run))[0]
    print(f"There are {int(msgs)} messages in {mbox}.")

    # Check how many messages are already marked 'deleted'...
    numdeleted = len(get_deleted_uids(server, options.sent_before))
    print(f'{numdeleted or "No"} message(s) currently marked as deleted in {mbox}')

    # Now get a list of the ones that aren't deleted.
    # That's what we'll actually use.
    all_uids = get_undeleted_uids(server, options.sent_before)

    start_index = 0
    checkpoint_uid = checkpoints.get(mbox)
    if checkpoint_uid is not None:
        try:
            start_index = all_uids.index(checkpoint_uid) + 1
            print(f"Resuming {mbox} after UID {checkpoint_uid} ({start_index} message(s) already processed).")
        except ValueError:
            print(f"Checkpoint UID {checkpoint_uid} no longer present in {mbox}; restarting scan for this mailbox.")

    if start_index == 0:
        # Starting (or restarting) this mailbox from scratch: forget any
        # sightings recorded against it by an earlier, interrupted attempt,
        # so a message already seen once isn't mistaken for a duplicate of
        # itself. Sightings from other, already-completed mailboxes are left
        # untouched.
        stale_prefix = f"{mbox}_"
        for stale_id in [mid for mid, label in msg_ids.items() if label.startswith(stale_prefix)]:
            del msg_ids[stale_id]

    uids = all_uids[start_index:]
    print(f"{len(uids)} others in {mbox}")

    chunkSize = 100
    if options.verbose:
        print(f"Reading the others... (in batches of {chunkSize})")

    for i in range(0, len(uids), chunkSize):
        if options.verbose:
            print(f"Batch starting at item {start_index + i}")

        chunk = uids[i: i + chunkSize]
        chunk_uids_to_delete = []

        # and parse them.
        for uid, hinfo in get_msg_headers(server, chunk):
            # Parse the header info into a Message object
            mp = parser.parsebytes(hinfo)

            if options.verbose:
                print(f"Checking {mbox} message {uid}")
                # Store message only when verbose is enabled (to print it later on)
                msg_map[uid] = mp

            # Record the message-ID header (or generate one from other headers)
            msg_id = get_message_id(
                mp, options.use_checksum, options.use_id_in_checksum
            )

            if msg_id:
                # If we've seen this message before, record it as one to be
                # deleted in this mailbox.
                if msg_id in msg_ids:
                    print(
                        f"Message {mbox}_{uid} is a duplicate of {msg_ids[msg_id]}" +
                         " and {} be {}".format(
                            options.dry_run and "would" or "will",
                            f"tagged as '{options.tag_name}'" if options.tag_name else "marked as deleted",
                        )
                    )
                    if options.show or options.verbose:
                        print("Subject:", mp["Subject"])
                        print("From:", mp["From"])
                        print("Date:", mp["Date"])
                    chunk_uids_to_delete.append(uid)
                # Otherwise just record the fact that we've seen it
                else:
                    msg_ids[msg_id] = f"{mbox}_{uid}"

        # Mark this batch's duplicates right away, before moving the
        # checkpoint past them - see the docstring for why the ordering
        # matters.
        if chunk_uids_to_delete and not options.dry_run:
            process_messages(server, chunk_uids_to_delete, options.tag_name, options.copy_mailbox)
        uids_to_delete.extend(chunk_uids_to_delete)
        checkpoints[mbox] = chunk[-1]

        print(f"{start_index + min(len(uids), i + chunkSize)} message(s) in {mbox} processed")

    # OK - we've been through this mailbox, and uids_to_delete holds a list
    # of the duplicates we've found (and, unless this was a dry run, already
    # marked). Note that if a connection drop caused this mailbox to be
    # resumed partway through, uids_to_delete (and msg_map, for the verbose
    # dump below) only cover what was found since the resume point - earlier
    # duplicates were already marked in a prior, interrupted call and aren't
    # re-counted here, so this summary can undercount after a resume even
    # though nothing was left unmarked.

    if not uids_to_delete:
        print(f"No duplicates were found in {mbox}")

    else:
        if options.verbose:
            print("These are the duplicate messages:\n")
            for uid in uids_to_delete:
                print_message_info(msg_map[uid])

        if options.dry_run:
            actioned = f"tagged as '{options.tag_name}'" if options.tag_name else "marked as deleted"
            print(
                "If you had NOT selected the 'dry-run' option,\n"
                f"  {len(uids_to_delete)} messages would now be {actioned}."
            )

        else:
            if options.copy_mailbox:
                print(f"Copied {len(uids_to_delete)} messages to '{options.copy_mailbox}'.")
            if options.tag_name:
                print(f"Tagged {len(uids_to_delete)} messages as '{options.tag_name}'.")
            else:
                print(f"Marked {len(uids_to_delete)} messages as deleted.")
            print("Confirming new numbers...")
            numdeleted = len(get_deleted_uids(server, options.sent_before))
            numundel = len(get_undeleted_uids(server, options.sent_before))
            print(
                "There are now {} messages marked as deleted and {} others in {}.".format(numdeleted, numundel, mbox)
            )
            if options.tag_name:
                numtagged = len(get_tagged_uids(server, options.tag_name, options.sent_before))
                print(
                "There are now {} messages tagged as '{}' in {}.".format(numtagged, options.tag_name, mbox)
            )

    if options.delete_marked_messages:
        delete_marked_messages(server)


def connect_and_login(options) -> imaplib.IMAP4:
    """
    Connect to the IMAP server (or process) described by options, and log in.
    Raises OSError on connection failure, or ImapDedupException on login
    failure. Used both for the initial connection and to reconnect after a
    dropped connection mid-run.
    """
    serverclass: type[Any]
    if options.process:
        serverclass = imaplib.IMAP4_stream
    elif options.ssl:
        serverclass = imaplib.IMAP4_SSL
    else:
        serverclass = imaplib.IMAP4

    if options.process:
        server = serverclass(options.process)
    elif options.port:
        server = serverclass(options.server, options.port, timeout=SOCKET_TIMEOUT)
    else:
        # Use the default, which will be different depending on SSL choice
        server = serverclass(options.server, timeout=SOCKET_TIMEOUT)

    #  server.debug = 4  # If you want to see what's going on

    if ("STARTTLS" in server.capabilities) and hasattr(server, "starttls"):
        server.starttls()
    elif options.starttls:
        raise ImapDedupException("Server did not offer TLS")
    elif not options.ssl:
        sys.stderr.write("\nWarning: Unencrypted connection\n")

    if not options.process:
        try:
            if options.authuser:
                # Authenticate command - more info in RFC2501 sect 6.2.2
                # and RFC2595 sect 6.
                authcb = lambda resp: f"{options.user}\x00{options.authuser}\x00{options.password}"
                server.authenticate("PLAIN", authcb)
            else:
                # Standard single user password-based login
                server.login(options.user, options.password)
        except Exception as e:
            raise ImapDedupException(f"Login failed: {e}") from e

    return server


def reconnect(options, max_attempts: int = MAX_RECONNECT_ATTEMPTS) -> imaplib.IMAP4:
    """
    Repeatedly try to reconnect and log back in to the server, with
    exponential backoff. Used to recover from a connection dropped mid-run,
    so processing can resume from the last checkpoint instead of starting
    the whole mailbox over.
    """
    for attempt in range(max_attempts):
        print(f"Reconnecting to the server (attempt {attempt + 1}/{max_attempts})...")
        try:
            server = connect_and_login(options)
            print("Reconnected.")
            return server
        except (OSError, ImapDedupException) as e:
            print(f"Reconnection attempt {attempt + 1} failed: {e}")
            if attempt + 1 == max_attempts:
                raise ImapDedupException(f"Failed to reconnect after {max_attempts} attempts") from e
            wait_time = min(60, 5 * (2 ** attempt))
            print(f"Waiting {wait_time}s before retrying...")
            time.sleep(wait_time)
    raise ImapDedupException("Failed to reconnect")


# This actually does the work
def process(options, mboxes: list[str]):
    try:
        server = connect_and_login(options)
    except OSError as e:
        sys.stderr.write(
            "\nFailed to connect to server. Might be host, port or SSL settings?\n"
        )
        sys.stderr.write(f"{e}\n\n")
        sys.exit(1)
    except ImapDedupException as e:
        sys.stderr.write(f"\nError: {e}\n\n")
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
        mboxes.extend(get_mailbox_list(server, parent, pattern))
        print(f"Working recursively from mailbox {parent}. There are {len(mboxes)} total mailboxes.")

    if options.reverse:
        mboxes.reverse()

    if len(mboxes) > 1:
        print("Working with mailboxes in order: {}".format(", ".join(mboxes)))

    # OK - let's get started.
    # Iterate through a set of named mailboxes and delete the later messages discovered.
    try:
        # Create a list of previously seen message IDs, in any mailbox
        msg_ids: dict[str, str] = {}
        # Per-mailbox "last processed UID" checkpoints, used to resume a scan
        # after a dropped connection instead of starting the mailbox over.
        # This only lives for the duration of this run - it isn't persisted
        # to disk, so a killed/restarted process still rescans from scratch.
        checkpoints: dict[str, int] = {}
        for mbox in mboxes:
            for attempt in range(MAX_RECONNECT_ATTEMPTS):
                try:
                    process_mailbox(server, mbox, options, msg_ids, checkpoints)
                    break
                except (imaplib.IMAP4.abort, socket.error, socket.timeout, TimeoutError, OSError) as e:
                    print(f"Connection error while processing '{mbox}' (attempt {attempt + 1}/{MAX_RECONNECT_ATTEMPTS}): {e}")
                    if attempt + 1 == MAX_RECONNECT_ATTEMPTS:
                        raise ImapDedupException(f"Failed to process '{mbox}' after {MAX_RECONNECT_ATTEMPTS} attempts") from e
                    time.sleep(5)
                    server = reconnect(options)

        if not options.no_close:
            server.close()

    except ImapDedupException as e:
        print("Error:", e, file=sys.stderr)
    finally:
        server.logout()

def main():
    options, mboxes = get_arguments()
    process(options, mboxes)

if __name__ == "__main__":
    main()
