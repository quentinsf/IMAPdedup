#! /usr/bin/env python3
#
#  imapdedup.py
#
#  Looks for duplicate messages in a set of IMAP mailboxes and removes all but the first.
#  Comparison is normally based on the Message-ID header, or a multi-header checksum (-c, -m).
#
#  This version uses IMAP UIDs for persistent message identification, includes checkpointing
#  to resume across network disconnects, handles server throttling backoff, supports OAuth2
#  authentication with automatic token refresh, and performs smart decoded body/attachment verification.
#
#  Copyright (c) 2013-2022 Quentin Stafford-Fraser.
#  All rights reserved, subject to the following:
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
import html
import imaplib
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta
from email.errors import HeaderParseError
from email.header import decode_header
from email.message import Message
from email.parser import BytesParser
from typing import Any, Dict, List, Optional, Tuple, Type

# Increase the max line length that imaplib expects to get back from the server,
# since we're often dealing with big folders and large numbers of messages.
imaplib._MAXLINE = max(10_000_000, imaplib._MAXLINE)

# Timeout in seconds for IMAP socket operations (increased for huge mailboxes/expunge).
SOCKET_TIMEOUT = 300

# --- OAuth2 Helper Code ---
IMAP_SERVERS = {
    'gmail.com': 'imap.gmail.com',
    'googlemail.com': 'imap.gmail.com',
    'outlook.com': 'outlook.office365.com',
    'office365.com': 'outlook.office365.com',
    'hotmail.com': 'outlook.office365.com',
    'live.com': 'outlook.office365.com',
}


def get_server_details(email_address: str, custom_server_map: Optional[Dict[str, str]] = None) -> str:
    """Determines the IMAP server hostname from the email address domain."""
    domain = email_address.split('@')[-1].lower()
    if custom_server_map and domain in custom_server_map:
        return custom_server_map[domain]
    if domain in IMAP_SERVERS:
        return IMAP_SERVERS[domain]
    raise ValueError(
        f"Error: Unsupported email domain '{domain}'. Please specify --server or --server-map {domain}=<imap_server>."
    )


def find_oauth2_token_file(email_address: str, custom_path: Optional[str] = None) -> str:
    """Finds the OAuth2 token file for the specified email address."""
    if custom_path:
        if os.path.exists(custom_path):
            return custom_path
        raise FileNotFoundError(f"Error: Specified token file not found at '{custom_path}'.")

    # Search in common token directories
    base_dirs = [
        os.getcwd(),
        os.path.dirname(os.path.abspath(__file__)),
        os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")),
        os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")),
    ]

    sub_dirs = [
        os.path.join("oauth2", "oauth2_imap", "tokens"),
        os.path.join("oauth2_imap", "tokens"),
        "tokens",
        os.path.join("oauth2", "oauth2_imap"),
        "oauth2_imap",
        ".",
    ]

    candidate_filenames = [
        f"oauth2_tokens_thunderbird_office365_{email_address}.txt",
        f"oauth2_tokens_thunderbird_gmail_{email_address}.txt",
        f"oauth2_tokens_office365_{email_address}.txt",
        f"oauth2_tokens_gmail_{email_address}.txt",
        f"oauth2_tokens_{email_address}.txt",
    ]

    for base in base_dirs:
        for sub in sub_dirs:
            token_dir = os.path.join(base, sub)
            if not os.path.isdir(token_dir):
                continue
            for fname in candidate_filenames:
                p = os.path.join(token_dir, fname)
                if os.path.isfile(p):
                    return p
            # Also search for any file containing the email address
            try:
                for f in os.listdir(token_dir):
                    if email_address.lower() in f.lower() and f.endswith(".txt") and "token" in f.lower():
                        return os.path.join(token_dir, f)
            except OSError:
                pass

    raise FileNotFoundError(f"Error: OAuth2 token file for '{email_address}' not found in any standard token directory.")


def read_oauth2_tokens(email_address: str, custom_path: Optional[str] = None) -> Tuple[str, str]:
    """Reads the access and refresh tokens from the token file."""
    token_path = find_oauth2_token_file(email_address, custom_path)
    with open(token_path, "r", encoding="utf-8") as f:
        access_token = f.readline().strip()
        refresh_token = f.readline().strip()
    if not access_token:
        raise ValueError(f"Error: Access token is missing from '{token_path}'.")
    return access_token, refresh_token


def build_xoauth2_string(user: str, access_token: str) -> bytes:
    """Constructs the authentication string required for IMAP XOAUTH2."""
    auth_string = f"user={user}\1auth=Bearer {access_token}\1\1"
    return auth_string.encode("utf-8")


def refresh_token(email_address: str) -> bool:
    """
    Runs the external oauth2_imap script or executable to refresh the OAuth2 token file.
    """
    print(f"[*] Attempting to refresh OAuth2 token for {email_address}...")
    base_dirs = [
        os.getcwd(),
        os.path.dirname(os.path.abspath(__file__)),
        os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")),
        os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")),
    ]
    sub_dirs = [
        os.path.join("oauth2", "oauth2_imap"),
        "oauth2_imap",
        ".",
    ]

    script_names = ["oauth2_imap.exe", "oauth2_imap"]
    if sys.platform != "win32":
        script_names = ["oauth2_imap", "oauth2_imap.exe"]

    target_script = None
    target_dir = None

    for base in base_dirs:
        for sub in sub_dirs:
            d = os.path.join(base, sub)
            if not os.path.isdir(d):
                continue
            for sname in script_names:
                sp = os.path.join(d, sname)
                if os.path.isfile(sp):
                    target_script = sp
                    target_dir = d
                    break
            if target_script:
                break
        if target_script:
            break

    if not target_script or not target_dir:
        print("[!] Error: Could not find oauth2_imap or oauth2_imap.exe to refresh token.")
        return False

    original_dir = os.getcwd()
    try:
        os.chdir(target_dir)
        cmd = [target_script, email_address]
        if sys.platform == "win32" and not target_script.endswith(".exe"):
            cmd = ["perl", target_script, email_address]
        print(f"[*] Running command: '{' '.join(cmd)}' in '{target_dir}'")
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("[+] Token refresh script executed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: Token refresh script failed with exit code {e.returncode}.\n{e.stderr}")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred during token refresh: {e}")
        return False
    finally:
        os.chdir(original_dir)


class ImapDedupException(Exception):
    pass


def check_response(resp: Tuple[str, List[bytes]]):
    """
    IMAP responses should normally begin 'OK'. Strip that off, or raise
    an exception if it isn't there.
    """
    status, value = resp
    if status != "OK":
        raise ImapDedupException(f"Got response: {str(value)} from server")
    return value


def get_arguments(args: Optional[List[str]] = None) -> Tuple[argparse.Namespace, List[str]]:
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
    parser.add_argument("-u", "--user", dest="user", help="IMAP user name or email address")
    parser.add_argument(
        "-o", "--oauth2", dest="oauth2", action="store_true", help="Use OAuth2 for authentication"
    )
    parser.add_argument(
        "--token-file", dest="token_file", help="Path to OAuth2 token file"
    )
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
        "--check-body",
        dest="check_body",
        action="store_true",
        default=True,
        help="When header checksums match, verify message bodies/attachments are identical before marking duplicate (default: enabled)",
    )
    parser.add_argument(
        "--no-check-body",
        dest="check_body",
        action="store_false",
        help="Do not verify message bodies; assume header hash match means duplicate",
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
    parser.add_argument(
        "--server-map",
        "--imap-server-map",
        dest="server_maps",
        action="append",
        metavar="DOMAIN=SERVER",
        help="Map a domain to an IMAP server (e.g. example.org=outlook.office365.com). Can be specified multiple times.",
    )
    parser.add_argument('mailbox', nargs='*')

    options = parser.parse_args(args)
    mboxes = options.mailbox

    options.custom_server_map = {}
    if options.server_maps:
        for entry in options.server_maps:
            if '=' in entry:
                dom, srv = entry.split('=', 1)
            elif ':' in entry:
                dom, srv = entry.split(':', 1)
            else:
                sys.stderr.write(f"\nError: Invalid --server-map format '{entry}'. Use domain=server.\n")
                sys.exit(1)
            options.custom_server_map[dom.strip().lower()] = srv.strip()

    if not options.process and not options.user:
        sys.stderr.write("\nError: Must specify user with -u/--user.\n\n")
        parser.print_help()
        sys.exit(1)

    if options.oauth2:
        options.ssl = True
        if not options.server and options.user:
            try:
                options.server = get_server_details(options.user, options.custom_server_map)
                if options.verbose:
                    print(f"Inferred IMAP server: {options.server}", file=sys.stderr)
            except ValueError as e:
                sys.stderr.write(f"\n{e}\n\n")
                parser.print_help()
                sys.exit(1)

    if not options.server and not options.process:
        sys.stderr.write("\nError: Must specify server with -s/--server.\n\n")
        parser.print_help()
        sys.exit(1)

    if len(mboxes) == 0 and not options.just_list:
        sys.stderr.write(
            "\nError: Must specify at least one mailbox (or use -l/--list).\n\n"
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
        import keyring
        options.password = keyring.get_password(options.keyring, options.user)

    if not options.password and not options.process and not options.oauth2:
        options.password = os.getenv("IMAPDEDUP_PASSWORD") or getpass.getpass()

    return (options, mboxes)


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
    """
    Return the value of the given header, properly decoding RFC 2047 encoded parts.
    """
    raw_val = parsed_message.get(name, "")
    if not raw_val:
        return ""
    try:
        hdrlist = decode_header(raw_val)
        parts = []
        for btext, charset in hdrlist:
            if isinstance(btext, str):
                parts.append(btext)
            elif isinstance(btext, bytes):
                if charset:
                    try:
                        parts.append(btext.decode(charset, "ignore"))
                    except (LookupError, UnicodeDecodeError):
                        parts.append(btext.decode("utf-8", "ignore"))
                else:
                    parts.append(btext.decode("utf-8", "ignore"))
        return " ".join(parts).lstrip()
    except Exception:
        return str(raw_val).lstrip()


def get_message_id(
    parsed_message: Message, options_use_checksum=False, options_use_id_in_checksum=False
) -> Optional[str]:
    """
    Normally, return the Message-ID header (or print a warning if it doesn't exist and return None).
    If options_use_checksum is specified, use hash of several headers (From, To, Subject, Date,
    Cc, Bcc, Content-Type, and optionally Message-ID).
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
            update(("Content-Type:" + str_header(parsed_message, "Content-Type")).encode())
            if options_use_id_in_checksum:
                update(("Message-ID:" + str_header(parsed_message, "Message-ID")).encode())
            msg_id = md5.hexdigest() + "|" + sha.hexdigest() + "|" + sha3.hexdigest()
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
        return msg_id.lstrip()

    except (ValueError, HeaderParseError):
        print("WARNING: There was an exception trying to parse the headers of this message.")
        print(f"Subject: {parsed_message.get('Subject')}\nFrom: {parsed_message.get('From')}\nDate: {parsed_message.get('Date')}\n")
        print("Message skipped.")
        return None


def extract_smart_body_hash(raw_msg_bytes: bytes) -> str:
    """
    Computes a robust hash of the email body and attachments, resilient to
    server-side HTML alterations (e.g. Gmail vs Office 365 metadata/CSS changes).

    1. For text content:
       - Prefers decoded text/plain content (normalizing whitespace and line endings).
       - If only text/html is present, strips scripts, styles, comments, and tags,
         decodes HTML entities, and collapses whitespace.
    2. For attachments:
       - Computes SHA-256 over the exact decoded binary attachment payloads and
         normalizes attachment filenames.
    """
    if not raw_msg_bytes:
        return ""

    try:
        msg = BytesParser().parsebytes(raw_msg_bytes)
    except Exception:
        return hashlib.sha256(raw_msg_bytes.replace(b"\r\n", b"\n").strip()).hexdigest()

    text_parts = []
    html_parts = []
    attachments = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type().lower()
        disposition = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename()

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = part.get_payload() or b""
            if isinstance(payload, str):
                payload = payload.encode("utf-8", "replace")

        # Check if this part is an attachment
        if "attachment" in disposition or filename:
            att_hash = hashlib.sha256(payload).hexdigest()
            fname_clean = str(filename or "").strip().lower()
            attachments.append((fname_clean, len(payload), att_hash))
        elif content_type == "text/plain":
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")
            text_clean = "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").split("\n")).strip()
            if text_clean:
                text_parts.append(text_clean)
        elif content_type == "text/html":
            charset = part.get_content_charset() or "utf-8"
            try:
                raw_html = payload.decode(charset, errors="replace")
            except Exception:
                raw_html = payload.decode("utf-8", errors="replace")
            cleaned_html = re.sub(r"(?is)<(script|style).*?>.*?(</\1>)", " ", raw_html)
            cleaned_html = re.sub(r"(?is)<!--.*?-->", " ", cleaned_html)
            cleaned_html = re.sub(r"<[^>]+>", " ", cleaned_html)
            cleaned_html = html.unescape(cleaned_html)
            text_clean = " ".join(cleaned_html.split())
            if text_clean:
                html_parts.append(text_clean)
        elif not content_type.startswith("text/"):
            # Other non-text binary part (inline image, embedded object, etc.)
            att_hash = hashlib.sha256(payload).hexdigest()
            attachments.append(("", len(payload), att_hash))

    if text_parts:
        content_repr = "\n---\n".join(text_parts)
    elif html_parts:
        content_repr = "\n---\n".join(html_parts)
    else:
        content_repr = ""

    attachments.sort()
    att_repr = ";".join(f"{fname}:{size}:{h}" for fname, size, h in attachments)

    final_str = f"BODY:{content_repr}\nATTACHMENTS:{att_repr}"
    return hashlib.sha256(final_str.encode("utf-8")).hexdigest()


def get_mailbox_list(server: imaplib.IMAP4, directory: str = '""', pattern: str = '"*"') -> List[str]:
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


def add_quotes(mbox: str) -> str:
    if len(mbox) >= 2 and mbox[0] == '"' and mbox[-1] == '"':
        return mbox
    if " " in mbox or "\\" in mbox:
        return f'"{mbox}"'
    return mbox


def strip_quotes(mbox: str) -> str:
    if len(mbox) >= 2 and mbox[0] == '"' and mbox[-1] == '"':
        return mbox[1:-1]
    return mbox


def print_message_info(parsed_message: Message):
    print("From: " + str_header(parsed_message, "From"))
    print("To: " + str_header(parsed_message, "To"))
    print("Cc: " + str_header(parsed_message, "Cc"))
    print("Bcc: " + str_header(parsed_message, "Bcc"))
    print("Subject: " + str_header(parsed_message, "Subject"))
    print("Date: " + str_header(parsed_message, "Date"))
    print("Content-Type: " + str_header(parsed_message, "Content-Type"))
    print("")


def connect_and_login(options: argparse.Namespace) -> imaplib.IMAP4:
    """Establishes a connection with a timeout and authenticates to the IMAP server."""
    if options.oauth2:
        options.ssl = True
        if not options.server and options.user:
            custom_map = getattr(options, 'custom_server_map', None)
            options.server = get_server_details(options.user, custom_map)
            if options.verbose:
                print(f"Inferred IMAP server: {options.server}", file=sys.stderr)

    try:
        if options.process:
            server = imaplib.IMAP4_stream(options.process)
            server.sock.settimeout(SOCKET_TIMEOUT)
        elif options.ssl:
            server = imaplib.IMAP4_SSL(
                host=options.server,
                port=options.port or imaplib.IMAP4_SSL_PORT,
                timeout=SOCKET_TIMEOUT,
            )
        else:
            server = imaplib.IMAP4(
                host=options.server,
                port=options.port or imaplib.IMAP4_PORT,
                timeout=SOCKET_TIMEOUT,
            )
    except (socket.error, socket.timeout, TimeoutError, OSError) as e:
        raise ImapDedupException(f"Connection to server failed: {e}")

    if ("STARTTLS" in server.capabilities) and hasattr(server, "starttls") and options.starttls:
        server.starttls()

    try:
        if not options.process:
            if options.oauth2:
                authenticated = False
                try:
                    access_token, _ = read_oauth2_tokens(options.user, options.token_file)
                    xoauth2_string = build_xoauth2_string(options.user, access_token)
                    server.authenticate('XOAUTH2', lambda x: xoauth2_string)
                    if options.verbose:
                        print("Successfully authenticated using existing OAuth2 token.")
                    authenticated = True
                except (FileNotFoundError, ValueError, imaplib.IMAP4.error) as e:
                    print(f"Could not authenticate with existing token ({e}). Refreshing token...")
                    if refresh_token(options.user):
                        try:
                            access_token, _ = read_oauth2_tokens(options.user, options.token_file)
                            xoauth2_string = build_xoauth2_string(options.user, access_token)
                            server.authenticate('XOAUTH2', lambda x: xoauth2_string)
                            print("Successfully authenticated after token refresh.")
                            authenticated = True
                        except Exception as refresh_e:
                            raise ImapDedupException(f"Authentication failed even after refreshing token: {refresh_e}")
                    else:
                        raise ImapDedupException("The OAuth2 token refresh script failed to execute successfully.")

                if not authenticated:
                    raise ImapDedupException("OAuth2 authentication failed after all attempts.")

            elif options.authuser:
                authcb = lambda resp: f"{options.user}\0{options.authuser}\0{options.password}"
                server.authenticate("PLAIN", authcb)
            else:
                server.login(options.user, options.password)
    except imaplib.IMAP4.error as e:
        raise ImapDedupException(f"Login failed: {e}")
    except Exception as e:
        raise ImapDedupException(f"Login failed: {e}")

    return server


class ImapDedupProcessor:
    def __init__(self, options: argparse.Namespace, mboxes: List[str]):
        self.options = options
        self.mboxes = [strip_quotes(m) for m in mboxes]
        self.server = connect_and_login(self.options)
        # Structure: msg_records[msg_id] = [ {'mbox': mbox, 'uid': uid, 'body_hash': Optional[str], 'label': f"{mbox}_UID_{uid}"}, ... ]
        self.msg_records: Dict[str, List[Dict[str, Any]]] = {}
        self.parser = BytesParser()
        self.checkpoints: Dict[str, str] = {}
        self.current_mailbox: Optional[str] = None

    def reconnect(self, max_attempts: int = 10):
        """Robustly reconnects to the IMAP server with retry and backoff."""
        for attempt in range(max_attempts):
            print(f"Reconnecting to the server (Attempt {attempt + 1}/{max_attempts})...")
            try:
                if hasattr(self, 'server'):
                    try:
                        self.server.logout()
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                self.server = connect_and_login(self.options)
                self.current_mailbox = None
                print("Reconnection successful.")
                return
            except Exception as e:
                print(f"Reconnection attempt {attempt + 1} failed: {e}")
                if attempt + 1 == max_attempts:
                    raise ImapDedupException(f"Failed to reconnect after {max_attempts} attempts: {e}")
                wait_time = min(60, 5 * (2 ** attempt))
                print(f"Waiting {wait_time}s before next reconnection attempt...")
                time.sleep(wait_time)

    def _get_uids_for_query(self, query: str) -> List[bytes]:
        final_query = query
        if self.options.sent_before:
            final_query = f"({query}) SENTBEFORE {self.options.sent_before}"
        uid_info = check_response(self.server.uid('search', None, final_query))
        if uid_info and uid_info[0]:
            return uid_info[0].split()
        return []

    def _get_headers_by_uid(self, uids: List[bytes]) -> List[Tuple[str, bytes]]:
        if not uids:
            return []
        uid_string = b','.join(uids)
        fetch_result = check_response(self.server.uid('fetch', uid_string, '(RFC822.HEADER)'))

        headers = []
        for i, item in enumerate(fetch_result):
            if not (isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes)):
                continue

            uid = None
            match = re.search(rb'UID\s+(\d+)', item[0])
            if match:
                uid = match.group(1).decode()
            elif (i + 1) < len(fetch_result):
                next_item = fetch_result[i + 1]
                if isinstance(next_item, bytes):
                    match = re.search(rb'UID\s+(\d+)', next_item)
                    if match:
                        uid = match.group(1).decode()

            if uid:
                headers.append((uid, item[1]))

        return headers

    def _get_body_hash_by_uid(self, mbox: str, uid: str) -> str:
        """
        Fetches the message payload by UID and returns its smart normalized hash
        (decoded plain text + attachment verification).
        Uses BODY.PEEK[] to avoid modifying the \\Seen flag.
        """
        body_bytes = b""
        original_mbox = self.current_mailbox

        try:
            if mbox != original_mbox:
                check_response(self.server.select(mailbox=add_quotes(mbox), readonly=True))
                self.current_mailbox = mbox

            try:
                ms = check_response(self.server.uid('fetch', str(uid), '(BODY.PEEK[])'))
                for item in ms:
                    if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
                        body_bytes = item[1]
                        break
            except Exception:
                body_bytes = b""

            if not body_bytes:
                try:
                    ms = check_response(self.server.uid('fetch', str(uid), '(RFC822)'))
                    for item in ms:
                        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
                            body_bytes = item[1]
                            break
                except Exception:
                    body_bytes = b""

        finally:
            if original_mbox and self.current_mailbox != original_mbox:
                check_response(self.server.select(mailbox=add_quotes(original_mbox), readonly=self.options.dry_run))
                self.current_mailbox = original_mbox

        return extract_smart_body_hash(body_bytes)

    def _process_uids_by_action(self, uids_to_act: List[str], copy_mailbox: Optional[str], tag_name: Optional[str]):
        if not uids_to_act:
            return
        uid_string = ','.join(uids_to_act)
        action = tag_name or r'(\Deleted)'
        if copy_mailbox:
            check_response(self.server.uid('copy', uid_string, copy_mailbox))
        check_response(self.server.uid('store', uid_string, '+FLAGS', action))

    def _process_mailbox(self, mbox: str):
        mbox_clean = mbox.strip()
        if not mbox_clean or mbox_clean.lower() in ["closing connection...", "processing complete."]:
            return
        mbox_quoted = add_quotes(mbox_clean)
        self.current_mailbox = mbox_clean
        try:
            check_response(self.server.select(mailbox=mbox_quoted, readonly=self.options.dry_run))
        except ImapDedupException as e:
            err_str = str(e).lower()
            if "doesn't exist" in err_str or "does not exist" in err_str or "nonexistent" in err_str or "no " in err_str:
                print(f"Warning: Mailbox '{mbox_clean}' does not exist on server. Skipping.", file=sys.stderr)
                return
            raise

        num_messages_raw = check_response(self.server.status(mbox_quoted, '(MESSAGES)'))
        num_messages = 0
        if num_messages_raw and num_messages_raw[0]:
            match = re.search(rb'MESSAGES\s+(\d+)', num_messages_raw[0])
            if match:
                num_messages = int(match.group(1))
            else:
                print(f"Warning: Could not determine number of messages for {mbox}.")
        else:
            print(f"Warning: Received an empty status response for {mbox}.")

        print(f"There are {num_messages} messages in {mbox}.")
        num_deleted_start = len(self._get_uids_for_query("DELETED"))
        print(f'{num_deleted_start or "No"} message(s) currently marked as deleted in {mbox}')

        all_uids = self._get_uids_for_query("UNDELETED")
        if not all_uids:
            print(f"No messages to process in {mbox}.")
            return

        start_index = 0
        last_processed_uid = self.checkpoints.get(mbox)
        if last_processed_uid:
            try:
                resume_index = all_uids.index(last_processed_uid.encode())
                start_index = resume_index + 1
                print(f"[*] Resuming processing for '{mbox}' from UID after {last_processed_uid}.")
            except ValueError:
                print(f"[!] Checkpoint UID {last_processed_uid} not found in '{mbox}'. Restarting scan for this mailbox.")

        if start_index == 0:
            # If starting or restarting this mailbox from message 0, clean out any old records for this mailbox
            self.msg_records = {
                mid: [r for r in recs if r["mbox"] != mbox]
                for mid, recs in self.msg_records.items()
            }
            self.msg_records = {mid: recs for mid, recs in self.msg_records.items() if recs}

        uids_to_process = all_uids[start_index:]
        if start_index > 0:
            print(f"[*] Skipped {start_index} already processed messages.")
        print(f"{len(uids_to_process)} others to process in {mbox}")

        uids_to_delete: List[str] = []
        msg_map: Dict[str, Message] = {}
        chunkSize = 100

        for i in range(0, len(uids_to_process), chunkSize):
            chunk = uids_to_process[i: i + chunkSize]
            if self.options.verbose:
                print(f"Processing batch of {len(chunk)} messages starting from UID {chunk[0].decode()}")

            headers = self._get_headers_by_uid(chunk)
            for uid, hinfo in headers:
                mp = self.parser.parsebytes(hinfo)
                if self.options.verbose or self.options.show:
                    msg_map[uid] = mp

                msg_id = get_message_id(mp, self.options.use_checksum, self.options.use_id_in_checksum)
                if msg_id:
                    current_label = f"{mbox}_UID_{uid}"
                    if msg_id in self.msg_records:
                        is_dup = False
                        matched_prior: Optional[Dict[str, Any]] = None

                        if self.options.check_body:
                            candidate_body_hash = self._get_body_hash_by_uid(mbox, uid)
                            for prior in self.msg_records[msg_id]:
                                # Never match against the exact same message (same mailbox and UID)
                                if prior["mbox"] == mbox and str(prior["uid"]) == str(uid):
                                    continue

                                if prior["body_hash"] is None:
                                    prior["body_hash"] = self._get_body_hash_by_uid(prior["mbox"], prior["uid"])

                                if candidate_body_hash == prior["body_hash"]:
                                    is_dup = True
                                    matched_prior = prior
                                    break

                            if not is_dup:
                                if not any(r["mbox"] == mbox and str(r["uid"]) == str(uid) for r in self.msg_records[msg_id]):
                                    if self.options.verbose:
                                        print(
                                            f"UID {uid} in {mbox} shares header checksum with {self.msg_records[msg_id][0]['label']} "
                                            f"but message bodies differ; keeping both."
                                        )
                                    self.msg_records[msg_id].append({
                                        "mbox": mbox,
                                        "uid": uid,
                                        "body_hash": candidate_body_hash,
                                        "label": current_label,
                                    })
                        else:
                            for prior in self.msg_records[msg_id]:
                                if prior["mbox"] == mbox and str(prior["uid"]) == str(uid):
                                    continue
                                is_dup = True
                                matched_prior = prior
                                break

                        if is_dup and matched_prior:
                            action_str = "tagged as '%s'" % self.options.tag_name if self.options.tag_name else "marked as deleted"
                            print(
                                "UID %s in %s is a duplicate of %s and %s be %s"
                                % (
                                    uid, mbox, matched_prior["label"],
                                    self.options.dry_run and "would" or "will",
                                    action_str,
                                )
                            )
                            if self.options.show or self.options.verbose:
                                print(
                                    "Subject: %s\nFrom: %s\nDate: %s\nContent-Type: %s\n"
                                    % (
                                        str_header(mp, "Subject"),
                                        str_header(mp, "From"),
                                        str_header(mp, "Date"),
                                        str_header(mp, "Content-Type"),
                                    )
                                )
                            uids_to_delete.append(uid)
                    else:
                        # First time seeing this msg_id
                        self.msg_records[msg_id] = [{
                            "mbox": mbox,
                            "uid": uid,
                            "body_hash": None,
                            "label": current_label,
                        }]

            if chunk:
                last_uid_in_chunk = chunk[-1].decode()
                self.checkpoints[mbox] = last_uid_in_chunk
                if self.options.verbose:
                    print(f"[*] Checkpoint for '{mbox}' saved at UID {last_uid_in_chunk}")

            print(f"{start_index + i + len(chunk)} of {len(all_uids)} message(s) in {mbox} scanned.")

        if not uids_to_delete:
            print(f"No new duplicates were found in {mbox}")
        elif self.options.dry_run:
            print(f"DRY-RUN: Would have marked {len(uids_to_delete)} messages in {mbox}.")
        else:
            action_str = "tagging" if self.options.tag_name else "marking"
            print(f"{action_str.capitalize()} {len(uids_to_delete)} duplicate messages in {mbox}...")
            for i in range(0, len(uids_to_delete), chunkSize):
                self._process_uids_by_action(uids_to_delete[i: i + chunkSize], self.options.copy_mailbox, self.options.tag_name)
            num_deleted_end = len(self._get_uids_for_query("DELETED"))
            print(f"There are now {num_deleted_end} messages marked as deleted in {mbox}.")
            if self.options.tag_name:
                num_tagged = len(self._get_uids_for_query(f"KEYWORD {self.options.tag_name}"))
                print(f"There are now {num_tagged} messages tagged as '{self.options.tag_name}' in {mbox}.")

        if self.options.delete_marked_messages:
            print("Expunging deleted messages...")
            try:
                check_response(self.server.expunge())
                print("Expunge complete.")
            except (socket.error, socket.timeout, TimeoutError, OSError, imaplib.IMAP4.abort) as e:
                print(f"[*] Note: Expunge command timed out ({e}). The server will finalize purge on mailbox close.")

    def run(self):
        try:
            if self.options.just_list:
                for mb in get_mailbox_list(self.server):
                    print(mb)
                return

            if self.options.recursive:
                parent = add_quotes(self.mboxes[0])
                bits = parse_list_response(check_response(self.server.list(parent, '""'))[0])
                delimiter = bits[1].decode()
                pattern = '"' + delimiter + '*"'
                all_mailboxes = get_mailbox_list(self.server, parent, pattern)
                self.mboxes.extend(all_mailboxes)
                print(f"Recursively processing {len(self.mboxes)} mailboxes starting from {parent}")

            if self.options.reverse:
                self.mboxes.reverse()

            if len(self.mboxes) > 1:
                print("Working with mailboxes in order: %s" % (", ".join(self.mboxes)))

            for mbox in self.mboxes:
                retries = 100
                for attempt in range(retries):
                    try:
                        self._process_mailbox(mbox)
                        break
                    except (imaplib.IMAP4.abort, imaplib.IMAP4.readonly, socket.error, socket.timeout, TimeoutError, OSError) as e:
                        print(f"\nConnection error or timeout while processing '{mbox}' (Attempt {attempt + 1}/{retries}): {e}")
                        if attempt + 1 == retries:
                            print(f"FATAL: Failed to process mailbox '{mbox}' after {retries} attempts.")
                            raise
                        time.sleep(5)
                        self.reconnect()
                    except imaplib.IMAP4.error as e:
                        error_str = str(e)
                        throttle_match = re.search(r'Suggested Backoff Time: (\d+)', error_str, re.IGNORECASE)
                        if throttle_match:
                            milliseconds = int(throttle_match.group(1))
                            wait_seconds = (milliseconds / 1000) + 1
                            print(f"[!] Server throttling detected while processing '{mbox}'.")
                            print(f"[*] Waiting for {wait_seconds:.1f} seconds as suggested by server (Attempt {attempt + 1}/{retries})...")
                            time.sleep(wait_seconds)
                            self.reconnect()
                        else:
                            print(f"FATAL: An unhandled IMAP error occurred: {e}")
                            raise

        finally:
            if not self.options.just_list:
                print("Closing connection...", file=sys.stderr)
            try:
                if hasattr(self, 'server') and self.server.state != 'LOGOUT':
                    if not self.options.no_close:
                        if self.mboxes:
                            try:
                                self.server.select(add_quotes(self.mboxes[-1]))
                                self.server.close()
                            except Exception:
                                pass
                    self.server.logout()
            except Exception as e:
                if not self.options.just_list:
                    print(f"Warning: Could not cleanly close or logout: {e}", file=sys.stderr)


def process(options: argparse.Namespace, mboxes: List[str]):
    processor = ImapDedupProcessor(options, mboxes)
    processor.run()


def main():
    options, mboxes = get_arguments()
    if len(mboxes) == 0 and not options.just_list:
        sys.stderr.write("\nError: Must specify at least one mailbox to process.\n")
        sys.exit(1)

    max_login_attempts = 100
    for attempt in range(max_login_attempts):
        try:
            processor = ImapDedupProcessor(options, mboxes)
            processor.run()
            if not options.just_list:
                print("\nProcessing complete.", file=sys.stderr)
            return

        except Exception as e:
            if 'AUTHENTICATE failed' in str(e) and options.oauth2:
                print(f"\nLogin failed with an authentication error (Attempt {attempt + 1}/{max_login_attempts}).", file=sys.stderr)
                if attempt + 1 < max_login_attempts:
                    print("[*] Stale token or temporary server auth issue.", file=sys.stderr)
                    print("[*] Re-running token refresh script...", file=sys.stderr)
                    print("[*] Waiting 60 seconds before retrying...", file=sys.stderr)
                    time.sleep(60)
                else:
                    print(f"\nAuthentication failed after {max_login_attempts} attempts.", file=sys.stderr)
                    sys.exit(1)
            elif isinstance(e, (socket.error, socket.timeout, TimeoutError, OSError, ImapDedupException, imaplib.IMAP4.error)):
                print(f"\nConnection or timeout error in main loop (Attempt {attempt + 1}/{max_login_attempts}): {e}", file=sys.stderr)
                if attempt + 1 < max_login_attempts:
                    print("[*] Waiting 15 seconds before retrying...", file=sys.stderr)
                    time.sleep(15)
                else:
                    print(f"\nFATAL: Exceeded maximum attempts ({max_login_attempts}). Exiting.", file=sys.stderr)
                    sys.exit(1)
            else:
                print(f"\nAn unrecoverable error occurred: {e}", file=sys.stderr)
                sys.exit(1)

        except KeyboardInterrupt:
            print("\nInterrupted by user. Exiting.")
            sys.exit(1)


if __name__ == "__main__":
    main()
