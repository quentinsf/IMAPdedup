# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IMAPdedup is a command-line utility that removes duplicate email messages from IMAP mailboxes. It marks duplicates as deleted (or tags them) based on Message-ID headers or checksums of key email headers. The project is a single-file Python application with minimal dependencies (Python 3.6+ stdlib only).

## Project Structure

- [src/imapdedup/imapdedup.py](src/imapdedup/imapdedup.py): Main application logic - all core functionality
- [src/imapdedup/__init__.py](src/imapdedup/__init__.py): Package exports (`main` and `process` functions)
- [pyproject.toml](pyproject.toml): Package configuration using Hatchling build system
- [Dockerfile](Dockerfile): Docker container definition using Hatch

## Development Commands

### Running the tool

IMAPdedup can be run in any different ways:

```bash
# Direct execution (no installation needed)
python3 src/imapdedup/imapdedup.py [options] [mailboxes]

# After pip installation
imapdedup [options] [mailboxes]

# Using uv (recommended for development)
uv run imapdedup [options] [mailboxes]

# Using Docker
docker build -t imapdedup .
docker run --rm -it imapdedup [options] [mailboxes]
```

### Installation

```bash
# Standard installation
pip install imapdedup

# User installation (no admin)
pip install --user imapdedup

# Development installation
pip install -e .

# Using uv (creates/manages virtualenv automatically)
uv tool run imapdedup
uvx imapdedup
uv run imapdedup
```



## Architecture

### Core Flow

1. **Connection**: Establish IMAP connection (SSL/STARTTLS/process-based)
2. **Mailbox Processing**: Iterate through specified mailboxes (supports recursive traversal)
3. **Message Scanning**: Fetch headers in batches (default: 100 messages)
4. **Duplicate Detection**: Track message identifiers (Message-ID or checksum) in `msg_ids` dict
5. **Action**: Mark/tag/copy duplicates as configured
6. **Cleanup**: Optionally expunge deleted messages

### Key Design Decisions

- **Batch processing**: Messages are fetched and processed in chunks to handle large mailboxes efficiently
- **First-seen wins**: First occurrence of a message is kept; subsequent duplicates are marked
- **Cross-mailbox tracking**: When processing multiple mailboxes, `msg_ids` dict persists across folders, so duplicates in later folders are removed
- **Stateless**: No persistent state between runs; each execution starts fresh
- **Read-only mode**: `dry_run` option opens mailboxes in read-only mode, preventing any changes

### Important Functions

- [get_arguments()](src/imapdedup/imapdedup.py#L66): Parses command-line args, handles password retrieval (keyring/env/prompt)
- [process()](src/imapdedup/imapdedup.py#L402): Main processing loop - handles IMAP connection, mailbox iteration, and orchestrates duplicate detection
- [get_message_id()](src/imapdedup/imapdedup.py#L234): Returns Message-ID or generates checksum from headers (To/From/Subject/Date/Cc/Bcc)
- [get_msg_headers()](src/imapdedup/imapdedup.py#L374): Fetches RFC822 headers for a batch of messages
- [process_messages()](src/imapdedup/imapdedup.py#L352): Performs the actual marking/tagging/copying of duplicates

### IMAP Server Compatibility

- Default behavior marks messages as `\Deleted`; actual deletion behavior depends on server
- Some servers purge deleted messages on mailbox close (use `--no-close` to prevent)
- Custom tags (`-t` option) require server support and may not be visible in all clients
- Admin authentication (`-a` option) uses AUTHENTICATE PLAIN (RFC 3501, RFC 2595) - tested with Zimbra
- Process-based access (`-P` option) works with Dovecot's stdin/stdout mode

### Password Handling

Priority order (first found is used):
1. `-w` command-line argument
2. System keyring (`-K` option, requires `keyring` package)
3. `IMAPDEDUP_PASSWORD` environment variable
4. Interactive prompt

## External Usage Pattern

The package can be imported and used programmatically from a wrapper script:

```python
import imapdedup

options = ["-s", "server", "-u", "user", "-w", "pass", "-x"]
mboxes = ["INBOX", "Sent"]
imapdedup.process(*imapdedup.get_arguments(options + mboxes))
```

## Important Constraints

- No test suite exists in this repository
- Zero external dependencies (pure Python 3.6+ stdlib)
- Single-file architecture - all logic in [imapdedup.py](src/imapdedup/imapdedup.py)
- Message-ID must be unique per message for safe operation (not always true, e.g., Gmail)
- `imaplib._MAXLINE` is increased to 10MB to handle large folders
- Folder names with spaces must be quoted when passed as arguments
