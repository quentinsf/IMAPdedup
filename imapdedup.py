#! /usr/bin/python
# 
#  imapdedup.py
#
#  Looks for duplicate messages in an IMAP mailbox and removes all but the first.
#  Comparison is purely based on Message-ID header.
#
#  Default behaviour is purely to mark the duplicates as deleted.  Some mail clients
#  will allow you to view these and undelete them if you change your mind.
#  
#  Copyright (c) 2010 Quentin Stafford-Fraser.   All rights reserved, subject to the following:
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


import sys, getpass, re
import imaplib, hashlib
from email.parser import Parser

# IMAP responses should normally begin 'OK' - we strip that off
def check_response(resp):
    status,value = resp
    if status !='OK':
        sys.stderr.write("Error: got '%s' response: " % status)
    return value
    
def get_arguments():
    # Get arguments and create link to server
    from optparse import OptionParser
    parser = OptionParser(usage="%prog [options] <mailboxname>")
    parser.add_option("-s", "--server",dest='server',help='IMAP server')
    parser.add_option("-p", "--port",  dest='port',  help='IMAP server port', type='int')
    parser.add_option("-x", "--ssl",   dest='ssl',   action="store_true", help='Use SSL')
    parser.add_option("-u", "--user",  dest='user',  help='IMAP user name')
    parser.add_option("-w", "--password", dest='password',  help='IMAP password (Will prompt if not specified)')
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose mode")
    parser.add_option("-n", "--dry-run", dest="dry_run", action="store_true", 
                        help="Don't actually do anything, just report what would be done")
    parser.add_option("-c","--checksum", dest="use_checksum", action="store_true", 
                        help="If the message has no Message-ID header, use a checksum of From, To, Date and Subject")
    parser.add_option("-l", "--list", dest="just_list", action="store_true", 
                                            help="Just list mailboxes")

    parser.set_defaults(verbose=False, ssl=False, dry_run=False, just_list=False)
    (options, args) = parser.parse_args()
    if (not options.server) or (not options.user):
        sys.stderr.write("\nError: Must specify mailbox, server, user and password.\n\n")
        parser.print_help()
        sys.exit(1)
    if not options.password:
        options.password = getpass.getpass()
        
    return (options, args)

# Thanks to http://www.doughellmann.com/PyMOTW/imaplib/
list_response_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')

def parse_list_response(line):
    flags, delimiter, mailbox_name = list_response_pattern.match(line).groups()
    mailbox_name = mailbox_name.strip('"')
    return (flags, delimiter, mailbox_name)

def get_message_id(parsed_message, options_use_checksum = False):
    """
    Return the Message-ID header, if it exists, or a checksum of 
    From,To,Date and Subject, if not and if the user has allowed that.
    Otherwise, print a warning.
    """
    msg_id = parsed_message['Message-ID']
    if not msg_id:
        if options_use_checksum:
            md5 = hashlib.md5()
            md5.update("From:"    + str(parsed_message['From']))
            md5.update("To:"      + str(parsed_message['To']))
            md5.update("Subject:" + str(parsed_message['Subject']))
            md5.update("Date:"    + str(parsed_message['Date']))
            msg_id = md5.hexdigest()
        else:
            print "Message '%s' dated '%s' has no Message-ID header." % (
                parsed_message['Subject'], parsed_message['Date'])
            print "You might want to use the -c option."
            return None
    return msg_id


# This actually does the work
def main():
    options, args = get_arguments()
    
    if options.ssl:
        serverclass=imaplib.IMAP4_SSL
    else:
        serverclass=imaplib.IMAP4
    
    if options.port:
        server=serverclass(options.server, options.port)
    else:
        # Use the default, which will be different depending on SSL choice
        server=serverclass(options.server)
    
    try:
        server.login(options.user, options.password)
    except:
        sys.stderr.write("\nError: Login failed\n")
        sys.exit(1)
        
    # List mailboxes option
    if options.just_list:
        for mb in check_response(server.list()):
            bits = parse_list_response(mb)
            if r'\\Noselect' not in bits[0]:
                print bits[2]
        sys.exit()

    if len(args) == 0:
        sys.stderr.write("\nError: Must specify mailbox\n")
        sys.exit(1)
    mbox = args[0]
    try:
        msgs = check_response(server.select(mbox, options.dry_run))[0]
        print "There are %d messages in %s." % (int(msgs), mbox)
        deleted = check_response(server.search(None, 'DELETED'))[0].split()
        numdeleted = len(deleted)
        print "%s message(s) currently marked as deleted" % (numdeleted or "No")
        msgnums = check_response(server.search(None, 'UNDELETED'))[0].split()
        print len(msgnums),"others."        
        if options.verbose: print "Reading the others..."
        p = Parser()
        msg_ids = {}
        msgs_to_delete = []
        for mnum in msgnums:
            m = check_response(server.fetch(mnum, '(UID RFC822.HEADER)'))
            mp = p.parsestr(m[0][1])
            if options.verbose:
                print "Checking message",mnum
            msg_id = get_message_id(mp, options.use_checksum)
            if msg_id:
                if msg_ids.has_key(msg_id):
                    print "Message %s is a duplicate of %s and %s be marked as deleted" % (
                                   mnum,    msg_ids[msg_id], options.dry_run and "would" or "will")
                    if options.verbose:
                        print "Subject: %s\nFrom: %s\nDate: %s\n" % (mp['Subject'], mp['From'], mp['Date'])
                    msgs_to_delete.append(mnum)
                else:
                    msg_ids[msg_id] = mnum
        
        if len(msgs_to_delete) == 0:
            print "No duplicates were found"
            
        else:
            print "These are the duplicate message numbers:"
            print ' '.join(msgs_to_delete)
        
            if options.dry_run:
                print "If you had not selected the 'dry-run' option,\nthese messages would now be marked as 'deleted'."
            else:
                print "Marking messages as deleted..."
                msg_ids = ','.join(msgs_to_delete)
                resp = check_response(server.store(msg_ids, '+FLAGS', r'(\Deleted)'))
                print "Confirming new numbers..."
                deleted = check_response(server.search(None, 'DELETED'))[0].split()
                numdeleted = len(deleted)
                undeleted = check_response(server.search(None, 'UNDELETED'))[0].split()
                numundel= len(undeleted)
                print "There are now %d messages marked as deleted and %d others." % (numdeleted, numundel)
                
        server.close()
    finally:
        server.logout()
        
        
if __name__=='__main__':
    main()
    