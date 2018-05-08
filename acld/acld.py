#!/usr/bin/env python

# Acld interface for the Network Control Framework of Bro, using Broker.

from __future__ import print_function

import argparse
import errno
import fcntl, os
import logging
import random
import re
import socket
import string
import sys
import thread
import threading
import time

from pybroker import *
from select import select
from logging.handlers import TimedRotatingFileHandler

MAX16INT = 2**16 - 1

def parseArgs():
    defaultuser = os.getlogin()
    defaulthost = socket.gethostname()
    defaultacldhost = '127.0.0.1'

    parser = argparse.ArgumentParser()
    parser.add_argument('--listen', default="127.0.0.1",
        help="Address to listen on for connections (default: %(default)s)")
    parser.add_argument('--port', type=int, default=9999,
        help="Port to listen on for connections (default: %(default)s)")
    parser.add_argument('--acld_host', metavar='HOST', action='append',
        help='ACLD hosts to connect to (default: %s)' % defaultacldhost)
    parser.add_argument('--acld_port', metavar='PORT', type=int, default=11775,
        help="ACLD port to connect to (default: %(default)s)")
    parser.add_argument('--log-user', default=defaultuser,
        help='user name provided to acld (default: %(default)s)')
    parser.add_argument('--log-host', default=defaulthost,
        help='host name provided to acld (default: %(default)s)')
    parser.add_argument('--topic', default="bro/event/pacf",
        help="Topic to subscribe to. (default: %(default)s)")
    parser.add_argument('--debug', const=logging.DEBUG, action='store_const',
        default=logging.INFO,
        help="Enable debug output")
    parser.add_argument('--logfile',
        help="Filename of logfile. If not given, logs to stdout")
    parser.add_argument('--rotate', action="store_true",
        help="If logging to file and --rotate is specified, log will rotate at midnight")

    args = parser.parse_args()
    if not args.acld_host:
        args.acld_host = [defaultacldhost]
    return args

def hostportpair(host, port):
    """Host is an ip address or ip address and port,
       port is the default port.
       return a host-port pair"""
    tup = host.split(',', 1)
    if len(tup) == 2:
        host = tup[0]
        sport = tup[1]
        if not sport.isdigit():
            self.logger.error('%s: port must be numeric' % host)
            sys.exit(-1)
        port = int(sport)
    if port <= 0 or port > MAX16INT:
        self.logger.error('%s: port must be > 0 and < %d ' % (host, MAX16INT))
        sys.exit(-1)
    return host, port

class Listen(object):
    TIMEOUT_INITIAL = 0.25
    TIMEOUT_MAX = 8.0

    def __init__(self, queue, host, port, acld_hosts, acld_port, log_user, log_host):
        self.logger = logging.getLogger("brokerlisten")

        self.queuename = queue
        self.epl = endpoint("listener")
        self.epl.listen(port, host)
        self.icsq = self.epl.incoming_connection_status()
        self.mql = message_queue(self.queuename, self.epl)

        # Create a random list of host port pairs
        self.acld_hosts = []
        for host in acld_hosts:
            self.acld_hosts.append(hostportpair(host, acld_port))
        random.shuffle(self.acld_hosts)

        self.ident = '{%s@%s}' % (log_user, log_host)
        self.remote_ident = '?'

        self.sock = None

        self.waiting = {}
        self.buffer = ''

        self.acldstring = False
        self.acldcmd = {}

        # try to connect to acld
        self.connect()

    def connect(self):
        """Round robin across multiple aclds with exponential backoff"""
        if self.sock:
            self.sock.close()
            self.sock = None;
        # No delay on first retry with multiple aclds
        if len(self.acld_hosts) > 1:
            timeout = 0.0
        else:
            timeout = self.TIMEOUT_INITIAL
        while True:
            self.sock = socket.socket()
            hostpair = self.get_hostpair()
            self.remote_ident = '[%s].%d' % (hostpair[0], hostpair[1])
            self.logger.debug('%s Connecting' % self.remote_ident)
            try:
                self.sock.connect(hostpair)
            except socket.error as e:
                self.logger.error('%s %s' % (self.remote_ident, e.strerror))
                time.sleep(timeout)
                if not timeout:
                    timeout = self.TIMEOUT_INITIAL
                else:
                    timeout *= 2
                    if timeout > self.TIMEOUT_MAX:
                        timeout = self.TIMEOUT_MAX
                continue

            fcntl.fcntl(self.sock, fcntl.F_SETFL, os.O_NONBLOCK)
            self.logger.info('%s Connected' % self.remote_ident)
            break

    def get_hostpair(self):
        """Round robin multiple ACLD hosts"""
        hostport = self.acld_hosts.pop(0)
        self.acld_hosts.append(hostport)
        return hostport

    def listen_loop(self):
        self.logger.debug("Broker loop...")

        while 1==1:
            self.logger.debug("Waiting for broker message")
            readable, writable, exceptional = select([self.icsq.fd(), self.mql.fd(), self.sock],[],[])
            msgs = None
            if ( self.icsq.fd() in readable ):
                msgs = self.icsq.want_pop()
            elif ( self.mql.fd() in readable ):
                msgs = self.mql.want_pop()
            elif ( self.sock in readable ):
                line = self.read_acld()
                while line != None:
                    self.logger.info("Received from ACLD: %s", line)
                    self.parse_acld(line)
                    line = self.read_acld()
                continue

            for m in msgs:
                self.logger.debug("Got broker message")
                self._handle_broker_message(m)

    def parse_acld(self, line):
        line = line.rstrip("\r")
        if self.acldstring == False:
            items = line.split(" ")
            if len(items) == 3:
                ts, cookie, command = items
                more = None
            elif len(items) == 4:
                ts, cookie, command, more = items
            else:
                self.logger.error("Could not parse acld line: %s", line)
                return

            self.acldcmd = {'ts': ts, 'cookie': cookie, 'command': command}
            if more != None:
                self.acldstring = True
                self.acldcmd['comment'] = ""
                if more != "-":
                    self.logger.error("Parse error while parsing acld line: %s?", more)
            else:
                self.execute_acld()
        else:
            if line == ".":
                self.acldstring = False
                self.execute_acld()
            else:
                self.acldcmd['comment']+=line

    def execute_acld(self):
        cmd = self.acldcmd['command']
        cookie = int(self.acldcmd['cookie'])
        comment = self.acldcmd.get('comment', "")

        if cmd == "acld":
            # we get this when connecting
            self.logger.info('%s acld connection succesful' % self.remote_ident)
            return

        if cookie in self.waiting:
            msg = self.waiting[cookie]
            del self.waiting[cookie]

            if "-failed" in cmd:
                if re.search(".* is on the whitelist .*", comment):
                    self.rule_event("exists", msg['id'], msg['arule'], msg['rule'], comment)
                else:
                    self.rule_event("error", msg['id'], msg['arule'], msg['rule'], comment)
            elif re.search("Note: .* is already ", comment):
                self.rule_event("exists", msg['id'], msg['arule'], msg['rule'], comment)
            else:
                type = "added"
                if msg['add'] == False:
                    type = "removed"
                self.rule_event(type, msg['id'], msg['arule'], msg['rule'], comment)

        else:
            self.logger.warning("Got response to cookie %d we did not send. Ignoring", cookie)
            return

    def read_acld(self):
        try:
            data = self.sock.recv(4096)
            if len(data) == 0:
                self.logger.warning('%s Disconnected' % self.remote_ident)
                self.connect()
            self.buffer += data
        except socket.error, e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                # socket not ready yet, just continue and see if something
                # is still in the buffer
                pass
            else:
                self.logger.error(e)
                sys.exit(-1)
                return

        if self.buffer.find("\r\n") != -1:
            line, self.buffer = self.buffer.split("\r\n", 1)
            return line
        else:
            return None

    def _handle_broker_message(self, m):
        if type(m).__name__ == "incoming_connection_status":
            self.logger.info("Incoming connection established.")
            return

        if type(m).__name__ != "tuple":
            self.logger.error("Unexpected type %s, expected tuple.", type(m).__name__)
            return

        if len(m) < 1:
            self.logger.error("Tuple without content?")
            return

        event_name = str(m[0])

        if event_name == "NetControl::acld_add_rule":
            self.add_remove_rule(m, True)
        elif event_name == "NetControl::acld_remove_rule":
            self.add_remove_rule(m, False)
        elif event_name == "NetControl::acld_rule_added":
            pass
        elif event_name == "NetControl::acld_rule_removed":
            pass
        elif event_name == "NetControl::acld_rule_error":
            pass
        elif event_name == "NetControl::acld_rule_exists":
            pass
        else:
            self.logger.error("Unknown event %s", event_name)
            return

    def add_remove_rule(self, m, add):
        if ( len(m) != 4 ) or ( m[1].which() != data.tag_count ) or ( m[2].which() != data.tag_record ) or ( m[3].which() != data.tag_record ):
            self.logger.error("wrong number of elements or type in tuple for acld_add|remove_rule")
            return

        name = m[0].as_string()
        id = m[1].as_count()
        arule = self.record_to_record("acldrule", m[3])

        self.logger.info("Got event %s. id=%d, arule: %s", name, id, arule)

        cmd = arule['command'] + " " + str(arule['cookie']) + " " + arule['arg'] + " -"
        sendlist = [cmd, self.ident]
        if 'comment' in arule and arule['comment'] != None and len(arule['comment']) > 0:
            sendlist.append(arule['comment'])
        sendlist.append(".")

        self.waiting[arule['cookie']] = {'add': add, 'cmd': cmd, 'id': m[1], 'rule': m[2], 'arule': m[3]}
        self.logger.info("Sending to ACLD: %s", ", ".join(sendlist))
        self.sock.sendall("\r\n".join(sendlist)+"\r\n")

    def rule_event(self, event, id, arule, rule, msg):
        arule = self.record_to_record("acldrule", arule)
        self.logger.info("Sending to Bro: NetControl::acld_rule_%s id=%d, arule=%s, msg=%s", event, id.as_count(), arule, msg)
        m = message([data("NetControl::acld_rule_"+event)])
        m.push_back(id)
        m.push_back(rule)
        m.push_back(data(msg))
        self.epl.send(self.queuename, m)

    def record_to_record(self, name, m):

        if m.which() != data.tag_record:
            self.logger.error("Got non record element")

        rec = m.as_record()

        elements = None
        if name == "acldrule":
            elements = ['command', 'cookie', 'arg', 'comment']
        else:
            self.logger.error("Unknown record type %s", name)
            return

        dict = {}
        for i in range(0, len(elements)):
            if rec.fields()[i].valid() == False:
                dict[elements[i]] = None
                continue
            elif rec.fields()[i].get().which() == data.tag_record:
                dict[elements[i]] = self.record_to_record(name+"->"+elements[i], rec.fields()[i].get())
                continue

            dict[elements[i]] = self.convert_element(rec.fields()[i].get())

        return dict

    def convert_element(self, el):
        if ( el.which() == data.tag_boolean ):
            return el.as_bool()
        if ( el.which() == data.tag_count ):
            return el.as_count()
        elif ( el.which() == data.tag_integer ):
            return el.as_int()
        elif ( el.which() == data.tag_real ):
            return el.as_real()
        elif ( el.which() == data.tag_string ):
            return el.as_string()
        elif ( el.which() == data.tag_address ):
            return str(el.as_address())
        elif ( el.which() == data.tag_subnet ):
            return str(el.as_subnet())
        elif ( el.which() == data.tag_port ):
            p = str(el.as_port())
            ex = re.compile('([0-9]+)(.*)')
            res = ex.match(p)
            return (res.group(1), res.group(2))
        elif ( el.which() == data.tag_time ):
            return el.as_time()
        elif ( el.which() == data.tag_duration ):
            return el.as_duration().value
        elif ( el.which() == data.tag_enum_value ):
            tmp = el.as_enum().name
            return re.sub(r'.*::', r'', tmp)
        elif ( el.which() == data.tag_vector ):
            tmp = el.as_vector()
            elements = []
            for sel in tmp:
                elements.append(self.convert_element(sel))
            return elements

        else:
            self.logger.error("Unsupported type %d", el.which() )
            return None

args = parseArgs()
logger = logging.getLogger('')
logger.setLevel(args.debug)

handler = None

if args.logfile:
    if args.rotate:
        handler = TimedRotatingFileHandler(args.logfile, 'midnight')
    else:
        handler = logging.FileHandler(args.logfile);
else:
    handler = logging.StreamHandler(sys.stdout)

formatter = logging.Formatter('%(created).6f:%(name)s:%(levelname)s:%(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

logging.info("Starting acld.py...")
brocon = Listen(args.topic, args.listen, args.port, args.acld_host,
    args.acld_port, args.log_user, args.log_host)
try:
    brocon.listen_loop()
except KeyboardInterrupt:
    pass
