#!/usr/bin/env python

# Command-line interface for the Network Control Framework of Bro, using Broker.

import logging
import time
import re
import thread
import yaml
import string

from subprocess import check_output
from subprocess import CalledProcessError
#from future.utils import viewitems

from pybroker import *
from select import select

queuename = "bro/event/pacf"
use_threads = True

class Listen:
    def __init__(self, queue, host, port, commands):
        self.logger = logging.getLogger("brokerlisten")

        self.queuename = queue
        self.epl = endpoint("listener")
        self.epl.listen(port, host)
        self.icsq = self.epl.incoming_connection_status()
        self.mql = message_queue(queuename, self.epl)
        self.commands = commands
        #thread.start_new_thread(self._listen_loop, ())

    def listen_loop(self):
        self.logger.info("Broker loop...")

        while 1==1:
            self.logger.info("Waiting for broker message")
            readable, writable, exceptional = select([self.icsq.fd(), self.mql.fd()],[],[])
            msgs = None
            if ( self.icsq.fd() in readable ):
                msgs = self.icsq.want_pop()
            elif ( self.mql.fd() in readable ):
                msgs = self.mql.want_pop()

            for m in msgs:
                self.logger.info("Got broker message")
                self._handle_broker_message(m)

    def _handle_broker_message(self, m):
        if ( type(m).__name__ == "incoming_connection_status" ):
            self.logger.info("Incoming connection established")
            return

        if ( type(m).__name__ != "tuple" ):
            self.logger.error("Unexpected type %s, expected tuple", type(m).__name__)
            return

        if ( len(m) < 1 ):
            self.logger.error("Tuple without content?")
            return

        event_name = str(m[0])
        print event_name

        if ( event_name == "Pacf::broker_add_rule" ):
            if use_threads:
                thread.start_new_thread(self.add_remove_rule, (m, True))
            else:
                self.add_remove_rule(m, True)
        elif ( event_name == "Pacf::broker_remove_rule" ):
            if use_threads:
                thread.start_new_thread(self.add_remove_rule, (m, False))
            else:
                self.add_remove_rule(m, False)
        elif ( event_name == "Pacf::broker_rule_added" ):
            pass
        elif ( event_name == "Pacf::broker_rule_removed" ):
            pass
        elif ( event_name == "Pacf::broker_rule_error" ):
            pass
        elif ( event_name == "Pacf::broker_rule_timeout" ):
            pass
        else:
            self.logger.error("Unknown event %s", event_name)
            return

    def add_remove_rule(self, m, add):
        if ( len(m) != 3 ) or ( m[1].which() != data.tag_count ) or ( m[2].which() != data.tag_record ) :
            self.logger.error("wrong number of elements or type in tuple for event_flow_mod")
            return

        id = m[1].as_count
        rule = self.record_to_record("rule", m[2])
        print rule
        cmd = self.rule_to_cmd_dict(rule)
        print cmd

        if add == True:
            type = 'add_rule'
        else:
            type = 'remove_rule'

        if not ( type in self.commands):
            self.logger.error("No %s in commands", type)
            return

        commands = self.commands[type]

        output = ""

        for i in commands:
            currcmd = self.replace_command(i, cmd)
            output += "Command: "+currcmd+"\n"

            try:
                print "Executing "+currcmd
                cmdout = check_output(currcmd)
                output += "Output: "+str(cmdout)+"\n"
            except CalledProcessError as err:
                output = "Command "+currcmd+" failed with return code "+err.returncode+" and output: "+str(err.output)
                self.rule_event("error", m[1], m[2], output)
                return

        if add == True:
            self.rule_event("added", m[1], m[2], output)
        else:
            self.rule_event("removed", m[1], m[2], output)

    def rule_event(self, event, id, rule, msg):
        m = message([data("Pacf::broker_rule_"+event)])
        m.push_back(id)
        m.push_back(rule)
        m.push_back(data(msg))
        self.epl.send(self.queuename, m)

    def replace_single_command(self, argstr, cmds):
        reg = re.compile('\[(?P<type>.)(?P<target>.*?)(?:\:(?P<argument>.*?))?\]')
        print argstr
        m = reg.search(argstr)

        if m == None:
            self.logger.error('%s could not be converted to rule', argstr)
            return ''

        type = m.group('type')
        target = m.group('target')
        arg = m.group('argument')

        if type == '?':
            if not ( target in cmds ):
                return ''
            elif arg == None:
                return cmds[target]

            # we have an argument *sigh*
            return re.sub(r'\.', cmds[target], arg)
        elif type == '!':
            if arg == None:
                self.logger.error("[!] needs argument for %s", argstr)
                return ''

            if not ( target in cmds ):
                return arg
            else:
                return ''
        else:
            self.logger.error("unknown command type %s in %s", type, argstr)
            return ''

    def replace_command(self, command, args):
        reg = re.compile('\[(?:\?|\!).*?\]')

        return reg.sub(lambda x: self.replace_single_command(x.group(), args), command)


    def rule_to_cmd_dict(self, rule):
        cmd = {}

        mapping = {
            'type': 'ty',
            'target': 'target',
            'expire': 'expire',
            'priority': 'priority',
            'id': 'id',
            'cid': 'cid',
            'entity.ip': 'address',
            'entity.mac': 'mac',
            'entity.conn.orig_h': 'conn.orig_h',
            'entity.conn.orig_p': 'conn.orig_p',
            'entity.conn.resp_h': 'conn.resp_h',
            'entity.conn.resp_p': 'conn.resp_p',
            'entity.flow.src_h': 'flow.src_h',
            'entity.flow.src_p': 'flow.src_p',
            'entity.flow.dst_h': 'flow.dst_h',
            'entity.flow.dst_p': 'flow.dst_p',
            'entity.flow.src_m': 'flow.src_m',
            'entity.flow.dst_m': 'flow.dst_m',
            'entity.mod.src_h': 'mod.src_h',
            'entity.mod.src_p': 'mod.src_p',
            'entity.mod.dst_h': 'mod.dst_h',
            'entity.mod.dst_p': 'mod.dst_p',
            'entity.mod.src_m': 'mod.src_m',
            'entity.mod.dst_m': 'mod.dst_m',
            'entity.mod.redirect_port': 'mod.port',
            'entity.i': 'mod.port',
        }

        for (k, v) in mapping.items():
            path = string.split(k, '.')
            e = rule
            for i in path:
                if e == None:
                    break
                elif i in e:
                    e = e[i]
                else:
                    e = None
                    break

            if e == None:
                continue

            if isinstance(e, tuple):
                cmd[v] = e[0]
                cmd[v+".proto"] = e[1]
            else:
                cmd[v] = e
                if isinstance(e, basestring):
                    spl = string.split(e, "/")
                    if len(spl) > 1:
                        cmd[v+".ip"] = spl[0]
                        cmd[v+".net"] = spl[1]

        proto = mapping.get('entity.conn.orig_p.proto', mapping.get('entity.conn.dest_p.proto', mapping.get('entity.flow.src_p.proto', mapping.get('entity.flow.dst_p.proto', None))))
        if proto != None:
            entity['proto'] = proto

        return cmd


    def record_to_record(self, name, m):

        if m.which() != data.tag_record:
            self.logger.error("Got non record element")

        rec = m.as_record()

        elements = None
        if name == "rule":
            elements = ['ty', 'target', 'entity', 'expire', 'priority', 'location', 'c', 'i', 'd', 's', 'mod', 'id', 'cid']
        elif name == "rule->entity":
            elements = ['ty', 'conn', 'flow', 'ip', 'mac']
        elif name == "rule->entity->conn":
            elements = ['orig_h', 'orig_p', 'resp_h', 'resp_p']
        elif name == "rule->entity->flow":
            elements = ['src_h', 'src_p', 'dst_h', 'dst_p', 'src_m', 'dst_m']
        elif name == "rule->mod":
            elements = ['src_h', 'src_p', 'dst_h', 'dst_p', 'src_m', 'dst_m', 'redirect_port']
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

stream = file('commands.yaml', 'r')
config = yaml.load(stream)

logging.basicConfig(level=logging.DEBUG)
logging.info("Starting...")
brocon = Listen(queuename, "127.0.0.1", 9999, config)
brocon.listen_loop()

