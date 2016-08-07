import logging
import re
from pybroker import *
from select import select
from enum import Enum, unique

logger = logging.getLogger(__name__)

def convertRecord(name, m):
    if m.which() != data.tag_record:
        logger.error("Got non record element")

    rec = m.as_record()

    elements = None
    if name == "rule":
        elements = ['ty', 'target', 'entity', 'expire', 'priority', 'location', 'out_port', 'mod', 'id', 'cid']
    elif name == "rule->entity":
        elements = ['ty', 'conn', 'flow', 'ip', 'mac']
    elif name == "rule->entity->conn":
        elements = ['orig_h', 'orig_p', 'resp_h', 'resp_p']
    elif name == "rule->entity->flow":
        elements = ['src_h', 'src_p', 'dst_h', 'dst_p', 'src_m', 'dst_m']
    elif name == "rule->mod":
        elements = ['src_h', 'src_p', 'dst_h', 'dst_p', 'src_m', 'dst_m', 'redirect_port']
    else:
        logger.error("Unknown record type %s", name)
        return

    dict = {}
    for i in range(0, len(elements)):
        if rec.fields()[i].valid() == False:
            dict[elements[i]] = None
            continue
        elif rec.fields()[i].get().which() == data.tag_record:
            dict[elements[i]] = convertRecord(name+"->"+elements[i], rec.fields()[i].get())
            continue

        dict[elements[i]] = convertElement(rec.fields()[i].get())

    return dict

def convertElement(el):
    if el.which() == data.tag_boolean:
        return el.as_bool()
    if el.which() == data.tag_count:
        return el.as_count()
    elif el.which() == data.tag_integer:
        return el.as_int()
    elif el.which() == data.tag_real:
        return el.as_real()
    elif el.which() == data.tag_string:
        return el.as_string()
    elif el.which() == data.tag_address:
        return str(el.as_address())
    elif el.which() == data.tag_subnet:
        return str(el.as_subnet())
    elif el.which() == data.tag_port:
        p = str(el.as_port())
        ex = re.compile('([0-9]+)(.*)')
        res = ex.match(p)
        return (res.group(1), res.group(2))
    elif el.which() == data.tag_time:
        return el.as_time()
    elif el.which() == data.tag_duration:
        return el.as_duration().value
    elif el.which() == data.tag_enum_value:
        tmp = el.as_enum().name
        return re.sub(r'.*::', r'', tmp)
    elif el.which() == data.tag_vector:
        tmp = el.as_vector()
        elements = []
        for sel in tmp:
            elements.append(convert_element(sel))
        return elements

    else:
        logger.error("Unsupported type %d", el.which() )
        return None

@unique
class ResponseType(Enum):
    ConnectionEstablished = 1
    Error = 2
    AddRule = 3
    RemoveRule = 4
    SelfEvent = 5

class NetControlResponse:
    def __init__(self):
        self.type = (ResponseType.Error)
        self.errormsg = ""
        self.rule = ""

    def __init__(self, rty, **kwargs):
        self.type = rty
        self.errormsg = kwargs.get('errormsg', '')
        self.pluginid = kwargs.get('pluginid', None)
        self.rule = kwargs.get('rule', None)
        self.rawrule = kwargs.get('rawrule', None)

class Endpoint:
    def __init__(self, queue, host, port):
        self.queuename = queue
        self.epl = endpoint("listener")
        self.epl.listen(port, host)
        self.icsq = self.epl.incoming_connection_status()
        self.mql = message_queue(self.queuename, self.epl)
        logger.debug("Set up listener for "+host+":"+str(port)+" ("+queue+")")
        self.msgs = None

    def getNextCommand(self):
        if self.msgs == None or len(self.msgs) == 0:
            logger.debug("Waiting for broker message...")
            readable, writable, exceptional = select([self.icsq.fd(), self.mql.fd()],[],[])
            if ( self.icsq.fd() in readable ):
                self.msgs = list(self.icsq.want_pop())
            elif ( self.mql.fd() in readable ):
                self.msgs = list(self.mql.want_pop())

        if self.msgs != None or len(self.msgs) > 0:
            logger.debug("Handling broker message...")
            msg = self.msgs.pop(0)
            return self.handleBrokerMessage(msg)

    def handleBrokerMessage(self, m):
        if type(m).__name__ == "incoming_connection_status":
            logger.info("Incoming connection established")
            return NetControlResponse(ResponseType.ConnectionEstablished)

        if type(m).__name__ != "tuple":
            logger.error("Unexpected type %s, expected tuple", type(m).__name__)
            return NetControlResponse(ResponseType.Error)

        if len(m) < 1:
            logger.error("Tuple without content?")
            return NetControlResponse(ResponseType.Error)

        event_name = str(m[0])
        logger.debug("Got event "+event_name)

        if event_name == "NetControl::broker_add_rule":
            return self._add_remove_rule(m, ResponseType.AddRule)
        elif event_name == "NetControl::broker_remove_rule":
            return self._add_remove_rule(m, ResponseType.RemoveRule)
        elif event_name == "NetControl::broker_rule_added":
            return NetControlResponse(ResponseType.SelfEvent)
        elif event_name == "NetControl::broker_rule_removed":
            return NetControlResponse(ResponseType.SelfEvent)
        elif event_name == "NetControl::broker_rule_error":
            return NetControlResponse(ResponseType.SelfEvent)
        elif event_name == "NetControl::broker_rule_timeout":
            return NetControlResponse(ResponseType.SelfEvent)
        else:
            logger.warning("Unknown event %s", event_name)
            return NetControlResponse(ResponseType.Error, errormsg="Unknown event"+event_name)

    def _add_remove_rule(self, m, rtype):
        if  ( (rtype == ResponseType.AddRule) and ( len(m) != 3 ) ) or ( (rtype == ResponseType.RemoveRule) and ( len(m) != 4 ) ):
            logger.error("wrong number of elements or type in tuple for add/remove_rule event")
            return NetControlResponse(ResponseType.Error, errormsg="wrong number of elements or type in tuple for add/remove_rule event")
        if ( m[0].which() != data.tag_string ) or ( m[1].which() != data.tag_count ) or ( m[2].which() != data.tag_record ) :
            logger.error("wrong types of elements or type in tuple for add/remove_rule event")
            return NetControlResponse(ResponseType.Error, errormsg="wrong types of elements or type in tuple for add/remove_rule event")

        name = m[0].as_string()
        id = m[1].as_count()
        rule = convertRecord("rule", m[2])

        return NetControlResponse(rtype, pluginid=id, rule=rule, rawrule=m[2])

    def sendRuleAdded(self, response, msg):
        self._rule_event("added", response, msg)

    def sendRuleRemoved(self, response, msg):
        self._rule_event("removed", response, msg)

    def sendRuleError(self, response, msg):
        self._rule_event("error", response, msg)

    def _rule_event(self, event, response, msg):
        m = message([data("NetControl::broker_rule_"+event)])
        m.push_back(data(response.pluginid))
        m.push_back(response.rawrule)
        m.push_back(data(msg))
        self.epl.send(self.queuename, m)
