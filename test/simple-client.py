
import logging
import netcontrol
import pprint

logging.basicConfig(level=logging.DEBUG)

ep = netcontrol.Endpoint("bro/event/netcontrol-example", "127.0.0.1", 9977);
pp = pprint.PrettyPrinter(indent=4)
while 1==1:
    pp.pprint(ep.getNextCommand().rule)
