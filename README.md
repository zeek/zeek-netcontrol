Bro NetControl connector scripts
================================

This repository contains scripts that can be used to connect the Bro NetControl
framework to systems outside of Bro and, e.g., send out switch commands via OpenFlow.

Please note that the NetControl framework and scripts is still under active
development; the API is not completely fixed yet and the scripts have not seen
thorough testing.

Installation Instructions
-------------------------

To use the connector scripts, you need to install the
[topic/johanna/netcontrol](https://github.com/bro/bro/tree/topic/johanna/netcontrol)
branch of Bro with commands similar to this:

	git clone --recursive -b topic/johanna/netcontrol git://git.bro.org/bro
	./configure --prefix=[install prefix] --with-libcaf=[libcaf location]
	make install

You also need an installation of the Bro Communication Library [broker](https://github.com/bro/broker)
with enabled python bindings. Installation will be similar to this:

	git clone --recursive git://git.bro.org/broker
	./configure --prefix=[install prefix] --with-libcaf=[libcaf location]
	make install

To allow python to find the installed python broker bindings, it might be necessary
to adjust the PYTHONPATH variable similar to this:

	export PYTHONPATH=[install prefix]/lib/python

after that, you should be able to launch the provided scripts.

OpenFlow connector
------------------

The [openflow](openflow/) directory contains the source for a Ryu OpenFlow
controller, that can be used to interface the Bro NetControl framework with an
OpenFlow capable switch. To use the controller, you need to first install the
[Ryu SDN framework](https://osrg.github.io/ryu/).

After installation, you can run the openflow controller by executing

	ryu-manager --verbose openflow/controller.py

or similar. After that, OpenFlow switches should be able to connect to port 6633;
Broker connections can be made to port 9999. An example script that shunts all
connection traffic to a switch after an SSL, SSH or GridFTP session has been
established is provided in [example.bro](openflow/example.bro).

Command-line connector
----------------------

The [command-line](command-line/) directory contains a script that can be used to
interface the NetControl framework to command-line invocations.
[commands.yaml](command-line/commands.yaml) shows an example that can be used to
invoke iptables.

Acld connector
--------------

The [acld](acld/) directory contains the source for an connector to [acld](ftp://ftp.ee.lbl.gov/acld.tar.gz) ([more information](http://ee.lbl.gov/leres/acl2.html)).
An example script that simply blocks all connections is provided in
[example.bro](acld/example.bro).

