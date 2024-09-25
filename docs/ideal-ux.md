# What does Lokinet actually do?

Lokinet is an onion routed authenticated unicast IP network. It exposes an IP tunnel to the user and provides a dns resolver that maps `.loki` and `.snode` gtld onto a user defined ip range.

Lokinet allows users to tunnel arbitrary ip ranges to go to a `.loki` address to act as a tunnel broker via another network accessible via another lokinet client. This is commonly known as an "exit node" but the way lokinet does this is much more generic so that term is not very accurate given what it actually does.

The `.snode` gtld refers to a router on the network by its public ed25519 key.

The `.loki` gtld refers to clients that publish the existence anonymously to the network by their ed25519 public key. (`.loki` also has the ability to use short names resolved via external consensus method, like a blockchain).

# How do I use Lokinet?

set system dns resolver to use the dns resolver provided by lokinet, make sure the upstream dns provider that lokinet uses for non lokinet gtlds is set as desired (see lokinet.ini `[dns]` section)

configure exit traffic provider if you want to tunnel ip traffic via lokinet, by default this is off as we cannot provide a sane defualt that makes everyone happy. to enable an exit node, see lokinet.ini `[network]` section, add multiple `exit-node=exitaddrgoeshere.loki` lines for each endpoint you want to use for exit traffic. each `exit-node` entry will be used to randomly stripe across per IP you are sending to. 

note: per flow (ip+proto/port) isolation is trivial on a technical level but currently not implemented at this time.

# Can I run lokinet on a soho router?

Yes and that is the best way to run it in practice. 

## The "easy" way

We have a community maintained solution for ARM SBCs like rasperry pi: https://github.com/necro-nemesis/LabyrinthAP

## The "fun" way (DIY)

It is quite nice to DIY. if you choose to do so there is some assembly required:

on the lokinet side, make sure that the...

* ip ranges for `.loki` and `.snode` are statically set (see lokinet.ini `[network]` section `ifaddr=` option)
* network interace used by lokinet is statically set (see lokinet.ini `[network]` section `ifname=` option)
* dns socket is bound to an address the soho router's dns resolver can talk to, see `[dns]` section `bind=` option) 

on the soho router side:

* route queries for `.loki` and `.snode` gtld to go to lokinet dns on soho router's dns resolver
* use dhcp options to set dns to use the soho router's dns resolver
* make sure that the ip ranges for lokinet are reachable via the LAN interface 
* if you are tunneling over an exit ensure that LAN traffic will only forward to go over the lokinet vpn interface
