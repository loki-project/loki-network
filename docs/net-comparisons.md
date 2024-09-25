# How is lokinet different than ...

## Tor Browser

Tor browser is a hardened Firefox Web Browser meant exclusively to surf http(s) sites via Tor. It is meant to be a complete self contained browser you open and run to surf the Web (not the internet) anonymously.
Lokinet does not provide a web browser at this time because that is not a small task to do at all, and an even larger task to do in a way that is secure, robust and private. Community Contribuitions Welcomed.

## Tor/Onion Services

While Tor Browser is the main user facing product made by Tor Project, the main powerhouse is Tor itself. Tor provides a way to anonymize tcp connections made by an initiator and optionally additionally the recipient, when using a .onion address. Lokinet provides a similar feature set but can carry anything that can be encapsulated in an IP packet (currently only unicast traffic). 

The Lokinet UX differs greatly from that of Tor. By default we do not provide exit connectivity. Because each user's threat model greatly varies in scope and breadth, there exists no one size fits all way to do exit connectivity. Users obtain their exit node information out-of-band at the moment. In the future we want to add decentralized network wide service discovery not limited to just exit providers, but this is currently unimplemented. We think that by being hands-off with respect to exit node requirements a far more diverse set of exit nodes can exist. In addition to having totally open unrestrcited exits, there is merit to permitting "specialized" exit providers that are allowed to do excessive filtering or geo blocking for security theatre checkbox compliance.

Lokinet additionally encourages the manual selection and pinning of edge connections to fit each user's threat model.

## I2P

Integrating applications to utilize i2p's network layer is painful and greatly stunts mainstream adoption.
Lokinet takes the inverse approach of i2p: make app integration in lokinet should require zero custom shims or modifications to code to make it work.

## DVPNs / Commercial VPN Proxies

One Hop VPNs can see your real IP and all of the traffic you tunnel over them. They are able to turn your data over to authorities even if they claim to not log.

Lokinet can see only 1 of these 2 things, but NEVER both:

* Encrypted data coming from your real IP going to the first hop Lokinet Router forwarded to another Lokinet Router.
* A lokinet exit sees traffic coming from a `.loki` address but has no idea what the real IP is for it.

One Hop Commericial VPN Tunnels are no log by **policy**.  You just have to trust that they are telling the truth.

Lokinet is no log by **design** it doesn't have a choice in this matter because the technology greatly hampers efforts to do so.

Any Lokinet Client can be an exit if they want to and it requires no service node stakes. Exits are able to charge users for exiting to the internet, tooling for orechestrating this is in development.
