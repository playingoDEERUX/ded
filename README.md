# Decentralized Endpoint Discovery

A PoW (Proof of Work)-assisted, PoA (Proof of Authority) driven decentralized discovery algorithm based on DGA generation + IP/8 fallback scanning hybrid.

The way it works: N amount of deterministic domains are generated every month. These are probed first, assuming no endpoint is discovered there, it'll build an endpoint list based on a hardcoded FIRST_OCTET using a /8 IP pool.

NOTE: For the Proof of Work, only the more modern SHA-NI based solution is currently implemented, implementing AVX2 and the conventional PoW variant should however be trivial.
A non-ASIC conform quadruple SHA256 is used, this does not mean that an ASIC couldn't be manufactured for this, but it is currently an asymmetrical way of protecting our outgoing bandwidth in the event of an attack.
The ASIC requirement causes such high costs on the other side just to get rid of an asymmetry and be back at an even playing field.

Furthermore:
The code does **NOT** secure or specify how secure post-discovery communication is, it only discovers domains/IPs that are proven to be of (y)our interest through the Proof of Authority check in a way that leaves enough asymmetries for attackers to be overwhelmed.
Also, the code is quite messy cause it mostly served as a lab experiment and playground for tinkering with decentralized designs like these.

Ideally, certain technology stacks (without necessarily naming which, this is up to the user) are deployed on each endpoint to process and respond to requests in line-rate at extremely high PPS.

# TODO

* Implement more variants of the PoW efficiently beyond current SHA-NI implementation. (AVX2 for instance)

* Implement loading from endpoint cache upon bootup

* Misc. stuff, cleanups

* Verify CGNAT conformity on multiple (perhaps even more constrained) setups

* RandomX PoW as an alternative, however, validating its PoW is quite slow for the authority side as well, therefore resorted to the conventional SHA256 PoW. Requires an ASIC for attackers to even just get back to even playing field, and even then this design is supposed to be highly robust depending on the server implementation (as mentioned before). You should be able to deploy plenty of endpoints to get the discovery time reduced as necessary and create sufficient redundancy.

Post-discovery communication should be secured cryptographically as well (since anyone who knows a bit more about networking, knows that the inherent nature of the internet is complete lack of confidentiality among other properties), but that's beyond the scope of this project.
