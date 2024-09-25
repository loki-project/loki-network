# High-Level Architecture

## Path Building

<p align="center">
    <img src="/docs/lokinet_pathbuild_no_steps.png">
</p>

Starting from the top, here's a high-level overview of how the lokinet client builds a path to a terminating node

1. Client semi-randomly selects SN's for hops 2 and 3 using Introset Hash Ring (IHR)
   - First hop is sticky: upon initialization of lokinet, 4-5 first hops are selected

2. Message sent to hop 1
   - Message consists of eight records in a linked list. Four hops are typically used, leaving the last 4 links as dummy records
   - Each record contains a TX (upstream) path ID and RX (downstream) path ID
   - Each record has a pointer to the next record, except for the final hops' record; the pointer here is recursive, signalling the end of the path-build

3. Hop 2 pops top record, appends metadata, and pushes record to the back of linked list
   - Hop adds metadata to the record, such as optional lifetime, pubkey to derive shared secret, etc

4. Steps 2-3 are repeated for the remaining hops until destination is reached
   - Final hop reads the recursive pointer signalling the end of the path-build process

5. Upon completion, plain-text reply is propagated backwards, where the client can then decrypt all records

6. Client measures latency
   - A) Routing message is sequentially encrypted using hop 4's key through hop 1's key
     - At each iteration, the nonce is permuted by XOR'ing the previous nonce with the hash of the secret key of each hop
   - B) Routing message is sent s.t. each hop can decrypt, with final hop receiving plain-text
     - Each hop appends latency and expiration time data, with the final hop interpreting the plain-text as a routing message and sending it back to the client

7. Introset is published to IHR upon successful completion; introset contains:
   - Path ID's of routers
   - Latency and expiration time for each hop
   - DNS SRV records
   - etc

### Failure Cases

1. Next hop is an invalid SN
2. Cannot connect to SN

In either case, the path-build status is sent backwards with an error flag. Once received by the client, metadata related to the prospective path is wiped and the path forgotten


