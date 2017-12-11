# Peer discovery

Peer discovery protocol based on Kademlia ([1]).

Key properties:

1) Nodes don't choose their identifiers freely. Instead they generate Ed25519
key pair and use Blake2b-256 hash of their public key as an identifier.

2) Every response is signed using responder's private key.

3) Support for nodes that are not globally reachable, i.e. behind NAT/firewall.

4) Enhanced resistance to Eclipse/Sybil attacks by utilizing ideas from [2].

## Communication overview

### Auxiliary types:

```haskell
-- | IPv4 peer.
data Peer = Peer
  { peerAddress :: !HostAddress
  , peerPort    :: !PortNumber
  }

-- | Peer along with his id.
data Node = Node
  { nodeId   :: !PeerId
  , nodePeer :: !Peer
  }
```

We strip original Kademlia protocol from DHT-related operations and retain only
two request types (FindNode, Ping) and two appropriate response types
(ReturnNodes, Pong).

### Request types:

```haskell
data FindNode = FindNode
  { fnPeerId     :: !PeerId             -- ^ Identifier of the sender
  , fnPublicPort :: !(Maybe PortNumber) -- ^ Port number we're globally reachable on
  , fnTargetId   :: !PeerId             -- ^ Identifier of the node we look for
  }

data Ping = Ping
  { pingReturnPort :: !(Maybe PortNumber) -- ^ Port number to send the Pong on
  }
```

### Appropriate response types:

```haskell
data ReturnNodes = ReturnNodes ![Node]

data Pong = Pong
```

Every request and response are encapsulated within the Signal type that
represents all incoming and outgoing communication.

```haskell
data Signal = Request  !RpcId                           !Request
            | Response !RpcId !C.PublicKey !C.Signature !Response
```

As previously mentioned, each request signal is assigned randomly generated
RpcId for protection from replay attacks.

Each response signal mirrors RpcId of the received request and apart from the
response includes responder's public key and a signature, which in turn includes
RpcId, Request and Response. Sender of the request can verify integrity of the
communication round by checking hash of the received public key against the node
identifier he knows and then verifying the signature.

It guarantees that an attacker can't modify messages exchanged between honest
nodes (assuming he doesn't possess the responder's private key): he can't modify
the request because the sender will know after he gets the response as signature
includes the request, he can't modify the response because the signature
includes the response and he can't collect request/response pairs and use them
later because the signature includes RpcId.

Note that an attacker can make the communication fail by either dropping one of
the messages or modifying it so that it won't verify.

## Request handling

### Ping

We send Pong to the source address. If the request includes port number, we
modify the source port appropriately (this is used by the sender to test whether
he's globally reachable on the specified port).

No additional actions are performed.

### FindNode

We return the list of k nodes closest to the target from our routing table.

If the request includes a port number, the sender claims that he is globally
reachable and he wants to join the network under his source address and given
port number. All the gate-keeping happens here as it's the only place where a
node can join the network.

We consider the sender for inclusion in our routing table, but only if his
identifier has different highest bit than ours. This has the following effects:

1) Branch of the routing table that corresponds to the highest bit can hold
nodes from approximately half of the network, hence (after the network has
bootstrapped) its buckets will be (almost) full. Because of this it's hard to
introduce a lot of new nodes into the network (as, per original Kademlia design,
we prioritize old nodes over new ones), so it impedes Sybil attacks.

2) It's impossible to directly influence node's entire routing table, which
impedes Eclipse attacks. It's still possible to influence direct neighbors and
wait until node pulls adversarial nodes in, but because of (1) and how a node
manages its routing table it's hard to do that at once, hence a node will have a
chance to detect and recover from the attack (more on that below).

We then try to add the node to our routing table. If the routing table already
contains a node with the same identifier, but a different address, it means that
either node's address changed and he's trying to rejoin the network or we're
dealing with an impersonator. To check, we ping the old address. If we get a
response, we do nothing. If we don't, we then ping the new node and only after
successful response we update his address in the routing table. This ensures that:

1) The old address is no longer valid and the sender is not trying to hijack the
id.

2) The new address responds to pings, so he possesses the private key
corresponding to his identifier (as responses are signed and verified).

Simply pinging the new address is not enough, because in principle an attacker
can act as a relay between us and genuine node for the ping message, get into
our routing table and then drop all subsequent messages, causing us to
eventually evict the node from the routing table. If he does that for all nodes
we know of, we're be left with empty routing table ready to be populated by the
attacker.

Note: in theory an attacker can still do the above if the node's address has
changed, but he didn't yet have a chance of informing us about it. It requires
an attacker to have that information though, which is unlikely (and is not
something that can be replicated for all nodes in our routing table).

## Bootstrapping

A node needs an address and an identifier of an initial node it connects to in
order to bootstrap their routing table (identifier is needed to perform
authentication). After that it checks whether it's globally reachable by issuing
appropriate Ping request, then populates its own neighborhood as well as branch
of the routing table corresponding to the highest bit of an identifier by
issuing a node lookup operation (more on that below) for each (two in total).

## Finding peers

To find peers to connect to we generate random target node identifier and
perform Kademlia node lookup procedure, which is guaranteed to return up to k
live nodes closest to the target id, which then can be ordered by an
application-specific metric, such as their response times.

However, because original Kademlia node lookup operation consists of only one
lookup path, it's relatively easy to encounter adversarial node along the way
that can either make the lookup fail by returning a bunch of invalid node
addresses or reroute us into adversarial subnet. To remedy that, per [2]
(section 4.4) we instead perform d independent lookups in parallel in a way that
each lookup path is disjoint with the others. After all of them finish, we
consider only nodes that were returned by the majority.

This limits the ability of adversarial nodes to make the lookup fail as well as
their ability to reroute us into their network, since they'd need to taint the
majority of lookup paths.

If a node lookup fails to return any nodes, we perform another one with a
different random target identifier. If a certain number of subsequent node
lookups fail, we consider the network tainted, scrap our routing table and
bootstrap using the initial peer (*).

It's not clear what do we do if the initial node is tainted.

## Maintenance of the routing table (*)

We need to periodically:
- Ping nodes we didn't interact with for a specific time.
- Issue node lookups to keep routing table fresh.

Besides that, for each node in the routing table we keep track of how many times
he failed to return a valid response. After 2 consecutive response failures, we
keep it in the table, but stop returning it in response to FindNode requests. We
also start periodically pinging it. After 5 consecutive response failures we
consider it stale and remove it whenever there's a suitable replacement.

We need to be careful about connectivity testing - it's possible to have an
adversarial node that will answer Ping requests, but ignore FindNode
requests. It can be taken care of by additionally counting connectivity loss
streaks and consider a node stale whenever it reaches 3.

We never reset timeout counts if a node contacts us - only it we successfully
contact him. Otherwise we can have a node that ignores all requests, but after
each ignored request pings us, thus taking space in our routing table while
being useless.

## Testing (*)

We should test various scenarios to see how the network behaves and whether
chosen countermeasures against attacks are working as intended.

Test:

1. Network of honest nodes.

2. Network of honest nodes with percent of adversaries that respond with bogus
node info. Check how % of adversaries corresponds to % of failed node lookups over
time.

3. Network of honest nodes with adversarial subnet. Check how the size of subnet
in relation to the whole network corresponds to % of reroutes into the
adversarial subnet over time and how reliably we can detect adversaries taking
over.

## Resistance to attacks

### Eclipse attack / routing corruption

Conjectured to be hard to execute undetected, as:

1) An adversary can't introduce a lot of new nodes to the network
simultaneously.

2) An adversary can gain a large influence in the routing table over time, but
because of (1) there will be a period when enough paths will be corrupted for
the node lookup to fail, but not enough to consider adversarial nodes viable
results, hence nodes should be able to detect it and recover.

[2] (section 4.1) advocates use of crypto-puzzles to further impede both Eclipse
and Sybil attacks (by slowing down the generation of new identities), however
the paper was written in 2007, when there was no *coin mining, so it's not clear
whether adjusting the difficulty of Ed25519 key generation to take around a
couple seconds on a typical, mid-range CPU will pose any challenge to a
determined adversary with access to computational power of modern GPUs.

### Sybil attack

Impossible to stop in fully decentralized environment. Slow as it's hard for new
nodes to join the network.

### Identity hijacking / reflection attack

Pretty much impossible due to response signing and verification.

----------------------------------------

(*) Not yet done.

[1] Kademlia: A Peer-to-Peer Information System Based on the XOR Metric
    https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf

[2] S/Kademlia: A practicable approach towards secure key-based routing
    https://pdfs.semanticscholar.org/0219/0db89bf2d898817aa600c3edca6ded294de0.pdf
