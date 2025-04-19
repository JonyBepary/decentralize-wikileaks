# decentralize-wikileaks

i need to build a decentralized wikileaks it won't need any phone, email or anything. and unlike other centralize system it won't collect Metadata. When users sign-up to wikileaks, their device generates a cryptographically secure
Account ID. This is used as their contact/post information on the app. No personal
information is required to create an Account ID, so you never need to link your
real identity to your identity on wikileaks. Account IDs are the public half of a
public/private key pair, making them secure, recyclable, and anonymous. The
private half, which is known as your Recovery Password, can be used to restore
your Account ID on a new device.

wikileaks utilises the decentralised p2p Network to store and route messages/post/proof/article/sensitive documents.
This means that unlike other centralise applications you can post article/ upload docs at wikileaks wherever they are whenever they. This network consists of community operated nodes which are stationed all over the world. Wikileaks Nodes are organised into collections of small co-operative groups called swarms. Swarms offer additional redundancy and post / article/document and content delivery guarantees even if unlike other centralize system become unreachable. By using this network, wikileaks won't have a central point of failure, and wikileaks creators have no capacity to collect or store personal information about people using the app.

To protect against individual operators attempting to survey the network or
collect information about users, all wikileaks content are onion-routed
through the network. Every encrypted datapacket is routed through three
nodes in the wikileaks Network, making it virtually impossible for the nodes to
compile meaningful information about the users of the network. 

When a message is sent, one node will know the sender has sent a
message—but not know its destination—and a different node will know the
receiver has received a message—but not know its origin. 

By restricting the creation or collection of metadata or identifying information about its users, Wikileaks also gains censorship-resistant qualities.
Because individual users in one-on-one and encrypted group chats cannot be identified, they cannot be personally targeted by censorship from third-parties unlike other centralize system contains open group chats intended for large
communities. These open groups are hosted on federated servers operated
by the communities themselves, and moderation policies are determined by
each individual community.
Because of the design of unlike other centralize system, users can have extreme confidence that whenever they send a message that only the person they send
it to will be able to know: the message contents; who they messaged; who
messaged; when they sent the message. 

Where would you like to begin? We could:

Create a basic directory structure for better organization (e.g., p2p, crypto, core, ui).
Start implementing the Account ID generation using the circl library.
Set up a minimal libp2p node to handle basic peer connections.
Discuss the design for the custom onion routing layer.
Explore options for the UI (perhaps a web-based UI using Go's net/http or a framework like Gin/Echo, or a desktop UI using Fyne/Wails).


Start implementing the DHT for discovery?
Begin defining the onion packet structure and relay logic?
Set up a basic blockstore and integrate Bitswap?











Our goal:

i need to build a decentralized wikileaks it won't need any phone, email or anything. and unlike other centralize system it won't collect Metadata. When users sign-up to wikileaks, their device generates a cryptographically secure
Account ID. This is used as their contact/post information on the app. No personal
information is required to create an Account ID, so you never need to link your
real identity to your identity on wikileaks. Account IDs are the public half of a
public/private key pair, making them secure, recyclable, and anonymous. The
private half, which is known as your Recovery Password, can be used to restore
your Account ID on a new device.

wikileaks utilises the decentralised p2p Network to store and route messages/post/proof/article/sensitive documents.
This means that unlike other centralise applications you can post article/ upload docs at wikileaks wherever they are whenever they. This network consists of community operated nodes which are stationed all over the world. Wikileaks Nodes are organised into collections of small co-operative groups called swarms. Swarms offer additional redundancy and post / article/document and content delivery guarantees even if unlike other centralize system become unreachable. By using this network, wikileaks won't have a central point of failure, and wikileaks creators have no capacity to collect or store personal information about people using the app.

To protect against individual operators attempting to survey the network or
collect information about users, all wikileaks content are onion-routed
through the network. Every encrypted datapacket is routed through three
nodes in the wikileaks Network, making it virtually impossible for the nodes to
compile meaningful information about the users of the network.

When a message is sent, one node will know the sender has sent a
message—but not know its destination—and a different node will know the
receiver has received a message—but not know its origin.

By restricting the creation or collection of metadata or identifying information about its users, Wikileaks also gains censorship-resistant qualities.
Because individual users in one-on-one and encrypted group chats cannot be identified, they cannot be personally targeted by censorship from third-parties unlike other centralize system contains open group chats intended for large
communities. These open groups are hosted on federated servers operated
by the communities themselves, and moderation policies are determined by
each individual community.
Because of the design of unlike other centralize system, users can have extreme confidence that whenever they send a message that only the person they send
it to will be able to know: the message contents; who they messaged; who
messaged; when they sent the message.

Goal: To prevent intermediate nodes and network observers from knowing both the original sender and the final recipient of a message, enhancing privacy and censorship resistance as described in the README.

Core Idea: Instead of sending a message directly from Peer A to Peer B, Peer A will select a sequence of intermediate relay nodes (e.g., R1, R2, R3). Peer A encrypts the message in layers, like an onion:

Encrypt the message + B's address for R3.
Encrypt the result + R3's address for R2.
Encrypt the result + R2's address for R1.
A sends this "onion" to R1.

R1 decrypts the outer layer using a shared key with A, finds R2's address, and forwards the inner onion to R2. R1 only knows the message came from A and is going to R2.
R2 decrypts its layer using its shared key with A, finds R3's address, and forwards the inner onion to R3. R2 only knows the message came from R1 and is going to R3.
R3 decrypts its layer using its shared key with A, finds the original message and B's address. R3 forwards the message to B. R3 only knows the message came from R2 and is going to B.
Integration with libp2p:

This onion routing will be an application-level protocol built on top of libp2p streams.
Nodes participating as relays will advertise a specific libp2p protocol ID (e.g., /wikileaks/onion-relay/1.0.0).
The actual message forwarding between A -> R1, R1 -> R2, R2 -> R3, R3 -> B will use standard libp2p streams, secured by libp2p's transport encryption (Noise/TLS). The onion encryption adds an extra layer of application-specific security and obfuscation.
Key Components & Design Considerations:

Node Discovery & Selection:

How do nodes find potential relays? We'll likely need a mechanism, perhaps using the libp2p DHT or a dedicated discovery protocol, for nodes to advertise their willingness to be relays.
How does the sender (A) choose the path (R1, R2, R3)? Random selection from the available pool? Considerations for node reputation, bandwidth, latency? Geographic diversity? (Start simple: random selection).
Need a minimum number of hops (e.g., 3 as mentioned in README).
Circuit Setup & Key Exchange:

Before sending data, A needs to establish temporary symmetric keys with R1, R2, and R3 for this specific circuit.
This requires a setup protocol. A common approach is a "telescoping" build:
A establishes a key with R1 (e.g., using Diffie-Hellman over a libp2p stream).
A tells R1 (over the encrypted channel) to extend the circuit to R2. R1 opens a stream to R2.
A performs a key exchange through R1 to establish a key with R2. R1 cannot read this exchange.
A tells R2 (through R1) to extend to R3. R2 opens a stream to R3.
A performs a key exchange through R1 and R2 to establish a key with R3.
This setup phase establishes the circuit and shared keys for each hop.
Onion Packet Format:

Define a structure for the data packets. Each layer needs:
Next Hop Address (libp2p Peer ID or Multiaddr).
Payload (the encrypted data for the next hop).
Maybe some integrity checks (HMAC).
The innermost payload contains the actual application message and the final destination (B's AccountID or PeerID).
Relay Logic:

When a relay node receives an onion packet on the designated protocol:
Decrypt its layer using the pre-established symmetric key for that circuit.
Extract the next hop address and the inner payload.
Open a stream to the next hop (or deliver locally if it's the exit node).
Forward the inner payload.
Need to manage circuit state (which incoming stream corresponds to which outgoing stream/key).
Exit Node Logic:

The final relay (R3) decrypts the last layer.
It finds the actual application message and the final recipient (B).
It needs a way to deliver this message to B (e.g., open a direct libp2p stream to B using a different protocol ID for application messages, or perhaps publish it via pub/sub if B is subscribed).
Reply Path (Anonymity for Recipient):

How does B reply to A without knowing A's identity?
Single-Use Reply Blocks (SURBs): A could pre-construct the return path (e.g., A <- R4 <- R5 <- R6) and keys, package this information into an opaque "reply block", and include it with the original message. B simply sends the reply message wrapped in the SURB to the first hop specified (R6). Each relay unwraps its layer until it reaches A. This is complex.
Simpler (Less Anonymous Replies): B could just establish its own onion circuit back to A's known AccountID/PeerID if that's acceptable.
Implementation Strategy:

Start with the core data structures for onion packets and circuit state in onion.
Define the libp2p protocol IDs for relaying and circuit setup.
Implement the relay logic first: receiving a packet, decrypting a layer, forwarding.
Implement the circuit setup protocol (key exchange).
Implement the sender logic: path selection, key exchange initiation, onion wrapping.
Implement the exit node logic.
Address reply paths later.
Challenges:

Complexity: This is significantly more complex than direct communication.
Latency: Each hop adds latency.
Throughput: Encryption/decryption and forwarding add overhead.
Need for Relays: The system relies on enough users running nodes willing to relay traffic.
This is a high-level overview. We can refine each part. Does this initial design direction make sense? Where should we start detailing first? Perhaps the onion packet structure
Publishing Path (Highest Anonymity): We absolutely need the strong anonymity provided by the onion routing layer we discussed. The author (A) uses the circuit (A -> R1 -> R2 -> R3) to inject the Document metadata and the actual content blocks into the network via the exit node (R3). R3 then announces the content (e.g., the Document CID) to a discovery mechanism (like the DHT or Pub/Sub) without knowing who A is.

Viewing Path (Flexible Anonymity):

Standard Mode (Less Anonymous, More Efficient): Viewers could directly query the discovery mechanism (DHT/PubSub) to find CIDs of interest. They would then use standard libp2p content routing protocols (like Bitswap) to fetch the Document and content blocks directly from peers who advertise having them. This is faster but exposes the viewer's IP address and requested CIDs to the peers they connect to.
High Anonymity Mode (Optional): Viewers who need stronger protection could potentially route their discovery queries and content requests through an anonymity layer (either our own onion routing system, if adapted for requests, or potentially an external one like Tor/I2P if integration is feasible). This would be slower but hide the viewer's activity.
Revised Flow:

Publish: Author -> Onion Circuit -> Exit Node -> Store Blocks & Announce CID to DHT/PubSub.
Discover (Standard): Viewer -> Query DHT/PubSub Directly -> Get CIDs.
Fetch (Standard): Viewer -> Request CIDs via Bitswap Directly -> Get Blocks.
Discover/Fetch (High Anonymity): Viewer -> Anonymity Layer -> Query DHT/PubSub / Request CIDs via Bitswap -> Get Blocks.
Here's a summary of what's in the file:

Relay Struct: This will manage the overall relaying service for a node. It holds a reference to the libp2p host and will manage active circuits.
Circuit Struct: Represents the state needed for one hop of a circuit passing through this node (like the previous/next peers and the symmetric key - currently using placeholders).
NewRelay Function: Initializes the Relay struct and, importantly, registers handleRelayStream as the handler for any incoming libp2p streams using the RelayProtocol ID we defined earlier.
handleRelayStream Function: This is the core logic:
It reads the incoming data, expecting an OnionPacket.
It uses placeholder logic to get a circuit key and decrypt the payload (real key management and encryption are needed later).
It tries to decode the decrypted payload as HopInfo.
If successful (Intermediate Relay): It extracts the NextPeer ID, opens a new stream to that peer using the RelayProtocol, and forwards the inner encrypted payload (the EncryptedPayload from the incoming packet) to that next peer.
If decoding HopInfo fails (Exit Node): It assumes the decrypted payload is the final InnerPayload. It logs the received payload details but includes placeholder comments for the actual handling (like storing blocks, announcing CIDs, etc.).
Important Notes:

Placeholders: This implementation relies heavily on placeholders, especially for circuit/key management and encryption/decryption. It won't function securely or correctly without implementing those parts.
No Circuit Setup Yet: The logic for establishing circuits and exchanging keys (CircuitSetupProtocol) is not yet implemented.
Basic Forwarding: The core idea of receiving, "decrypting" (placeholder), and forwarding is sketched out.







Current Status: We've made significant progress in implementing and testing the core components, but a few key tests are still failing, indicating issues in network traversal simulation and concurrency handling.

Key Successes & Completed Components:

Cryptography (crypto.go, crypto_test.go):

All cryptographic functions (key generation, Diffie-Hellman key exchange, AES-GCM encryption/decryption, onion layer creation) are implemented and passing all tests.
This confirms the security foundation (encryption, forward secrecy, integrity) is solid.
Packet Structures & Serialization (packet.go, packet_test.go):

Definitions for HopInfo, OnionPacket, and InnerPayload are in place.
Serialization/deserialization functions (using gob) for these structures are implemented and passing tests, including corner cases.
Protocol Definitions (protocol.go, protocol_test.go):

Protocol IDs, message types, and status constants are defined.
Message structures (CircuitSetupMessage, etc.) are defined.
Tests confirm the consistency and correctness of these definitions.
Basic Circuit Management (relay.go, circuit_test.go):

The basic lifecycle (creation, lookup, teardown) of circuits within the Relay struct is passing tests.
Remaining Issues & Failing Tests:

TestOnionNetworkTraversalFixed (onion_network_test.go):

Error: Not equal: expected: int(1) actual : uint(0x1)
Problem: There's a type mismatch when comparing the expected MessageTypePublishDocument (which is likely an int constant) with the MessageType field recovered from the decoded InnerPayload (which is a uint). This needs a simple type cast in the assertion.
TestOnionNetworkTraversal (packet_routing_test.go):

Error: failed to decode HopInfo: gob: type mismatch in decoder: want struct type onion.HopInfo; got non-struct
Problem: This test, which uses the CreateOnionLayers helper function, seems to be failing because an intermediate relay is trying to decode HopInfo but receiving something else (likely the encrypted inner payload or incorrectly layered data). This suggests the CreateOnionLayers function might not be correctly structuring the layers for multi-hop routing, or the test logic simulating traversal is flawed. The TestOnionNetworkTraversalFixed attempts a manual layering which might be closer to the correct approach.
TestStaleCircuitCleanup (relay_management_test.go):

Error: fatal error: sync: Unlock of unlocked RWMutex
Problem: This indicates a race condition or incorrect lock handling within the cleanupStaleCircuits or teardownCircuit functions when accessed concurrently or during the test setup/teardown. The mutex is being unlocked when it wasn't locked by the same goroutine, or it's being unlocked twice.
Next Steps for Next Session:

Fix TestOnionNetworkTraversalFixed: Apply a type cast uint(MessageTypePublishDocument) in the assertion comparing message types.
Debug TestStaleCircuitCleanup: Carefully review the locking/unlocking logic in cleanupStaleCircuits and teardownCircuit, especially around the loop where stale circuits are identified and removed. Ensure relay.mu.Unlock() is only called if relay.mu.Lock() or relay.mu.RLock() was previously called in the same scope or goroutine.
Revisit TestOnionNetworkTraversal & CreateOnionLayers: Compare the logic in CreateOnionLayers with the manual layering done in TestOnionNetworkTraversalFixed. The helper function likely needs adjustment to correctly embed HopInfo within the encrypted layers for intermediate hops. The test itself might also need refinement in how it simulates packet forwarding.
Overall, the cryptographic core is strong, but the simulation of packet traversal through multiple hops and the concurrent management of circuit state need refinement and debugging.

# Project Overview and Current Status - Decentralized WikiLeaks

## Current Status Summary

We're working on a decentralized WikiLeaks platform focusing on privacy, censorship resistance, and metadata protection. The core components we've been implementing revolve around onion routing for anonymous document publishing. 

Here's the current state of implementation and issues:

### Completed Components:
1. **Cryptography (crypto.go)**
   - Key generation, Diffie-Hellman key exchange
   - AES-GCM encryption/decryption 
   - Onion layer creation

2. **Packet Structures & Serialization (packet.go)**
   - Defined structures for HopInfo, OnionPacket, and InnerPayload
   - Implemented serialization/deserialization using gob encoding

3. **Protocol Definitions (protocol.go)**
   - Protocol IDs, message types, and status constants
   - Message structures (CircuitSetupMessage, etc.)

4. **Basic Circuit Management (relay.go)**
   - Circuit creation, lookup, and teardown

### Remaining Issues:
We've been fixing several failing tests:

1. **TestOnionNetworkTraversalFixed** - Fixed with a type cast for MessageTypePublishDocument

2. **TestStaleCircuitCleanup** - Still failing with mutex unlock error
   - Error: `fatal error: sync: Unlock of unlocked RWMutex`
   - Need to revise the locking pattern in `cleanupStaleCircuits` function

3. **TestOnionNetworkTraversal & TestCreateOnionLayers** - Failing with encryption/decryption errors
   - `failed to decode HopInfo: gob: type mismatch` 
   - `cipher: message authentication failed`
   - Issue with `CreateOnionLayers` function not correctly structuring the data layers

## Next Steps

1. **Fix `cleanupStaleCircuits` in relay.go**:
   - Implement a more robust locking pattern, possibly using a read lock for collecting circuit IDs and a write lock for actual deletions
   - Add additional safeguards to prevent race conditions

2. **Fix `CreateOnionLayers` in crypto.go**:
   - Correct the NextHop index calculation
   - Ensure proper embedding of LayeredPayload for intermediate hops
   - Update the encryption loop to properly handle the exit node case

3. **Update Test Implementations**:
   - Modify `TestCreateOnionLayers` and `TestOnionPacketCreationAndRouting` to correctly simulate the decryption and forwarding process
   - Ensure that intermediate relays correctly decode LayeredPayload and exit nodes correctly decode InnerPayload

4. **Once Tests Pass**: 
   - Continue with integrating the onion routing system with the document publishing mechanism
   - Implement circuit setup and key exchange protocol for establishing paths
   - Develop the node discovery mechanism for finding relay nodes

## Technical Implementation Details

The core of our onion routing approach:

1. **For publishing documents**: 
   - Author selects 3 relay nodes (R1, R2, R3)
   - Creates layered encryption: Message for Exit → R3 → R2 → R1
   - Only exit node can see final destination but doesn't know original sender

2. **For consuming content**:
   - Standard mode: Direct queries to DHT/PubSub
   - High anonymity mode: Route requests through onion circuit (slower but more private)

## Core System Architecture

The system consists of:
- Account ID generation (public/private key pairs)
- P2P network using libp2p
- Custom onion routing protocol
- Swarm-based node organization for redundancy
- DHT for content discovery

After fixing the tests, we'll need to focus on implementing the document storage, retrieval, and publishing mechanisms that will leverage this secure communication layer.


Okay, the analysis of CreateOnionLayers suggests the layering logic itself might be correct, but the handling in handleRelayStream doesn't match what CreateOnionLayers produces.

Specifically:

CreateOnionLayers encrypts a gob-encoded LayeredPayload for intermediate hops.
handleRelayStream decrypts the payload but then tries to decode it as HopInfo first, which will cause the gob: type mismatch error.
When forwarding, handleRelayStream re-encodes a new OnionPacket instead of just forwarding the already correctly encrypted inner payload (LayeredPayload.Payload).
Let's adjust handleRelayStream to correctly expect LayeredPayload for intermediate hops and InnerPayload for the exit hop, and fix the forwarding logic. We also need to simplify DecodeLayeredPayload.

Step 1: Simplify DecodeLayeredPayload


Cline wants to edit this file:

Checkpoint
Compare
Restore


Step 2: Modify handleRelayStream

Now, let's update handleRelayStream in relay.go to correctly handle the LayeredPayload structure for intermediate hops and forward the inner payload directly.


Cline wants to edit this file:

Checkpoint
Compare
Restore


Okay, the relay handler logic has been updated to align with the structure produced by CreateOnionLayers.

Let's run the TestOnionNetworkTraversal test again to see if these changes resolved the issues.


Cline wants to execute this command:
go test ./internal/onion -run TestOnionNetworkTraversal -v
Command Output

Checkpoint
Compare
Restore


Excellent! Both TestOnionNetworkTraversalFixed and TestOnionNetworkTraversal are now passing, along with TestStaleCircuitCleanup which we fixed earlier.

It appears the changes to handleRelayStream and DecodeLayeredPayload correctly addressed the type mismatch and decryption issues.


Task Completed
All previously failing tests (TestStaleCircuitCleanup, TestOnionNetworkTraversalFixed, TestOnionNetworkTraversal) in the internal/onion package are now passing. The mutex issue in circuit cleanup and the packet layering/decoding logic in the relay handler have been corrected.


See new changes

now focus on next task


Alright, we've successfully fixed the failing tests related to onion packet relaying and circuit cleanup. The core relaying mechanism seems solid now.

Based on our overall goal and the components we have, the next logical step is to implement the Circuit Setup Protocol. Currently, we have the handleCircuitSetup function on the relay side, but we need the client-side logic to actually initiate the creation of these circuits.

Here's a plan for that:

Define Client-Side Circuit Setup Logic:

Create functions within the internal/onion package (or potentially a new client-focused file like internal/onion/client.go or circuit_builder.go) responsible for building a new circuit.
This logic will need to:
Select a path of relay nodes (initially, we can use a predefined or randomly selected list for testing).
Perform the "telescoping" key exchange:
Connect to the first relay (R1), perform Diffie-Hellman, get a shared key (K1).
Instruct R1 (over the encrypted channel) to extend the circuit to R2.
Perform DH through R1 to get a shared key with R2 (K2).
Repeat for all relays in the path.
Store the resulting circuit path and shared keys securely on the client side.
Handle potential errors during setup (e.g., a relay being unavailable).
Implement Supporting Structures:

Define necessary message structures for the client-to-relay communication during setup (if different from CircuitSetupMessage or if additional client-specific info is needed).
Define a structure on the client side to hold the state of an established circuit (path, keys, ID).
Write Tests:

Create tests (e.g., in circuit_builder_test.go) to verify the circuit setup process.
These tests will likely involve mock relays or setting up a small local libp2p network to simulate the key exchange and forwarding process.
Test successful circuit creation with multiple hops.
Test error handling scenarios (e.g., relay failure).
This will give us the ability to establish the secure, layered paths needed before we can send actual application data (like document publish requests) through them.

Does this sound like the right next step? If so, you can switch me to ACT MODE, and we can start by defining the necessary functions and structures for the client-side circuit building.