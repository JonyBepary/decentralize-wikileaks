## Project Plan: Decentralized Wikileaks Platform (MVP)

**1. Project Goal:**

To create a decentralized, anonymous, and censorship-resistant platform for publishing and accessing sensitive documents and articles, inspired by Wikileaks, using peer-to-peer technologies.

**2. Core Principles:**

*   **Anonymity:** Protect the identity and metadata (sender, receiver, timing) of users and publishers.
*   **Decentralization:** No central points of control or failure; rely on a network of peers.
*   **Censorship Resistance:** Design the system to be resilient against attempts to block content or identify users.
*   **Security:** Ensure confidentiality and integrity of communications and stored data.

**3. Key Features (MVP Focus):**

*   **Anonymous Identity:**
    *   Generation of a cryptographic key pair (Public Key = Account ID, Private Key = Recovery Password).
    *   No requirement for personal information.
    *   Ability to save/load/recover identity using the private key.
*   **Document Publishing:**
    *   Ability for users to anonymously publish documents/articles.
    *   Content stored verifiably and decentrally using IPFS.
*   **Document Retrieval:**
    *   Ability for users to anonymously retrieve and view published documents using their IPFS Content Identifier (CID).
*   **Content Discovery:**
    *   A mechanism (libp2p PubSub) for announcing newly published content CIDs on specific topics/channels.
*   **Anonymity Layer:**
    *   All network traffic (libp2p connections, PubSub messages, IPFS requests) must be routed through an anonymity-preserving network (mixnet).
    *   Abstract interaction with the anonymity layer via a dedicated interface.

**4. Architecture (MVP):**

```mermaid
graph TD
    subgraph UserClient [User Client Application (Go)]
        direction LR
        UI(User Interface/CLI) --> AppLogic(Application Logic)
        AppLogic -- Generate/Load --> Identity(Identity Mgmt - Keys)
        AppLogic -- Publish/Retrieve --> IPFSInt(IPFS Interaction)
        AppLogic -- Announce/Subscribe --> PubSubInt(PubSub Interaction)
        AppLogic -- All Network Ops --> AnonProvider(AnonymityProvider Interface)
    end

    subgraph Libp2pStack [Libp2p Stack (Go)]
        direction LR
        Libp2pHost(Libp2p Host) -- Uses --> Transport(libp2p Transports)
        Libp2pHost -- Uses --> PubSub(libp2p PubSub)
        Libp2pHost -- Uses --> Identify(libp2p Identify)
        %% Other core libp2p services
    end

    subgraph ExternalServices [External Dependencies]
        direction TB
        AnonymityNetwork(Nym Mixnet / Future Custom Layer)
        IPFSNetwork(IPFS Network / Hosting Nodes)
        PinningService(Optional: Pinning Service)
    end

    %% Interactions via AnonymityProvider
    AnonProviderImpl(NymProvider - Implements AnonProvider) --> Libp2pHost
    AnonProviderImpl -- Routes Traffic --> AnonymityNetwork

    %% IPFS Interaction
    IPFSInt -- Add/Get Data --> IPFSLocalNode(Local IPFS Node / Library)
    IPFSLocalNode -- Network Requests --> AnonProvider %% Route IPFS traffic

    %% PubSub Interaction
    PubSubInt -- Publish/Subscribe --> PubSub
    PubSub -- Network Traffic --> AnonProvider %% Route PubSub traffic

    %% IPFS Network Interaction via AnonProvider
    AnonProvider -- Routed IPFS Req --> IPFSNetwork
    IPFSNetwork -- Optionally Pins --> PinningService

    %% Direct Libp2p Node-to-Node (Conceptual Path through AnonymityNetwork)
    UserClient -- Libp2p Connections --> UserClient

style UserClient fill:#f9f,stroke:#333,stroke-width:2px
style Libp2pStack fill:#ccf,stroke:#333,stroke-width:2px
style ExternalServices fill:#cfc,stroke:#333,stroke-width:2px
```

*   **Client Application (Go):** Handles user interaction, identity management, and orchestrates interactions with IPFS, PubSub, and the anonymity layer.
*   **Libp2p Stack:** Provides the core P2P networking capabilities (connections, PubSub, peer identity).
*   **`AnonymityProvider` Interface:** A crucial abstraction layer defined in Go to decouple the application logic from the specific anonymity network implementation.
*   **Initial `NymProvider` Implementation:** A Go struct implementing the `AnonymityProvider` interface, using Nym for traffic routing.
*   **IPFS Integration:** Using a local IPFS node (e.g., Kubo run as a separate process or potentially an embedded Go IPFS library) for content-addressed storage. IPFS network requests are routed through the `AnonymityProvider`.
*   **PubSub for Discovery:** Using libp2p's PubSub implementation to broadcast/receive CIDs over the anonymity network.
*   **External Dependencies:** Relies on the operational Nym mixnet and the public IPFS network (including incentivized hosting/pinning nodes).

**5. Technology Stack (MVP):**

*   **Language:** Go
*   **Networking:** `go-libp2p`
*   **Storage:** IPFS (via Kubo API or embedded library like `boxo`)
*   **Anonymity (Initial):** Nym (via Go SDK, bindings, or interacting with a local Nym client)
*   **Persistence (Initial):** Relies on the IPFS network effect and potentially incentivized pinning (details TBD, simplified for MVP).

**6. Development Methodology:**

*   **Test-Driven Development (TDD):** Rigorous testing starting from the lowest level components (identity) and moving up. Unit, integration, and eventually end-to-end tests (using test networks).

**7. Key Design Decisions & Trade-offs (MVP):**

*   **Modular Anonymity Layer:** Prioritizing flexibility by defining the `AnonymityProvider` interface, allowing future replacement of Nym with a custom solution without rewriting the core application.
*   **Leveraging Nym:** Choosing Nym initially provides strong metadata protection against global adversaries but comes with higher latency compared to direct connections or Tor. This trade-off prioritizes anonymity strength for the MVP.
*   **Using IPFS:** Benefits from content addressing, verifiability, and existing infrastructure. Requires managing persistence through pinning (addressed potentially by future incentives). Metadata leakage during IPFS operations will be mitigated by routing requests through the `AnonymityProvider`.
*   **Simple PubSub Discovery:** Easy to implement for MVP, but may have scalability limitations compared to DHTs for large numbers of topics/announcements. Routing over the anonymity layer is essential.
*   **Deferred Features:** Complex features like real-time chat, custom routing/storage, advanced node ranking, sophisticated consensus/incentives, and open groups are postponed to focus on the core publishing/retrieval functionality for the MVP.

**8. Addressing Challenges (MVP Strategy):**

*   **Scalability:** Addressed by leveraging existing scalable systems (Nym, IPFS) and focusing on core functionality first. Application-level scaling will be considered post-MVP.
*   **Performance:** Latency impact of Nym is accepted for the MVP. Application logic will be optimized where possible.
*   **Usability:** MVP likely to have a basic CLI or simple UI. Focus is on demonstrating core functionality, not polished UX initially. A smaller initial user base for testing is acceptable and expected.
*   **Deployment/Maintenance:** Standard Go application deployment. Relies on the maintenance of the external Nym and IPFS networks.
*   **Incentives:** Deferred. MVP relies on intrinsic motivation or simulated rewards. Pinning might require manual intervention or reliance on public infrastructure initially.
*   **Robustness:** Leverage the robustness of Go, libp2p, Nym, and IPFS. TDD will enhance application-level robustness.

**9. Initial Development Steps (TDD Cycle):**

1.  **Setup:** Initialize Go project structure (`go mod init`, directories like `internal/identity`, `internal/network`, `internal/ipfs`, `internal/app`, `cmd/client`).
2.  **Interfaces:** Define the core `AnonymityProvider` interface in Go.
3.  **Identity:**
    *   TDD: Write failing test for `GenerateKeyPair()`.
    *   TDD: Implement `GenerateKeyPair()` using `go-libp2p-core/crypto`. Make test pass. Refactor.
    *   TDD: Write tests for saving/loading keys securely (e.g., to password-protected files).
    *   TDD: Implement saving/loading. Make tests pass. Refactor.
4.  **Libp2p Host:**
    *   TDD: Write test to create a basic libp2p host locally.
    *   TDD: Implement host creation. Make test pass. Refactor.
5.  **Mock Provider:**
    *   TDD: Implement a `MockAnonymityProvider` satisfying the interface for local testing *without* needing Nym/network. This provider could simulate connections/message passing locally.
6.  **IPFS Integration:**
    *   TDD: Write test for adding data to IPFS via an `IPFSInteraction` component (using local Kubo daemon or embedded library).
    *   TDD: Implement IPFS add. Make test pass. Refactor.
7.  **Nym Integration (Parallel or Next):**
    *   TDD: Research Nym Go options (SDK, client interaction). Write initial failing test for `NymProvider.DialPeerAnonymously` (might require setting up local Nym testnet/sandbox).
    *   TDD: Implement basic `NymProvider` methods. Make tests pass. Refactor.
8.  **PubSub Integration:**
    *   TDD: Write test for publishing/subscribing via the `AnonProvider` interface (using the `MockAnonymityProvider` first).
    *   TDD: Implement PubSub logic in `AppLogic` using the interface. Make test pass. Refactor.
9.  **IPFS Retrieval:**
    *   TDD: Write test for retrieving data from IPFS via `IPFSInteraction` (using CID).
    *   TDD: Implement retrieval. Make test pass. Refactor.
10. **Application Workflow:**
    *   TDD: Combine components to test the end-to-end publish (add to IPFS -> announce CID via PubSub) and retrieve (receive CID -> get from IPFS) flows, using the `MockAnonymityProvider`.
    *   Integrate with NymProvider for end-to-end testing over Nym testnet/sandbox.
11. **CLI/UI:** Build basic command-line interface or simple UI to interact with `AppLogic`.

**10. Test Network Strategy:**

*   **Unit Tests:** Standard Go testing for individual functions/components.
*   **Integration Tests:**
    *   Use `MockAnonymityProvider` to test interactions between AppLogic, IPFSInt, PubSubInt without real network/mixnet.
    *   Use local Kubo daemon for IPFS tests.
*   **End-to-End Tests:**
    *   Run multiple instances of the client application locally.
    *   Run a local IPFS node/network.
    *   Run a local Nym testnet (requires investigation based on Nym tooling) or use a Nym sandbox.
    *   Automate test scenarios simulating publishing and retrieval across multiple nodes via the anonymity layer.

