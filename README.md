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