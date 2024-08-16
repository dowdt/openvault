# OpenVault
A decentralized archiving network written in C, made for the Openmesh data verification hackathon.
With the goal of making HTTPS connection recordings non-repudiable.


# What's Implemented
I've implemented the chain request process.
This is the stage where the chain of fixed peers is given an HTTP host and an address.

So far it can handle most addresses and requests.
It can't yet parse sha384 requests since the library I'm using to parse TLS, doesn't support it.
Some connections also don't terminate properly.

Each node hashes every message and signs it before dumping it into a log file located in log/node*.txt.
From this it should be possible to reconstruct the message given the raw data connection data and TLS encryption keys are also given.

There are early designs and explorations for the blocks and for the a pseudo-random verifier chain determination, and a dns server, but those will be crystalized in the future.

The next step would be to share the TLSContext struct around which should let me recreate TLS connection after the fact.

# Hackathon submission video
[![YouTube](http://i.ytimg.com/vi/BomzJLw8PcI/hqdefault.jpg)](https://www.youtube.com/watch?v=BomzJLw8PcI)

# Hackathon presentation video
[![YouTube](http://i.ytimg.com/vi/YiRW_hjkDfo/hqdefault.jpg)](https://www.youtube.com/watch?v=YiRW_hjkDfo)

# Navigating the repo

## Dependencies
- c compiler
- tomcrypt
- tommath

The structure of each block has been layed out in block.c

node.c defines most of the code used in the demo.
It currently stores the state of all the nodes and their data, plus all the HTTPS logic that isn't tls or parsing.

net.c is my thin layer on top of basic berkley sockets which lets me override default operations and assists me in debugging.

types.h and util.c have a couple of utility functions and types mostly for debugging and stuff.

block.c has some types used in the node as well as some initial datastructure designs for the blockchain and network.
It shows a good outlook into the future direction of the project.

tlse a public domain C tls protocol implementation 

libhttp an MIT licensed C HTTP parser, used to show only content on node0's output.

run.sh is the script used to compile and run the program.
I'm using unity builds so all the imports are compiled every build, even the dependency libraries.
This was done to speed up development.


# Design and description of the protocol (Part of the hachathon submission)

## Philosophy
I value truth and think we need more concrete anchors to verify online content.

My goal is to make a system that is as robust and trustless as possible.
This means not trusting authorities, a shared consensus, or "known" peers.

From this principle I came up with the design of this system.
I'm open to feedback my email address is tomd AT airmail.cc.

## Design
The idea for the protocol is a proof of work chain that builds a queue of requested GET and HTTP requests.
These are then read and actioned by validators which self organize to address the query.

In essence each HTTPS request is marshaled through a chain of peers.
These peers each record, hash, and sign the encrypted packet data and send it to the chain.
Once the connection is closed, everything is sent to a proof of stake blockchain which logs it permanently.

Since the first peer can't fake the connection, the middle peers have no access or control, and the last peer has no means to fake the encrypted portion of the connections, the server is secure.
To maximize this guarantee all validators have to stake coins to begin to validate any blocks, which reduces the odds that one or more validators are the same person.

In other words. 
For someone to fake a connection, they'd have to stake enough coins to run more than half of the validators.
And even in that case, there's no guarantee that it will work.

### How would validators connect to one another?
I was inspired by the way the lokinet (renamed to oxen) project sometimes choses to verify peers.

Basically the last three block's pending GET requests each have a nonce which would be hashed and mixed with the previous block nonce and the offset into the current GET request buffer to get the index of a validator in a sequence.
If the validator is taken (meaning assigned to a different request), the next one sequentially is chosen.
In this way the order of the connections is chosen, then all they'd have to do is find each other in the network by broadcasting their intention to connect and form tcp connections in sequence.

### Why proof of work
Currently it is the only *completely trustless* way to get decentralised consensus.
By this I mean there are zero authorities, governing agencies, community controls, etc.
The cannonical bitcoin is the one with the most power put into it, not the one Satoshi endorses.

### Why HTTP
It's the lingua franca of the internet.
Most servers use it and crucially it's also supported by most APIs.

### What are some sample use cases
- archive API requests
    - archive GPT output from a JSON message and compare it to later periouds
    - archive financial data
    - archive fraudulent data in an irrecovacle way.
- generic archival site
    - archive.org alternative, post just HTML or hyperlinks, etc
- provide verification of unverified data
    - unsigned emails can be verified by running a GET request on a public email address (unlike screenshots or videos or copies it can't be faked)
    - log historic prices by running a GET request an ebay page
- archive important information to prevent reputability even in high stakes situations
    - holding governments accountable for previous statements / policies

## Learning
I learned heaps about C, blockchain, cryptography, TLS, and even HTTP.
This project really challenged my understanding of these technologies and broadened my perspective.

## Future plans
My idea of this network is a generic archiving system with high trust in it's content.
I would like this to be a kind of objective metric to ground the internet in more truth.

In terms of infrastructure, apart from finishing the initial design, the raw data for each connection should be stored off chain. So an ipfs integration seems pretty critical here.

I'd also like to create some tools to be able to record and publish private network HTTPS connections.
Meaning you'd be like the A node in the connection and your private email data could be verified in the future.

Similarly, tools to parse the blockchain to find specific details is pretty key as well as at least a wallet cli to make transactions and request .

Attaching the project to stronger proof of work chain might also be a good direction, given adoption is a key priority.
This is a likely outcome, but the a lot this code would probably stay the same.
The new chain would be a superset of the current system, minus address or signing details.

In terms of future direction, creating an archive.org alternative sounds like an achievable outcome.
Here people could donate some of their tokens to minor organizations or groups to cover a balanced perspective of the internet.
People might be able to vote for where to allocate certain tokens in a smart contract or some other such mechanism.
So long as a single institution doesn't control more than 51% of all tokens this decentralised version of archive.org would belong entirely to the users and be free of any tampering (and more importantly the possibility of tampering).

- fix sha384 bug
- finish full protocol
- improve reliability
- extend to full http
- make a client app to record personal messages and compare
- come up with some kind of ...
