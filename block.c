#include "types.h"

typedef struct
{
    // in bitcoin they use base 58 hash of public key
} Address;

typedef struct
{
    
} Signature;

typedef struct
{
    Address from;
    unsigned int nonce;
    union
    {
        struct
        {
            Address to;
            int amount;
        };

        // give to miner

        struct
        {
            // ???
        };
    };
} Transaction;

// Address util functions
// - sign(Address a, Hash* ret)
// - verify(Address a, Hash b?)
// - send
// - connect

#define MAX_VERIFIERS_PER_BLOCK 64
#define MAX_REQUESTS_PER_BLOCK 64
#define MAX_HOST_LENGTH 32
#define MAX_PATH_LENGTH 64

typedef struct
{
    // hash of previous block / founding block
    byte prev_block[32];
    byte difficulty; // 0 - 255 bits of difficulty

    // transactions
        // dest, recp, amount, signature
    unsigned int transaction_count;

    // transaction showing money for miner

    // "alive" verifiers, addresses + signature from last block proving they are active
    //  - list of available verifiers or if overflowing, list of random verifiers
    //  - a verifier is an address with a minimum amount of $$ that is broadcasting it wants to participate
    unsigned int verifier_count;
    struct
    {
        // verifier address, verifier prev nonce signature
    } verifiers[MAX_VERIFIERS_PER_BLOCK];

    // ---
    // completed requests
    unsigned int requests_completed_count; // can be zero
    struct
    {
        /* Address from; */
        /* unsigned int reward; */
        /* // this should just point to the hash of the previous block's reward? */
        /* // how do i turn address to ip? */
        /* //  - well, we know the order of the connections so A broadcasts Enc(ip address, B), B sends Enc(ip address, C) and so on */
        /* Address chainers[5]; */
        /* Address verifiers[5]; */
        // result?
        // maybe keep in IPFS / bitorrent?

        // signatures of chainers
        // A sign, B sign
        // signatures of verifiers
        // E sign, F sign, etc


        byte status; // success, fail

        // if success
        struct
        {
            
        };
    } requests_completed[MAX_REQUESTS_PER_BLOCK];

    // requests missing
        // 95 / 5 split between verifiers and person mining this block
        // there is a minimum spend to be in list, oldest requests are dropped
    unsigned int requests_unfulfilled_count;
    struct
    {
        // should store a random value that expands to correct ordering based on available verifiers from last block
        // random value that encodes which nodes to chose and stuff, random value is nonce XOR with request #
        int seed;

        // request
        char host[MAX_HOST_LENGTH];
        char path[MAX_PATH_LENGTH]; // full HTTP GET request ie google.com/test or youtube.com/home

        // transaction
        Address from;
        unsigned int value;

        Signature s;

    } requests_unfulfilled[MAX_REQUESTS_PER_BLOCK];
    
    unsigned int nonce;
    unsigned long timestamp_unix;
    // hash of next block
    byte solved_hash[32];
} BlockShared;

typedef struct
{
    BlockShared block_shared;
    BlockShared* prev;
    byte next_amount;
    BlockShared* next[256]; // cap bc otherwise infinite alloc
} BlockInternal;


// check that the block is correctamundo
void verify_block()
{
    // can't check if validators field is correct
    //  - there has to be a different way to verify/enlist these guys
    //  - maybe they can randomly sort themselves after every block?
    //  - how do they find their addresses and stuff?
    //      - maybe they can use a kind of proof of work to draw a lottery?
    //      - or they can chose randomly amongst themselves?
    //      - maybe you just publish the results to the chain from addresses that are already established
    //      - maybe I can reward miner based on # of verifiers detected
    //      - actually miner is incentivised to have highest number of verifiers possible


    // TODO: Things to check
    //  - is timestamp greater than previous
    //  - are the verifiers legitimate
    //  - are the transactions legit
    //  - is the reward the correct amount
    //  - make sure that requests aren't removed unless no more space is left
    //  - make sure
}

// XXX: node should handle this actually
void sync()
{
    // start at genesis block and build up chain, by verifying blocks
    
    // announce syncing
    // ann
}
