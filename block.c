#include "types.h"
#include <stdio.h>
#include <tomcrypt.h>

typedef struct
{
    int a;
    rsa_key key;
    // in bitcoin they use base 58 hash of public key
} Address;

typedef struct
{
    int b;
} Signature;


bool address_equals(Address a, Address b)
{
    if (a.a == b.a)
        return 1;
    else
        return 0;
}


typedef struct
{
    Address from;
    unsigned int nonce; // aparently this is incremented for every transaction
    union
    {
        struct
        {
            unsigned int amount;
            unsigned int fee; // optional fee
            Address to;
        };

        // just a reward

        struct
        {
            unsigned int reward;
        };
    };
} Transaction;

typedef struct
{
    byte hash[32];
    Signature s;
} HashedBlock;

// Address util functions
// - sign(Address a, Hash* ret)
// - verify(Address a, Hash b?)
// - send
// - connect

#define MAX_VERIFIERS_PER_BLOCK 32
#define MAX_TRANSACTIONS_PER_BLOCK 128
#define MAX_REQUESTS_PER_BLOCK 64
#define MAX_HOST_LENGTH 32
#define MAX_PATH_LENGTH 64
#define MAX_CHAINERS_PER_REQUEST 5
#define MAX_VERIFIERS_PER_REQUEST MAX_CHAINERS_PER_REQUEST

#define MAX_DATA_PER_REQUEST 1028
#define VERIFY_BLOCK_SIZE_BYTES 256
#define MAX_BLOCKS_PER_REQUEST (unsigned int)(MAX_DATA_PER_REQUEST / VERIFY_BLOCK_SIZE_BYTES) + 1

#define TARGET_BLOCK_DURATION_SECONDS 60

typedef struct
{
    // hash of previous block / founding block
    byte prev_block[32];
    byte difficulty; // 0 - 255 bits of difficulty

    // transactions
        // dest, recp, amount, signature
    unsigned int transaction_count;
    Transaction* transactions;
    Transaction mine_block_reward;

    // "alive" verifiers, addresses + signature from last block proving they are active
    //  - list of available verifiers or if overflowing, list of verifiers that weren't in last block
    //  - a verifier is an address with a minimum amount of $$ that is broadcasting it wants to participate
    unsigned int verifier_count;
    struct
    {
        Address address;
        Signature s; // signature is H(address + prev hash)
    } verifiers[MAX_VERIFIERS_PER_BLOCK];

    // ---
    // completed requests
    unsigned int requests_completed_count; // can be zero
    struct
    {
        // reference from previous block
        // snoopers get 50% of the 95%
        struct SnooperResult
        {
            int nonce; // each verifier increments the nonce
            HashedBlock signed_encrypted_blocks[MAX_BLOCKS_PER_REQUEST];
        }* snooper_results;
        // witnesses get 50% of the 95%
        struct WitnessResult
        {
            int nonce;
            HashedBlock signed_plaintext_blocks[MAX_BLOCKS_PER_REQUEST];
        }* witness_results;

        enum {
            NO_SERVER,
            INVALID_CERT,
            NO_PEERS,
            SUCCESS
        } status;
        // stored elsewhere in pc, bc too much mem otherwise
        byte* data;
        // make optional??
        byte* encrypted_data;
    } requests_completed[MAX_REQUESTS_PER_BLOCK];

    // requests missing
        // 95 / 5 split between verifiers and person mining this block
        // there is a minimum spend to be in list, oldest requests are dropped
    unsigned int requests_pending_count;
    struct RequestPending
    {
        // should store a random value that expands to correct ordering based on available verifiers from last block
        // random value that encodes which nodes to chose and stuff, random value is nonce XOR with request #
        int nonce;

        // request
        char host[MAX_HOST_LENGTH];
        char path[MAX_PATH_LENGTH]; // full HTTP GET request ie google.com/test or youtube.com/home

        // transaction
        Address from;
        unsigned int value;

        Signature s;
    }* requests_pending;
    
    unsigned int nonce;
    unsigned long timestamp_unix;
    // hash of next block
    byte solved_hash[32];
} BlockchainShared;

/* typedef struct */
/* { */
/*     BlockchainShared block_shared; */
/*     BlockchainShared* prev; */
/*     byte next_amount; */
/*     BlockchainShared* next[256]; // cap bc otherwise infinite alloc */
/* } BlockchainInternal; */


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
    //  - make sure data is valid
    //      - compare against max size for all fields
    //  - check previous block is correct
    //  - check difficulty is correct
    //  - check block reward is correct
    //  - check verifier addresses match signatures
    //  --- 
    //  - check snooper amounts match

    //  - is timestamp greater than previous
    //  - are the verifiers legitimate
    //  - are the transactions legit
    //  - is the reward the correct amount
    //  - make sure that requests aren't removed unless no more space is left
    //  - make sure that request proposal accounts actually have the money they pledge
    //  - make sure that 
}

// XXX: node should handle this actually
void sync()
{
    // start at genesis block and build up chain, by verifying blocks
    
    // announce syncing
    // ann
}

void block_test()
{
    printf("%lu\n", sizeof(BlockchainShared));

    BlockchainShared b;
    
    printf("%lu\n", sizeof(struct WitnessResult));
    printf("%lu\n", sizeof(b.requests_completed));
    printf("%lu\n", sizeof(b.requests_completed[0]));
}
