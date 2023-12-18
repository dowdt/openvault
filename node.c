#include "net.c"
#include "block.c"
#include "tlse/tlse.h"

#define WITH_TLS_13
#include "tlse/tlse.c"

// for now just handling the verification

// SPOILERS!!
//  - Blockchain node behaviour
//  - what should a node do?
//  - is a verifier and a miner the same thing?
//  - probably not right?
//  - but it could be in the same exe or changed at compile time
//  - they both have to verify all the blockchain, keep track of state, connect to peers. it makes sense to combine all that here
//  - need deterministic method to derive verifiers from rest


// first things first, do the verification
//  - wire-tapping MitM
//  - connect and get data from server
//  - verify the data WITH SCIENCE! separately
typedef struct
{
    Socket towardsClient;
    Socket towardsServer;

    unsigned short block_count;
    HashedBlock blocks[MAX_BLOCKS_PER_REQUEST];
    Address address; // you know to sign and stuff
} SnooperNode;

typedef struct
{
    Socket towardsClient;
    Socket towardsServer;

    char blocks;
    Signature s;
} WitnessNode; // rename to verifier node maybe?

void edge_node()
{
    // ??
}

int main()
{
    // TLS request coming up
    tls_init();


    return 0;
}
