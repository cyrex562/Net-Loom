#pragma once
#include <cstdint>

struct PppPcb;

/*
 * The following struct gives the addresses of procedures to call
 * for a particular protocol.
 */
struct Protent {
    uint16_t protocol;		/* PPP protocol number */
    /* Initialization procedure */
    void (*init) (PppPcb* pcb);
    /* Process a received packet */
    void (*input) (PppPcb* pcb, uint8_t* pkt, int len, Protent** protocols);
    /* Process a received protocol-reject */
    void (*protrej) (PppPcb* pcb);
    /* Lower layer has come up */
    void (*lowerup) (PppPcb* pcb);
    /* Lower layer has gone down */
    void (*lowerdown) (PppPcb* pcb);
    /* Open the protocol */
    void (*open) (PppPcb* pcb);
    /* Close the protocol */
    void (*close) (PppPcb* pcb, const char* reason);
    /* Process a received data packet */
    void (*datainput) (PppPcb* pcb, uint8_t* pkt, int len);
    // option_t *options;		/* List of command-line options */
    /* Check requested options, assign defaults */
    void (*check_options) (void);
    /* Configure interface for demand-dial */
    int  (*demand_conf) (int unit);
    /* Say whether to bring up link for this pkt */
    int  (*active_pkt) (uint8_t* pkt, int len);
};

// END OF FILE