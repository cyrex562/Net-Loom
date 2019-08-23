#pragma once

/**
 * Protocol field values.
 */
enum PppProtoFieldValue
{
    PPP_IP = 0x21,
    /* Internet Protocol */
    PPP_VJC_COMP = 0x2d,
    /* VJ compressed TCP */
    PPP_VJC_UNCOMP = 0x2f,
    /* VJ uncompressed TCP */
    PPP_IPV6 = 0x57,
    /* Internet Protocol Version 6 */
    PPP_COMP = 0xfd,
    /* compressed packet */
    PPP_IPCP = 0x8021,
    /* IP Control Protocol */
    PPP_IPV6CP = 0x8057,
    /* IPv6 Control Protocol */
    PPP_CCP = 0x80fd,
    /* Compression Control Protocol */
    PPP_ECP = 0x8053,
    /* Encryption Control Protocol */
    PPP_LCP = 0xc021,
    /* Link Control Protocol */
    PPP_PAP = 0xc023,
    /* Password Authentication Protocol */
    PPP_LQR = 0xc025,
    /* Link Quality Report protocol */
    PPP_CHAP = 0xc223,
    /* Cryptographic Handshake Auth. Protocol */
    PPP_CBCP = 0xc029,
    /* Callback Control Protocol */
    PPP_EAP = 0xc227,
    /* Extensible Authentication Protocol */
};

// END OF FILE