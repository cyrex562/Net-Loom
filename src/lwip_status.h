//
// file: lwip_error.h
//
#pragma once
#include <string>
#include <map>


/** Definitions for error constants. */
enum LwipStatus : uint32_t
{
    /** No error, everything OK. */
    STATUS_SUCCESS = 0,
    /** Out of memory error.     */
    ERR_MEM,
    /** Buffer error.            */
    ERR_BUF,
    /** Timeout.                 */
    ERR_TIMEOUT,
    /** Routing problem.         */
    STATUS_E_ROUTING,
    /** Operation in progress    */
    ERR_INPROGRESS,
    /** Illegal value.           */
    ERR_VAL,
    /** Operation would block.   */
    ERR_WOULDBLOCK,
    /** Address in use.          */
    ERR_USE,
    /** Already connecting.      */
    ERR_ALREADY,
    /** Conn already established.*/
    ERR_ISCONN,
    /** Not connected.           */
    ERR_CONN,
    /** Low-level netif error    */
    ERR_IF,
    /** Connection aborted.      */
    ERR_ABRT,
    /** Connection reset.        */
    ERR_RST,
    /** Connection closed.       */
    ERR_CLSD,
    /** Illegal argument.        */
    STATUS_E_INVALID_ARG,

    STATUS_NOT_FOUND,
    STATUS_E_NOT_IMPLEMENTED,
    STATUS_E_INVALID_PARAM,
    STATUS_ERROR,
};


//
//
//
inline std::string
status_to_string(const LwipStatus status)
{
    if (status == STATUS_SUCCESS) {
        return "success";
    }
    if (status == ERR_MEM) {
        return "memory allocation error";
    }
    if (status == ERR_BUF) {
        return "buffer error";
    }
    if (status == ERR_TIMEOUT) {
        return "timeout";
    }
    if (status == STATUS_E_ROUTING) {
        return "routing error";
    }
    if (status == ERR_INPROGRESS) {
        return "operation in progress";
    }
    if (status == ERR_VAL) {
        return "illegal value";
    }
    if (status == ERR_WOULDBLOCK) {
        return "operation would block";
    }
    if (status == ERR_USE) {
        return "address in use";
    }
    if (status == ERR_ALREADY) {
        return "already connecting";
    }
    if (status == ERR_ISCONN) {
        return "connection already established";
    }
    if (status == ERR_CONN) {
        return "not connected";
    }
    if (status == ERR_IF) {
        return "low-level network interface error";
    }
    if (status == ERR_ABRT) {
        return "connection aborted";
    }
    if (status == ERR_RST) {
        return "connection reset";
    }
    if (status == ERR_CLSD) {
        return "connection closed";
    }
    if (status == STATUS_E_INVALID_ARG) {
        return "invalid argument";
    }
    if (status == STATUS_E_NOT_IMPLEMENTED) {
        return "not implemented";
    }
    return "unknown status code";
}


//
// END OF FILE
//
