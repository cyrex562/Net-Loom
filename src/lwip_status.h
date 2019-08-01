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
    STATUS_OK = 0,
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
    ERR_ARG,

    STATUS_NOT_FOUND,
    STATUS_E_NOT_IMPLEMENTED,
    STATUS_E_INVALID_PARAM,
};


const std::map<LwipStatus, std::string> STATUS_STRINGS = {
        {STATUS_OK, "success"},
        {ERR_MEM, "out of memory"},
        {ERR_BUF, "buffer error"},
        {ERR_TIMEOUT, "timeout"},
        {STATUS_E_ROUTING, "routing error"},
        {ERR_INPROGRESS, "operation in progress"},
        {ERR_VAL, "illegal value"},
        {ERR_WOULDBLOCK, "operation would block"},
        {ERR_USE, "address in use"},
        {ERR_ALREADY, "already connecting"},
        {ERR_ISCONN, "connection already established"},
        {ERR_CONN, "not connected"},
        {ERR_IF, "low-level network interface error"},
        {ERR_ABRT, "connection aborted"},
        {ERR_RST, "connection reset"},
        {ERR_CLSD, "connection closed"},
        {ERR_ARG, "illegal argument"},
        {STATUS_NOT_FOUND, "search didnt find anything"},
        {STATUS_E_NOT_IMPLEMENTED, "function not implemented"},
};

//
//
//
inline std::string
status_to_string(LwipStatus status)
{
    return STATUS_STRINGS[status];
}


//
// END OF FILE
//
