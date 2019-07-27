//
// file: lwip_error.h
//
#pragma once
#include <string>
#include <map>


/** Definitions for error constants. */
enum LwipStatus
{
    /** No error, everything OK. */
    ERR_OK = 0,
    /** Out of memory error.     */
    ERR_MEM = -1,
    /** Buffer error.            */
    ERR_BUF = -2,
    /** Timeout.                 */
    ERR_TIMEOUT = -3,
    /** Routing problem.         */
    ERR_RTE = -4,
    /** Operation in progress    */
    ERR_INPROGRESS = -5,
    /** Illegal value.           */
    ERR_VAL = -6,
    /** Operation would block.   */
    ERR_WOULDBLOCK = -7,
    /** Address in use.          */
    ERR_USE = -8,
    /** Already connecting.      */
    ERR_ALREADY = -9,
    /** Conn already established.*/
    ERR_ISCONN = -10,
    /** Not connected.           */
    ERR_CONN = -11,
    /** Low-level netif error    */
    ERR_IF = -12,
    /** Connection aborted.      */
    ERR_ABRT = -13,
    /** Connection reset.        */
    ERR_RST = -14,
    /** Connection closed.       */
    ERR_CLSD = -15,
    /** Illegal argument.        */
    ERR_ARG = -16
};


const std::map<int, std::string> STATUS_STRINGS = {
    {0, "success"},
    {-1, "out of memory"},
    {-2, "buffer error"},
    {-3, "timeout"},
    {-4, "routing error"},
    {-5, "operation in progress"},
    {-6, "illegal value"},
    {-7, "operation would block"},
    {-8, "address in use"},
    {-9, "already connecting"},
    {-10, "connection already established"},
    {-11, "not connected"},
    {-12, "low-level network interface error"},
    {-13, "connection aborted"},
    {-14, "connection reset"},
    {-15, "connection closed"},
    {-16, "illegal argument"}
};

//
//
//
inline std::string
status_to_string(const LwipStatus status)
{
    return STATUS_STRINGS[int(status)];
}


//
// END OF FILE
//
