#pragma once

/** X.x.x: Major version of the stack */
// #define LWIP_VERSION_MAJOR      2
/** x.X.x: Minor version of the stack */
// #define LWIP_VERSION_MINOR      1
/** x.x.X: Revision of the stack */
// #define LWIP_VERSION_REVISION   2
/** For release candidates, this is set to 1..254
  * For official releases, this is set to 255 (LWIP_RC_RELEASE)
  * For development versions (Git), this is set to 0 (LWIP_RC_DEVELOPMENT) */
// #define LWIP_VERSION_RC         LWIP_RC_RELEASE

/** LWIP_VERSION_RC is set to LWIP_RC_RELEASE for official releases */
// #define LWIP_RC_RELEASE         255
/** LWIP_VERSION_RC is set to LWIP_RC_DEVELOPMENT for Git versions */
// #define LWIP_RC_DEVELOPMENT     0

// #define LWIP_VERSION_IS_RELEASE     (LWIP_VERSION_RC == LWIP_RC_RELEASE)
// #define LWIP_VERSION_IS_DEVELOPMENT (LWIP_VERSION_RC == LWIP_RC_DEVELOPMENT)
// #define LWIP_VERSION_IS_RC          ((LWIP_VERSION_RC != LWIP_RC_RELEASE) && (LWIP_VERSION_RC != LWIP_RC_DEVELOPMENT))

/* Some helper defines to get a version string */
// #define LWIP_VERSTR2(x) #x
// #define LWIP_VERSTR(x) LWIP_VERSTR2(x)
// #if LWIP_VERSION_IS_RELEASE
// #define LWIP_VERSION_STRING_SUFFIX ""
// #elif LWIP_VERSION_IS_DEVELOPMENT
// #define LWIP_VERSION_STRING_SUFFIX "d"
// #else
// #define LWIP_VERSION_STRING_SUFFIX "rc" LWIP_VERSTR(LWIP_VERSION_RC)
// #endif

/** Provides the version of the stack */
// #define LWIP_VERSION   ((LWIP_VERSION_MAJOR) << 24   | (LWIP_VERSION_MINOR) << 16 | \
//                         (LWIP_VERSION_REVISION) << 8 | (LWIP_VERSION_RC))
/** Provides the version of the stack as string */
// #define LWIP_VERSION_STRING     LWIP_VERSTR(LWIP_VERSION_MAJOR) "." LWIP_VERSTR(LWIP_VERSION_MINOR) "." LWIP_VERSTR(LWIP_VERSION_REVISION) LWIP_VERSION_STRING_SUFFIX

/**
 * @}
 */

/* Modules initialization */
void lwip_init(void);

//
// END OF FILE
//