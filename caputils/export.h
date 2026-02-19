#ifndef CAPUTILS_EXPORT_H
#define CAPUTILS_EXPORT_H


/** @todo should feature-detect this instead */
/*
#if defined(__GNUC__) && !defined(__clang__)
#define CAPUTILS_API __attribute__ ((pure, visibility ("default")))
#else
#define CAPUTILS_API 
#endif
#ifndef CAPUTILS_EXPORT_H
#define CAPUTILS_EXPORT_H
*/


#if defined(__GNUC__) && __GNUC__ >= 4
#  define CAPUTILS_API __attribute__((visibility("default")))
#else
#  define CAPUTILS_API
#endif

/* Optional: a separate “pure” macro if you ever need it */
#if defined(__GNUC__)
#  define CAPUTILS_PURE __attribute__((pure))
#else
#  define CAPUTILS_PURE
#endif

#endif /* CAPUTILS_EXPORT_H */
