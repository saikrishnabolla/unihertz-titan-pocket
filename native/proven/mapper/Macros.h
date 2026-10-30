#pragma once
#include <cassert>
#define ALOGW_IF(...) ((void)0)
template<class... T> inline void discardLogArguments(T&&...) {}
#define ALOGW(...) discardLogArguments(__VA_ARGS__)
#define ALOGE(...) ((void)0)
#define LOG_ALWAYS_FATAL_IF(c,...) assert(!(c))
#define DEBUG_POINTERS false
