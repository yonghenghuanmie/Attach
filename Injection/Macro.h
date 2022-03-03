#pragma once

#ifdef Export

#undef Export
#ifdef __cplusplus
#define Export extern "C" __declspec(dllexport)
#else
#define Export __declspec(dllexport)
#endif // __cplusplus

#else

#ifdef __cplusplus
#define Export extern "C" __declspec(dllimport)
#else
#define Export __declspec(dllimport)
#endif // __cplusplus

#endif // Export