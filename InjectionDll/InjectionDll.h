#pragma once
#include "..\Injection\Macro.h"

Export HHOOK SetHook(int tid);
Export int Unhook(HHOOK hhook);
Export void SetPathA(char* buffer);
Export void SetPathW(WCHAR* buffer);
Export int load;

#ifdef UNICODE
#define SetPath SetPathW
#else
#define SetPath SetPathA
#endif // UNICODE
