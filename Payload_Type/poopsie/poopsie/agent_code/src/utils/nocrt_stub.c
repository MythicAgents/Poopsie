/* Minimal stubs for -nostartfiles (nocrt) builds.
 * When the CRT startup objects are removed, mingw's pseudo-relocation
 * mechanism still references _pei386_runtime_relocator. This provides
 * a no-op stub. For DLL builds a minimal DllMainCRTStartup is also
 * provided that forwards to Nim's generated DllMain. */

void _pei386_runtime_relocator(void) {}

#if defined(NOCRT_DLL)
#include <windows.h>
extern BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);
BOOL WINAPI DllMainCRTStartup(HINSTANCE h, DWORD r, LPVOID p) {
    return DllMain(h, r, p);
}
#endif
