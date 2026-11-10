// ForceFG (experimental) for Wuthering Waves.
// The game turns DLSS-FG off by setting the cvar r.Streamline.DLSSG.Enable to 0
// (menus/dialogue). Console commands from a plugin are ignored, so this locates the
// FConsoleVariable<int32> object in memory and writes its shadowed values back.
// Enabled only when ww_fgtrace.ini next to this DLL has [FGTrace] Enable=1.
//   ForceMode=0  log cvar changes only;  ForceMode=2  force non-zero by polling
//   (Raising the cvar's SetBy priority was tried and does not stop the game's writes.)
//   ForceValue=1 value written while forcing (1 = always on; 0 = game's last non-zero)
#include <windows.h>
#include <atomic>
#include <climits>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include <SDK.hpp>

using namespace SDK;

extern bool scanOffsetsDone;

namespace {

wchar_t g_logPath[MAX_PATH];
std::mutex g_logMutex;
uintptr_t g_base = 0;
size_t g_imageSize = 0;
int g_forceMode = 0;
int g_forceValue = 1;

void Log(const char* fmt, ...)
{
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    SYSTEMTIME st;
    GetLocalTime(&st);
    std::lock_guard<std::mutex> lock(g_logMutex);
    FILE* fp = _wfopen(g_logPath, L"a");
    if (!fp) return;
    fprintf(fp, "[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    fclose(fp);
}

bool InImage(uintptr_t a) { return a >= g_base && a < g_base + g_imageSize; }

bool SafeRead(const void* src, void* dst, size_t n)
{
    __try { memcpy(dst, src, n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool ReadInt(uintptr_t a, int* v) { return SafeRead(reinterpret_cast<void*>(a), v, 4); }
bool WriteInt(uintptr_t a, int v)
{
    __try { *reinterpret_cast<volatile int*>(a) = v; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Reads a cvar through KismetSystemLibrary (ProcessEvent). Used only while learning.
int CVarImpl(const wchar_t* name) { return UKismetSystemLibrary::GetConsoleVariableIntValue(FString(name)); }
bool SafeCVar(const wchar_t* name, int* out)
{
    __try { *out = CVarImpl(name); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---------------- locate the cvar object ----------------
const wchar_t kEnableName[] = L"r.Streamline.DLSSG.Enable";
const wchar_t kEnableHelp[] = L"DLSS-FG mode (default = 0)\n0: off\n1: always on\n2: auto mode (on only when it helps)\n";
constexpr int kScanFrom = 0x18;
constexpr int kScanTo = 0x60;      // keep the search inside a small object

bool PrivateRW(const MEMORY_BASIC_INFORMATION& m)
{
    return m.State == MEM_COMMIT && m.Type == MEM_PRIVATE && m.Protect == PAGE_READWRITE;
}

int FindWStrInRegion(const char* region, size_t size, const wchar_t* str, size_t bytes, uintptr_t* out, int max)
{
    int n = 0;
    __try {
        for (size_t i = 0; i + bytes <= size && n < max; i += 2)
            if (*reinterpret_cast<const wchar_t*>(region + i) == str[0] && memcmp(region + i, str, bytes) == 0)
                out[n++] = (uintptr_t)(region + i);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return n;
}

int FindQwordInRegion(const uintptr_t* q, size_t count, uintptr_t value, uintptr_t* out, int max)
{
    int n = 0;
    __try {
        for (size_t i = 0; i < count && n < max; ++i)
            if (q[i] == value) out[n++] = (uintptr_t)&q[i];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return n;
}

template <typename F>
void ForEachPrivateRW(F f)
{
    MEMORY_BASIC_INFORMATION mbi;
    for (uintptr_t p = 0x10000; p < 0x7FFFFFFF0000ull; p += mbi.RegionSize) {
        if (!VirtualQuery(reinterpret_cast<void*>(p), &mbi, sizeof(mbi))) break;
        if (PrivateRW(mbi) && !f(mbi)) break;
    }
}

struct CVarMem {
    uintptr_t obj = 0;
    uintptr_t vtable = 0;
    uintptr_t help = 0;
    int candidates[32];
    int numCandidates = 0;
    int dataOff = -1;     // confirmed offset of ShadowedValue[0]; [1] at +4
    int confirmations = 0;
};

// The object is still the one we found (vtable and Help pointer unchanged).
bool StillValid(const CVarMem& cv)
{
    uintptr_t h[2];
    return SafeRead(reinterpret_cast<void*>(cv.obj), h, sizeof(h)) && h[0] == cv.vtable && h[1] == cv.help;
}

bool LocateEnableCVar(CVarMem& cv, int current)
{
    const size_t bytes = sizeof(kEnableHelp);           // includes terminator
    const int numChars = (int)(bytes / sizeof(wchar_t));
    uintptr_t strHits[8];
    int ns = 0;
    ULONGLONG t0 = GetTickCount64();
    ForEachPrivateRW([&](const MEMORY_BASIC_INFORMATION& m) {
        ns += FindWStrInRegion((const char*)m.BaseAddress, m.RegionSize, kEnableHelp, bytes, strHits + ns, 8 - ns);
        return ns < 8;
    });
    Log("help string copies on heap: %d (%llu ms)", ns, GetTickCount64() - t0);

    int found = 0;
    CVarMem best;
    for (int s = 0; s < ns; ++s) {
        uintptr_t refs[8];
        int nr = 0;
        ForEachPrivateRW([&](const MEMORY_BASIC_INFORMATION& m) {
            nr += FindQwordInRegion((const uintptr_t*)m.BaseAddress, m.RegionSize / 8, strHits[s], refs + nr, 8 - nr);
            return nr < 8;
        });
        for (int r = 0; r < nr; ++r) {
            uintptr_t obj = refs[r] - 8;              // FString Help right after the vtable
            unsigned char dump[kScanTo + 8];
            if (!SafeRead((void*)obj, dump, sizeof(dump))) continue;
            uintptr_t vt = *reinterpret_cast<uintptr_t*>(dump);
            int num = *reinterpret_cast<int*>(dump + 0x10), max = *reinterpret_cast<int*>(dump + 0x14);
            if (!InImage(vt) || num != numChars || max < num) continue;
            uintptr_t vfn0 = 0;
            if (!SafeRead((void*)vt, &vfn0, 8) || !InImage(vfn0)) continue;

            char hex[sizeof(dump) * 2 + 1];
            for (size_t i = 0; i < sizeof(dump); ++i) sprintf_s(hex + i * 2, 3, "%02X", dump[i]);
            Log("candidate object %p vtable_rva=0x%llX dump=%s", (void*)obj, (unsigned long long)(vt - g_base), hex);

            CVarMem c;
            c.obj = obj; c.vtable = vt; c.help = strHits[s];
            for (int off = kScanFrom; off + 8 <= kScanTo + 8 && c.numCandidates < 32; off += 4) {
                int a = *reinterpret_cast<int*>(dump + off), b = *reinterpret_cast<int*>(dump + off + 4);
                if (a == current && b == current) c.candidates[c.numCandidates++] = off;
            }
            Log("  value pair candidates for %d: %d", current, c.numCandidates);
            if (c.numCandidates > 0) { best = c; ++found; }
        }
    }
    if (found != 1) {
        Log("need exactly one candidate object, got %d", found);
        return false;
    }
    cv = best;
    return true;
}

// Each time the game changes the value, keep only candidates whose BOTH shadow
// values followed it. Writing is allowed after 2 confirmations with one survivor.
void Confirm(CVarMem& cv, int newValue)
{
    int keep = 0;
    for (int i = 0; i < cv.numCandidates; ++i) {
        int a = INT_MIN, b = INT_MIN;
        int off = cv.candidates[i];
        // the render-thread copy may lag by a frame; give it up to 200 ms
        for (int t = 0; t < 100; ++t) {
            if (!ReadInt(cv.obj + off, &a) || !ReadInt(cv.obj + off + 4, &b)) break;
            if (a == newValue && b == newValue) break;
            Sleep(2);
        }
        if (a == newValue && b == newValue) cv.candidates[keep++] = off;
    }
    cv.numCandidates = keep;
    if (keep == 1) {
        ++cv.confirmations;
        Log("offset 0x%X followed value %d (%d/2)", cv.candidates[0], newValue, cv.confirmations);
        if (cv.confirmations >= 2) {
            cv.dataOff = cv.candidates[0];
            Log("confirmed ShadowedValue offset 0x%X, forcing armed", cv.dataOff);
        }
    } else {
        Log("%d candidates followed value %d", keep, newValue);
    }
}

// ---------------- force loop ----------------
bool KeyPressedEdge(bool& wasDown)
{
    bool down = (GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(VK_F9) & 0x8000);
    bool edge = down && !wasDown;
    wasDown = down;
    return edge;
}

void ForceLoop()
{
    Log("ForceFG mode=%d value=%d (Ctrl+F9 toggles)", g_forceMode, g_forceValue);
    int v = 0;
    while (!SafeCVar(kEnableName, &v) || v == 0) Sleep(200);
    CVarMem cv;
    if (!LocateEnableCVar(cv, v)) { Log("cvar object not found; ForceFG disabled"); return; }

    // Learning: follow the game's own changes until the offset is confirmed.
    int last = v, lastNonZero = v;
    while (cv.dataOff < 0) {
        if (!StillValid(cv)) { Log("object changed during learning; ForceFG disabled"); return; }
        if (cv.numCandidates == 0) { Log("no candidate survived; ForceFG disabled"); return; }
        if (SafeCVar(kEnableName, &v) && v != last) {
            Confirm(cv, v);
            Log("game set Enable %d -> %d", last, v);
            last = v;
            if (v != 0) lastNonZero = v;
        }
        Sleep(20);
    }

    bool on = true, keyDown = false;
    RECT lastRect{};
    ULONGLONG rectChanged = 0, lastLog = 0, lastWindowCheck = 0;
    bool stable = false;
    unsigned writes = 0, zeroSeen = 0;
    int lastS0 = last;
    for (;;) {
        if (KeyPressedEdge(keyDown)) { on = !on; Log("ForceFG toggled %s", on ? "ON" : "OFF"); }

        int s0 = 0, s1 = 0;
        if (!StillValid(cv) || !ReadInt(cv.obj + cv.dataOff, &s0) || !ReadInt(cv.obj + cv.dataOff + 4, &s1)) {
            Log("cvar object no longer valid; ForceFG stopped");
            return;
        }
        if ((unsigned)s0 > 2 || (unsigned)s1 > 2) {
            Log("unexpected values game=%d render=%d; ForceFG stopped", s0, s1);
            return;
        }
        ULONGLONG now = GetTickCount64();
        if (s0 != lastS0) {
            if (s0 == 0) ++zeroSeen; else if (s0 != g_forceValue) lastNonZero = s0;
            if (now - lastLog > 1000) {
                Log("Enable game=%d render=%d (game zero writes %u, our writes %u)", s0, s1, zeroSeen, writes);
                lastLog = now;
            }
            lastS0 = s0;
        }

        if (now - lastWindowCheck >= 100) {     // window checks are cheap but not free; 10 Hz is enough
            lastWindowCheck = now;
            HWND w = FindWindowA("UnrealWindow", nullptr);
            RECT r{};
            if (w) GetClientRect(w, &r);
            if (memcmp(&r, &lastRect, sizeof(r)) != 0) { lastRect = r; rectChanged = now; }
            stable = w && !IsIconic(w) && now - rectChanged > 3000;
        }

        if (on && stable && (s0 == 0 || s1 == 0)) {
            int target = g_forceValue > 0 ? g_forceValue : lastNonZero;
            if (!WriteInt(cv.obj + cv.dataOff, target) || !WriteInt(cv.obj + cv.dataOff + 4, target)) {
                Log("write failed; ForceFG stopped");
                return;
            }
            if (writes++ == 0) Log("forcing Enable to %d", target);
            lastS0 = target;
        }
        Sleep(1);
    }
}

void LogOnlyLoop()
{
    int last = INT_MIN, v = 0;
    for (;;) {
        if (SafeCVar(kEnableName, &v) && v != last) { Log("CVAR Enable = %d", v); last = v; }
        Sleep(50);
    }
}

DWORD WINAPI TraceThread(LPVOID)
{
    while (!scanOffsetsDone) Sleep(100);
    Log("offsets ready");
    if (g_forceMode >= 2) ForceLoop(); else LogOnlyLoop();
    return 0;
}

} // namespace

void StartFGTrace(HMODULE hModule)
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(hModule, path, MAX_PATH);
    std::wstring dir = path;
    dir = dir.substr(0, dir.find_last_of(L"\\/") + 1);
    std::wstring ini = dir + L"ww_fgtrace.ini";
    if (GetPrivateProfileIntW(L"FGTrace", L"Enable", 0, ini.c_str()) != 1) return;

    g_forceMode = GetPrivateProfileIntW(L"FGTrace", L"ForceMode", 0, ini.c_str());
    g_forceValue = GetPrivateProfileIntW(L"FGTrace", L"ForceValue", 1, ini.c_str());
    if (g_forceValue < 0 || g_forceValue > 2) g_forceValue = 1;
    wcsncpy_s(g_logPath, (dir + L"ww_fgtrace.log").c_str(), _TRUNCATE);
    HMODULE exe = GetModuleHandleW(nullptr);
    g_base = reinterpret_cast<uintptr_t>(exe);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(exe);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(g_base + dos->e_lfanew);
    g_imageSize = nt->OptionalHeader.SizeOfImage;
    Log("FGTrace start base=%p", exe);
    CreateThread(nullptr, 0, TraceThread, nullptr, 0, nullptr);
}
