// ForceFG (experimental) for Wuthering Waves.
// The game turns DLSS-FG off by setting the cvar r.Streamline.DLSSG.Enable to 0
// (menus/dialogue). Console commands from a plugin are ignored, so this locates the
// FConsoleVariable<int32> object in memory and writes its shadowed values back.
// (Raising the cvar's SetBy priority was tried and does not stop the game's writes.)
//
// Runs only if configww.ini [Configs] EnableForceFG=1 (written by the launcher) at launch;
// afterwards it is re-read once a second:
//   EnableForceFG=1  keep Enable at 1 (always on) whenever the game sets it to 0
// Ctrl+F9 toggles forcing in game. Log: ww_fgtrace.log next to this DLL.
#include <windows.h>
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
wchar_t g_configPath[MAX_PATH];
std::mutex g_logMutex;
uintptr_t g_base = 0;
size_t g_imageSize = 0;

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

bool ReadForceSetting()
{
    return GetPrivateProfileIntW(L"Configs", L"EnableForceFG", 0, g_configPath) == 1;
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

// Reads a cvar through KismetSystemLibrary (ProcessEvent). Used for learning and verifying.
int CVarImpl(const wchar_t* name) { return UKismetSystemLibrary::GetConsoleVariableIntValue(FString(name)); }
bool SafeCVar(const wchar_t* name, int* out)
{
    __try { *out = CVarImpl(name); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---------------- locate cvar objects ----------------
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

struct CVarObj {
    uintptr_t obj = 0;
    uintptr_t vtable = 0;
    uintptr_t help = 0;
    unsigned char dump[kScanTo + 8];
};

// Finds console variable objects whose FString Help (right after the vtable) points
// to a heap copy of `help`.
template <size_t N>
int FindCVarObjects(const wchar_t (&help)[N], CVarObj* out, int max)
{
    const size_t bytes = N * sizeof(wchar_t);           // includes terminator
    uintptr_t strHits[8];
    int ns = 0;
    ULONGLONG t0 = GetTickCount64();
    ForEachPrivateRW([&](const MEMORY_BASIC_INFORMATION& m) {
        ns += FindWStrInRegion((const char*)m.BaseAddress, m.RegionSize, help, bytes, strHits + ns, 8 - ns);
        return ns < 8;
    });
    Log("help string copies on heap: %d (%llu ms)", ns, GetTickCount64() - t0);

    int found = 0;
    for (int s = 0; s < ns; ++s) {
        uintptr_t refs[8];
        int nr = 0;
        ForEachPrivateRW([&](const MEMORY_BASIC_INFORMATION& m) {
            nr += FindQwordInRegion((const uintptr_t*)m.BaseAddress, m.RegionSize / 8, strHits[s], refs + nr, 8 - nr);
            return nr < 8;
        });
        for (int r = 0; r < nr; ++r) {
            CVarObj c;
            c.obj = refs[r] - 8;
            c.help = strHits[s];
            if (!SafeRead((void*)c.obj, c.dump, sizeof(c.dump))) continue;
            c.vtable = *reinterpret_cast<uintptr_t*>(c.dump);
            int num = *reinterpret_cast<int*>(c.dump + 0x10), cap = *reinterpret_cast<int*>(c.dump + 0x14);
            if (!InImage(c.vtable) || num != (int)N || cap < num) continue;
            uintptr_t vfn0 = 0;
            if (!SafeRead((void*)c.vtable, &vfn0, 8) || !InImage(vfn0)) continue;

            char hex[sizeof(c.dump) * 2 + 1];
            for (size_t i = 0; i < sizeof(c.dump); ++i) sprintf_s(hex + i * 2, 3, "%02X", c.dump[i]);
            Log("candidate object %p vtable_rva=0x%llX dump=%s", (void*)c.obj, (unsigned long long)(c.vtable - g_base), hex);
            if (found < max) out[found] = c;
            ++found;
        }
    }
    return found;
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
    CVarObj objs[4];
    int n = FindCVarObjects(kEnableHelp, objs, 4);
    if (n > 4) { Log("too many cvar objects (%d)", n); return false; }
    int found = 0;
    for (int i = 0; i < n; ++i) {
        CVarMem c;
        c.obj = objs[i].obj; c.vtable = objs[i].vtable; c.help = objs[i].help;
        for (int off = kScanFrom; off + 8 <= kScanTo + 8 && c.numCandidates < 32; off += 4) {
            int a = *reinterpret_cast<int*>(objs[i].dump + off), b = *reinterpret_cast<int*>(objs[i].dump + off + 4);
            if (a == current && b == current) c.candidates[c.numCandidates++] = off;
        }
        Log("  value pair candidates for %d: %d", current, c.numCandidates);
        if (c.numCandidates > 0) { cv = c; ++found; }
    }
    if (found != 1) {
        Log("need exactly one candidate object, got %d", found);
        return false;
    }
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
    bool cfgForce = ReadForceSetting();
    Log("config EnableForceFG=%d (Ctrl+F9 toggles forcing)", cfgForce);

    int v = 0;
    while (!SafeCVar(kEnableName, &v) || v == 0) Sleep(200);
    CVarMem cv;
    if (!LocateEnableCVar(cv, v)) { Log("cvar object not found; ForceFG disabled"); return; }

    // Learning: follow the game's own changes until the offset is confirmed.
    int last = v;
    while (cv.dataOff < 0) {
        if (!StillValid(cv)) { Log("object changed during learning; ForceFG disabled"); return; }
        if (cv.numCandidates == 0) { Log("no candidate survived; ForceFG disabled"); return; }
        if (SafeCVar(kEnableName, &v) && v != last) {
            Confirm(cv, v);
            Log("game set Enable %d -> %d", last, v);
            last = v;
        }
        Sleep(20);
    }

    bool on = cfgForce, keyDown = false;
    RECT lastRect{};
    ULONGLONG rectChanged = 0, lastLog = 0, lastWindowCheck = 0, lastConfig = 0;
    bool stable = false;
    unsigned writes = 0, zeroSeen = 0;
    int lastS0 = last;
    for (;;) {
        ULONGLONG now = GetTickCount64();
        if (now - lastConfig >= 1000) {
            lastConfig = now;
            bool n = ReadForceSetting();
            if (n != cfgForce) { on = n; Log("config: forcing %s", on ? "ON" : "OFF"); }
            cfgForce = n;
        }

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
        if (s0 != lastS0) {
            if (s0 == 0) ++zeroSeen;
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
            if (!WriteInt(cv.obj + cv.dataOff, 1) || !WriteInt(cv.obj + cv.dataOff + 4, 1)) {
                Log("write failed; ForceFG stopped");
                return;
            }
            if (writes++ == 0) Log("forcing Enable to 1");
            lastS0 = 1;
        }
        Sleep(1);
    }
}

DWORD WINAPI TraceThread(LPVOID)
{
    while (!scanOffsetsDone) Sleep(100);
    Log("offsets ready");
    ForceLoop();
    return 0;
}

} // namespace

void StartFGTrace(HMODULE hModule)
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(hModule, path, MAX_PATH);
    std::wstring dir = path;
    dir = dir.substr(0, dir.find_last_of(L"\\/") + 1);
    wcsncpy_s(g_configPath, (dir + L"configww.ini").c_str(), _TRUNCATE);
    if (!ReadForceSetting()) return;      // not requested at launch; nothing runs

    wcsncpy_s(g_logPath, (dir + L"ww_fgtrace.log").c_str(), _TRUNCATE);
    HMODULE exe = GetModuleHandleW(nullptr);
    g_base = reinterpret_cast<uintptr_t>(exe);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(exe);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(g_base + dos->e_lfanew);
    g_imageSize = nt->OptionalHeader.SizeOfImage;
    Log("FGTrace start base=%p", exe);
    CreateThread(nullptr, 0, TraceThread, nullptr, 0, nullptr);
}
