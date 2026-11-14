// language: C++, file: main.cpp
// target: Windows 10/11 x64, MSVC (/utf-8 /MT /O2)
// build: cl /nologo /EHsc /W1 /O2 /MT /utf-8 /D_CRT_SECURE_NO_WARNINGS main.cpp /Fe:BYrank1shop.exe /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib kernel32.lib dwmapi.lib

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <dwmapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <cwchar>

#pragma comment(lib, "dwmapi.lib")

// ─── colors ─────────────────────────────────────────────
static const COLORREF C_BG    = RGB(6,5,8);
static const COLORREF C_WHITE = RGB(215,215,220);
static const COLORREF C_GREEN = RGB(40,200,75);
static const COLORREF C_DIM   = RGB(75,75,88);
static const COLORREF C_ORAN  = RGB(255,80,20);

// ─── fonts ──────────────────────────────────────────────
static HFONT g_fLogo  = nullptr;
static HFONT g_fMenu  = nullptr;
static HFONT g_fSmall = nullptr;
static HFONT g_fTiny  = nullptr;

// ─── state ──────────────────────────────────────────────
enum Screen { S_MENU, S_RUN, S_DONE };
static Screen  g_screen   = S_MENU;
static int     g_mode     = 0;
static bool    g_blink    = true;
static int     g_titleIdx = 0;
static HWND    g_mainHwnd = nullptr;

static std::vector<std::wstring> g_log;
static CRITICAL_SECTION g_logCS;
static volatile LONG g_workerDone = 0;

// ─── AOB table ──────────────────────────────────────────
struct AobPatch {
    const wchar_t* name;
    BYTE  search[16];  int searchLen;
    BYTE  patch[16];   int patchLen;
    BYTE  orig[16];    int origLen;
    std::vector<LPVOID> addrs;
};

static AobPatch g_aob1 = {
    L"AOB_1",
    {0xCD,0xCC,0x94,0x40,0x01,0x00,0x00,0x00}, 8,
    {0x77,0x77,0x97,0x40,0x01,0x00,0x00,0x00}, 8,
    {0}, 0, {}
};

static AobPatch g_aob2 = {
    L"AOB_2",
    {0x77,0x77,0x97,0x40,0x01,0x00,0x00,0x00}, 8,
    {0xCD,0xCC,0x94,0x40,0x01,0x00,0x00,0x00}, 8,
    {0}, 0, {}
};

// ─── log helper ─────────────────────────────────────────
static void LogPush(const std::wstring& s) {
    EnterCriticalSection(&g_logCS);
    g_log.push_back(s);
    if (g_log.size() > 14)
        g_log.erase(g_log.begin(), g_log.begin() + (g_log.size() - 14));
    LeaveCriticalSection(&g_logCS);
    if (g_mainHwnd) InvalidateRect(g_mainHwnd, nullptr, FALSE);
}

// ─── process finder ─────────────────────────────────────
static const wchar_t* kTargets[] = {
    L"FiveM_GTAProcess.exe",
    L"FiveM_b2060_GTAProcess.exe", L"FiveM_b2189_GTAProcess.exe",
    L"FiveM_b2372_GTAProcess.exe", L"FiveM_b2545_GTAProcess.exe",
    L"FiveM_b2612_GTAProcess.exe", L"FiveM_b2699_GTAProcess.exe",
    L"FiveM_b2802_GTAProcess.exe", L"FiveM_b2944_GTAProcess.exe",
    L"FiveM_b3095_GTAProcess.exe", L"FiveM_b3179_GTAProcess.exe",
    L"FiveM_b3258_GTAProcess.exe", L"FiveM_b3323_GTAProcess.exe",
    L"FiveM_b3407_GTAProcess.exe", L"FiveM_b3411_GTAProcess.exe",
    L"FiveM_b3751_GTAProcess.exe", L"FiveM_b3889_GTAProcess.exe",
};

static HANDLE OpenTarget() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    HANDLE hp = nullptr;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (auto* t : kTargets) {
                if (_wcsicmp(pe.szExeFile, t) == 0) {
                    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                    if (hp) goto done;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
done:
    CloseHandle(snap);
    return hp;
}

// ─── AOB scanner ────────────────────────────────────────
static std::vector<LPVOID> ScanAobAll(HANDLE hp, const BYTE* pat, int plen) {
    std::vector<LPVOID> out;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    BYTE* base = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* max  = (BYTE*)si.lpMaximumApplicationAddress;
    const SIZE_T CHUNK = 0x10000;
    std::vector<BYTE> buf(CHUNK);

    while (base < max) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(hp, base, &mbi, sizeof(mbi))) break;

        BYTE* rbase = (BYTE*)mbi.BaseAddress;
        SIZE_T rsize = mbi.RegionSize;

        bool okProt = (mbi.State == MEM_COMMIT) &&
            (mbi.Protect == PAGE_EXECUTE_READ ||
             mbi.Protect == PAGE_EXECUTE_READWRITE ||
             mbi.Protect == PAGE_READWRITE);

        if (okProt) {
            SIZE_T off = 0;
            while (off < rsize) {
                SIZE_T toRead = (rsize - off > CHUNK) ? CHUNK : (rsize - off);
                SIZE_T got = 0;
                if (ReadProcessMemory(hp, rbase + off, buf.data(), toRead, &got) && got >= (SIZE_T)plen) {
                    for (SIZE_T i = 0; i + plen <= got; ) {
                        if (memcmp(buf.data() + i, pat, plen) == 0) {
                            out.push_back(rbase + off + i);
                            i += plen - 1;
                        }
                        ++i;
                    }
                }
                off += toRead;
            }
        }
        base = rbase + rsize;
    }
    return out;
}

// ─── patch helpers ──────────────────────────────────────
static void PatchAll(HANDLE hp, AobPatch& p, const BYTE* bytes, int len) {
    bool savedOrig = false;
    for (LPVOID addr : p.addrs) {
        if (!savedOrig) {
            SIZE_T got = 0;
            ReadProcessMemory(hp, addr, p.orig, len, &got);
            p.origLen = (int)got;
            savedOrig = true;
        }
        DWORD old = 0;
        if (VirtualProtectEx(hp, addr, len, PAGE_EXECUTE_READWRITE, &old)) {
            SIZE_T wrote = 0;
            WriteProcessMemory(hp, addr, bytes, len, &wrote);
            DWORD dummy = 0;
            VirtualProtectEx(hp, addr, len, old, &dummy);
        }
    }
}

static void RestoreAll(HANDLE hp, AobPatch& p, const BYTE* bytes, int len) {
    for (LPVOID addr : p.addrs) {
        DWORD old = 0;
        if (VirtualProtectEx(hp, addr, len, PAGE_EXECUTE_READWRITE, &old)) {
            SIZE_T wrote = 0;
            WriteProcessMemory(hp, addr, bytes, len, &wrote);
            DWORD dummy = 0;
            VirtualProtectEx(hp, addr, len, old, &dummy);
        }
    }
}

// ─── worker thread ──────────────────────────────────────
static DWORD WINAPI WorkerProc(LPVOID param) {
    int mode = (int)(INT_PTR)param;

    LogPush(L">> opening process handle...");
    HANDLE hp = OpenTarget();
    if (!hp) {
        LogPush(L"[!!] Error: Failed to open process handle.");
        InterlockedExchange(&g_workerDone, 1);
        if (g_mainHwnd) PostMessageW(g_mainHwnd, WM_APP + 1, 0, 0);
        return 0;
    }
    LogPush(L"[OK] process handle acquired.");

    if (mode == 1) {
        LogPush(L">> Step 2: Applying Memory Patches...");
        AobPatch* list[] = { &g_aob1, &g_aob2 };
        for (auto* p : list) {
            LogPush(std::wstring(L">> scanning: ") + p->name);
            p->addrs = ScanAobAll(hp, p->search, p->searchLen);
            if (!p->addrs.empty()) {
                PatchAll(hp, *p, p->patch, p->patchLen);
                wchar_t buf[128];
                swprintf_s(buf, L"[OK] %zu patch(es) applied.", p->addrs.size());
                LogPush(buf);
            } else {
                LogPush(L"[--] pattern not found (may already be patched).");
            }
        }
        LogPush(L">> Step 5: Finalizing Synchronization...");
        LogPush(L"*** INSTALL COMPLETE -- RANK1 ACTIVE ***");
    } else {
        LogPush(L">> Step 2: Reverting Memory Patches...");
        AobPatch* list[] = { &g_aob2, &g_aob1 };
        for (auto* p : list) {
            LogPush(std::wstring(L">> restoring: ") + p->name);
            if (!p->addrs.empty()) {
                RestoreAll(hp, *p, p->orig, p->origLen);
                wchar_t buf[128];
                swprintf_s(buf, L"[OK] %zu addr(s) restored.", p->addrs.size());
                LogPush(buf);
                p->addrs.clear();
            } else {
                auto found = ScanAobAll(hp, p->patch, p->patchLen);
                if (!found.empty()) {
                    for (auto* addr : found) {
                        DWORD old = 0;
                        if (VirtualProtectEx(hp, addr, p->searchLen, PAGE_EXECUTE_READWRITE, &old)) {
                            SIZE_T wrote = 0;
                            WriteProcessMemory(hp, addr, p->search, p->searchLen, &wrote);
                            DWORD dummy = 0;
                            VirtualProtectEx(hp, addr, p->searchLen, old, &dummy);
                        }
                    }
                    wchar_t buf[128];
                    swprintf_s(buf, L"[OK] %zu addr(s) restored via re-scan.", found.size());
                    LogPush(buf);
                } else {
                    LogPush(L"[--] not found.");
                }
            }
        }
        LogPush(L">> Step 5: Finalizing Synchronization...");
        LogPush(L"*** RESET COMPLETE -- RANK1 Cleaned Successfully ***");
    }

    CloseHandle(hp);
    InterlockedExchange(&g_workerDone, 1);
    if (g_mainHwnd) PostMessageW(g_mainHwnd, WM_APP + 1, 0, 0);
    return 0;
}

// ─── GDI draw helpers ───────────────────────────────────
static void DrawTextGlow(HDC dc, const wchar_t* s, int x, int y, COLORREF main, COLORREF shadow) {
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, shadow);
    TextOutW(dc, x + 1, y + 1, s, (int)wcslen(s));
    SetTextColor(dc, main);
    TextOutW(dc, x, y, s, (int)wcslen(s));
}

static void DrawTextCentered(HDC dc, const wchar_t* s, int cx, int y,
                             HFONT f, COLORREF main, COLORREF shadow, bool glow) {
    HFONT old = (HFONT)SelectObject(dc, f);
    SIZE sz{};
    GetTextExtentPoint32W(dc, s, (int)wcslen(s), &sz);
    int x = cx - sz.cx / 2;
    SetBkMode(dc, TRANSPARENT);
    if (glow) {
        SetTextColor(dc, shadow);
        TextOutW(dc, x + 1, y + 1, s, (int)wcslen(s));
    }
    SetTextColor(dc, main);
    TextOutW(dc, x, y, s, (int)wcslen(s));
    SelectObject(dc, old);
}

static void HLine(HDC dc, int x1, int x2, int y, COLORREF c, int thick) {
    HPEN pen = CreatePen(PS_SOLID, thick, c);
    HPEN old = (HPEN)SelectObject(dc, pen);
    MoveToEx(dc, x1, y, nullptr);
    LineTo(dc, x2, y);
    SelectObject(dc, old);
    DeleteObject(pen);
}

// ─── logo ───────────────────────────────────────────────
static const wchar_t* LOGO[7] = {
    L"\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584 \u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2584 \u2588\u2588\u2588\u2584 \u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588",
    L"\u2588\u2588\u2588\u2588 \u2580\u2588\u2588\u2588\u258c \u258c\u2593\u2588\u2593\u2588 \u2588\u2588\u2593\u258c \u2588\u2588\u2593\u2588\u2588\u2584\u2588\u2588\u2593\u2588 \u2588\u2588\u2593\u2588 \u2584\u2588\u2588\u2593\u2580 \u2588\u2588\u2593\u2588",
    L"\u2592\u2593\u2588\u2588\u2584\u2593\u2588\u2593\u2580 \u2592\u2593\u2588\u2593\u2593\u2580\u2592\u2593\u2588\u2593 \u2592\u2593\u2588\u2593 \u2580\u2592\u2593\u2588\u2593 \u2592\u2593\u2588\u2593\u2580\u2588\u2592\u2593\u2584 \u2592\u2593\u2588\u2593",
    L"\u2591\u2591\u2592\u2593\u2580\u2593\u2592\u2592\u2593\u2584 \u2591\u2591\u2592\u2593 \u2591\u2591\u2592\u2593 \u2591\u2591\u2592\u2593 \u2591\u2591\u2592\u2593 \u2591\u2591\u2592\u2593 \u2591\u2591\u2592\u2593",
    L" \u2591 \u2591\u2591\u2592\u2591\u258c \u2591 \u2591 \u2591 \u2591 \u2591 \u2591 \u2591",
    L" \u2580 \u2580 \u2580\u2580\u2580\u2580 \u2580\u2580\u2580\u2580 \u2580\u2580\u2580\u2580 \u2580\u2580\u2580\u2580 \u2580\u2580\u2580\u2580 \u2580\u2580\u2580\u2580",
    L" \u2580 ",
};

static const COLORREF kLogoGrad[7] = {
    RGB(255,120,120), RGB(255,75,75), RGB(240,45,45), RGB(215,25,25),
    RGB(185,12,12),   RGB(145,5,5),   RGB(100,2,2),
};

// ─── menu draw ──────────────────────────────────────────
static void DrawMenu(HDC dc, int W, int H) {
    HFONT oldF = (HFONT)SelectObject(dc, g_fLogo);
    SIZE ls{};
    GetTextExtentPoint32W(dc, LOGO[0], (int)wcslen(LOGO[0]), &ls);
    int lx = (W - ls.cx) / 2;
    int ly = 10;

    SetBkMode(dc, TRANSPARENT);
    for (int i = 0; i < 7; i++) {
        int y = ly + i * 13;
        SetTextColor(dc, RGB(40, 3, 3));
        TextOutW(dc, lx + 1, y + 1, LOGO[i], (int)wcslen(LOGO[i]));
        SetTextColor(dc, kLogoGrad[i]);
        TextOutW(dc, lx, y, LOGO[i], (int)wcslen(LOGO[i]));
    }
    SelectObject(dc, oldF);

    int y = ly + 7 * 13 + 6;
    HLine(dc, 30, W - 30, y + 0, RGB(120, 5, 5), 1);
    HLine(dc, 30, W - 30, y + 2, RGB(200, 12, 12), 2);
    HLine(dc, 30, W - 30, y + 5, RGB(80, 3, 3), 1);

    y += 12;
    DrawTextCentered(dc, L"\u30E9\u30F3\u30AF1 \u2665 RANK1SHOP \u2665 \u30E9\u30F3\u30AF1",
                     W / 2, y, g_fSmall, RGB(60, 18, 18), RGB(0, 0, 0), false);

    y += 26;
    DrawTextCentered(dc, L"\u2014\u2014 S E L E C T   M O D E \u2014\u2014",
                     W / 2, y, g_fSmall, RGB(140, 22, 22), RGB(40, 3, 3), true);

    y += 24;
    HLine(dc, 40, W - 40, y, RGB(40, 8, 8), 1);

    y += 16;
    DrawTextCentered(dc, L">> [ 1 ]  I N S T A L L  <<",
                     W / 2, y, g_fMenu, RGB(255, 55, 55), RGB(80, 5, 5), true);

    y += 40;
    DrawTextCentered(dc, L">> [ 2 ]  R E S E T  <<",
                     W / 2, y, g_fMenu, RGB(190, 20, 20), RGB(60, 3, 3), true);

    y += 40;
    HLine(dc, 40, W - 40, y, RGB(40, 8, 8), 1);

    y += 18;
    if (g_blink) {
        DrawTextCentered(dc, L" >> \u2588",
                         W / 2, y, g_fMenu, RGB(220, 30, 30), RGB(60, 3, 3), true);
    }
}

// ─── run / done draw ────────────────────────────────────
static void DrawRun(HDC dc, int W, int H) {
    const wchar_t* header = (g_mode == 1)
        ? L">> I N S T A L L   M O D E  <<"
        : L">> R E S E T   M O D E  <<";

    DrawTextCentered(dc, header, W / 2, 22, g_fMenu,
                     RGB(255, 55, 55), RGB(80, 5, 5), true);

    HLine(dc, 30, W - 30, 60, RGB(120, 5, 5), 1);
    HLine(dc, 30, W - 30, 62, RGB(200, 12, 12), 2);
    HLine(dc, 30, W - 30, 65, RGB(80, 3, 3), 1);

    HFONT old = (HFONT)SelectObject(dc, g_fSmall);
    SetBkMode(dc, TRANSPARENT);

    EnterCriticalSection(&g_logCS);
    int startY = 82;
    for (size_t i = 0; i < g_log.size(); i++) {
        const std::wstring& s = g_log[i];
        COLORREF c = C_WHITE;
        if (s.rfind(L"[OK]", 0) == 0)       c = C_GREEN;
        else if (s.rfind(L"***", 0) == 0)   c = C_ORAN;
        else if (s.rfind(L"[--]", 0) == 0)  c = C_DIM;
        else if (s.rfind(L"[!!]", 0) == 0)  c = C_ORAN;
        else if (s.rfind(L" press", 0) == 0) c = C_DIM;

        SetTextColor(dc, c);
        TextOutW(dc, 36, startY + (int)i * 19, s.c_str(), (int)s.size());
    }
    int lines = (int)g_log.size();
    LeaveCriticalSection(&g_logCS);

    int yStatus = startY + lines * 19 + 8;

    if (g_screen == S_RUN) {
        static const wchar_t* spin = L" -/|\\ working...";
        static int t = 0;
        wchar_t buf[32];
        swprintf_s(buf, L" %c working...", spin[t % 8]);
        t++;
        SetTextColor(dc, RGB(255, 70, 20));
        TextOutW(dc, 36, yStatus, buf, (int)wcslen(buf));
    } else {
        SetTextColor(dc, C_DIM);
        const wchar_t* msg = L" press [R] to return / [ESC] to exit";
        TextOutW(dc, 36, yStatus, msg, (int)wcslen(msg));
    }
    SelectObject(dc, old);
}

// ─── status bar ─────────────────────────────────────────
static void DrawStatusBar(HDC dc, int W, int H) {
    int y0 = H - 24;
    HLine(dc, 0, W, y0,     RGB(50, 8, 8), 1);
    HLine(dc, 0, W, y0 + 1, RGB(25, 3, 3), 1);

    DrawTextCentered(dc, L"\u2665 rank1shop.com \u2014 RANK1 CMD V.1 \u2665",
                     W / 2, y0 + 4, g_fTiny, RGB(55, 12, 12), RGB(0, 0, 0), false);
}

// ─── paint ──────────────────────────────────────────────
static void OnPaint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc;
    GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP memBM = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP oldBM = (HBITMAP)SelectObject(memDC, memBM);

    HBRUSH bg = CreateSolidBrush(C_BG);
    FillRect(memDC, &rc, bg);
    DeleteObject(bg);

    if (g_screen == S_MENU) {
        DrawMenu(memDC, W, H);
    } else {
        DrawRun(memDC, W, H);
    }
    DrawStatusBar(memDC, W, H);

    BitBlt(hdc, 0, 0, W, H, memDC, 0, 0, SRCCOPY);

    SelectObject(memDC, oldBM);
    DeleteObject(memBM);
    DeleteDC(memDC);
    EndPaint(hwnd, &ps);
}

// ─── title bar rotation ─────────────────────────────────
static const wchar_t* TITLES[5] = {
    L"RANK1 | \u30E9\u30F3\u30AF1\u30B7\u30E7\u30C3\u30D7\u3088\u308A\u611B\u3092\u8FBC\u3081\u3066 \u2665",
    L"RANK1 | \u611B\u3057\u3066\u308B\u3001\u30E9\u30F3\u30AF1 \u2665",
    L"RANK1 | rank1shop \u304B\u3089\u3042\u306A\u305F\u3078 \u2665",
    L"RANK1 | \u6C38\u9060\u306B\u3042\u308A\u304C\u3068\u3046 \u2665 rank1shop",
    L"RANK1 | \u6700\u9AD8\u306E\u30C4\u30FC\u30EB\u3001\u6700\u9AD8\u306E\u611B \u2665",
};

// ─── window proc ────────────────────────────────────────
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_mainHwnd = hwnd;

        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));
        DwmSetWindowAttribute(hwnd, 19, &dark, sizeof(dark));
        COLORREF capColor = RGB(0, 0, 0);
        DwmSetWindowAttribute(hwnd, 35, &capColor, sizeof(capColor));

        SetLayeredWindowAttributes(hwnd, 0, 230, LWA_ALPHA);

        SetTimer(hwnd, 1, 2500, nullptr);
        SetTimer(hwnd, 2, 500, nullptr);

        SetWindowTextW(hwnd, TITLES[0]);
        return 0;
    }

    case WM_TIMER:
        if (wp == 1) {
            g_titleIdx = (g_titleIdx + 1) % 5;
            SetWindowTextW(hwnd, TITLES[g_titleIdx]);
        } else if (wp == 2) {
            g_blink = !g_blink;
            InvalidateRect(hwnd, nullptr, FALSE);
        } else if (wp == 3) {
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT:
        OnPaint(hwnd);
        return 0;

    case WM_KEYDOWN: {
        if (g_screen == S_MENU) {
            if (wp == '1') {
                g_mode = 1;
                g_screen = S_RUN;
                g_log.clear();
                InterlockedExchange(&g_workerDone, 0);
                SetTimer(hwnd, 3, 100, nullptr);
                CreateThread(nullptr, 0, WorkerProc, (LPVOID)(INT_PTR)1, 0, nullptr);
                InvalidateRect(hwnd, nullptr, FALSE);
            } else if (wp == '2') {
                g_mode = 2;
                g_screen = S_RUN;
                g_log.clear();
                InterlockedExchange(&g_workerDone, 0);
                SetTimer(hwnd, 3, 100, nullptr);
                CreateThread(nullptr, 0, WorkerProc, (LPVOID)(INT_PTR)2, 0, nullptr);
                InvalidateRect(hwnd, nullptr, FALSE);
            } else if (wp == VK_ESCAPE) {
                DestroyWindow(hwnd);
            }
        } else if (g_screen == S_DONE) {
            if (wp == 'R' || wp == VK_RETURN) {
                g_screen = S_MENU;
                InvalidateRect(hwnd, nullptr, FALSE);
            } else if (wp == VK_ESCAPE) {
                DestroyWindow(hwnd);
            }
        }
        return 0;
    }

    case WM_CHAR: {
        wchar_t c = (wchar_t)wp;
        if (g_screen == S_MENU) {
            if (c == L'1') PostMessageW(hwnd, WM_KEYDOWN, '1', 0);
            else if (c == L'2') PostMessageW(hwnd, WM_KEYDOWN, '2', 0);
        } else if (g_screen == S_DONE) {
            if (c == L'R' || c == L'r') PostMessageW(hwnd, WM_KEYDOWN, 'R', 0);
        }
        return 0;
    }

    case WM_APP + 1: {
        if (g_screen == S_RUN) {
            g_screen = S_DONE;
            KillTimer(hwnd, 3);
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ─── entry ──────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    InitializeCriticalSection(&g_logCS);

    g_fLogo  = CreateFontW(-13, 0, 0, 0, FW_BOLD,   FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Courier New");
    g_fMenu  = CreateFontW(-18, 0, 0, 0, FW_BOLD,   FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Courier New");
    g_fSmall = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Courier New");
    g_fTiny  = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Courier New");

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(C_BG);
    wc.lpszClassName = L"RANK1CMD_CLASS";
    wc.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    int W = 630, H = 560;
    int sx = (GetSystemMetrics(SM_CXSCREEN) - W) / 2;
    int sy = (GetSystemMetrics(SM_CYSCREEN) - H) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_APPWINDOW | WS_EX_LAYERED,
        L"RANK1CMD_CLASS",
        L"RANK1 | loading...",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        sx, sy, W, H,
        nullptr, nullptr, hInst, nullptr
    );
    if (!hwnd) return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    DeleteObject(g_fLogo);
    DeleteObject(g_fMenu);
    DeleteObject(g_fSmall);
    DeleteObject(g_fTiny);
    DeleteCriticalSection(&g_logCS);
    return 0;
}
