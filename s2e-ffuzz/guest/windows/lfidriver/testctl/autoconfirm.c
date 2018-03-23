#define USER_APP
#pragma warning(disable:4201)

#include <windows.h>
#include <s2e.h>

#define MAX_WND_TITLE 255
static HWND find_window_recursive(HWND Root, LPCSTR Text, BOOLEAN SubString)
{
    HWND ChildWnd = NULL;
    HWND RetVal = 0;
    CHAR Buffer[MAX_WND_TITLE + 1] = {0};

    ChildWnd = GetWindow(Root, GW_CHILD);
    while (ChildWnd && RetVal == 0) {
        GetWindowTextA(ChildWnd, Buffer, MAX_WND_TITLE);
        if (!SubString) {
            if (!_stricmp(Text, Buffer)) {
                return ChildWnd;
            }
        } else {
            if (strstr(Buffer, Text)) {
                S2EMessageFmt("%s %s %s\n", __FUNCTION__, Text, Buffer);
                return ChildWnd;
            }
        }

        RetVal = find_window_recursive(ChildWnd, Text, SubString);
        ChildWnd = GetWindow(ChildWnd, GW_HWNDNEXT);
    }

    return RetVal;
}

static DWORD WINAPI AutoconfirmWinXP(LPVOID Param)
{
    int State = 0;

    LPCSTR WizTitle = "Found New Hardware Wizard";
    LPCSTR NotThisTime = "No, not this &time";
    LPCSTR Next = "&Next >";
    LPCSTR Finish = "Finish";
    HWND WizHwnd = NULL;
    HWND NextButtonHwnd = NULL, FinishButtonHwnd = NULL, RadioButtonHwnd = NULL;

    UNREFERENCED_PARAMETER(Param);

    S2EMessageFmt("testctl: started %s\n", __FUNCTION__);

    for (;;) {

        Sleep(1000);

        /* Step 1: pass the first page */
        if (State == 0) {
            WizHwnd = FindWindowA(NULL, WizTitle);
            if (WizHwnd == NULL) {
                continue;
            }

            SetForegroundWindow(WizHwnd);

            S2EMessageFmt("Found %s window\n", WizTitle);
            RadioButtonHwnd = find_window_recursive(WizHwnd, NotThisTime, FALSE);
            NextButtonHwnd = find_window_recursive(WizHwnd, Next, FALSE);
            if (RadioButtonHwnd) {
                S2EMessageFmt("Clicking %s\n", NotThisTime);
                SendMessageA(RadioButtonHwnd, BM_CLICK, 0, 0);
                if (NextButtonHwnd) {
                    S2EMessageFmt("Clicking %s\n", Next);
                    SendMessageA(NextButtonHwnd, BM_CLICK, 0, 0);
                    Sleep(1000);
                    SendMessageA(NextButtonHwnd, BM_CLICK, 0, 0);
                    Sleep(1000);
                    State = 1;
                }
            } else {
                S2EMessageFmt("No radio button %s\n", NotThisTime);
            }
        }

        if (State == 1) {
            FinishButtonHwnd = find_window_recursive(WizHwnd, Finish, FALSE);
            if (FinishButtonHwnd && IsWindowEnabled(FinishButtonHwnd) && IsWindowVisible(FinishButtonHwnd)) {
                SendMessageA(FinishButtonHwnd, BM_CLICK, 0, 0);
                State = 0;
            }
        }
    }
}

static DWORD WINAPI AutoconfirmWin8(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    S2EMessageFmt("testctl: started %s\n", __FUNCTION__);

    for (;;) {
        LPCSTR WinSec = "Windows Security";
        LPCSTR InstallButton = "&Install";
        LPCSTR InstallAnywayButton = "&Install this driver software anyway";

        HWND Window, Button;
        Sleep(1000);

        Window = FindWindowA(NULL, WinSec);
        if (Window == NULL) {
            continue;
        }
        S2EMessageFmt("Found %s window\n", WinSec);
        Button = find_window_recursive(Window, InstallButton, FALSE);
        if (Button) {
            S2EMessageFmt("Found %s button. Clicking...\n", InstallButton);
            SetActiveWindow(Button);
            SendMessageA(Button, BM_CLICK, 0, 0);
            continue;
            //SendMessageA(Button, WM_LBUTTONDOWN, 0, 0);
            //SendMessageA(Button, WM_LBUTTONUP, 0, 0);
        }

        Button = find_window_recursive(Window, InstallAnywayButton, FALSE);
        if (Button) {
            S2EMessageFmt("Found %s button. Clicking...\n", InstallAnywayButton);
            SetActiveWindow(Button);
            SendMessageA(Button, BM_CLICK, 0, 0);
            continue;
        }
    }
}

static DWORD WINAPI KillOnApplicationError(LPVOID Param)
{
    LPCSTR AppError = "Application Error";
    LPCSTR OKButton = "OK";

    UNREFERENCED_PARAMETER(Param);

    S2EMessageFmt("testctl: started %s\n", __FUNCTION__);

    for (;;) {
        HWND Button = NULL;
        HWND Dialog = find_window_recursive(GetDesktopWindow(), AppError, TRUE);
        if (!Dialog) {
            Sleep(1000);
            continue;
        }

        S2EMessageFmt("Found application error dialog\n");
        Button = find_window_recursive(Dialog, OKButton, FALSE);
        if (Button) {
            S2EMessageFmt("Found %s button. Clicking...\n", OKButton);
            SetActiveWindow(Button);
            SendMessageA(Button, BM_CLICK, 0, 0);
        }
    }
}

BOOLEAN StartAutoConfirm(VOID)
{
    OSVERSIONINFO OSVersion;
    HANDLE Threads[2];

    OSVersion.dwOSVersionInfoSize = sizeof(OSVersion);
    if (!GetVersionEx(&OSVersion)) {
        S2EMessage("testctl: could not determine OS version\n");
        return FALSE;
    }

    //Create the thread that will validate application errors
    Threads[0] = CreateThread(NULL, 0, KillOnApplicationError, NULL, 0, NULL);
    if (!Threads[0]) {
        S2EMessage("testctl: could not start KillOnApplicationError thread\n");
        return FALSE;
    }

    if (OSVersion.dwMajorVersion == 5 && OSVersion.dwMinorVersion == 1) {
        Threads[1] = CreateThread(NULL, 0, AutoconfirmWinXP, NULL, 0, NULL);
    } else {
        Threads[1] = CreateThread(NULL, 0, AutoconfirmWin8, NULL, 0, NULL);
    }

    if (!Threads[1]) {
        S2EMessage("testctl: could not start driver autoconfirm thread\n");
        return FALSE;
    }

    WaitForMultipleObjects(2, Threads, TRUE, INFINITE);

    return TRUE;
}