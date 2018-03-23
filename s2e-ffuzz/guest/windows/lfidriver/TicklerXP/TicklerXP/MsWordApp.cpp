#include <iostream>

#include "MsWordApp.h"
#include "Tickler.h"


void MsWordApp::initCPUMonitor(PDH_HQUERY &cpuQuery) {
    PdhAddCounter(cpuQuery, L"\\Process(WINWORD)\\% Processor Time", NULL, &m_cpuTotal);
}


void MsWordApp::getCurrentCpuUsage(PLONG Total, PLONG targets) {
    PDH_FMT_COUNTERVALUE counterVal;

    PdhGetFormattedCounterValue(m_cpuTotal, PDH_FMT_LONG, NULL, &counterVal);
    *targets = counterVal.longValue;
}

bool MsWordApp::handleWindowOpenEventByWindowClass(BSTR &className, IUIAutomationElement *pSender) 
{
    if (!m_startedHandlingOpenEvent) {
        return true;
    }

    if (!IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        TakeScreenShot();
        return true;
    }

    return false;
}

bool MsWordApp::handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender) 
{
    if (!m_startedHandlingOpenEvent) {
        return true;
    }

    if (!IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        TakeScreenShot();
        return true;
    }

    m_lastTimeWindowOpened = BaseInstrGetHostClockMs();

    /* Close "Microsoft Office Activation Wizard" window */
    if (wcscmp(name, L"Microsoft Office Activation Wizard") == 0) {
        TICKLERMSG("closing Microsoft Office Activation Wizard\n");
        CloseWindow(pSender);
    } else {
        UIA_HWND windowHandle;
        pSender->get_CurrentNativeWindowHandle(&windowHandle);
        SendWindowInfoToS2E(pSender, pAutomation);
        TICKLERMSG("clicking unknown window button\n");
        ClickDialogButton(pSender, true);
    }

    return false;
}

VOID MsWordApp::PostScrollHandler(HWND windowHandle)
{

}

/**
 * Word needs a mouse click on the document to properly scroll.
 * Sending messages doesn't work so just press the key.
 */
VOID MsWordApp::PrepareScroll(HWND ScrollableWindow)
{
    /* Find a clickable area */
    HWND ClickableWindow = FindWindowWithTitleOrClass(ScrollableWindow, "_WwG", TRUE, TRUE);
    if (!ClickableWindow) {
        ClickableWindow = ScrollableWindow;
    }

    RECT Rect;
    if (GetWindowRect(ClickableWindow, &Rect)) {
        TICKLERMSG("GetWindowRect x:%d y:%d\n", Rect.left, Rect.top);
        Click((Rect.left + Rect.right) / 2, (Rect.top + Rect.bottom) / 2);
    } else {
        TICKLERMSG("GetWindowRect failed\n");
    }

    /**
     * TODO: word seems much slower regarding scrolling,
     * need to figure out how to ensure that the pages were scrolled.
     */
    Sleep(2000);

    /* Put this in the common code eventually */
    PressKey(VK_NEXT, 500);
}

HWND MsWordApp::GetScrollableWindow(HWND MainWindow)
{
    unsigned Timeout = 240; /* Can take a lot of time on word...*/
    HWND Ret;
    while (!(Ret = FindWindowWithTitleOrClass(m_topLevelWindowHandle, "_WwF", TRUE, TRUE))) {
        TICKLERMSG("Waiting for scrollable window to appear (root=%p)...\n", MainWindow);

        Sleep(1000);
        if (--Timeout == 0) {
            return NULL;
        }
    }

    Sleep(5000);

    /* Return the main window handle after the document appears */
    return MainWindow;
}
