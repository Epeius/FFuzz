#pragma once
#include "targetapp.h"


class MsWordApp :
    public TargetApp
{
private:
    PDH_HCOUNTER m_cpuTotal;

protected:
    virtual VOID PostScrollHandler(HWND windowHandle);

public:
    MsWordApp() {}

    virtual std::string getName() { return "MsWord"; }
    virtual std::string getTopLevelWindowClass() { return "OpusApp"; }

    virtual void initCPUMonitor(PDH_HQUERY &cpuQuery);
    virtual void getCurrentCpuUsage(PLONG Total, PLONG targets);
    virtual bool handleWindowOpenEventByWindowClass(BSTR &name, IUIAutomationElement *pSender);
    virtual bool handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender);
    virtual bool handleWindowCloseEventByWindowName(BSTR &name, IUIAutomationElement *pSender) { return false; }
    virtual VOID PrepareScroll(HWND ScrollableWindow);
    virtual HWND GetScrollableWindow(HWND MainWindow);
};

