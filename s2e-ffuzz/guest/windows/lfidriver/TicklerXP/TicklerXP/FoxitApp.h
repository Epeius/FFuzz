#pragma once
#include "targetapp.h"


class FoxitApp :
    public TargetApp
{
private:
    PDH_HCOUNTER foxitCpuTotal;

protected:
    virtual VOID PostScrollHandler(HWND windowHandle);

public:
    FoxitApp() {}
    
    virtual std::string getName() { return "FoxitReader"; }
    virtual std::string getTopLevelWindowClass() { return "classFoxitReader"; }

    virtual void initCPUMonitor(PDH_HQUERY &cpuQuery);
    virtual void getCurrentCpuUsage(PLONG Total, PLONG targets);
    virtual bool handleWindowOpenEventByWindowClass(BSTR &name, IUIAutomationElement *pSender);
    virtual bool handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender);
    virtual bool handleWindowCloseEventByWindowName(BSTR &name, IUIAutomationElement *pSender) { return false; }
    virtual VOID PrepareScroll(HWND ScrollableWindow) {};
    virtual HWND GetScrollableWindow(HWND MainWindow);
};

