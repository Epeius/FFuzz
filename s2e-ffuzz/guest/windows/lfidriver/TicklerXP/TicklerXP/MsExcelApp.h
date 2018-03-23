#pragma once
#include "targetapp.h"


class MsExcelApp :
    public TargetApp
{
private:
    PDH_HCOUNTER m_cpuTotal;

protected:
    virtual VOID PostScrollHandler(HWND windowHandle);

public:
    MsExcelApp() {}

    virtual std::string getName() { return "MsExcel"; }
    virtual std::string getTopLevelWindowClass() { return "XLMAIN"; }

    virtual void initCPUMonitor(PDH_HQUERY &cpuQuery);
    virtual void getCurrentCpuUsage(PLONG Total, PLONG targets);
    virtual bool handleWindowOpenEventByWindowClass(BSTR &name, IUIAutomationElement *pSender);
    virtual bool handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender);
    virtual bool handleWindowCloseEventByWindowName(BSTR &name, IUIAutomationElement *pSender) { return false; }
    virtual VOID PrepareScroll(HWND ScrollableWindow);
    virtual HWND GetScrollableWindow(HWND MainWindow);
};