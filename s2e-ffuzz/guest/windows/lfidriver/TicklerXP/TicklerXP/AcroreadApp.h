#pragma once
#include "targetapp.h"

class AcroreadApp :
	public TargetApp
{
private:
    PDH_HCOUNTER acrobatCpuTotal0, acrobatCpuTotal1;

    bool closeLaunchExecutableWindow(IUIAutomationElement *pSender, const std::string &windowText);
    bool closeOpenFileWindow(IUIAutomationElement *pSender, const std::string &windowText);
    bool closeEmbeddedFontError(IUIAutomationElement *pSender, const std::string &windowText);
    bool closePassword(IUIAutomationElement *pSender, const std::string &windowText);
    bool closePageError(IUIAutomationElement *pSender, const std::string &windowText);
    bool closeXmlParsingError(IUIAutomationElement *pSender, const std::string &windowText);
    bool closeOpenDocumentError(IUIAutomationElement *pSender, const std::string &windowText);

    bool handleSecurityWarning(IUIAutomationElement *pSender, const std::string &windowText);
    
public:
    AcroreadApp() {}

    virtual std::string getName() { return "AdobeReader"; }
    virtual std::string getTopLevelWindowClass() { return "AcrobatSDIWindow"; }
    
    virtual void initCPUMonitor(PDH_HQUERY &cpuQuery);
    virtual void getCurrentCpuUsage(PLONG Total, PLONG targets);
    virtual bool handleWindowOpenEventByWindowClass(BSTR &className, IUIAutomationElement *pSender);
    virtual bool handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender);
    virtual bool handleWindowCloseEventByWindowName(BSTR &name, IUIAutomationElement *pSender);
    virtual VOID PrepareScroll(HWND ScrollableWindow);
    virtual HWND GetScrollableWindow(HWND MainWindow);
};
