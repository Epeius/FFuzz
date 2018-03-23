#pragma once

#define DEBUG 0

#define SCROLL_USING_JS_API 0
#define MAX_DOCUMENT_PAGES 10
#define SCROLL_DELAY 500 //0.5 sec
#define SCROLL_TIMEOUT 20000 //20 secs


#define USER_APP
extern "C" {
#include "SimpleCFIReportCollector.h"
#include <BaseInstructions.h>
}

#define TICKLERMSG(a, ...) S2EMessageFmt("tickler: " ## a, __VA_ARGS__)

void CloseWindow(IUIAutomationElement* pSender);

void SendWindowInfoToS2E(std::string windowText);

void SendWindowInfoToS2E(IUIAutomationElement* pSender, IUIAutomation* pAutomation);

void sendFYI(const char* message);

std::string GetAllWindowText(IUIAutomationElement* pSender, IUIAutomation* pAutomation);

static void TerminateAnalysis() {
    S2E_CFI cmd;
    cmd.command = DONE;
#if DEBUG
    std::cout << "    >>>>> asking S2E to terminate <<<<< \n";
#endif
    S2EMessage("Tickler: asking S2E to terminate, invoking SimpleCFIChecker plugin\n");
    S2EInvokePlugin("SimpleCFIChecker", &cmd, sizeof(cmd));
}

/* Override class to take specific actions when each control it visited */
class TicklerDialogTraversal
{
public:
    virtual bool onButton(const std::wstring &text, IUIAutomationElement *pNode) { 
        return true; 
    }
};

bool TraverseDialog(IUIAutomation* pAutomation, IUIAutomationElement *root, TicklerDialogTraversal &t);