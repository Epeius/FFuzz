#include <windows.h>
#include <stdio.h>
#include <UIAutomation.h>
#include <iostream>
#include <sstream>

#include "Tickler.h"


VOID CloseWindow(IUIAutomationElement* pSender) {
    /**
     * Sleeping should help avoiding various race conditions
     * in Acrobat that might cause it to crash.
     */
    Sleep(3);

    UIA_HWND _dialogWindowHandle;
    pSender->get_CurrentNativeWindowHandle(&_dialogWindowHandle);
    //close this window
    TakeScreenShot();
    SendMessage((HWND)_dialogWindowHandle, WM_SYSCOMMAND, SC_CLOSE, 0);
}



PSTR GetSingleWindowText(HWND windowHandle) {
    int cTxtLen = GetWindowTextLength(windowHandle);
    PSTR pszMem = (PSTR) VirtualAlloc((LPVOID) NULL, (DWORD) (cTxtLen + 1), MEM_COMMIT, PAGE_READWRITE);
    GetWindowTextA(windowHandle, pszMem, cTxtLen + 1);      //TODO: check return value
    return pszMem;
}

void TraverseDescendants(IUIAutomation* pAutomation, IUIAutomationElement* pParent, std::stringstream &ss) {

    if (pParent == NULL)
        return;

    IUIAutomationTreeWalker* pControlWalker = NULL;
    IUIAutomationElement* pNode = NULL;

    pAutomation->get_ControlViewWalker(&pControlWalker);
    if (pControlWalker == NULL)
        goto cleanup;

    pControlWalker->GetFirstChildElement(pParent, &pNode);
    if (pNode == NULL)
        goto cleanup;

    while (pNode) {
        UIA_HWND _windowHandle;
        pNode->get_CurrentNativeWindowHandle(&_windowHandle);
        HWND windowHandle = (HWND)_windowHandle;
        ss << GetSingleWindowText(windowHandle);
        TraverseDescendants(pAutomation, pNode, ss);
        IUIAutomationElement* pNext;
        pControlWalker->GetNextSiblingElement(pNode, &pNext);
        pNode->Release();
        pNode = pNext;
    }

cleanup:
    if (pControlWalker != NULL)
        pControlWalker->Release();
    if (pNode != NULL)
        pNode->Release();
    return;
}

std::string GetAllWindowText(IUIAutomationElement* pSender, IUIAutomation* pAutomation) {
    std::stringstream ss;
    TraverseDescendants(pAutomation, pSender, ss);
    return ss.str();
}

void SendWindowInfoToS2E(std::string windowText) {
    S2E_CFI cmd;
    cmd.command = WINDOW_TEXT;
    cmd.ptr_info = (UINT64) windowText.c_str();
    TICKLERMSG("sending window text to S2E\n");
    S2EInvokePlugin("SimpleCFIChecker", &cmd, sizeof(cmd));
    TakeScreenShot();
}

void SendWindowInfoToS2E(IUIAutomationElement* pSender, IUIAutomation* pAutomation) {
    //get all window text
    std::string windowText = GetAllWindowText(pSender, pAutomation);
    SendWindowInfoToS2E(windowText);
}


VOID sendFYI(const char* message) {
    S2E_CFI cmd;
    cmd.command = FYI;

    cmd.ptr_info = (UINT64) message;

#if DEBUG
    std::cout << "    >>>>> sending FYI info to S2E <<<<< \n";
    std::cout << "cmd.ptr_info " << cmd.ptr_info << "\n";
#endif

    TICKLERMSG("sending FYI info, invoking SimpleCFIChecker plugin\n");
    S2EInvokePlugin("SimpleCFIChecker", &cmd, sizeof(cmd));

    TakeScreenShot();
}

bool TraverseDialog(IUIAutomation* pAutomation, IUIAutomationElement *root, TicklerDialogTraversal &t)
{
    bool ret = true;

    if (root == NULL) {
        return false;
    }

    IUIAutomationTreeWalker* pControlWalker = NULL;
    IUIAutomationElement* pNode = NULL;

    pAutomation->get_ControlViewWalker(&pControlWalker);
    if (pControlWalker == NULL) {
        goto cleanup;
    }

    pControlWalker->GetFirstChildElement(root, &pNode);
    if (pNode == NULL) {
        goto cleanup;
    }

    while (pNode) {
        CONTROLTYPEID type;
        pNode->get_CurrentControlType(&type);

        if (type == UIA_ButtonControlTypeId) {
            VARIANT Text;
            pNode->GetCurrentPropertyValue(UIA_NamePropertyId, &Text);
            std::wstring buttonText(Text.bstrVal, SysStringLen(Text.bstrVal));

            if (!t.onButton(buttonText, pNode)) {
                ret = false;
                goto cleanup;
            }
        }

        if (!TraverseDialog(pAutomation, pNode, t)) {
            ret = false;
            goto cleanup;
        }

        IUIAutomationElement* pNext;
        pControlWalker->GetNextSiblingElement(pNode, &pNext);
        pNode->Release();
        pNode = pNext;
    }

cleanup:
    if (pControlWalker != NULL) {
        pControlWalker->Release();
    }

    if (pNode != NULL) {
        pNode->Release();
    }

    return ret;
}
