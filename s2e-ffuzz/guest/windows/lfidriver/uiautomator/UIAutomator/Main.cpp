#include <windows.h>
#include <stdio.h>
#include <UIAutomation.h>
#include <iostream>

#define USER_APP
extern "C" {
#include "s2e.h"
}

#define DEBUG 0

IUIAutomation* pAutomation;
IUIAutomationElementArray* GetEnabledButtons(IUIAutomationElement* pParent);

typedef enum S2E_CFI_COMMAND {
	DONE,
	FYI
} S2E_CFI_COMMAND;

typedef struct S2E_CFI {
	S2E_CFI_COMMAND command;
	UINT64 ptr_info; //pointer to the info string
} S2E_CFI;


struct WINDOW_DATA {
	HWND handle;
};

class EventHandler :
	public IUIAutomationEventHandler
{
private:
	LONG _refCount;

public:
	int _eventCount;
	int openWindowNotificationCount;

	// Constructor.
	EventHandler() : _refCount(1), _eventCount(0)
	{
		openWindowNotificationCount = 0;
	}

	~EventHandler() {
	}

	// IUnknown methods.
	ULONG STDMETHODCALLTYPE AddRef()
	{
		ULONG ret = InterlockedIncrement(&_refCount);
		return ret;
	}

	ULONG STDMETHODCALLTYPE Release()
	{
		ULONG ret = InterlockedDecrement(&_refCount);
		if (ret == 0)
		{
			delete this;
			return 0;
		}
		return ret;
	}

	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppInterface)
	{
		if (riid == __uuidof(IUnknown))
			*ppInterface = static_cast<IUIAutomationEventHandler*>(this);
		else if (riid == __uuidof(IUIAutomationEventHandler))
			*ppInterface = static_cast<IUIAutomationEventHandler*>(this);
		else
		{
			*ppInterface = NULL;
			return E_NOINTERFACE;
		}
		this->AddRef();
		return S_OK;
	}

	VOID printSenderInfo(IUIAutomationElement * pSender) {
		HRESULT h;
		BSTR name;
		BSTR className;
		h = pSender->get_CurrentName(&name);
		if (SUCCEEDED(h)) {
			wprintf(L"   >> UI element name: %ls ", name);
			SysFreeString(name);
		}

		h = pSender->get_CurrentClassName(&className);
		if (SUCCEEDED(h)) {
			wprintf(L"class: %ls ", className);
			SysFreeString(className);
		}

		int pid;
		h = pSender->get_CurrentProcessId(&pid);
		if (SUCCEEDED(h)) {
			wprintf(L"pid: %d ", pid);
		}
		wprintf(L"\n");
	}

	static VOID selectCodeTicklerMenuItem(HWND hwnd, HMENU menu)
	{
		int menuItemID = GetMenuItemID(menu, GetMenuItemCount(menu) - 1);
		PostMessage(hwnd, WM_COMMAND, menuItemID, 0);
		S2EMessage("UIAutomator: started AutoScroll\n");
#if DEBUG
		std::cout << "        >> Started AutoScroll\n";
#endif
	}

	VOID CloseWindow(IUIAutomationElement* pSender) {
		UIA_HWND _dialogWindowHandle;
		pSender->get_CurrentNativeWindowHandle(&_dialogWindowHandle);
		//close this window
		SendMessage((HWND)_dialogWindowHandle, WM_SYSCOMMAND, SC_CLOSE, 0);
	}


	VOID TerminateAnalysis() {
		S2E_CFI cmd;
		cmd.command = DONE;
		std::cout << "    >>>>> asking S2E to terminate <<<<< \n";
		S2EMessage("UIAutomator: asking S2E to terminate, invoking SimpleCFIChecker plugin\n");
		S2EInvokePlugin("SimpleCFIChecker", &cmd, sizeof(cmd));
	}

	static DWORD WINAPI ThreadedScroll(LPVOID lpParam)
	{
		WINDOW_DATA* data = (WINDOW_DATA*)lpParam;
		HWND acrobatWindowHandle = data->handle;
		HMENU mainMenu = GetMenu(acrobatWindowHandle);
		HMENU viewMenu = GetSubMenu(mainMenu, 2); //the View Menu

		Sleep(5000);

		selectCodeTicklerMenuItem(acrobatWindowHandle, viewMenu);
		return 0;
	}

	VOID DelayedScroll(HWND acrobatWindowHandle) {
		DWORD tid;
		//create a new thread to run in background with a delay
		WINDOW_DATA* win_data = 
			(WINDOW_DATA*) HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			sizeof(WINDOW_DATA));

		win_data->handle = acrobatWindowHandle;

		HANDLE threadHandle = CreateThread(
			NULL,                   // default security attributes
			0,                      // use default stack size  
			ThreadedScroll,  // thread function name
			win_data,               // argument to thread function 
			0,                      // use default creation flags 
			&tid);                  // returns the thread identifier 

		if (threadHandle == NULL) {
			std::cout << "cannot spawn thread for delayed scrolling\n";
			S2EMessage("cannot spawn thread for delayed scrolling\n");
		}
	}


	VOID sendFYI(const char* message) {
		S2E_CFI cmd;
		cmd.command = FYI;
		std::cout << "    >>>>> sending FYI info to S2E <<<<< \n";

		cmd.ptr_info = (UINT64) message;
		std::cout << "cmd.ptr_info " << cmd.ptr_info << "\n";

		S2EMessage("UIAutomator: sending FYI info, invoking SimpleCFIChecker plugin\n");
		S2EInvokePlugin("SimpleCFIChecker", &cmd, sizeof(cmd));
	}

	// IUIAutomationEventHandler methods
	HRESULT STDMETHODCALLTYPE HandleAutomationEvent(IUIAutomationElement * pSender, EVENTID eventID)
	{
		_eventCount++;
		switch (eventID)
		{
		case UIA_Window_WindowOpenedEventId:
			BSTR name, className;
			if (SUCCEEDED(pSender->get_CurrentClassName(&className))) {
#if DEBUG
				std::cout << ">> Event WindowOpened Received, event count =  " << _eventCount << std::endl;
				printSenderInfo(pSender);
#endif

				if (wcscmp(className, L"AcrobatSDIWindow") == 0) {
					openWindowNotificationCount++;
					if (openWindowNotificationCount == 1) {
						//Acrobat opens two similar windows (of the same class)
						//so we are skipping the first one
						std::cout << "      >> Skipping first notification for the Acrobat window\n";
						break;
					}
					else {
						std::cout << "      >> Finished loading Acrobat window\n";
					}

					UIA_HWND _acrobatWindowHandle;
					pSender->get_CurrentNativeWindowHandle(&_acrobatWindowHandle);
					HWND acrobatWindowHandle = (HWND)_acrobatWindowHandle;
					DelayedScroll(acrobatWindowHandle);
					break;
				}
			}

			if (SUCCEEDED(pSender->get_CurrentName(&name))) {
				if (wcscmp(name, L"CodeTickler: AutoScroll done!") == 0) {
					std::cout << "      >> AutoScroll done!\n";
					CloseWindow(pSender);
					TerminateAnalysis();
				}
				else if (wcsncmp(name, L"Reading", 7) == 0) {
					std::cout << "      >> Closing Reading window popped by Acrobat!\n";
					CloseWindow(pSender);
				}
				else if (wcsncmp(name, L"Accessibility", 13) == 0) {
					std::cout << "      >> Closing Accessibility setup window popped by Acrobat!\n";
					CloseWindow(pSender);
				} else if (wcsncmp(name, L"Security Warning", 16) == 0) {
					std::cout << "      >> FYI: Security Warning opened by document\n";
					//TODO: also send the text in the Security Warning window to the FYI info
					sendFYI("opens Security Warning");
					//TODO: implement click on Allow to see the action happening 
					//ClickAllow(pSender);
				} else if (wcsncmp(name, L"Save As", 7) == 0) {
					std::cout << "      >> FYI: Save As dialog opened by document\n";
					sendFYI("opens Save As dialogue");
					//TODO: implement click on Save As to see the action happening 
					//ClickSave(pSender);
				} else if (wcsncmp(name, L"Warning: JavaScript Window", 20) == 0) {
#if DEBUG
					std::cout << "            >> pressing OK button of the JavaScript window\n";
#endif
					UIA_HWND windowHandle;
					pSender->get_CurrentNativeWindowHandle(&windowHandle);
					//press OK
					SendMessage((HWND) windowHandle, WM_COMMAND, 1, NULL);
					S2EMessage("UIAutomator: pressing OK for Warning: JavaScript Window\n");
					//clicking can fail if the window is not in focus, so we can close the window instead
					CloseWindow(pSender);
					S2EMessage("UIAutomator: closing Warning: JavaScript Window\n");
					//obsolete way to click buttons
					//clickAllButtons(pSender);
				}
				else {
					//TODO: send info about all the windows that are opened in the system
					//sendWindowNotification(name);
				}
			}
			break;
		default:
			std::cout << ">> Unhandled event " << eventID <<
				" event count " << _eventCount << std::endl;
			break;
		}
		return S_OK;
	}
};

IUIAutomationElement* GetTopLevelWindowByName(IUIAutomation* g_pAutomation, LPWSTR windowName)
{
	if (windowName == NULL)
	{
		return NULL;
	}

	VARIANT varProp;
	varProp.vt = VT_BSTR;
	varProp.bstrVal = SysAllocString(windowName);
	if (varProp.bstrVal == NULL)
	{
		return NULL;
	}

	IUIAutomationElement* pRoot = NULL;
	IUIAutomationElement* pFound = NULL;

	// Get the desktop element. 
	HRESULT hr = g_pAutomation->GetRootElement(&pRoot);
	if (FAILED(hr) || pRoot == NULL)
		goto cleanup;

	// Get a top-level element by name, such as "Program Manager"
	IUIAutomationCondition* pCondition;
	hr = g_pAutomation->CreatePropertyCondition(UIA_NamePropertyId, varProp, &pCondition);
	if (FAILED(hr))
		goto cleanup;

	pRoot->FindFirst(TreeScope_Children, pCondition, &pFound);

cleanup:
	if (pRoot != NULL)
		pRoot->Release();

	if (pCondition != NULL)
		pCondition->Release();

	VariantClear(&varProp);
	return pFound;
}


IUIAutomationElementArray* GetEnabledButtons(IUIAutomationElement* pParent)
{
	if (pParent == NULL)
	{
		return NULL;
	}

	IUIAutomationCondition* pButtonCondition = NULL;
	IUIAutomationCondition* pEnabledCondition = NULL;
	IUIAutomationCondition* pCombinedCondition = NULL;
	IUIAutomationElementArray* pFound = NULL;

	// Create a property condition for the button control type.
	VARIANT varProp;
	varProp.vt = VT_I4;
	varProp.lVal = UIA_ButtonControlTypeId;
	pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, varProp, &pButtonCondition);
	if (pButtonCondition == NULL)
		goto cleanup;

	// Create a property condition for the enabled property.
	varProp.vt = VT_BOOL;
	varProp.boolVal = VARIANT_TRUE;
	pAutomation->CreatePropertyCondition(UIA_IsEnabledPropertyId, varProp, &pEnabledCondition);
	if (pEnabledCondition == NULL)
		goto cleanup;

	// Combine the conditions.
	pAutomation->CreateAndCondition(pButtonCondition, pEnabledCondition, &pCombinedCondition);
	if (pCombinedCondition == NULL)
		goto cleanup;

	// Find the matching elements. Note that if the scope is changed to TreeScope_Descendants, 
	// system buttons on the caption bar will be found as well.

	pParent->FindAll(TreeScope_Subtree, pCombinedCondition, &pFound);

cleanup:
	if (pButtonCondition != NULL)
		pButtonCondition->Release();

	if (pEnabledCondition != NULL)
		pEnabledCondition->Release();

	if (pCombinedCondition != NULL)
		pCombinedCondition->Release();

	return pFound;
}


// CAUTION: Do not pass in the root (desktop) element. Traversing the entire subtree
// of the desktop could take a very long time and even lead to a stack overflow.
void ListDescendants(IUIAutomation* g_pAutomation, IUIAutomationElement* pParent, int indent)
{
	if (pParent == NULL)
		return;

	IUIAutomationTreeWalker* pControlWalker = NULL;
	IUIAutomationElement* pNode = NULL;

	g_pAutomation->get_ControlViewWalker(&pControlWalker);
	if (pControlWalker == NULL)
		goto cleanup;

	pControlWalker->GetFirstChildElement(pParent, &pNode);
	if (pNode == NULL)
		goto cleanup;

	while (pNode)
	{
		BSTR name;
		pNode->get_CurrentName(&name);
		if (name != NULL) {
			for (int x = 0; x <= indent; x++)
			{
				std::wcout << L"   ";
			}
			std::wcout << name << L"\n";
			SysFreeString(name);
		}

		ListDescendants(g_pAutomation, pNode, indent + 1);
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


int main(int argc, char* argv[])
{
	HRESULT hr;
	int ret = 0;
	IUIAutomationElement* pTargetElement = NULL;
	EventHandler* pEHTemp = NULL;

	CoInitializeEx(NULL, COINIT_MULTITHREADED);
	pAutomation = NULL;
	hr = CoCreateInstance(__uuidof(CUIAutomation), NULL,
		CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&pAutomation);
	if (FAILED(hr) || pAutomation == NULL)
	{
		ret = 1;
		goto cleanup;
	}

	// Use root element for listening to window and tooltip creation and destruction.
	hr = pAutomation->GetRootElement(&pTargetElement);
	if (FAILED(hr) || pTargetElement == NULL)
	{
		ret = 1;
		goto cleanup;
	}

	pEHTemp = new EventHandler();
	if (pEHTemp == NULL)
	{
		ret = 1;
		goto cleanup;
	}

	wprintf(L"-Adding Event Handlers.\n");

	hr = pAutomation->AddAutomationEventHandler(UIA_Window_WindowOpenedEventId,
		pTargetElement,
		TreeScope_Subtree,
		NULL,
		(IUIAutomationEventHandler*)pEHTemp);
	if (FAILED(hr))
	{
		ret = 1;
		goto cleanup;
	}

	wprintf(L"-Press any key to remove event handlers and exit\n");
	getchar();

	wprintf(L"-Removing Event Handlers.\n");

cleanup:
	// Remove event handlers, release resources, and terminate
	if (pAutomation != NULL)
	{
		hr = pAutomation->RemoveAllEventHandlers();
		if (FAILED(hr))
			ret = 1;
		pAutomation->Release();
	}

	if (pEHTemp != NULL)
		pEHTemp->Release();

	if (pTargetElement != NULL)
		pTargetElement->Release();

	CoUninitialize();
	return ret;
}
