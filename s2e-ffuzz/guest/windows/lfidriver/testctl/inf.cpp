// Copyright And Configuration Management ----------------------------------
//
//               NDISPROT Software Installer - ProtInstall.cpp
//
//                  Companion Sample Code for the Article
//
//                "Installing NDIS Protocols Programatically"
//                     Published on http://www.ndis.com
//
//   Copyright (c) 2004-2006 Printing Communications Associates, Inc. (PCAUSA)
//                          http://www.pcausa.com
//
// GPL software is an abomination. Far from being free, it is available ONLY
// to members of the "GPL Club". If you don't want to join the club, then GPL
// software is poison.
//
// This software IS free software under the terms of a BSD-style license:
//
// The right to use this code in your own derivative works is granted so long
// as 1.) your own derivative works include significant modifications of your
// own, 2.) you retain the above copyright notices and this paragraph in its
// entirety within sources derived from this code.
//
// This product includes software developed by PCAUSA. The name of PCAUSA
// may not be used to endorse or promote products derived from this software
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
//
// End ---------------------------------------------------------------------

#pragma warning(disable:4201)

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include "advpub.h"
#include "testctl.h"
#include "netcfgapi.h"

#define APP_NAME    _T("testctl")

VOID ErrMsg (HRESULT hr, LPCTSTR  lpFmt, ...)
{
    LPTSTR   lpSysMsg;
    va_list  vArgList;

    if (hr != 0) {
        _tprintf(_T("Error %#lx: "), hr);
    }

    va_start(vArgList, lpFmt);
    _vtprintf(lpFmt, vArgList);
    va_end(vArgList);

    if (hr != 0) {
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            hr,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpSysMsg,
            0,
            NULL
           );

        if (lpSysMsg) {
            _tprintf(_T("Possible cause:\n\n%s"), lpSysMsg);
            LocalFree((HLOCAL)lpSysMsg);
        }
    }

    return;
}



//
// Function:  InstallSpecifiedComponent
//
// Purpose:   Install a network component from an INF file.
//
// Arguments:
//    lpszInfFile [in]  INF file.
//    lpszPnpID   [in]  PnpID of the network component to install.
//    pguidClass  [in]  Class GUID of the network component.
//
// Returns:   None.
//
// Notes:
//

HRESULT SetupSpecifiedComponent(
    LPCTSTR lpszInfFile,
    LPCTSTR lpszPnpID,
    const GUID *pguidClass,
    BOOL uninstall
   )
{
    INetCfg    *pnc;
    LPTSTR     lpszApp;
    HRESULT    hr = NULL;

    hr = HrGetINetCfg(TRUE, APP_NAME, &pnc, &lpszApp);

    if (hr != S_OK) {
        if ((hr == NETCFG_E_NO_WRITE_LOCK) && lpszApp) {
            ErrMsg(hr, _T("%s currently holds the lock, try later."), lpszApp);
            CoTaskMemFree(lpszApp);
        }
        else {
            ErrMsg(hr, _T("Couldn't the get notify object interface."));
        }
        goto err0;
    }

    if (uninstall) {
        hr = HrUninstallNetComponent(pnc, lpszPnpID);
    } else {
        hr = HrInstallNetComponent(pnc, lpszPnpID, pguidClass, lpszInfFile);
    }

    if ((hr == S_OK) || (hr == NETCFG_S_REBOOT)) {
        hr = pnc->Apply();
    }

    if (hr != S_OK) {
        ErrMsg(hr, _T("Couldn't install/uninstall"));
    }
    HrReleaseINetCfg(pnc, TRUE);

    err0: return hr;
}


DWORD UninstallDriver(LPCTSTR pnpId)
{
    _tprintf(_T("Uninstalling %s...\n"), pnpId);

    INetCfg              *pnc;
    INetCfgComponent     *pncc;
    INetCfgClass         *pncClass;
    INetCfgClassSetup    *pncClassSetup;
    LPTSTR               lpszApp;
    GUID                 guidClass;
    OBO_TOKEN            obo;
    HRESULT              hr;

    hr = HrGetINetCfg(TRUE, APP_NAME, &pnc, &lpszApp);

    if (hr != S_OK) {
        if ((hr == NETCFG_E_NO_WRITE_LOCK) && lpszApp) {
            ErrMsg(hr, _T("%s currently holds the lock, try later."), lpszApp);
            CoTaskMemFree(lpszApp);
        } else {
            ErrMsg(hr, _T("Couldn't get the notify object interface."));
        }
        goto err0;
    }

    /* Get a reference to the network component to uninstall. */
    hr = pnc->FindComponent(pnpId, &pncc);
    if (hr != S_OK) {
        ErrMsg(hr, _T("Couldn't get an interface pointer to %s."), pnpId);
        goto err1;
    }

    /* Get the class GUID. */
    hr = pncc->GetClassGuid(&guidClass);
    if (hr != S_OK) {
        ErrMsg(hr, L"Couldn't get the class guid of %s.", pnpId);
        goto err2;
    }

    /* Get a reference to component's class. */
    hr = pnc->QueryNetCfgClass(&guidClass, IID_INetCfgClass, (PVOID *)&pncClass);
    if (hr != S_OK) {
        ErrMsg(hr, L"Couldn't get a pointer to class interface of %s.", pnpId);
        goto err2;
    }

    /* Get the setup interface. */
    hr = pncClass->QueryInterface(IID_INetCfgClassSetup,
        (LPVOID *)&pncClassSetup);

    if (hr != S_OK) {
        ErrMsg(hr, L"Couldn't get an interface to setup class.");
        goto err3;
    }

    /* Uninstall the component. */
    ZeroMemory(&obo, sizeof(OBO_TOKEN));
    obo.Type = OBO_USER;

    hr = pncClassSetup->DeInstall(pncc, &obo,  NULL);
    if (!((hr == S_OK) || (hr == NETCFG_S_REBOOT))) {
        ErrMsg(hr, L"Failed to uninstall %s.", pnpId);
        goto err4;
    }

    hr = pnc->Apply();

    if ((hr != S_OK) && (hr != NETCFG_S_REBOOT)) {
            ErrMsg(hr, L"Couldn't apply the changes after uninstalling %s.", pnpId);
    }

err4: ReleaseRef(pncClassSetup);
err3: ReleaseRef(pncClass);
err2: ReleaseRef(pncc);
err1: HrReleaseINetCfg(pnc, TRUE);
err0:
    return 0;
}

HRESULT RunINFSection(LPCSTR infFile, LPCSTR pnpId)
{
    TCHAR szInfFile[MAX_PATH + 1];
    TCHAR szPnpId[MAX_PATH + 1];
    GUID ClassGUID;
    TCHAR ClassName[MAX_CLASS_NAME_LEN];

    mbstowcs(szInfFile, infFile, MAX_PATH);
    mbstowcs(szPnpId, pnpId, MAX_PATH);

    if (!SetupDiGetINFClass(szInfFile, &ClassGUID,ClassName,sizeof(ClassName),0)) { 
        ErrMsg(0, _T("Could not get class GUID from INF file\n"));
        return NULL;
    }

    HRESULT hr = SetupSpecifiedComponent(
        szInfFile,
        szPnpId,
        &ClassGUID,
        FALSE
       );

    if(hr != S_OK) {
        ErrMsg(hr, L"InstallSpecifiedComponent\n");
    }

    return hr;
}

HRESULT InstallINF(LPCTSTR lpszInfFullPath)
{
    DWORD     dwError;
    HRESULT   hr = S_OK;
    TCHAR szDrive[_MAX_DRIVE + 1];
    TCHAR szDir[_MAX_DIR + 1];
    TCHAR szDirWithDrive[_MAX_DRIVE + _MAX_DIR + 1];

    /* Get the path where the INF file is. */
    _tsplitpath_s(lpszInfFullPath, szDrive, _MAX_DRIVE, szDir, _MAX_DIR, NULL, 0, NULL, 0);

    _tcscpy_s(szDirWithDrive, _MAX_DRIVE + _MAX_DIR, szDrive);
    _tcscat_s(szDirWithDrive, _MAX_DRIVE + _MAX_DIR, szDir);

    /* Copy the Service INF file to the \Windows\Inf Folder */
    if (!SetupCopyOEMInfW(
        lpszInfFullPath,
        szDirWithDrive, // Other files are in the
        // same dir. as primary INF
        SPOST_PATH,    // First param is path to INF
        0,             // Default copy style
        NULL,          // Name of the INF after
        // it's copied to %windir%\inf
        0,             // Max buf. size for the above
        NULL,          // Required size if non-null
        NULL)          // Optionally get the filename
        // part of Inf name after it is copied.
        )
    {
        dwError = GetLastError();
        hr = HRESULT_FROM_WIN32(dwError);
    }

    if (hr != S_OK) {
        ErrMsg(hr, _T("Could not copy INF file\n"));
    }

    return hr;
}
