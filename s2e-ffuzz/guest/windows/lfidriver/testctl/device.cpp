#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <stdlib.h>
#include <cfgmgr32.h>
#include <tchar.h>
#include <shlwapi.h>
#include "testctl.h"

BOOLEAN WaitForDeviceInstallation(LPCTSTR DeviceIdToLookFor)
{
    BOOLEAN Ret = FALSE;
    HDEVINFO DevInfo;
    SP_DEVINFO_LIST_DETAIL_DATA Details;
    SP_DEVINFO_DATA DevData;
    INT i;

    /**
     * Quick hack to skip the first wildcard character.
     * Accounts for the common use case where DeviceIdToLookFor
     * is of the form *PCI\VEN_8086&DEV_1229
     */
    if (DeviceIdToLookFor[0] == '*') {
        DeviceIdToLookFor++;
    }

    DevInfo = SetupDiGetClassDevsEx(NULL, NULL, NULL,
                                    DIGCF_ALLCLASSES, NULL, NULL, NULL);

    if (DevInfo == INVALID_HANDLE_VALUE) {
        goto err1;
    }

    Details.cbSize = sizeof(Details);
    if(!SetupDiGetDeviceInfoListDetail(DevInfo,&Details)) {
        goto err2;
    }

    DevData.cbSize = sizeof(DevData);

    for (i = 0; SetupDiEnumDeviceInfo(DevInfo, i, &DevData); ++i) {
        TCHAR DeviceID[MAX_DEVICE_ID_LEN];
        BOOL GDRet = CM_Get_Device_ID_Ex(DevData.DevInst,
                                         DeviceID, MAX_DEVICE_ID_LEN,
                                         0, Details.RemoteMachineHandle);

        if (GDRet != CR_SUCCESS) {
            DeviceID[0] = TEXT('\0');
        }

        if (StrStr(DeviceID, DeviceIdToLookFor)) {
            _tprintf(_T("Found %s\n"), DeviceID);
            Ret = TRUE;
            break;
        }
    }

    err2: SetupDiDestroyDeviceInfoList(DevInfo);
    err1: return Ret;
}