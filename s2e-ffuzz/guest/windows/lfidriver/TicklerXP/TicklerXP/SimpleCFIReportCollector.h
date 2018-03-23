#ifndef SIMPLECFIREPORTCOLLECTOR

#define SIMPLECFIREPORTCOLLECTOR

#include <s2e.h>

typedef enum S2E_CFI_COMMAND {
	DONE,
	FYI,
	TAKE_SCREENSHOT,
	WINDOW_TEXT,
} S2E_CFI_COMMAND;

typedef struct S2E_CFI {
	S2E_CFI_COMMAND command;
	UINT64 ptr_info; //pointer to the info string
} S2E_CFI;

//XXX: This must be sent to the screenshot plugin
static VOID TakeScreenShot() 
{
	S2E_CFI cmd;
	//instruct S2E to take screenshot
	cmd.command = TAKE_SCREENSHOT;
	S2EMessage("Tickler: taking screenshot\n");
	S2EInvokePlugin("SimpleCFIChecker", &cmd, sizeof(cmd));
}

typedef enum S2E_CFI_REPORT_COLLECTOR_COMMANDS {
	CPU_USAGE,
	AUTOSCROLL_DONE,
    MAIN_WINDOW_OPEN
} S2E_CFI_REPORT_COLLECTOR_COMMANDS;

typedef struct S2E_CFI_RC_CPU {
	UINT32 TotalCpuUsage;
	UINT32 ProgramCpuUsage;
} S2E_CFI_RC_CPU;

typedef struct S2E_CFI_REPORT_COLLECTOR_COMMAND {
	S2E_CFI_REPORT_COLLECTOR_COMMANDS Command;
	S2E_CFI_RC_CPU CpuUsage;
} S2E_CFI_REPORT_COLLECTOR_COMMAND;


static void S2EReportCpuUsage(UINT32 Total, UINT32 Program)
{
	S2E_CFI_REPORT_COLLECTOR_COMMAND Cmd;
	Cmd.Command = CPU_USAGE;
	Cmd.CpuUsage.TotalCpuUsage = Total;
	Cmd.CpuUsage.ProgramCpuUsage = Program;
	S2EInvokePlugin("SimpleCFIReportCollector", &Cmd, sizeof(Cmd));
}

static void S2ENotifyAutoscrollDone(VOID)
{
	S2E_CFI_REPORT_COLLECTOR_COMMAND Cmd;
	Cmd.Command = AUTOSCROLL_DONE;
	S2EInvokePlugin("SimpleCFIReportCollector", &Cmd, sizeof(Cmd));
}

static void S2ENotifyMainWindowOpen(VOID)
{
	S2E_CFI_REPORT_COLLECTOR_COMMAND Cmd;
	Cmd.Command = MAIN_WINDOW_OPEN;
	S2EInvokePlugin("SimpleCFIReportCollector", &Cmd, sizeof(Cmd));
}

#endif