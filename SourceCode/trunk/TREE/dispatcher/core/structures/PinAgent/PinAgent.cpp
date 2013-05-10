// PinAgent.cpp : Defines the entry point for the console application.
/*PINAgent:
	Main file for connect TREE trace request to PIN tracer that collects an execution trace for dynamic offline analysis
	Author:
		Nathan Li
	Original Date: 05/09/2013
*/

#include "stdafx.h"

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>

//load windows socket
#pragma comment(lib, "wsock32.lib")

static SOCKET listenSocket;

HANDLE ghExit;
DWORD  gdwListenThread;
#define SERVER_PORT 23966
#define MESSAGE_LEN 4096
#define PINEXEC "C:\\pin\\ia32\\bin\\pin.exe"
#define PINTOOL "C:\\pin\\ia32\\bin\\exetrace.dll"
#define TRACE_SHARE "Z:\\TREE-TRACE\\"

bool bDebug = FALSE;

DWORD WINAPI process_pintrace(LPVOID lpParam);
void SpawnPin(char *AppName, char *CmdLine, char *CurrentDir);
void StartPinTracer(char * Message);

int GetLocalAddress(LPSTR lpStr, LPDWORD lpdwStrLen)
{
    struct in_addr *pinAddr;
    LPHOSTENT	lpHostEnt;
	int			nRet;
	int			nLen;

	//
	// Get our local name
	//
    nRet = gethostname(lpStr, *lpdwStrLen);
	if (nRet == SOCKET_ERROR)
	{
		lpStr[0] = '\0';
		return SOCKET_ERROR;
	}

	//
	// "Lookup" the local name
	//
	lpHostEnt = gethostbyname(lpStr);
    if (lpHostEnt == NULL)
	{
		lpStr[0] = '\0';
		return SOCKET_ERROR;
	}

	//
    // Format first address in the list
	//
	pinAddr = ((LPIN_ADDR)lpHostEnt->h_addr);
	nLen = strlen(inet_ntoa(*pinAddr));
	if ((DWORD)nLen > *lpdwStrLen)
	{
		*lpdwStrLen = nLen;
		WSASetLastError(WSAEINVAL);
		return SOCKET_ERROR;
	}

	*lpdwStrLen = nLen;
	strcpy(lpStr, inet_ntoa(*pinAddr));
    return 0;
}
/* Get Windows version where the Pin-ed Program is going to run

typedef struct _OSVERSIONINFOEX {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  TCHAR szCSDVersion[128];
  WORD  wServicePackMajor;
  WORD  wServicePackMinor;
  WORD  wSuiteMask;
  BYTE  wProductType;
  BYTE  wReserved;
} OSVERSIONINFOEX, *POSVERSIONINFOEX, *LPOSVERSIONINFOEX;

Operating system Version number dwMajorVersion dwMinorVersion Other

Windows 8 6.2 6 2 OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION 
Windows Server 2012 6.2 6 2 OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION 
Windows 7 6.1 6 1 OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION 
Windows Server 2008 R2 6.1 6 1 OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION 
Windows Server 2008 6.0 6 0 OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION 
Windows Vista 6.0 6 0 OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION 
Windows Server 2003 R2 5.2 5 2 GetSystemMetrics(SM_SERVERR2) != 0 
Windows Home Server 5.2 5 2 OSVERSIONINFOEX.wSuiteMask & VER_SUITE_WH_SERVER 
Windows Server 2003 5.2 5 2 GetSystemMetrics(SM_SERVERR2) == 0 
Windows XP Professional x64 Edition 5.2 5 2 (OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION) && (SYSTEM_INFO.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64) 
Windows XP 5.1 5 1 Not applicable 
Windows 2000 5.0 5 0 Not applicable 

Corresponding Windows OS pin number used by our PIN Tracer:
0 -- OS_NT_SP3,
1 -- OS_NT_SP4,
2 -- OS_NT_SP5,
3 -- OS_NT_SP6,
4 -- OS_2K_SP0,
5 -- OS_2K_SP1,
6 -- OS_2K_SP2,
7 -- OS_2K_SP3,
8 -- OS_2K_SP4,
9 -- OS_XP_SP0,
10 -- OS_XP_SP1,
11- OS_XP_SP2,
12- OS_XP_SP3,
13 -- OS_2003_SP0,
14 --OS_2003_SP1,
15 -- OS_VISTA_SP0,
16 -- OS_SEVEN_SP0"
*/
int GetWindowsOSPinNumber()
{
	int os_pin = -1;
    OSVERSIONINFOEXA osviex;

    ZeroMemory(&osviex, sizeof(OSVERSIONINFOEXA));
    osviex.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);

    GetVersionExA((LPOSVERSIONINFOA)&osviex);

	if(osviex.dwMajorVersion == 5) // 
	{
		if(osviex.dwMinorVersion==0) //Win 2K
		{
			if(osviex.wServicePackMajor==0)
				os_pin= 4;
			else 
			if(osviex.wServicePackMajor==1)
				os_pin= 5;
			else 
			if(osviex.wServicePackMajor==2)
				os_pin= 6;
			else 
			if(osviex.wServicePackMajor==3)
				os_pin= 7;
			else
			if(osviex.wServicePackMajor==4)
				os_pin= 8;
		}
		else
		if(osviex.dwMinorVersion==1) //Win XP
		{
			if(osviex.wServicePackMajor==0)
				os_pin= 9;
			else 
			if(osviex.wServicePackMajor==1)
				os_pin= 10;
			else 
			if(osviex.wServicePackMajor==2)
				os_pin= 11;
			else 
			if(osviex.wServicePackMajor==3)
				os_pin= 12;
		}
		else
		if(osviex.dwMinorVersion==2) //Win2003
		{
			if(osviex.wServicePackMajor==0)
				os_pin= 13;
			else 
			if(osviex.wServicePackMajor==1)
				os_pin= 14;
		}
	}
	else
	if(osviex.dwMajorVersion == 6) // 
	{
		if(osviex.dwMinorVersion==0) //Win Vista
		{
			if(osviex.wServicePackMajor==0)
				os_pin= 15;
		}
		else 
		if(osviex.dwMinorVersion==1) //Win7
		{
			if(osviex.wServicePackMajor==0){
					os_pin= 16;
			}
		}
	}

	return os_pin;
}

void StartPinTracer(char * trace_msg)
{
	char cmdLine[256] ={0};
	char fileFilter[128] = {0};
	char networkFilter[128]={0};
	char pin_line[1024]={0};
	char exename[64]={0};
	char currentdir[128]={0};

	// Parse the message into tokens
	char * pch;
	if(bDebug)
		printf ("Splitting string \"%s\" into tokens:\n",trace_msg);
	pch = strtok (trace_msg,"!");
	int count =0;
	while (pch != NULL)
	{
		if(bDebug)
			printf ("%s\n",pch);
		if (count ==0)
		{
			strcpy(cmdLine,pch);
			count++;
		}
		else
		{
			if(strstr(pch,"FF="))
				strcpy(fileFilter,pch+3);
			if(strstr(pch,"NF="))
				strcpy(networkFilter,pch+3);

		}
		pch = strtok (NULL, "!");
	}

	if (strlen(cmdLine)>0){
		char fullpath[128]={0};
		strcpy(fullpath, cmdLine);
		if(bDebug)
			printf("fullpath:%s\n",fullpath);
		// extract executable name
		char * pch;
		pch = strtok (fullpath," \\");
		int count =0;
		while (pch != NULL)
		{
			if(bDebug)
				printf ("%s\n",pch);
			if (strstr(pch, ".exe"))
			{
				strncpy(exename,pch,16);
				break;
			}
			else {
				strcat(currentdir,pch);
				strcat(currentdir,"\\");
			}
			pch = strtok (NULL, " \\");
		}
	}

	if(bDebug)
		if (strlen(fileFilter)>0)
			printf("FileFilter:%s\n",fileFilter);
	
	if(bDebug)
		if (strlen(networkFilter)>0)
			printf("networkFilter:%s\n",networkFilter);

	int ospin= GetWindowsOSPinNumber();
	if(bDebug)
		printf("ospin= %d ",ospin);

	if (strlen(cmdLine)>0){
		if ((strlen(fileFilter)>0) && (strlen(networkFilter)>0))
			sprintf(pin_line," -t %s -taint_file %s -taint_winsock 1 -windows_os %d -binary_trace 1 -silent 1  -outpath %s -o %s -- %s",PINTOOL,ospin,fileFilter,TRACE_SHARE,exename,cmdLine);
		else
		if ((strlen(fileFilter)>0))
			sprintf(pin_line," -t %s -taint_file %s -windows_os %d -binary_trace 1 -silent 1 -outpath %s -o %s -- %s",PINTOOL,fileFilter,ospin,TRACE_SHARE,exename,cmdLine);
		else
		if ((strlen(networkFilter)>0))
			sprintf(pin_line," -t %s -taint_winsock 1 -windows_os %d -binary_trace 1 -silent 1  -outpath %s -o %s -- %s",PINTOOL,ospin,TRACE_SHARE,exename,cmdLine);
		else
			sprintf(pin_line," -t %s -windows_os %d -binary_trace 1 -silent 1  -outpath %s -o %s -- %s",PINTOOL,ospin,TRACE_SHARE,exename,cmdLine);
		if(bDebug)
			printf("exefile is %s, dir is %s, and pin_line is %s",exename,currentdir,pin_line);
		SpawnPin(PINEXEC, pin_line,currentdir);
	}
	else
		printf("Wrong Message: %s",trace_msg);
}
// Worker thread for processing PIN trace
DWORD WINAPI process_pintrace(LPVOID lpParam)
{

	printf("Worker thread created\r\n");

	// set our socket to the socket passed in as a parameter
	SOCKET clientSocket = (SOCKET)lpParam;

	int rVal;
	char Message[MESSAGE_LEN];
	char Reply[64]="Trace is Ready at Shared Folder TREE-TRACE";
	memset(Message,0,MESSAGE_LEN);

	rVal = recv(clientSocket, Message, MESSAGE_LEN, 0);

	if ( rVal > 0 ){
		printf("Bytes received: %d. Message = %s\n", rVal,Message);
		// Must have space before -t in the next line
		//Parse and construct the Pin command line like below
		// Figure out guest Windows version(or host if running locally)
		// Generate trace and relevent(index) files in a shared folder
		
		StartPinTracer(Message);

		//TEST
		//SpawnPin(L"C:\\pin\\ia32\\bin\\pin.exe", L" -t C:\\pin\\ia32\\bin\\exetrace.dll -windows_os 12 -taint_file mytaint -binary_trace 1 -silent 1 -o Z:\\Test\\pin_basicov\\exetrace.trace -- C:\\basicOV\\basicov.exe");
		//SpawnPin("C:\\pin\\ia32\\bin\\pin.exe", " -t C:\\pin\\ia32\\bin\\exetrace.dll -windows_os 12 -taint_file mytaint -binary_trace 1 -silent 1 -o Z:\\Test\\pin_basicov\\exetrace.trace -- C:\\basicOV\\basicov.exe");
	}
	else if ( rVal == 0 )
		printf("Connection closed\n");
	else
		printf("recv failed with error: %d\n", WSAGetLastError());

	// Spawn PIN procss to get the trace, wait for it to finish 

	//send back the notification of process end and trace file
	rVal = send( clientSocket, Reply, (int)strlen(Reply), 0 );

	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{

	WORD sockVersion;
	WSADATA wsaData;
	int rVal;
	DWORD thread;


	//wsock32 initialized for usage
	sockVersion = MAKEWORD(1,1);
	WSAStartup(sockVersion, &wsaData);

	//create server socket
	SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);

	if(serverSocket == INVALID_SOCKET)
	{
	   printf("Failed socket()");
	   return -1;
	}

	SOCKADDR_IN sin;
	sin.sin_family = PF_INET;
	sin.sin_port = htons(SERVER_PORT);
	sin.sin_addr.s_addr = INADDR_ANY;

	//bind the socket
	rVal = bind(serverSocket, (LPSOCKADDR)&sin, sizeof(sin));
	if(rVal == SOCKET_ERROR)
	{
	   printf("Failed bind()");
	   WSACleanup();
	   return -1;
	}

	//get socket to listen
	rVal = listen(serverSocket, 10);
	if(rVal == SOCKET_ERROR)
	{
	   printf("Failed listen()");
	   WSACleanup();
	   return -1;
	}

	char			szBuf[256];		
	char			szAddress[80];
	DWORD			dwAddrStrLen;
	//
	// Display the host name and address
	//
	gethostname(szBuf, sizeof(szBuf));
	dwAddrStrLen = sizeof(szAddress);
	GetLocalAddress(szAddress, &dwAddrStrLen);
	printf( "PinTrace Remote Agent: %s [%s] on port %d\n",szBuf,szAddress,SERVER_PORT);

	SOCKET clientSocket;

	while ( 1 ) {

		/*  Wait for a connection, then accept() it  */
		if ( (clientSocket = accept(serverSocket, NULL, NULL) ) == INVALID_SOCKET) {
		   printf("Failed accept()");
		}
		else
		{
			printf("Client connected\r\n");
			CreateThread(NULL, 0,process_pintrace,(LPVOID)clientSocket, 0, &thread);
		}
	}


	//close server socket
	closesocket(serverSocket);

	WSACleanup();

	return S_OK;
}

void SpawnPin(char *AppName, char *CmdLine, char *CurrentDir)
{
    printf("\n Spawn A PINed Process...\n");
	if(bDebug){
	    printf(" AppName: %s\n", AppName);
		printf(" CmdLine: %s\n", CmdLine);
	}

    PROCESS_INFORMATION processInformation;
    STARTUPINFOA startupInfo;
    memset(&processInformation, 0, sizeof(processInformation));
    memset(&startupInfo, 0, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    BOOL result;
    char tempCmdLine[MAX_PATH * 2];  
    if (CmdLine != NULL)
    {
        strncpy(tempCmdLine,CmdLine,MAX_PATH *2);
        result = ::CreateProcessA(AppName, tempCmdLine, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, CurrentDir, &startupInfo, &processInformation);
    }
    else
    {
        result = ::CreateProcessA(AppName, CmdLine, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, CurrentDir, (LPSTARTUPINFOA)&startupInfo, &processInformation);
    }

    if (result == 0)
    {
        printf("ERROR: CreateProcess failed!Error=0x%x",GetLastError());
    }
    else
    {
		printf("\n PINed Process running...\n");
        WaitForSingleObject( processInformation.hProcess, INFINITE );
        CloseHandle( processInformation.hProcess );
        CloseHandle( processInformation.hThread );
		printf("\n PINed Process exit...\n");
    }
}
