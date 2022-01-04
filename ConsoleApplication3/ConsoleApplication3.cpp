// ConsoleApplication3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#define _WIN32_WINNT 0x0400

#define WIN32_LEAN_AND_MEAN   // 从 Windows 头中排除极少使用的资料
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Tlhelp32.h>

//
// coded by robinh00d[VX Z0NE]
// Email:robinh00d_at_qq_dot_com
// 向指定进程的线程里插入APC实现DLL注入
//思路来自PJF的老文
//
typedef struct _TIDLIST
{
	DWORD dwTid;
	_TIDLIST *pNext;
}TIDLIST;

DWORD EnumThread(HANDLE hProcess, TIDLIST *pThreadIdList)
{
	TIDLIST *pCurrentTid = pThreadIdList;

	const char szInjectModName[] = "D:\\Program Files\\Foxmail 7.2\\7.2.20.258\\tinyxml.dll";
	DWORD dwLen = strlen(szInjectModName);

	PVOID param = VirtualAllocEx(hProcess, \
		NULL, dwLen, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

	if (param != NULL)
	{
		DWORD dwRet;
		if (WriteProcessMemory(hProcess, param, (LPVOID)szInjectModName, dwLen, &dwRet))
		{

			while (pCurrentTid)
			{
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pCurrentTid->dwTid);

				if (hThread != NULL)
				{
					//
					// 注入DLL到指定进程
					//
					QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)param);
				}

				printf("TID:%d\n", pCurrentTid->dwTid);
				pCurrentTid = pCurrentTid->pNext;
			}
		}
	}
	return 0;
}

DWORD GetProcID(const char *szProcessName)
{
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0xFFFFFFFF;
	}

	if (!Process32First(hSnapshot, &pe32))
	{
		return 0xFFFFFFFF;
	}

	do
	{
		if (!_strnicmp(szProcessName, pe32.szExeFile, strlen(szProcessName)))
		{
			printf("%s的PID是:%d\n", pe32.szExeFile, pe32.th32ProcessID);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &pe32));

	return 0xFFFFFFFF;

}

TIDLIST* InsertTid(TIDLIST *pdwTidListHead, DWORD dwTid)
{
	TIDLIST *pCurrent = NULL;
	TIDLIST *pNewMember = NULL;

	if (pdwTidListHead == NULL)
	{
		return NULL;
	}
	pCurrent = pdwTidListHead;

	while (pCurrent != NULL)
	{

		if (pCurrent->pNext == NULL)
		{
			//
			// 定位到链表最后一个元素
			//
			pNewMember = (TIDLIST *)malloc(sizeof(TIDLIST));

			if (pNewMember != NULL)
			{
				pNewMember->dwTid = dwTid;
				pNewMember->pNext = NULL;
				pCurrent->pNext = pNewMember;
				return pNewMember;
			}
			else
			{
				return NULL;
			}
		}
		pCurrent = pCurrent->pNext;
	}

	return NULL;
}

int EnumThreadID(DWORD dwPID, TIDLIST *pdwTidList)
{
	int i = 0;

	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPID);

	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		if (Thread32First(hSnapshot, &te32))
		{
			do
			{
				if (te32.th32OwnerProcessID == dwPID)
				{
					if (pdwTidList->dwTid == 0)
					{
						pdwTidList->dwTid = te32.th32ThreadID;
					}
					else
					{
						if (NULL == InsertTid(pdwTidList, te32.th32ThreadID))
						{
							printf("插入失败!\n");
							return 0;
						}
					}

				}
			} while (Thread32Next(hSnapshot, &te32));
		}
	}
	return 1;
}

int main(int argc, char* argv[])
{
	TIDLIST *pTidHead = (TIDLIST *)malloc(sizeof(TIDLIST));

	if (pTidHead == NULL)
	{
		return 1;
	}
	RtlZeroMemory(pTidHead, sizeof(TIDLIST));

	DWORD dwPID = 0;

	if ((dwPID = GetProcID("WXWork.exe")) == 0xFFFFFFFF)
	{
		printf("进程ID获取失败!\n");
		return 1;
	}

	//
	// 枚举线程ID
	//
	EnumThreadID(dwPID, pTidHead);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

	if (hProcess == NULL)
	{
		return 1;
	}
	EnumThread(hProcess, pTidHead);

	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
