
// Leg_DebugDlg.cpp : 實作檔
//

#include "stdafx.h"
#include "Leg_Debug.h"
#include "Leg_DebugDlg.h"
#include "afxdialogex.h"
#include "DebugData.h"
//#include "Decode2Asm.cpp"
#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <Psapi.h>
#pragma comment(lib,"Psapi.lib")

using namespace std;
#pragma warning(disable: 4800) 
#pragma warning(disable: 4806) 
#pragma warning(disable: 4996) 
#define BEA_ENGINE_STATIC  // 指明使用靜態Lib庫
#define BEA_USE_STDCALL    // 指明使用stdcall調用約定
#define MoveMemory RtlMoveMemory
#define CopyMemory RtlCopyMemory
#define FillMemory RtlFillMemory
#define ZeroMemory RtlZeroMemory

#ifdef __cplusplus


extern "C"{
#endif


#include "beaengine-win64/headers/BeaEngine.h"
#pragma comment(lib, "beaengine-win64\\Win64\\Lib\\BeaEngine64.lib")


#ifdef __cplusplus
};
#endif
DISASM MyDisasm;
int len, i = 0;
int aError = 0;

//void DisassembleCode(char* StartCodeSection,char* EndCodeSection,int (*virtual_Address)(int argc, _TCHAR* argv[]));

PVOID pBuffer = NULL;


//保存映射的基址
extern char* pFile = NULL;
#define BUFSIZE 512
/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
//調試線程函數
DWORD WINAPI DebugThreadProc(LPVOID lpParameter);


extern HANDLE g_hProcess = NULL;

extern HANDLE g_hThread = NULL;


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 對話方塊資料
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支援

// 程式碼實作
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnOpen();
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
	ON_COMMAND(ID_32771, &CAboutDlg::OnOpen)
END_MESSAGE_MAP()


// CLeg_DebugDlg 對話方塊

CLeg_DebugDlg::CLeg_DebugDlg(CWnd* pParent /*=NULL*/)
: CDialogEx(CLeg_DebugDlg::IDD, pParent)

{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}



void CLeg_DebugDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_Result);
	DDX_Control(pDX, IDC_LIST2, m_AsmList);
	DDX_Control(pDX, IDC_LIST_REG, m_ctl_RegList);
	DDX_Control(pDX, IDC_LIST_DLL, m_ctl_DllList);
	//  DDX_Text(pDX, IDC_EDIT1, m_dwMemoryAddress);
	DDX_Control(pDX, IDC_LIST_DATA, m_ctl_DataList);
	DDX_Control(pDX, IDC_LIST_ST, m_Stack);
	DDX_Control(pDX, IDC_EDIT2, m_command);
	DDX_Control(pDX, IDC_EDIT3, m_asm_adr);
	DDX_Control(pDX, IDC_EDIT1, m_dwMemoryAddress);
}

BEGIN_MESSAGE_MAP(CLeg_DebugDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_COMMAND(ID_32771, &CLeg_DebugDlg::OnOpen)
	ON_BN_CLICKED(IDC_BUTTON1, &CLeg_DebugDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CLeg_DebugDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CLeg_DebugDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CLeg_DebugDlg::OnBnClickedButton4)
	ON_EN_CHANGE(IDC_EDIT2, &CLeg_DebugDlg::OnEnChangeEdit2)
END_MESSAGE_MAP()

enum{
	REGLIST_RAX = 0,
	REGLIST_RBX,
	REGLIST_RCX,
	REGLIST_RDX,

	REGLIST_RSP,
	REGLIST_RBP,
	REGLIST_RSI,
	REGLIST_RDI,
	REGLIST_RIP,

	REGLIST_R8,
	REGLIST_R9,
	REGLIST_R10,
	REGLIST_R11,
	REGLIST_R12,
	REGLIST_R13,
	REGLIST_R14,
	REGLIST_R15,

	REGLIST_CS,
	REGLIST_SS,
	REGLIST_DS,
	REGLIST_ES,
	REGLIST_FS,
	REGLIST_GS,

	REGLIST_CF,
	REGLIST_PF,
	REGLIST_AF,
	REGLIST_ZF,
	REGLIST_SF,
	REGLIST_TF,
	REGLIST_IF,
	REGLIST_DF,
	REGLIST_OF,

};
// CLeg_DebugDlg 訊息處理常式

BOOL CLeg_DebugDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 將 [關於...] 功能表加入系統功能表。

	// IDM_ABOUTBOX 必須在系統命令範圍之中。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 設定此對話方塊的圖示。當應用程式的主視窗不是對話方塊時，
	// 框架會自動從事此作業
	SetIcon(m_hIcon, TRUE);			// 設定大圖示
	SetIcon(m_hIcon, FALSE);		// 設定小圖示

	// TODO:  在此加入額外的初始設定
	
	memset(m_szFilePath, 0, sizeof(m_szFilePath));
	memset(&m_tpInfo, 0, sizeof(m_tpInfo));
	memset(&m_tpInfo, 0, sizeof(m_tpInfo));
	memset(&m_Recover_BP, 0, sizeof(m_Recover_BP));
	memset(&m_Dr_Use, 0, sizeof(m_Dr_Use));
	m_isDebuging = FALSE;
	m_GetModule = FALSE;
	m_IsGo = FALSE;
	m_IsOepBP = TRUE;
	m_IsF8 = FALSE;
	m_IsAutoF8 = FALSE;
	m_isDelete = FALSE;
	m_IsAutoF7 = FALSE;
	m_tpInfo.bCC = 0xcc;
	m_Uaddress = 0;
	m_Recover_HBP.dwIndex = -1;
	memset(&m_Recover_Mpage, 0, sizeof(m_Recover_Mpage));
	m_isMoreMem = FALSE;
	m_Attribute[0] = 0;//做占位用 實際有用的是 1 3
	m_Attribute[1] = PAGE_EXECUTE_READ;
	m_Attribute[2] = 0;
	m_Attribute[3] = PAGE_NOACCESS;
	//=====================================
	m_ctl_DataList.InsertColumn(0, "地址", LVCFMT_LEFT, 110);
	m_ctl_DataList.InsertColumn(1, "HEX數值", LVCFMT_LEFT, 140);
	m_ctl_DataList.InsertColumn(2, "ASCII", LVCFMT_LEFT, 90);
	m_ctl_DataList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	//=====================================
	m_ctl_DllList.InsertColumn(0, "DLL完整路徑", LVCFMT_LEFT, 700);
	m_ctl_DllList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	//=====================================
	m_ctl_RegList.InsertColumn(0, "暫存器", LVCFMT_LEFT, 80);
	m_ctl_RegList.InsertColumn(1, "數值", LVCFMT_LEFT, 130);
	m_ctl_RegList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	//=====================================
	m_Stack.InsertColumn(0, "堆疊地址", LVCFMT_LEFT, 80);
	m_Stack.InsertColumn(1, "數值", LVCFMT_LEFT, 130);
	m_Stack.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_ctl_RegList.InsertItem(REGLIST_RAX, "RAX");
	m_ctl_RegList.InsertItem(REGLIST_RBX, "RBX");
	m_ctl_RegList.InsertItem(REGLIST_RCX, "RCX");
	m_ctl_RegList.InsertItem(REGLIST_RDX, "RDX");

	m_ctl_RegList.InsertItem(REGLIST_RSP, "RSP");
	m_ctl_RegList.InsertItem(REGLIST_RBP, "RBP");
	m_ctl_RegList.InsertItem(REGLIST_RSI, "RSI");
	m_ctl_RegList.InsertItem(REGLIST_RDI, "RDI");

	m_ctl_RegList.InsertItem(REGLIST_RIP, "RIP");

	m_ctl_RegList.InsertItem(REGLIST_R8, "R8");
	m_ctl_RegList.InsertItem(REGLIST_R9, "R9");
	m_ctl_RegList.InsertItem(REGLIST_R10, "R10");
	m_ctl_RegList.InsertItem(REGLIST_R11, "R11");
	m_ctl_RegList.InsertItem(REGLIST_R12, "R12");
	m_ctl_RegList.InsertItem(REGLIST_R13, "R13");
	m_ctl_RegList.InsertItem(REGLIST_R14, "R14");
	m_ctl_RegList.InsertItem(REGLIST_R15, "R15");

	m_ctl_RegList.InsertItem(REGLIST_CS, "CS");
	m_ctl_RegList.InsertItem(REGLIST_SS, "SS");
	m_ctl_RegList.InsertItem(REGLIST_DS, "DS");
	m_ctl_RegList.InsertItem(REGLIST_ES, "ES");
	m_ctl_RegList.InsertItem(REGLIST_FS, "FS");
	m_ctl_RegList.InsertItem(REGLIST_GS, "GS");

	m_ctl_RegList.InsertItem(REGLIST_CF, "CF");
	m_ctl_RegList.InsertItem(REGLIST_PF, "PF");
	m_ctl_RegList.InsertItem(REGLIST_AF, "AF");
	m_ctl_RegList.InsertItem(REGLIST_ZF, "ZF");
	m_ctl_RegList.InsertItem(REGLIST_SF, "SF");
	m_ctl_RegList.InsertItem(REGLIST_TF, "TF");
	m_ctl_RegList.InsertItem(REGLIST_IF, "IF");
	m_ctl_RegList.InsertItem(REGLIST_DF, "DF");
	m_ctl_RegList.InsertItem(REGLIST_OF, "OF");
	//=====================================
	m_AsmList.InsertColumn(0, "地址", LVCFMT_LEFT, 90);
	m_AsmList.InsertColumn(1, "HEX數值", LVCFMT_LEFT, 140);
	m_AsmList.InsertColumn(2, "反編譯", LVCFMT_LEFT, 400);
	m_AsmList.SetExtendedStyle(m_AsmList.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	return TRUE;  // 傳回 TRUE，除非您對控制項設定焦點
}

void CLeg_DebugDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果將最小化按鈕加入您的對話方塊，您需要下列的程式碼，
// 以便繪製圖示。對於使用文件/檢視模式的 MFC 應用程式，
// 框架會自動完成此作業。

void CLeg_DebugDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 繪製的裝置內容

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 將圖示置中於用戶端矩形
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 描繪圖示
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 當使用者拖曳最小化視窗時，
// 系統呼叫這個功能取得游標顯示。
HCURSOR CLeg_DebugDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}





void CAboutDlg::OnOpen()
{
	
	// TODO:  在此加入您的命令處理常式程式碼
}


//得到可執行文件的路徑
void CLeg_DebugDlg::GetExeFilePath(char* szFilePath)
{
	OPENFILENAME file = { 0 };
	file.lpstrFile = szFilePath;
	file.lStructSize = sizeof(OPENFILENAME);
	file.nMaxFile = 256;
	file.lpstrFilter = "Executables\0*.exe\0All Files\0*.*\0\0";
	file.nFilterIndex = 1;

	if (!::GetOpenFileName(&file))
	{
		//點了取消按鈕就退出函數
		return;
	}
}
//輸出錯誤信息 
void CLeg_DebugDlg::GetErrorMessage(DWORD dwErrorCode)
{
	LPVOID lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
		);

	::MessageBox(NULL, (LPCTSTR)lpMsgBuf, TEXT("Error"), MB_OK | MB_ICONINFORMATION);
	//釋放堆空間
	LocalFree(lpMsgBuf);
}
//映射文件 并檢查PE有效性以及是不是EXE文件
BOOL CLeg_DebugDlg::MapPEFile()
{
	HANDLE hFile = NULL;
	//打開文件獲得文件句柄
	hFile = CreateFile(m_szFilePath, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		OutputDebugString("EasyDbgDlg.cpp 3424行出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		//輸出錯誤信息
		GetErrorMessage(dwErrorCode);

		return FALSE;
	}
	HANDLE hFileMap = NULL;
	//創建文件映射
	hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hFileMap == NULL)
	{
		OutputDebugString("EasyDbgDlg.cpp 3437行出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		GetErrorMessage(dwErrorCode);
		CloseHandle(hFile);
		return FALSE;
	}
	//映射文件
	pFile = (char*)MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pFile == NULL)
	{
		OutputDebugString("EasyDbgDlg.cpp 3448行出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		GetErrorMessage(dwErrorCode);

		CloseHandle(hFile);
		CloseHandle(hFileMap);
		return FALSE;
	}

	//判斷PE有效性
	PIMAGE_DOS_HEADER pDos = NULL;
	pDos = (PIMAGE_DOS_HEADER)pFile;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFile + pDos->e_lfanew);

	//檢查MZ PE 兩個標志
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE || pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		AfxMessageBox("不是有效的PE文件");
		CloseHandle(hFile);
		CloseHandle(hFileMap);
		return FALSE;
	}
	if (pNt->FileHeader.Characteristics&IMAGE_FILE_DLL)
	{
		AfxMessageBox("該文件是DLL,EXE文件");
		CloseHandle(hFile);
		CloseHandle(hFileMap);
		return FALSE;
	}


	CloseHandle(hFile);
	CloseHandle(hFileMap);

	return TRUE;

}






void CLeg_DebugDlg::OnOpen()
{
	// TODO: Add your command handler code here

	if (m_isDebuging == TRUE)
	{
		AfxMessageBox("調試器正在調試中!不能在調試另一個程序");
		return;
	}

	//GetExeFilePath(m_SzFilePath);
	CFileDialog filedlg(TRUE, "exe", "", OFN_OVERWRITEPROMPT, "文件(*.exe)|*.exe|(*.dll)|*.dll||", this);
	if (filedlg.DoModal() != IDOK){
		return;
	}
	OnInitial(filedlg.GetPathName().GetBuffer(0));



	//如果用戶點擊了關閉按鈕 m_SzFilePath沒有值
	/*if (m_SzFilePath[0] == 0x00){
		return;
	}
	if (!MapPEFile())
	{
		return;
	}
	m_isDebuging = TRUE;*/


	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DebugThreadProc, this, NULL, NULL);

	// TODO:  在此加入您的命令處理常式程式碼
}

//調試線程函數
DWORD WINAPI DebugThreadProc(
	LPVOID lpParameter   // thread data
	)
{
	STARTUPINFO si = { 0 };
	//要初始化此成員
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };
	char szFilePath[256] = { 0 };
	CLeg_DebugDlg* pDebug = (CLeg_DebugDlg*)lpParameter;
	//要用工作線程 創建調試進程
	if (CreateProcess(pDebug->m_szFilePath, NULL, NULL, NULL, false, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi) == 0)
	{
		OutputDebugString("創建調試進程出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		//獲得出錯信息并輸出
		pDebug->GetErrorMessage(dwErrorCode);
		return FALSE;

	}

	BOOL isExit = FALSE;//被調試進程是否退出的標志
	//調試事件
	DEBUG_EVENT de = { 0 };
	//作為系統第一次斷點的標志
	BOOL bFirstBp = FALSE;
	//標志 被調試線程以怎樣的方式恢復
	LONGLONG  dwContinueStatus = DBG_CONTINUE;
	//調試循環
	while (!isExit&&WaitForDebugEvent(&de, INFINITE))//如果不加上isExit則被調試進程退出時,調試器還會一直等待它
	{
		switch (de.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			switch (de.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
			{
											   DWORD dwAccessAddress = 0;
											   //異常訪問的地址
											   dwAccessAddress = (LONGLONG)de.u.Exception.ExceptionRecord.ExceptionInformation[1];
											   /*dwContinueStatus = pDebug->ON_EXCEPTION_ACCESS_VIOLATION(
												   (DWORD)de.u.Exception.ExceptionRecord.ExceptionAddress,
												   dwAccessAddress
												   );*/
											   break;
			}
			case EXCEPTION_BREAKPOINT:
				if (bFirstBp)
				{

					dwContinueStatus = pDebug->ON_EXCEPTION_BREAKPOINT((LONGLONG)de.u.Exception.ExceptionRecord.ExceptionAddress);

				}
				else
				{
					//處理系統第一次斷點

					bFirstBp = TRUE;
				}

				break;
			case EXCEPTION_SINGLE_STEP:

				dwContinueStatus = pDebug->ON_EXCEPTION_SINGLE_STEP(
					(LONGLONG)de.u.Exception.ExceptionRecord.ExceptionAddress
					);

				break;


			}

			break;
		case CREATE_THREAD_DEBUG_EVENT:


			//主線程創建不會有此事件
			// AfxMessageBox("線程創建");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:

			//主線程創建
			dwContinueStatus = pDebug->ON_CREATE_PROCESS_DEBUG_EVENT(de.dwProcessId,
				de.dwThreadId,
				de.u.CreateProcessInfo.lpStartAddress);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			//主線程退出不會產生此事件
			//AfxMessageBox("線程退出");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			//主線程退出
			AfxMessageBox("進程退出");

			isExit = TRUE;

			AfxMessageBox("被調試進程退出");

			break;

		case LOAD_DLL_DEBUG_EVENT:
			//加載DLL事件
			pDebug->ON_LOAD_DLL_DEBUG_EVENT(de.u.LoadDll.hFile, de.u.LoadDll.lpBaseOfDll);


			break;
		case UNLOAD_DLL_DEBUG_EVENT:

			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		}

		//恢復被調試線程的運行
		if (!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, (LONGLONG)dwContinueStatus))
		{
			OutputDebugString("EasyDbgDlg.cpp 442行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			pDebug->GetErrorMessage(dwErrorCode);

			return DBG_EXCEPTION_NOT_HANDLED;


		}
		//重置此標志
		dwContinueStatus = DBG_CONTINUE;


	}



	return 0;

}

	//處理加載DLL事件
	void CLeg_DebugDlg::ON_LOAD_DLL_DEBUG_EVENT(HANDLE hFile, LPVOID pBase)
	{
		if (hFile == NULL || pBase == NULL)
		{
			return;
		}

		GetDllInfoFromHandle(hFile, pBase);
		GetFileNameFromHandle(hFile, pBase);

	}


	//得到加載DLL時的路徑
	void CLeg_DebugDlg::GetFileNameFromHandle(HANDLE hFile, LPVOID pBase)
	{
		//有DLL加載 提示模塊信息表要更新
		m_GetModule = TRUE;

		//傳入參數的有效性判斷
		if (hFile == NULL)
		{
			AfxMessageBox("句柄無效");
			return;
		}

		TCHAR pszFilename[MAX_PATH + 1];
		HANDLE hFileMap;

		// Get the file size.
		DWORD dwFileSizeHi = 0;
		DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

		if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
		{
			_tprintf(TEXT("Cannot map a file with a length of zero.\n"));
			return;
		}

		// Create a file mapping object.

		hFileMap = CreateFileMapping(hFile,
			NULL,
			PAGE_READONLY,
			0,
			0,
			NULL);

		if (hFileMap)
		{
			// Create a file mapping to get the file name.
			void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);

			if (pMem)
			{
				//獲得導出函數信息
				GetExportFunAddress(hFile, (char*)pMem, pBase);
				if (GetMappedFileName(GetCurrentProcess(),
					pMem,
					pszFilename,
					MAX_PATH))
				{

					// Translate path with device name to drive letters.
					TCHAR szTemp[BUFSIZE];
					szTemp[0] = '\0';

					if (GetLogicalDriveStrings(BUFSIZE - 1, szTemp))
					{
						TCHAR szName[MAX_PATH];
						TCHAR szDrive[3] = TEXT(" :");
						BOOL bFound = FALSE;
						TCHAR* p = szTemp;

						do
						{
							// Copy the drive letter to the template string
							*szDrive = *p;

							// Look up each device name
							if (QueryDosDevice(szDrive, szName, MAX_PATH))
							{
								size_t uNameLen = _tcslen(szName);

								if (uNameLen < MAX_PATH)
								{
									bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0;

									if (bFound && *(pszFilename + uNameLen) == _T('\\'))
									{
										// Reconstruct pszFilename using szTempFile
										// Replace device path with DOS path
										TCHAR szTempFile[MAX_PATH];
										sprintf_s(szTempFile,

											TEXT("%s%s"),
											szDrive,
											pszFilename + uNameLen);
										_tcsncpy_s(pszFilename, szTempFile, MAX_PATH);
									}
								}
							}

							// Go to the next NULL character.
							while (*p++);
						} while (!bFound && *p); // end of string
					}
				}

				UnmapViewOfFile(pMem);
				pMem = NULL;
			}

			CloseHandle(hFileMap);
			hFileMap = NULL;
		}


		m_Result.AddString(pszFilename);

		m_Result.SetTopIndex(m_Result.GetCount() - 1);



	}



	// 獲得導入表函數地址
	
	BOOL CLeg_DebugDlg::GetExportFunAddress(HANDLE hFile, char* pDll, LPVOID pBase)
	{


		PIMAGE_DOS_HEADER pDos = NULL;
		PIMAGE_FILE_HEADER pFileHeader = NULL;
		PIMAGE_OPTIONAL_HEADER pOption = NULL;
		PIMAGE_SECTION_HEADER pSec = NULL;

		//獲取各結構的指針
		pDos = (PIMAGE_DOS_HEADER)pDll;

		pFileHeader = (PIMAGE_FILE_HEADER)(pDll + pDos->e_lfanew + 4);
		pOption = (PIMAGE_OPTIONAL_HEADER)((char*)pFileHeader + sizeof(IMAGE_FILE_HEADER));
		pSec = (PIMAGE_SECTION_HEADER)((char*)pOption + pFileHeader->SizeOfOptionalHeader);
		//節表數目
		DWORD dwSecNum = 0;
		dwSecNum = pFileHeader->NumberOfSections;
		//導出表偏移
		DWORD dwExportRva = 0;

		dwExportRva = pOption->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;


		DWORD dwExportOffset = 0;
		//獲得導入表的文件偏移
		dwExportOffset = RvaToFileOffset(dwExportRva, dwSecNum, pSec);
		PIMAGE_EXPORT_DIRECTORY pExp = NULL;
		pExp = (PIMAGE_EXPORT_DIRECTORY)(pDll + dwExportOffset);

		EXPORT_FUN_INFO ExFun = { 0 };


		DWORD dwNameOffset = 0;
		dwNameOffset = RvaToFileOffset(pExp->Name, dwSecNum, pSec);
		char*pName = NULL;
		//DLL名
		pName = (char*)(pDll + dwNameOffset);
		strcpy_s(ExFun.szDLLName, pName);

		DWORD dwBase = 0;
		dwBase = pExp->Base;
		DWORD dwFunNum = 0;
		dwFunNum = pExp->NumberOfFunctions;
		for (DWORD j = 0; j<dwFunNum; j++)
		{
			//先遍歷函數地址數組
			PDWORD pAddr = (PDWORD)(pDll + RvaToFileOffset(pExp->AddressOfFunctions, dwSecNum, pSec));
			//地址有效
			if (pAddr[j] != 0)
			{
				//通過序號得到相應函數名數組下標
				//序號數組
				PWORD pNum = (PWORD)(pDll + RvaToFileOffset(pExp->AddressOfNameOrdinals, dwSecNum, pSec));
				for (WORD k = 0; k<pExp->NumberOfNames; k++)
				{
					//在序號數組里找序號相同的 找到下標然后讀函數名
					if (j == pNum[k])
					{
						//導出函數名(或變量名數組) 得到的是RVA
						PDWORD pName = (PDWORD)(pDll + RvaToFileOffset(pExp->AddressOfNames, dwSecNum, pSec));

						char *pszName = (char*)(pDll + RvaToFileOffset(pName[k], dwSecNum, pSec));

						memcpy(&ExFun.szFunName, pszName, strlen(pszName) + 1);


						if (pBase)
						{
							ExFun.dwAddress = (LONGLONG)pBase + pAddr[j];
							//加入CMAP中
							m_ExFunList.SetAt(ExFun.dwAddress, ExFun);
							//加入函數名與地址對應表
							m_Fun_Address.SetAt(pszName, ExFun.dwAddress);
						}


						break;
					}
				}


			}


		}


		return TRUE;

	}


	//參數一 導入表的RVA 參數2區塊表的數目 參數3區塊表的首地址
	DWORD CLeg_DebugDlg::RvaToFileOffset(DWORD dwRva, DWORD dwSecNum, PIMAGE_SECTION_HEADER pSec)
	{
		if (dwSecNum == 0)
		{
			return 0;
		}

		for (DWORD i = 0; i<dwSecNum; i++)
		{

			if (dwRva >= pSec[i].VirtualAddress&&dwRva<pSec[i].VirtualAddress + pSec[i].SizeOfRawData)
			{

				return dwRva - pSec[i].VirtualAddress + pSec[i].PointerToRawData;

			}
		}
		return 0;

	}

	bool CLeg_DebugDlg::OnInitial(char* lpszFilename)
	{
		if (lpszFilename == NULL){
			return false;
		}
		strcpy_s(m_szFilePath, lpszFilename);//初始化要DBG的檔案名稱
		m_GetModule = FALSE;
		return true;
	}



	//處理 CREATE_PROCESS_DEBUG_EVENT 事件的函數 
	DWORD CLeg_DebugDlg::ON_CREATE_PROCESS_DEBUG_EVENT(DWORD dwProcessId, DWORD dwThreadId, LPTHREAD_START_ROUTINE lpOepAddress){
		HMODULE hDll = GetModuleHandle("Kernel32.dll");
		if (hDll == NULL)
		{

			hDll = LoadLibrary("Kernel32.dll");
			if (hDll == NULL)
			{
				DWORD dwErrorCode = 0;
				dwErrorCode = GetLastError();
				GetErrorMessage(dwErrorCode);
				return DBG_EXCEPTION_NOT_HANDLED;
			}
		}
		m_tpInfo.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
		if (m_tpInfo.hThread == INVALID_HANDLE_VALUE){
			return DBG_EXCEPTION_NOT_HANDLED;
		}
		m_tpInfo.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (m_tpInfo.hThread == INVALID_HANDLE_VALUE){
			return DBG_EXCEPTION_NOT_HANDLED;
		}
		m_tpInfo.OepAddress = lpOepAddress;

		//全局句柄賦值
		g_hProcess = m_tpInfo.hProcess;
		g_hThread = m_tpInfo.hThread;

		m_tpInfo.dwProcessId = dwProcessId;
		m_tpInfo.dwThreadId = dwThreadId;
		m_tpInfo.OepAddress = lpOepAddress;
		if (!ReadProcessMemory(m_tpInfo.hProcess, m_tpInfo.OepAddress, &m_tpInfo.OriginalCode, 1, NULL))
		{
			OutputDebugString("EasyDbgDlg.cpp 946行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			GetErrorMessage(dwErrorCode);
			return DBG_EXCEPTION_NOT_HANDLED;
		}

		if (!WriteProcessMemory(m_tpInfo.hProcess, m_tpInfo.OepAddress, &m_tpInfo.bCC, 1, NULL))
		{
			OutputDebugString("EasyDbgDlg.cpp 954行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			GetErrorMessage(dwErrorCode);
			return DBG_EXCEPTION_NOT_HANDLED;

		}

		return DBG_CONTINUE;




	}


	/*void CLeg_DebugDlg::ShowAsm(LONGLONG dwAddress){
		BYTE lpBuffer[500] = { 0 };
		OnReadMemory(dwAddress, lpBuffer, 500);
		DisassembleCode((char*)lpBuffer, (char*)lpBuffer + 500, dwAddress);
		return;
	}*/

	BOOL CLeg_DebugDlg::OnReadMemory(IN LONGLONG dwAdderss, OUT BYTE* lpBuffer, DWORD dwSize){
		DWORD dwRet = 0;
		DWORD dwOldProtect = 0;
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAdderss, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		if (!ReadProcessMemory(m_tpInfo.hProcess, (LPVOID)dwAdderss, lpBuffer, dwSize, NULL)){
			return DBG_EXCEPTION_HANDLED;
		}
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAdderss, dwSize, dwOldProtect, &dwRet);
		return true;
	}


	void CLeg_DebugDlg::DisassembleCode(char* StartCodeSection, char* EndCodeSection, LONGLONG virtual_Address){
		LONGLONG aa = 0;
		int i = 0;
		string b;
		BYTE lpBuffer2[50] = { 0 };
		BYTE lpBuffer[16] = { 0 };
		BYTE lpBuffer1[16] = { 0 };
		char szTemp[MAX_PATH] = { 0 };
		/*初始化DISASM結構*/
		(void)memset(&MyDisasm, 0, sizeof(DISASM));
		/*初始化EIP*/
		MyDisasm.EIP = (LONGLONG)StartCodeSection;
		/*初始化虛擬地址*/
		MyDisasm.VirtualAddr = (LONGLONG)virtual_Address;

		/*設置為64位元*/
		MyDisasm.Archi = 64;

		/*DISASM循環解析代碼*/

		while (!aError){

			//設置安全鎖
			MyDisasm.SecurityBlock = (long)(EndCodeSection - StartCodeSection);
			len = Disasm(&MyDisasm);

			if (len == OUT_OF_BLOCK){
				//(void)printf("Disasm Engine is not allowed to read more memory\n");
				aError = true;
			}
			else if (len == UNKNOWN_OPCODE){
				//(void)printf("unknow opcode\n");
				aError = true;
			}
			else{
				sprintf_s(szTemp, "%16p", MyDisasm.VirtualAddr);
				m_AsmList.InsertItem(i, szTemp);
				OnReadMemory(MyDisasm.VirtualAddr, lpBuffer, len);
				for (int x = 0; x<len; x++){
					aa = aa * 256 + (int)lpBuffer[x];
				}
				sprintf_s(szTemp, "%8X", aa);
				m_AsmList.SetItemText(i, 1, szTemp);

				aa = 0;

				sprintf_s(szTemp, "%s", MyDisasm.CompleteInstr);
				m_AsmList.SetItemText(i, 2, szTemp);

				i = i + 1;

				MyDisasm.EIP = MyDisasm.EIP + len;
				MyDisasm.VirtualAddr = MyDisasm.VirtualAddr + len;

				if (MyDisasm.EIP >= (int)EndCodeSection){
					//(void)printf("End of buffer reached!\n");
					aError = true;
				}

			}


		}

	}

	void CLeg_DebugDlg::OnBnClickedButton1()
	{
		ON_VK_F9();
		// TODO:  在此加入控制項告知處理常式程式碼
	}


	void CLeg_DebugDlg::ShowRegData(){
		CONTEXT ctThreadContext;
		char szTemp[MAX_PATH] = { 0 };
		ctThreadContext.ContextFlags = CONTEXT_FULL;
		if (OnGetThreadContext(&ctThreadContext) == FALSE){
			return;
		}


		sprintf_s(szTemp, "%16p", ctThreadContext.Rax);
		m_ctl_RegList.SetItemText(REGLIST_RAX, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.Rbx);
		m_ctl_RegList.SetItemText(REGLIST_RBX, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.Rcx);
		m_ctl_RegList.SetItemText(REGLIST_RCX, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.Rdx);
		m_ctl_RegList.SetItemText(REGLIST_RDX, 1, szTemp);

		sprintf_s(szTemp, "%16p", ctThreadContext.Rsp);
		m_ctl_RegList.SetItemText(REGLIST_RSP, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.Rbp);
		m_ctl_RegList.SetItemText(REGLIST_RBP, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.Rsi);
		m_ctl_RegList.SetItemText(REGLIST_RSI, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.Rdi);
		m_ctl_RegList.SetItemText(REGLIST_RDI, 1, szTemp);

		sprintf_s(szTemp, "%16p", ctThreadContext.Rip);
		m_ctl_RegList.SetItemText(REGLIST_RIP, 1, szTemp);

		sprintf_s(szTemp, "%16p", ctThreadContext.R8);
		m_ctl_RegList.SetItemText(REGLIST_R8, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.R9);
		m_ctl_RegList.SetItemText(REGLIST_R9, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.R10);
		m_ctl_RegList.SetItemText(REGLIST_R10, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.R11);
		m_ctl_RegList.SetItemText(REGLIST_R11, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.R12);
		m_ctl_RegList.SetItemText(REGLIST_R12, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.R13);
		m_ctl_RegList.SetItemText(REGLIST_R13, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.R14);
		m_ctl_RegList.SetItemText(REGLIST_R14, 1, szTemp);
		sprintf_s(szTemp, "%16p", ctThreadContext.R15);
		m_ctl_RegList.SetItemText(REGLIST_R15, 1, szTemp);


		sprintf_s(szTemp, "%08X", ctThreadContext.SegCs);
		m_ctl_RegList.SetItemText(REGLIST_CS, 1, szTemp);
		sprintf_s(szTemp, "%08X", ctThreadContext.SegSs);
		m_ctl_RegList.SetItemText(REGLIST_SS, 1, szTemp);
		sprintf_s(szTemp, "%08X", ctThreadContext.SegDs);
		m_ctl_RegList.SetItemText(REGLIST_DS, 1, szTemp);
		sprintf_s(szTemp, "%08X", ctThreadContext.SegEs);
		m_ctl_RegList.SetItemText(REGLIST_ES, 1, szTemp);
		sprintf_s(szTemp, "%08X", ctThreadContext.SegFs);
		m_ctl_RegList.SetItemText(REGLIST_FS, 1, szTemp);
		sprintf_s(szTemp, "%08X", ctThreadContext.SegGs);
		m_ctl_RegList.SetItemText(REGLIST_GS, 1, szTemp);

		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0001);
		m_ctl_RegList.SetItemText(REGLIST_CF, 1, szTemp);
		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0004);
		m_ctl_RegList.SetItemText(REGLIST_PF, 1, szTemp);
		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0010);
		m_ctl_RegList.SetItemText(REGLIST_AF, 1, szTemp);

		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0040);
		m_ctl_RegList.SetItemText(REGLIST_ZF, 1, szTemp);
		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0080);
		m_ctl_RegList.SetItemText(REGLIST_SF, 1, szTemp);
		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0100);
		m_ctl_RegList.SetItemText(REGLIST_TF, 1, szTemp);

		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0200);
		m_ctl_RegList.SetItemText(REGLIST_IF, 1, szTemp);
		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0400);
		m_ctl_RegList.SetItemText(REGLIST_DF, 1, szTemp);
		sprintf_s(szTemp, "%.1X", (bool)ctThreadContext.EFlags & 0x0800);
		m_ctl_RegList.SetItemText(REGLIST_OF, 1, szTemp);

	}
	BOOL CLeg_DebugDlg::OnGetThreadContext(CONTEXT *pctThreadContext){

		if (GetThreadContext(m_tpInfo.hThread, pctThreadContext)){
			return TRUE;
		}
		else{
			return FALSE;
		}

	}

	void CLeg_DebugDlg::GetDllInfoFromHandle(HANDLE hFile, LPVOID pBase){

		//有DLL加載 DLL獵表要更新
		m_GetModule = TRUE;
		if (hFile == NULL){
			return;
		}

		HANDLE hFileMap;
		char lpszFileName[MAX_PATH + 1] = {};
		hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

		if (hFileMap)
		{
			void *pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
			if (pMem)
			{
				//
				if (GetMappedFileName(GetCurrentProcess(), pMem, lpszFileName, MAX_PATH))
				{
					TCHAR szTemp[MAX_PATH];
					szTemp[0] = '\0';

					if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp))
					{
						TCHAR szName[MAX_PATH];
						TCHAR szDrive[3] = TEXT(" :");
						BOOL bFound = FALSE;
						TCHAR* p = szTemp;

						do
						{
							*szDrive = *p;
							if (QueryDosDevice(szDrive, szName, MAX_PATH))
							{
								size_t uNameLen = _tcslen(szName);

								if (uNameLen < MAX_PATH)
								{
									bFound = _tcsnicmp(lpszFileName, szName, uNameLen) == 0;

									if (bFound && *(lpszFileName + uNameLen) == _T('\\'))
									{
										TCHAR szTempFile[MAX_PATH];
										sprintf_s(szTempFile,

											TEXT("%s%s"),
											szDrive,
											lpszFileName + uNameLen);
										_tcsncpy_s(lpszFileName, szTempFile, MAX_PATH);
									}
								}
							}

							while (*p++);
						} while (!bFound && *p);
					}
					m_ctl_DllList.InsertItem(0, lpszFileName, 0);
				}
			}
		}
	}


	void CLeg_DebugDlg::OnBnClickedButton2()
	{

		this->UpdateData(TRUE);
		char buffer[100] = { 0 };
		m_dwMemoryAddress.GetWindowText(buffer, 200);


		LONGLONG dwAddress = 0;
		//提取U后面的地址
		sscanf(buffer, "%16p", &dwAddress);
		this->ShowMemoryData(dwAddress);
		this->ShowStack();

		// TODO:  在此加入控制項告知處理常式程式碼
	}

	void CLeg_DebugDlg::ShowMemoryData(LONGLONG dwAddress){

		char szTemp[MAX_PATH] = { 0 };
		BYTE lpBuffer[16] = { 0 };
		m_ctl_DataList.DeleteAllItems();
		for (int i = 0; i<100; i++){
			if (OnIsAddressIsValid(dwAddress + i * 8)){
				ZeroMemory(szTemp, MAX_PATH);
				ZeroMemory(lpBuffer, 10);
				sprintf_s(szTemp, "%16p", dwAddress + i * 8);
				m_ctl_DataList.InsertItem(i, szTemp, 0);
				OnReadMemory(dwAddress + i * 8, lpBuffer, 8);
				sprintf_s(szTemp, "%02X %02X %02X %02X %02X %02X %02X %02X ", lpBuffer[0], lpBuffer[1], lpBuffer[2], lpBuffer[3], lpBuffer[4], lpBuffer[5], lpBuffer[6], lpBuffer[7], lpBuffer[8]);
				m_ctl_DataList.SetItemText(i, 1, szTemp);
				m_ctl_DataList.SetItemText(i, 2, (char*)lpBuffer);
			}
			else{
				break;
			}
		}
	}

	BOOL CLeg_DebugDlg::OnIsAddressIsValid(LONGLONG dwAddress){
		MEMORY_BASIC_INFORMATION mbi;
		LONGLONG dwRet = 0;
		dwRet = VirtualQueryEx(m_tpInfo.hProcess, (LPCVOID)dwAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (dwRet = !sizeof(MEMORY_BASIC_INFORMATION)){
			return true;
		}

		if (mbi.State == MEM_COMMIT){
			return true;
		}
		return false;
	}

	void CLeg_DebugDlg::ON_VK_F9()
	{
		SetDlgItemTextA(IDC_STATIC1, "");
		m_IsGo = TRUE;
		SetEvent(hEvent);
		SetDlgItemTextA(IDC_STATIC1, TEXT("運行中"));
		//m_pFatherDlg->SetDlgItemTextA(IDC_STATE,"被調試程序運行成功");
	}

	//處理斷點
	LONGLONG CLeg_DebugDlg::ON_EXCEPTION_BREAKPOINT(LONGLONG dwExpAddress)
	{

		//判斷是否是OEP斷點
		if (m_IsOepBP){
			SetDlgItemTextA(IDC_STATIC1, TEXT("目前停在oep"));
			//恢復斷點
			RecoverBP(m_tpInfo.hProcess, (LONGLONG)m_tpInfo.OepAddress, m_tpInfo.OriginalCode);
			//EIP--
			ReduceEIP();

			ShowRegData();
			ShowAsm((LONGLONG)dwExpAddress);
			//ShowAsm(dwExpAddress); 
			//設置U命令的默認地址
			m_Uaddress = dwExpAddress;

			//設置為FALSE
			m_IsOepBP = FALSE;
			ShowMemoryData(dwExpAddress);
			WaitForSingleObject(hEvent, INFINITE);

			return DBG_CONTINUE;

		}
		
		//如果為其他斷點就直接執行過去就像OD WINDBG一樣
		//判斷是用戶設置的斷點還是被調試程序本來就存在的斷點指令
		if (isUserBP(dwExpAddress))
		{
			SetDlgItemTextA(IDC_STATIC1, TEXT("INT3斷點抵達"));

			RecoverBP(m_tpInfo.hProcess, dwExpAddress, m_Recover_BP.bOrginalCode);
		//EIP--
		ReduceEIP();
		//如果是自動單步模式的INT3
		if (m_IsAutoF8)
		{
		ShowRegData();
		ShowAsm((LONGLONG)dwExpAddress);
		m_Uaddress=dwExpAddress;
		//刪除這兩類斷點 非永久性斷點
		DeleteUserBP(m_tpInfo.hProcess, dwExpAddress);

		ON_VK_F8();

		return DBG_CONTINUE;

		}


		if (m_IsF8 || m_IsGo)
		{
		if(m_IsGo)
		{
		//清空列表框
		m_Result.ResetContent();

		}
		//刪除這兩類斷點 非永久性斷點
		DeleteUserBP(m_tpInfo.hProcess,dwExpAddress);


		ShowRegData();

		ShowAsm(dwExpAddress);
		m_Uaddress=dwExpAddress;

		m_IsF8=FALSE;
		m_IsGo=FALSE;


		WaitForSingleObject(hEvent,INFINITE);
		}


		return DBG_CONTINUE;
		}
		
		//不是用戶斷點 就不處理
		return DBG_EXCEPTION_NOT_HANDLED;

	}


	void CLeg_DebugDlg::RecoverBP(HANDLE hProcess, LONGLONG dwBpAddress, BYTE bOrignalCode)
	{
		DWORD dwOldProtect = 0;
		DWORD dwRet = 0;
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);

		if (!WriteProcessMemory(hProcess, (LPVOID)dwBpAddress, &bOrignalCode, sizeof(bOrignalCode), NULL))
		{
			OutputDebugString("EasyDbgDlg.cpp 1694行出錯");
			DWORD dwErrcode = 0;
			dwErrcode = GetLastError();
			//向用戶輸出錯誤信息
			GetErrorMessage(dwErrcode);
			VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, dwOldProtect, &dwRet);
			return;
		}
	}

	void CLeg_DebugDlg::ReduceEIP()
	{

		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_FULL;
		GetThreadContext(m_tpInfo.hThread, &ct);
		ct.Rip--;
		SetThreadContext(m_tpInfo.hThread, &ct);

	}

	//判斷是否是用戶設置的INT3斷點 通過查詢INT3鏈表 
	BOOL CLeg_DebugDlg::isUserBP(LONGLONG dwBpAddress){
		POSITION pos = NULL;
		//標志是否找到
		BOOL isYes = FALSE;
		pos = m_Int3BpList.GetHeadPosition();
		while (pos != NULL)
		{
			INT3_BP bp = m_Int3BpList.GetNext(pos);
			//判斷該斷點地址是否在地址列表中
			if (bp.dwAddress == dwBpAddress)
			{
				//如果找到,判斷是否是永久斷點 是則需要在但不異常中在設置為斷點
				//在單步異常中重設斷點后在重設m_Recover_BP.isNeedRecover為FALSE
				m_Recover_BP.isNeedRecover = bp.isForever;
				m_Recover_BP.dwAddress = bp.dwAddress;
				m_Recover_BP.bOrginalCode = bp.bOriginalCode;


				isYes = TRUE;

				break;
			}
		}

		return isYes;

	}
	//刪除用戶斷點
	void CLeg_DebugDlg::DeleteUserBP(HANDLE hProcess, LONGLONG dwBpAddress)
	{
		//判斷要刪除斷點地址在不在斷點鏈表中
		POSITION pos = NULL;
		INT3_BP bp = { 0 };
		BOOL isFind = FALSE; 
		pos = m_Int3BpList.GetHeadPosition();
		while (pos != NULL)
		{
			bp = m_Int3BpList.GetNext(pos);
			if (bp.dwAddress == dwBpAddress)
			{
				//考慮到有同一地址下兩個斷點 即臨時斷點和永久斷點如G命令全部用continue
				if (bp.isForever)
				{
					isFind = TRUE;
					//恢復為原來的字節
					RecoverBP(hProcess, dwBpAddress, bp.bOriginalCode);


					if (m_isDelete)
					{

						if (m_Int3BpList.GetCount() == 1)
						{
							m_Int3BpList.RemoveHead();
							m_isDelete = FALSE;
							SetDlgItemText(IDC_STATIC1, "斷點刪除成功");
							return;
						}

						if (pos == NULL)
						{
							m_Int3BpList.RemoveTail();
							m_isDelete = FALSE;
							SetDlgItemText(IDC_STATIC1, "斷點刪除成功");
							return;


						}

						m_Int3BpList.GetPrev(pos);

						m_Int3BpList.RemoveAt(pos);
						SetDlgItemText(IDC_STATIC1, "斷點刪除成功");
					}
					m_isDelete = FALSE;

					continue;;
				}
				else
				{
					//在這里刪除非永久斷點

					if (m_Int3BpList.GetCount() == 1)
					{
						m_Int3BpList.RemoveHead();
						m_isDelete = FALSE;
						SetDlgItemText(IDC_STATIC1, "斷點刪除成功");
						return;
					}

					if (pos == NULL)
					{
						m_Int3BpList.RemoveTail();
						m_isDelete = FALSE;
						SetDlgItemText(IDC_STATIC1, "斷點刪除成功");
						return;


					}

					m_Int3BpList.GetPrev(pos);

					m_Int3BpList.RemoveAt(pos);
					SetDlgItemText(IDC_STATIC1, "斷點刪除成功");

					continue;
				}
				//找到

			}
		}
		//如果沒有在斷點鏈表中找到此地址
		if (!isFind)
		{
			AfxMessageBox("要刪除的斷點是無效斷點");
			return;

		}





	}


	void CLeg_DebugDlg::OnBnClickedButton3()
	{
		ON_VK_F8();
		// TODO:  在此加入控制項告知處理常式程式碼
	}

	//F8鍵的處理函數 單步步過
	void CLeg_DebugDlg::ON_VK_F8()
	{

		SetDlgItemText(IDC_STATIC1, "");
		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(m_tpInfo.hThread, &ct))
		{
			OutputDebugString("EasyDbgDlg.cpp 1178行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			GetErrorMessage(dwErrorCode);
			return;
		}
		BYTE szCodeBuffer[40] = { 0 };

		DWORD dwOldProtect = 0;
		DWORD dwRet = 0;

		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)ct.Rip, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		//獲得當前EIP處的指令
		if (!ReadProcessMemory(m_tpInfo.hProcess, (LPCVOID)ct.Rip, szCodeBuffer, sizeof(szCodeBuffer), NULL))
		{
			OutputDebugString("EasyDbgDlg.cpp 1193行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			GetErrorMessage(dwErrorCode);
			VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)ct.Rip, 4, dwOldProtect, &dwRet);
			return;
		}
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)ct.Rip, 4, dwOldProtect, &dwRet);

		char szAsm[120] = { 0 };
		char szOpCode[120] = { 0 };
		UINT CodeSize = 0;
		//反匯編并判斷當前指令是不是call指令
		Decode2AsmOpcode(szCodeBuffer, (char*)szAsm, szOpCode,(UINT*)&CodeSize, ct.Rip);
		if (szAsm[0] == 'c' && szAsm[1] == 'a' && szAsm[2] == 'l' && szAsm[3] == 'l')
		{
			//如果當前指令是call指令,那么就在下一條指令上下臨時斷點

			//判斷如果下一條指令已經有斷點了,則不需要在下
			POSITION pos = NULL;
			pos = m_Int3BpList.GetHeadPosition();
			INT3_BP bp = { 0 };

			while (pos != NULL)
			{
				bp = m_Int3BpList.GetNext(pos);
				//如果找到斷點則 不需要在下斷點
				if (bp.dwAddress == ct.Rip + CodeSize)
				{
					//設置標志位
					m_IsF8 = TRUE;

					SetEvent(hEvent);
					return;

				}

			}
			//非永久斷點
			bp.dwAddress = ct.Rip + CodeSize;
			bp.isForever = FALSE;

			VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)bp.dwAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			if (!ReadProcessMemory(m_tpInfo.hProcess, (LPCVOID)bp.dwAddress, &bp.bOriginalCode, sizeof(BYTE), NULL))
			{
				OutputDebugString("EasyDbgDlg.cpp 1239行出錯");
				DWORD dwErrorCode = 0;
				dwErrorCode = GetLastError();
				GetErrorMessage(dwErrorCode);
				VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)bp.dwAddress, 4, dwOldProtect, &dwRet);
				return;
			}
			if (!WriteProcessMemory(m_tpInfo.hProcess, (LPVOID)bp.dwAddress, &m_tpInfo.bCC, sizeof(BYTE), NULL))
			{
				OutputDebugString("EasyDbgDlg.cpp 1248行出錯");
				DWORD dwErrorCode = 0;
				dwErrorCode = GetLastError();
				GetErrorMessage(dwErrorCode);
				VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)bp.dwAddress, 4, dwOldProtect, &dwRet);
				return;
			}
			VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)bp.dwAddress, 4, dwOldProtect, &dwRet);
			FlushInstructionCache(m_tpInfo.hProcess, (LPCVOID)bp.dwAddress, sizeof(BYTE));
			//把斷點加入鏈表
			m_Int3BpList.AddTail(bp);
			//設置標志位
			m_IsF8 = TRUE;


			SetEvent(hEvent);

		}
		else
		{
			//如果當前指令不是CALL指令,那么就置單步
			ON_VK_F7();
		}


	}


	//F7鍵的處理函數 單步步入
	void CLeg_DebugDlg::ON_VK_F7()
	{
		//置單步
		SetDlgItemText(IDC_STATIC1, "");
		CONTEXT ct;
		ct.ContextFlags = CONTEXT_FULL;
		GetThreadContext(m_tpInfo.hThread, &ct);
		ct.EFlags |= 0x100;
		SetThreadContext(m_tpInfo.hThread, &ct);

		SetEvent(hEvent);
	}

	//vu顯示ASM
	void CLeg_DebugDlg::ShowAsm(LONGLONG dwStartAddress)
	{

		ShowAsmInWindow(dwStartAddress);

		//顯示堆棧 默認自動單步模式下不顯示堆棧以增加速度
		if (!m_IsAutoF7 && !m_IsAutoF8)
		{
			ShowStack();
		}

		BYTE pCode[40] = { 0 };

		DWORD dwOldProtect = 0;
		DWORD dwRet = 0;
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwStartAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		if (!ReadProcessMemory(m_tpInfo.hProcess, (LPCVOID)dwStartAddress, pCode, sizeof(pCode), NULL))
		{
			OutputDebugString("EasyDbgDlg.cpp 594行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			//向用戶輸出錯誤信息
			GetErrorMessage(dwErrorCode);
			VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwStartAddress, 4, dwOldProtect, &dwRet);
			return;
		}
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwStartAddress, 4, dwOldProtect, &dwRet);
		//判斷是否有斷點命中在斷點鏈表中 若命中則就在緩沖區中恢復 
		for (int i = 0; i<16; i++)
		{

			POSITION pos = NULL;
			pos = m_Int3BpList.GetHeadPosition();
			while (pos != NULL)
			{
				INT3_BP bp = m_Int3BpList.GetNext(pos);
				//判斷斷點地址是否命名在這段緩沖區中
				//還原永久斷點的東西

				if (bp.dwAddress == dwStartAddress + i)
				{
					//如果命中 則說明此為用戶斷點則把原字節還原
					pCode[i] = bp.bOriginalCode;
				}



			}


		}

		char szAsm[120] = { 0 };
		char szOpCode[120] = { 0 };
		UINT CodeSize = 0;

		Decode2AsmOpcode(pCode, szAsm, szOpCode, &CodeSize, dwStartAddress);
		EXPORT_FUN_INFO expFun = { 0 };
		//如果找到改變顯示方式
		if (IsExportFun(szAsm, expFun))
		{
			//顯示在列表框控件內
			/*char szResult[200] = { 0 };
			sprintf(szResult, "%16p    %s        %s <%s.%s>", dwStartAddress, szOpCode, szAsm, expFun.szDLLName, expFun.szFunName);
			m_Result.AddString(szResult);

			m_Result.SetTopIndex(m_Result.GetCount() - 1);*/


			//如果在自動F8模式
			if (m_IsAutoF8)
			{
				OPCODE_RECORD op = { 0 };
				//如果該指令在映射表中已存在 就不再寫文件 (判斷地址)
				if (m_Opcode.Lookup(dwStartAddress, op))
				{
					return;
				}
				//如果沒有就加入映射表并寫文件
				op.dwAddress = dwStartAddress;
				m_Opcode.SetAt(dwStartAddress, op);
				//此時也要改變顯示方式
				char szNowShow[100] = { 0 };
				sprintf(szNowShow, "%s <%s.%s>", szAsm, expFun.szDLLName, expFun.szFunName);
				WriteOpcodeToFile(dwStartAddress, szNowShow);
			}

			return;
		}
		//顯示在列表框控件內
		/*char szResult[200] = { 0 };
		sprintf(szResult, "%16p    %s        %s", dwStartAddress, szOpCode, szAsm);
		m_Result.AddString(szResult);

		m_Result.SetTopIndex(m_Result.GetCount() - 1);*/

		//如果在自動F8模式
		if (m_IsAutoF8)
		{
			OPCODE_RECORD op = { 0 };
			//如果該指令在映射表中已存在 就不再寫文件 (判斷地址)
			if (m_Opcode.Lookup(dwStartAddress, op))
			{
				return;
			}
			//如果沒有就加入映射表并寫文件
			op.dwAddress = dwStartAddress;
			m_Opcode.SetAt(dwStartAddress, op);
			WriteOpcodeToFile(dwStartAddress, szAsm);

		}




	}


	//在反匯編窗口顯示匯編代碼  參數 要高亮的指令地址
	void CLeg_DebugDlg::ShowAsmInWindow(LONGLONG dwStartAddress)
	{
		//設置標題
		SetDebuggerTitle(dwStartAddress);

		//判斷該地址是否在當前顯示的指令地址數組中
		LONGLONG dwRet = 0;
		dwRet = IsFindAsmAddress(dwStartAddress);
		if (dwRet != -1)
		{

			m_AsmList.SetItemState(dwRet, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
			return;

		}
		//如果不在數組就重新讀
		m_AsmList.DeleteAllItems();
		CString szText;
		for (int k = 0; k<20; k++)
		{
			BYTE pCode[40] = { 0 };

			DWORD dwOldProtect = 0;
			DWORD dwRet = 0;
			VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwStartAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			if (!ReadProcessMemory(m_tpInfo.hProcess, (LPCVOID)dwStartAddress, pCode, sizeof(pCode), NULL))
			{
				OutputDebugString("EasyDbgDlg.cpp 4296行出錯");
				DWORD dwErrorCode = 0;
				dwErrorCode = GetLastError();
				//向用戶輸出錯誤信息
				GetErrorMessage(dwErrorCode);
				VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwStartAddress, 4, dwOldProtect, &dwRet);
				return;
			}
			VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwStartAddress, 4, dwOldProtect, &dwRet);

			for (int i = 0; i<16; i++)
			{

				POSITION pos = NULL;
				pos = m_Int3BpList.GetHeadPosition();
				while (pos != NULL)
				{
					INT3_BP bp = m_Int3BpList.GetNext(pos);
					//判斷斷點地址是否命名在這段緩沖區中
					if (bp.dwAddress == dwStartAddress + i)
					{
						//如果命中 則說明此為用戶斷點則把原字節還原
						pCode[i] = bp.bOriginalCode;
					}
				}


			}

			char szAsm[120] = { 0 };
			char szOpCode[120] = { 0 };
			UINT CodeSize = 0;
			Decode2AsmOpcode(pCode, szAsm, szOpCode, &CodeSize, dwStartAddress);
			EXPORT_FUN_INFO expFun = { 0 };
			//如果找到改變顯示方式
			if (IsExportFun(szAsm, expFun))
			{
				//顯示在列表框控件內
				szText.Format("%16p", dwStartAddress);
				m_AsmList.InsertItem(k, szText);
				m_AsmList.SetItemText(k, 1, szOpCode);
				szText.Format("%s <%s.%s>", szAsm, expFun.szDLLName, expFun.szFunName);
				m_AsmList.SetItemText(k, 2, szText);

				m_AsmAddress[k] = dwStartAddress;
				dwStartAddress = CodeSize + dwStartAddress;
				continue;
			}
			//顯示在列表框控件內
			szText.Format("%16p", dwStartAddress);
			m_AsmList.InsertItem(k, szText);
			m_AsmList.SetItemText(k, 1, szOpCode);
			m_AsmList.SetItemText(k, 2, szAsm);

			m_AsmAddress[k] = dwStartAddress;
			dwStartAddress = CodeSize + dwStartAddress;

		}


		m_AsmList.SetItemState(0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);







	}


	//設置調試器標題(在調試什么程序,以及當前指令在哪個模塊)
	//參數為當前指令地址
	void CLeg_DebugDlg::SetDebuggerTitle(LONGLONG dwAddress)
	{

		//如果模塊需要更新  只要有DLL加載就需要更新
		if (m_GetModule)
		{

			if (!GetCurrentModuleList(m_tpInfo.hProcess))
			{
				return;

			}

		}

		//判斷當前地址在哪個模塊

		POSITION pos = NULL;
		pos = m_Module.GetHeadPosition();
		CString szText;
		while (pos != NULL)
		{
			MODULE_INFO mem = { 0 };
			mem = m_Module.GetNext(pos);
			if (dwAddress >= mem.dwBaseAddress && dwAddress <= (mem.dwSize + mem.dwBaseAddress))
			{

				MODULE_INFO mFirst = { 0 };
				mFirst = m_Module.GetHead();
				//設置標題
				szText.Format("Leg_Dbg -%s- [CPU - 主線程,模組 - %s]", mFirst.szModuleName, mem.szModuleName);
				SetWindowText(szText);
				break;

			}


		}



	}
	//獲得當前加載模塊信息
	BOOL CLeg_DebugDlg::GetCurrentModuleList(HANDLE hProcess)
	{
		if (hProcess == NULL)
		{
			return FALSE;
		}
		//刪除所有元素
		m_Module.RemoveAll();


		HMODULE  hModule[500];
		//接收返回的字節數
		DWORD nRetrun = 0;
		//枚舉
		BOOL isSuccess = EnumProcessModules(hProcess, hModule, sizeof(hModule), &nRetrun);
		if (isSuccess == 0)
		{
			OutputDebugString(TEXT("EasyDbgDlg.cpp 4538行出錯"));
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			//輸出錯誤信息
			GetErrorMessage(dwErrorCode);

			return FALSE;

		}

		TCHAR ModuleName[500];
		//模塊信息結構體
		MODULEINFO minfo;
		//開始添加
		for (DWORD i = 0; i<(nRetrun / sizeof(HMODULE)); i++)
		{
			MODULE_INFO mem = { 0 };
			//獲取模塊名
			DWORD nLength = GetModuleBaseName(hProcess, hModule[i], ModuleName, sizeof(ModuleName));
			if (nLength == 0)
			{
				OutputDebugString(TEXT("EasyDbgDlg.cpp 4559行出錯"));
				DWORD dwErrorCode = 0;
				dwErrorCode = GetLastError();
				//輸出錯誤信息
				GetErrorMessage(dwErrorCode);

				return FALSE;
			}

			strncpy(mem.szModuleName, ModuleName, strlen(ModuleName) + 1);
			//格式化模塊基址
			mem.dwBaseAddress = (LONGLONG)hModule[i];
			//獲取模塊信息
			nLength = GetModuleInformation(g_hProcess, hModule[i], &minfo, sizeof(minfo));
			if (nLength == 0)
			{
				OutputDebugString(TEXT("EasyDbgDlg.cpp 4575行出錯"));
				DWORD dwErrorCode = 0;
				dwErrorCode = GetLastError();
				//輸出錯誤信息
				GetErrorMessage(dwErrorCode);

				return FALSE;

			}

			mem.dwSize = minfo.SizeOfImage;
			//添加到鏈表
			m_Module.AddTail(mem);


		}
		//把標志設為FALSE
		m_GetModule = FALSE;
		return TRUE;


	}

	//根據要顯示的指令地址 判斷當前IsExportFun指令地址數組中是否有 若有就返回其下標 否則返回-1
	LONGLONG CLeg_DebugDlg::IsFindAsmAddress(LONGLONG dwStartAddress)
	{
		for (DWORD i = 0; i<25; i++)
		{
			if (dwStartAddress == m_AsmAddress[i])
			{
				return i;
			}
		}
		return -1;
	}

	//判斷解析指令中的函數調用
	BOOL CLeg_DebugDlg::IsExportFun(char* szBuffer, EXPORT_FUN_INFO& expFun)
	{
		if (szBuffer == NULL)
		{
			return FALSE;
		}
		//指令長度
		int nLength = 0;
		nLength = strlen(szBuffer);
		char szCall[5] = { 0 };
		char szJmp[4] = { 0 };
		//看是不是CALL JMP之類的 //對CALL 寄存器要處理
		//對 call [00400000] call dword ptr[00400000]  jmp [00400000]進行解析 注意一定要有[]否則是在調用自身函數
		memcpy(szCall, szBuffer, 4);
		memcpy(szJmp, szBuffer, 3);


		//暫時不處理CALL reg的情況
		if (szBuffer[5] == 'e')
		{
			return FALSE;
		}



		if (strcmp(szCall, "call") == 0 || strcmp(szJmp, "jmp") == 0)
		{
			//如果直接是[]則直接解析
			if (nLength != 0 && szBuffer[nLength - 1] == ']')
			{
				//找到[]內的地址值 并解析函數名
				char Address[20] = { 0 };
				for (int i = 0; i<16; i++)
				{
					Address[i] = szBuffer[nLength - 16 + i ];

				}
				LONGLONG dwAddress = 0;

				sscanf(Address, "%16p", &dwAddress);
				//讀取地址值處的內容
				LONGLONG dwActualAddress = 0;
				//修改保護屬性 
				DWORD dwOldProtect = 0;
				DWORD dwRet = 0;
				VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 8, PAGE_READONLY, &dwOldProtect);
				if (!ReadProcessMemory(m_tpInfo.hProcess, (LPVOID)dwAddress, &dwActualAddress, sizeof(LONGLONG), NULL))
				{
					OutputDebugString("EasyDbgDlg.cpp 3669行出錯");
					DWORD dwErrorCode = 0;
					dwErrorCode = GetLastError();


					VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
					return FALSE;
				}


				VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
				//查詢有沒有符合的函數地址
				if (m_ExFunList.Lookup(dwActualAddress, expFun))
				{
					return TRUE;
				}



			}


			//如果不是[]就看其下一條是不是[]
			else if (nLength != 0 && szBuffer[nLength - 1] != ']')
			{
				//不解析多級跳了 直解析到兩級

				//找到地址值 反匯編下一條指令
				char Address[20] = { 0 };


				if (szBuffer[2] == 'p'){
					for (int j = 0; j<14; j++)
					{

						Address[j] = szBuffer[nLength - 16 + j + 1];
					}
				}
				/*else if ((szBuffer[0] = 'c')&&(szBuffer[4] = ' ')){
					for (int j = 0; j<8; j++)
					{
						Address[j] = szBuffer[nLength - 9 + j];
					}
				}*/
				else{
					for (int j = 0; j<14; j++)
					{
						Address[j] = szBuffer[nLength - 16 + j + 1];
					}
				}
				

				LONGLONG dwAddress = 0;
				//error
				sscanf(Address, "%16p", &dwAddress);
				//讀取地址值處的內容
				DWORD dwActualAddress = 0;
				//修改保護屬性 
				DWORD dwOldProtect = 0;
				DWORD dwRet = 0;
				//這里就不判斷了判斷Read是一樣的效果
				VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
				BYTE pCode[40] = { 0 };
				if (!ReadProcessMemory(m_tpInfo.hProcess, (LPVOID)dwAddress, &pCode, sizeof(pCode), NULL))
				{
					OutputDebugString("EasyDbgDlg.cpp 3717行出錯");
					DWORD dwErrorCode = 0;
					dwErrorCode = GetLastError();

					//GetErrorMessage(dwErrorCode);
					return FALSE;
				}

				VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);


				for (int i = 0; i<16; i++)
				{

					POSITION pos = NULL;
					pos = m_Int3BpList.GetHeadPosition();
					while (pos != NULL)
					{
						INT3_BP bp = m_Int3BpList.GetNext(pos);
						//判斷斷點地址是否命名在這段緩沖區中
						if (bp.dwAddress == dwAddress + i)
						{
							//如果命中 則說明此為用戶斷點則把原字節還原
							pCode[i] = bp.bOriginalCode;
						}
					}
				}

				char szAsm[120] = { 0 };
				char szOpCode[120] = { 0 };
				UINT CodeSize = 0;
				Decode2AsmOpcode(pCode, szAsm, szOpCode, &CodeSize, dwAddress);
				//判斷本條指令

				//指令長度
				int nLength = 0;
				nLength = strlen(szAsm);
				char szCall[5] = { 0 };
				char szJmp[4] = { 0 };
				//看是不是CALL JMP之類的
				//對 call [00400000] call dword ptr[00400000]  jmp [00400000]進行解析 注意一定要有[]否則是在調用自身函數
				memcpy(szCall, szBuffer, 4);
				memcpy(szJmp, szBuffer, 3);
				if (strcmp(szCall, "call") == 0 || strcmp(szJmp, "jmp") == 0)
				{
					//如果直接是[]則直接解析
					if (nLength != 0 && szAsm[nLength - 1] == ']')
					{
						//找到[]內的地址值 并解析函數名
						char Address[20] = { 0 };
						//問題點

						for (int i = 0; i<16; i++)
						{
							Address[i] = szAsm[nLength - 18 + i];

						}

						LONGLONG dwAddress = 0;

						sscanf(Address, "%16p", &dwAddress);
						//讀取地址值處的內容
						DWORD dwActualAddress = 0;
						//修改保護屬性 
						DWORD dwOldProtect = 0;
						DWORD dwRet = 0;
						VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 8, PAGE_READONLY, &dwOldProtect);
						if (!ReadProcessMemory(m_tpInfo.hProcess, (LPVOID)dwAddress, &dwActualAddress, sizeof(DWORD), NULL))
						{
							OutputDebugString("EasyDbgDlg.cpp 3783行出錯");
							DWORD dwErrorCode = 0;
							dwErrorCode = GetLastError();
							// GetErrorMessage(dwErrorCode);

							VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
							return FALSE;
						}


						VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
						//查詢有沒有符合的函數地址
						


					}
				}

			}
		}
		return FALSE;

	}


	//顯示堆棧
	void CLeg_DebugDlg::ShowStack()
	{
		m_Stack.DeleteAllItems();
		BYTE lpBuffer[16] = { 0 };
		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(m_tpInfo.hThread, &ct) == 0)
		{
			return;
		}
		CString szText;
		for (int i = 0; i<50; i++){
			ZeroMemory(lpBuffer, 16);
			szText.Format("0x%16p", ct.Rsp + i * 8);
			m_Stack.InsertItem(i, szText);
			OnReadMemory(ct.Rsp + i * 8, lpBuffer, 8);
			szText.Format("%02X%02X%02X%02X%02X%02X%02X%02X", lpBuffer[7], lpBuffer[6], lpBuffer[5], lpBuffer[4], lpBuffer[3], lpBuffer[2], lpBuffer[1], lpBuffer[0] );
			m_Stack.SetItemText(i, 1, szText);


		}


	}




	//把記錄寫入文件  參數 指令地址 指令緩沖 不顯示機器碼 了,
	//顯示了在文本文件中不好對齊 
	void CLeg_DebugDlg::WriteOpcodeToFile(LONGLONG dwAddress, char* szAsm)
	{
		if (m_hFile == INVALID_HANDLE_VALUE || szAsm == NULL || dwAddress == 0)
		{
			return;
		}

		DWORD dwLength = 0;
		dwLength = strlen(szAsm);
		//回車換行
		szAsm[dwLength] = '\r';
		szAsm[dwLength + 1] = '\n';
		char szBuffer[16] = { 0 };

		sprintf(szBuffer, "%08X", dwAddress);

		WriteFile(m_hFile, (LPVOID)szBuffer, sizeof(szBuffer), &dwLength, NULL);

		WriteFile(m_hFile, (LPVOID)szAsm, strlen(szAsm), &dwLength, NULL);






	}


	void CLeg_DebugDlg::OnBnClickedButton4()
	{
		ON_VK_F7();
		// TODO:  在此加入控制項告知處理常式程式碼
	}

	//單步異常處理函數  參數異常地址
	LONGLONG CLeg_DebugDlg::ON_EXCEPTION_SINGLE_STEP(LONGLONG dwExpAddress)
	{


		//是否是自動步過模式
		if (m_IsAutoF8)
		{
			//置單步

			ShowAsm(dwExpAddress);
			ShowRegData();
			ON_VK_F8();


			return DBG_CONTINUE;

		}
		//是否為自動步入模式
		if (m_IsAutoF7)
		{
			ShowAsm(dwExpAddress);
			ShowRegData();
			ON_VK_F7();

			return DBG_CONTINUE;

		}
		//先判斷有沒有要重新恢復的INT3斷點
		if (m_Recover_BP.isNeedRecover)
		{

			DebugSetBp(m_tpInfo.hProcess, m_Recover_BP.dwAddress, m_tpInfo.bCC);

			//重新置為FALSE
			m_Recover_BP.isNeedRecover = FALSE;
		}
		//如果有硬件斷點要恢復
		if (m_Recover_HBP.dwIndex != -1)
		{
			//恢復硬件斷點
			RecoverHBP(m_Recover_HBP.dwIndex);


			m_Recover_HBP.dwIndex = -1;
		}
		//如果有內存斷點要恢復
		if (m_Recover_Mpage.isNeedRecover)
		{
			DWORD dwOldProtect = 0;
			if (!VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)m_Recover_Mpage.dwBaseAddress, 4,
				m_Recover_Mpage.dwProtect, &dwOldProtect)
				)
			{

				OutputDebugString("EasyDbgDlg.cpp 1595行出錯");
				DWORD dwErrorCode = 0;

				dwErrorCode = GetLastError();
				//輸出錯誤信息
				GetErrorMessage(dwErrorCode);
			}
			//重新置為FALSE
			m_Recover_Mpage.isNeedRecover = FALSE;
		}


		//判斷單步異常是不是因為硬件斷點 即DR6的低四位有沒有置位
		LONGLONG dwBpAddress = 0;
		if (IfStepHard(dwBpAddress))
		{
			SetDlgItemText(IDC_STATIC1, TEXT("硬件斷點到達"));
			//讓硬件斷點無效
			InvalidHardBP(dwBpAddress);

		}
		//如果是因為一個G模式的內存斷點就不要等待同步事件
		if (m_isMoreMem)
		{

			if (m_IsF8)
			{
				m_IsGo = FALSE;
				m_isMoreMem = FALSE;
				//ShowAsm(dwExpAddress);
				// ShowReg(m_tpInfo.hThread);
				//設置U命令的起始地址
				m_Uaddress = dwExpAddress;

				//WaitForSingleObject(hEvent,INFINITE);
				//m_IsF8=FALSE;
				return DBG_CONTINUE;


			}
			//多次G到達多個N內存斷點直接運行到斷點
			if (m_IsGo)
			{
				m_isMoreMem = FALSE;

				return DBG_CONTINUE;


			}

			m_isMoreMem = FALSE;
			ShowAsm(dwExpAddress);
			ShowRegData();

			m_Uaddress = dwExpAddress;

			WaitForSingleObject(hEvent, INFINITE);

			return DBG_CONTINUE;


		}


		ShowAsm(dwExpAddress);
		ShowRegData();
		//設置U命令的起始地址
		m_Uaddress = dwExpAddress;

		WaitForSingleObject(hEvent, INFINITE);

		return DBG_CONTINUE;
	}


	//設置斷點  斷點地址 0xCC 用于永久斷點重新恢復為斷點
	void CLeg_DebugDlg::DebugSetBp(HANDLE hProcess, LONGLONG dwBpAddress, BYTE bCCode)
	{
		DWORD dwOldProtect = 0;
		DWORD dwRet = 0;
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		if (!WriteProcessMemory(hProcess, (LPVOID)dwBpAddress, &bCCode, sizeof(bCCode), NULL))
		{
			OutputDebugString("EasyDbgDlg.cpp 1724行出錯");
			DWORD dwErrcode = 0;
			dwErrcode = GetLastError();
			//向用戶輸出錯誤信息
			GetErrorMessage(dwErrcode);
			VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, dwOldProtect, &dwRet);
			return;
		}

		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, dwOldProtect, &dwRet);
		//刷新
		FlushInstructionCache(hProcess, (LPCVOID)dwBpAddress, sizeof(BYTE));

	}

	//恢復硬件斷點 參數為 調試寄存器的編號
	void CLeg_DebugDlg::RecoverHBP(DWORD dwIndex)
	{
		//傳入參數的判斷
		if (dwIndex == -1)
		{
			AfxMessageBox("恢復硬件斷點出錯");
			return;
		}

		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(m_tpInfo.hThread, &ct))
		{
			OutputDebugString("EasyDbgDlg.cpp 2857行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			//輸出錯誤信息
			GetErrorMessage(dwErrorCode);
			return;
		}

		DR7 tagDr7 = { 0 };
		tagDr7.dwDr7 = ct.Dr7;

		switch (dwIndex)
		{

		case 0:
			//設置L位
			tagDr7.DRFlag.L0 = 1;
			m_Recover_HBP.dwIndex = -1;
			break;
		case 1:
			tagDr7.DRFlag.L1 = 1;
			m_Recover_HBP.dwIndex = -1;
			break;
		case 2:
			tagDr7.DRFlag.L2 = 1;
			m_Recover_HBP.dwIndex = -1;
			break;
		case 3:
			tagDr7.DRFlag.L3 = 1;
			m_Recover_HBP.dwIndex = -1;
			break;

		}
		//寫 回CONTEXT
		ct.Dr7 = tagDr7.dwDr7;

		if (!SetThreadContext(m_tpInfo.hThread, &ct))
		{
			OutputDebugString("EasyDbgDlg.cpp 2895行出錯");

			DWORD dwErrorCode = 0;

			dwErrorCode = GetLastError();
			//輸出錯誤信息
			GetErrorMessage(dwErrorCode);
			return;
		}





	}

	//判斷單步異常是否是硬件斷點引起的 傳出參數 斷點地址
	BOOL CLeg_DebugDlg::IfStepHard(LONGLONG& dwBPAddress)
	{

		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(m_tpInfo.hThread, &ct))
		{
			OutputDebugString("EasyDbgDlg.cpp 2705行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			//輸出錯誤信息
			GetErrorMessage(dwErrorCode);
			return FALSE;
		}
		//判斷Dr6的低4位是否為0
		int nIndex = ct.Dr6 & 0xf;
		if (nIndex == 0)
		{
			return FALSE;
		}

		switch (nIndex)
		{
		case 0x1:
			//保存找到的斷點地址
			dwBPAddress = ct.Dr0;
			break;
		case 0x2:
			dwBPAddress = ct.Dr1;
			break;
		case 0x4:
			dwBPAddress = ct.Dr2;
			break;
		case 0x8:
			dwBPAddress = ct.Dr3;
			break;
		}
		return TRUE;


	}

	//使硬件斷點暫時無效
	void CLeg_DebugDlg::InvalidHardBP(LONGLONG dwBpAddress)
	{
		//傳入參數的判斷
		if (dwBpAddress == 0)
		{
			AfxMessageBox("斷點為0無效值");
			return;
		}

		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(m_tpInfo.hThread, &ct))
		{
			OutputDebugString("EasyDbgDlg.cpp 2754行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			//輸出錯誤信息
			GetErrorMessage(dwErrorCode);
			return;
		}
		//判斷中斷地址在那個調試寄存器中
		DR7 tagDr7 = { 0 };
		tagDr7.dwDr7 = ct.Dr7;
		//     DWORD dwDr0=ct.Dr0;
		//     DWORD dwDr1=ct.Dr1;
		//     DWORD dwDr2=ct.Dr2;
		//     DWORD dwDr3=ct.Dr3;
		//     switch (dwBpAddress)
		//     {
		// 
		//     case dwDr0:
		//         //清L位讓斷點無效 不清地址了,免得還得保存地址
		//         tagDr7.DRFlag.L0=0;
		//         //設置要恢復的調試寄存器編號
		//         m_Recover_HBP.dwIndex=0;
		// 
		//         break;
		//     case dwDr1:
		//         tagDr7.DRFlag.L1=0;
		//         m_Recover_HBP.dwIndex=1;
		// 
		//         break;
		//     case dwDr2:
		//         tagDr7.DRFlag.L2=0;
		//         m_Recover_HBP.dwIndex=2;
		// 
		//         break;
		//     case dwDr3:
		//         tagDr7.DRFlag.L3=0;
		//         m_Recover_HBP.dwIndex=3;
		//         break;
		// 
		//     }
		if (ct.Dr0 == dwBpAddress)
		{
			//清L位讓斷點無效 不清地址了,免得還得保存地址
			tagDr7.DRFlag.L0 = 0;
			//設置要恢復的調試寄存器編號
			m_Recover_HBP.dwIndex = 0;

		}

		if (ct.Dr1 == dwBpAddress)
		{
			tagDr7.DRFlag.L1 = 0;
			m_Recover_HBP.dwIndex = 1;

		}

		if (ct.Dr2 == dwBpAddress)
		{
			tagDr7.DRFlag.L2 = 0;
			m_Recover_HBP.dwIndex = 2;

		}

		if (ct.Dr3 == dwBpAddress)
		{
			tagDr7.DRFlag.L3 = 0;
			m_Recover_HBP.dwIndex = 3;
		}

		//賦值回去
		ct.Dr7 = tagDr7.dwDr7;
		//設置線程上下文
		if (!SetThreadContext(m_tpInfo.hThread, &ct))
		{
			OutputDebugString("EasyDbgDlg.cpp 2828行出錯");

			DWORD dwErrorCode = 0;

			dwErrorCode = GetLastError();
			//輸出錯誤信息
			GetErrorMessage(dwErrorCode);
			return;
		}


	}

	//截獲消息
BOOL CLeg_DebugDlg::PreTranslateMessage(MSG* pMsg)
	{
		// TODO: Add your specialized code here and/or call the base class

		//處理 手工輸入命令的消息
		if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_RETURN)
		{

			if (m_command.GetFocus()->GetDlgCtrlID() == IDC_EDIT2)
			{

				char buffer[100] = { 0 };
				m_command.GetWindowText(buffer, 200);

				//處理命令
				Handle_User_Command(buffer);


			}


		}
		if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_RETURN){
			if (m_asm_adr.GetFocus()->GetDlgCtrlID() == IDC_EDIT3)
			{

				char buffer[100] = { 0 };
				m_asm_adr.GetWindowText(buffer, 200);


				LONGLONG dwAddress = 0;
				//提取U后面的地址
				sscanf(buffer, "%16p", &dwAddress);

				ShowAsm(dwAddress);


			}
		}

		if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_RETURN){
			if (m_dwMemoryAddress.GetFocus()->GetDlgCtrlID() == IDC_EDIT1)
			{

				char buffer[100] = { 0 };
				m_dwMemoryAddress.GetWindowText(buffer, 200);


				LONGLONG dwAddress = 0;
				//提取U后面的地址
				sscanf(buffer, "%16p", &dwAddress);

				ShowMemoryData(dwAddress);


			}
		}

		//處理F7快捷鍵
		if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_F7)
		{

			ON_VK_F7();
		}
		//處理F8快捷鍵
		if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_F8)
		{
			ON_VK_F8();
		}
		//處理F9快捷鍵
		if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_F9)
		{
			OnRun();
		}
		//處理F6快捷鍵  自動步過
		if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_F6)
		{
			OnAutostepout();
		}
		//處理F5快捷鍵 自動步入
		if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_F5)
		{
			OnAutostepinto();
		}

		return CDialog::PreTranslateMessage(pMsg);



	}
	
//自動步入
void CLeg_DebugDlg::OnAutostepinto()
{
	DeleteAllBreakPoint();
	m_IsAutoF7 = TRUE;
	ON_VK_F7();
	// TODO: Add your command handler code here

}


void CLeg_DebugDlg::OnAutostepout()
{
	// TODO: Add your command handler code here
	m_hFile = INVALID_HANDLE_VALUE;

	char            szFileName[MAX_PATH] = "Record";
	OPENFILENAME    ofn = { 0 };
	char            CodeBuf[24] = { 0 };
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFile = szFileName;
	ofn.lpstrDefExt = "txt";
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = "填入要保存的指令記錄文件名(*.txt)\0*.txt\0";
	ofn.nFilterIndex = 1;
	if (GetSaveFileName(&ofn) == FALSE)
	{
		return;
	}
	//創建文件
	m_hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//自動單步 刪除所有斷點
	DeleteAllBreakPoint();
	m_IsAutoF8 = TRUE;
	ON_VK_F8();


}

//刪除所有斷點 用于記錄指令
void CLeg_DebugDlg::DeleteAllBreakPoint()
{


	POSITION pos = NULL;

	//刪除所有的內存斷點
	pos = m_MemBpList.GetHeadPosition();
	MEM_BP memBP = { 0 };
	while (pos != NULL)
	{
		memBP = m_MemBpList.GetNext(pos);
		DeleteMemBP(memBP.dwBpAddress);


	}
	//刪除所有的INT3斷點
	INT3_BP bp = { 0 };
	pos = NULL;
	pos = m_Int3BpList.GetHeadPosition();
	while (pos != NULL)
	{
		bp = m_Int3BpList.GetNext(pos);
		//恢復為原來的字節
		RecoverBP(m_tpInfo.hProcess, bp.dwAddress, bp.bOriginalCode);


	}

	m_Int3BpList.RemoveAll();

	//刪除所有的硬件斷點

	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(m_tpInfo.hThread, &ct);
	if (ct.Dr0 != 0)
	{
		DeleteHardBP(ct.Dr0);

	}
	if (ct.Dr1 != 0)
	{
		DeleteHardBP(ct.Dr1);

	}
	if (ct.Dr2 != 0)
	{
		DeleteHardBP(ct.Dr2);

	}
	if (ct.Dr3 != 0)
	{
		DeleteHardBP(ct.Dr3);

	}

}


void CLeg_DebugDlg::OnRun()
{
	// TODO: Add your command handler code here
	ON_VK_F9();

}

//用戶命令的處理函數
void CLeg_DebugDlg::Handle_User_Command(char* szCommand)
{
	//去掉前后的空格
	if (!Kill_SPACE(szCommand))
	{
		AfxMessageBox("命令輸入錯誤");
		return;
	}
	//根據命令處理
	switch (szCommand[0])
	{
	case 't':
	case 'T':
		ON_VK_F7();
		break;
	case 'p':
	case 'P':
		ON_VK_F8();
		break;
	case 'u':
	case 'U':
	{
				//uf  函數 對函數反匯編
				if (szCommand[1] == 'F' || szCommand[1] == 'f')
				{
					char szName[100] = { 0 };
					sscanf(szCommand, "%s%s", stderr, &szName);
					DisassemblerExcFun(szName);


				}
				else
				{
					LONGLONG dwAddress = 0;
					//提取U后面的地址
					sscanf(szCommand, "%s%16p", stderr, &dwAddress);
					ON_U_COMMAND(dwAddress);
				}
				break;
	}
	case 'b':
	case 'B':
		Handle_B_Command(szCommand);

		break;
	case 'g':
	case 'G':
	{
				unsigned int dwAddress = 0;
				//提取U后面的地址
				sscanf(szCommand, "%s%x", stderr, &dwAddress);
				ON_G_COMMAND(dwAddress);
				break;

	}
	case 's':
	case 'S':

		//自動步過
		OnAutostepout();
		break;
	case 'o':
	case 'O':
		//跳出函數
		StepOutFromFun();
		break;
	case 'e':
	case 'E':
		if (szCommand[1] == 'B' || szCommand[1] == 'b')
		{
			LONGLONG dwAddress = 0;
			int inn = 0;
			//提取U后面的地址
			sscanf(szCommand, "%s%16p%2X", stderr, &dwAddress,&inn);
			ChangeByte(m_tpInfo.hProcess,dwAddress, inn);


		}
		break;
	default:
		AfxMessageBox(TEXT("命令錯誤"));
	}



}


//處理eb函數
void CLeg_DebugDlg::ChangeByte(HANDLE hProcess, LONGLONG dwAddress, byte chby){
	DWORD dwOldProtect = 0;
	DWORD dwRet = 0;
	int bOriginalCode;
	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	//讀取首字節
	if (!ReadProcessMemory(hProcess, (LPVOID)dwAddress, &bOriginalCode, sizeof(BYTE), NULL))
	{
		OutputDebugString("EasyDbgDlg.cpp 1927行出錯");
		DWORD dwErrcode = 0;
		dwErrcode = GetLastError();
		//向用戶輸出錯誤信息
		GetErrorMessage(dwErrcode);

		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
		return;

	}

	//寫入0xCC
	if (!WriteProcessMemory(hProcess, (LPVOID)dwAddress, &chby, sizeof(chby), NULL))
	{
		OutputDebugString("EasyDbgDlg.cpp 1942行出錯");
		DWORD dwErrcode = 0;
		dwErrcode = GetLastError();
		//向用戶輸出錯誤信息
		GetErrorMessage(dwErrcode);
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
		return;
	}
	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);


	return ;
}


//跳出函數  僅適用于MOV EBP ,ESP指令之后 POP EBP之前 利用堆棧原理讀取返回地址
void CLeg_DebugDlg::StepOutFromFun()
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(m_tpInfo.hThread, &ct) == 0)
	{
		return;
	}

	DWORD dwBpAddress = 0;
	DWORD dwOldProtect = 0;
	DWORD dwRet = 0;
	//讀取函數的返回地址
	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)(ct.Rbp + 4), 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (!ReadProcessMemory(m_tpInfo.hProcess, (LPVOID)(ct.Rbp + 4), &dwBpAddress, 4, NULL))
	{
		OutputDebugString("EasyDbgDlg.cpp 3961行出錯");
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)(ct.Rbp + 4), 4, dwOldProtect, &dwRet);
		return;

	}
	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)(ct.Rbp + 4), 4, dwOldProtect, &dwRet);
	ON_G_COMMAND(dwBpAddress);




}


//去掉命令的左邊和右邊的空格字符
BOOL CLeg_DebugDlg::Kill_SPACE(char* szCommand)
{
	//計算字符數 不包括最后的終止符
	int nSize = strlen(szCommand);
	//沒輸入命令就按回車鍵
	if (*szCommand == 0)
	{
		AfxMessageBox("沒有輸入命令");
		return FALSE;
	}
	//去掉前面的空格
	for (int i = 0; i<nSize; i++)
	{
		if (szCommand[i] != 0x20)
		{
			//去掉前面的空格之后的字符串大小
			int  nNowSize = nSize - i;
			for (int j = 0; j<nNowSize; j++)
			{
				//向前移動
				szCommand[j] = szCommand[i];
				i++;
			}
			szCommand[nNowSize] = 0;

		}
	}
	//之后再去掉后面的空格
	for (int i = strlen(szCommand) - 1; i>0; i--)
	{
		//從后向前遍歷,遇到第一個不是空格的字符即可
		if (szCommand[i] != 0x20)
		{
			//后面置為終止符
			szCommand[i + 1] = 0;
			break;
		}
	}

	return TRUE;

}

//對DLL導出函數進行反匯編
void CLeg_DebugDlg::DisassemblerExcFun(char* szFunName)
{

	LONGLONG dwAddress = 0;
	if (!m_Fun_Address.Lookup(szFunName, dwAddress))
	{
		AfxMessageBox("無此函數");
		return;
	}

	m_Result.ResetContent();

	//如果模塊需要更新  只要有DLL加載就需要更新
	if (m_GetModule)
	{

		if (!GetCurrentModuleList(m_tpInfo.hProcess))
		{
			return;

		}

	}

	//獲得當前反匯編函數在哪個模塊

	POSITION pos = NULL;
	pos = m_Module.GetHeadPosition();
	CString szText;
	while (pos != NULL)
	{
		MODULE_INFO mem = { 0 };
		mem = m_Module.GetNext(pos);
		if (dwAddress >= mem.dwBaseAddress && dwAddress <= (mem.dwSize + mem.dwBaseAddress))
		{

			//顯示要反匯編的函數名以及其所在模塊
			szText.Format("%s!%s:", mem.szModuleName, szFunName);
			m_Result.AddString(szText);
			m_Result.SetTopIndex(m_Result.GetCount() - 1);
			break;

		}


	}

	//反匯編

	ON_U_COMMAND(dwAddress);

}

//處理U命令 如果沒有地址就從以前的地址接著U 在單步或者斷點異常中再把這個地址設為當前EIP的值
void CLeg_DebugDlg::ON_U_COMMAND(LONGLONG dwAddress)
{
	//默認顯示8條指令
	//如果指明了地址則賦值m_Uaddress
	if (dwAddress)
	{
		m_Uaddress = dwAddress;
	}



	BYTE pCode[120] = { 0 };
	DWORD dwOldProtect = 0;
	DWORD dwRet = 0;
	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)m_Uaddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	if (!ReadProcessMemory(m_tpInfo.hProcess, (LPCVOID)m_Uaddress, pCode, sizeof(pCode), NULL))
	{
		OutputDebugString("EasyDbgDlg.cpp 1804行出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		GetErrorMessage(dwErrorCode);

		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)m_Uaddress, 4, dwOldProtect, &dwRet);
		return;

	}

	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)m_Uaddress, 4, dwOldProtect, &dwRet);


	//要判斷是斷點的情況 如果是斷點則不能顯示出CC而要在緩沖區中還原它
	for (int j = 0; j<120; j++)
	{
		POSITION pos = NULL;
		pos = m_Int3BpList.GetHeadPosition();
		while (pos != NULL)
		{
			INT3_BP bp = m_Int3BpList.GetNext(pos);
			//判斷斷點地址是否命名在這段緩沖區中
			if (bp.dwAddress == m_Uaddress + j)
			{
				//如果命中 則說明此為用戶斷點則把原字節還原
				pCode[j] = bp.bOriginalCode;
			}
		}

	}


	char szAsm[120] = { 0 };
	char szOpCode[120] = { 0 };
	UINT CodeSize = 0;
	int nIndex = 0;
	//開始反匯編
	for (int i = 0; i<8; i++)
	{

		Decode2AsmOpcode(&pCode[nIndex], szAsm, szOpCode, &CodeSize, m_Uaddress);
		//顯示在列表框控件內
		char szResult[200] = { 0 };
		EXPORT_FUN_INFO expFun = { 0 };
		//如果是導出函數則解析出來
		if (IsExportFun(szAsm, expFun))
		{
			sprintf(szResult, "%16p    %s       %s <%s.%s>", m_Uaddress, szOpCode, szAsm, expFun.szDLLName, expFun.szFunName);
			m_Result.AddString(szResult);

			m_Result.SetTopIndex(m_Result.GetCount() - 1);
			m_Uaddress += CodeSize;
			nIndex += CodeSize;
			continue;


		}
		sprintf(szResult, "%16p    %s        %s", m_Uaddress, szOpCode, szAsm);
		m_Result.AddString(szResult);

		m_Result.SetTopIndex(m_Result.GetCount() - 1);
		m_Uaddress += CodeSize;
		nIndex += CodeSize;

	}



}


//處理B命令
void CLeg_DebugDlg::Handle_B_Command(char* szCommand)
{
	switch (szCommand[1])
	{
	case 'p':
	case 'P':
	{
				LONGLONG dwAddress = 0;

				//提取P后面的地址
				sscanf(szCommand, "%s%16p", stderr, &dwAddress);
				if (dwAddress == 0)
				{
					AfxMessageBox("輸入錯誤,請輸入斷點地址");
					break;
				}
				//設置斷點
				UserSetBP(m_tpInfo.hProcess, dwAddress, m_tpInfo.bCC);

				break;
	}
	case 'l':
	case 'L':
		//列出當前斷點
		ListBP();

		break;
	case 'c':
	case 'C':
	{
				unsigned int dwAddress = 0;
				//提取C后面的地址
				sscanf(szCommand, "%s%x", stderr, &dwAddress);
				if (dwAddress == 0)
				{
					AfxMessageBox("輸入錯誤,請輸入斷點地址");
					return;
				}
				//刪除永久性斷點 標志設為TRUE
				m_isDelete = TRUE;
				DeleteUserBP(m_tpInfo.hProcess, dwAddress);

				break;
	}
	case 'h':
		//設置硬件斷點或刪除
	case 'H':
	{
				//對用戶輸入的指令只做簡單的判斷
				if (szCommand[2] == 'C' || szCommand[2] == 'c')
				{
					unsigned int dwAddress = 0;
					//提取C后面的地址
					sscanf(szCommand, "%s%x", stderr, &dwAddress);
					if (dwAddress == 0)
					{
						AfxMessageBox("輸入錯誤,請輸入斷點地址");
						return;
					}
					DeleteHardBP(dwAddress);

				}
				else
				{

					DWORD dwAddress = 0;
					DWORD dwAttribute = 0;
					DWORD dwLength = 0;
					//提取各個值
					sscanf(szCommand, "%s%x%x%x", stderr, &dwAddress, &dwAttribute, &dwLength);
					//設置硬件斷點
					SetHardBP(dwAddress, dwAttribute, dwLength);
				}

				break;
	}
	case 'm':
	case 'M':
	{
				//清除內存斷點
				if (szCommand[2] == 'C' || szCommand[2] == 'c')
				{
					unsigned int dwAddress = 0;
					//提取C后面的地址
					sscanf(szCommand, "%s%x", stderr, &dwAddress);
					if (dwAddress == 0)
					{
						AfxMessageBox("輸入錯誤,請輸入斷點地址");
						return;
					}
					DeleteMemBP(dwAddress);

				}
				else
				{

					DWORD dwAddress = 0;
					DWORD dwAttribute = 0;
					DWORD dwLength = 0;
					//提取各個值
					sscanf(szCommand, "%s%x%x%x", stderr, &dwAddress, &dwAttribute, &dwLength);
					SetMemBP(dwAddress, dwAttribute, dwLength);
				}

				break;
	}
	}


}


//用戶設置斷點
void CLeg_DebugDlg::UserSetBP(HANDLE hProcess, LONGLONG dwBpAddress, BYTE bCCode)
{
	//判斷該地址是否已經是斷點
	POSITION pos = NULL;
	INT3_BP bp = { 0 };
	while (pos != NULL)
	{
		bp = m_Int3BpList.GetNext(pos);
		if (bp.dwAddress == dwBpAddress)
		{
			AfxMessageBox("此地址已經設置斷點,設置無效");
			return;
		}
	}
	memset(&bp, 0, sizeof(INT3_BP));
	bp.dwAddress = dwBpAddress;
	bp.isForever = TRUE;

	DWORD dwOldProtect = 0;
	DWORD dwRet = 0;
	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//讀取首字節
	if (!ReadProcessMemory(hProcess, (LPVOID)dwBpAddress, &bp.bOriginalCode, sizeof(BYTE), NULL))
	{
		OutputDebugString("EasyDbgDlg.cpp 1927行出錯");
		DWORD dwErrcode = 0;
		dwErrcode = GetLastError();
		//向用戶輸出錯誤信息
		GetErrorMessage(dwErrcode);

		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, dwOldProtect, &dwRet);
		return;

	}


	//寫入0xCC
	if (!WriteProcessMemory(hProcess, (LPVOID)dwBpAddress, &bCCode, sizeof(bCCode), NULL))
	{
		OutputDebugString("EasyDbgDlg.cpp 1942行出錯");
		DWORD dwErrcode = 0;
		dwErrcode = GetLastError();
		//向用戶輸出錯誤信息
		GetErrorMessage(dwErrcode);
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, dwOldProtect, &dwRet);
		return;
	}
	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBpAddress, 4, dwOldProtect, &dwRet);
	//刷新
	SetDlgItemText(IDC_STATIC1, "設置斷點成功");
	FlushInstructionCache(hProcess, (LPCVOID)dwBpAddress, sizeof(BYTE));
	m_Int3BpList.AddTail(bp);


}

//刪除硬件斷點
void CLeg_DebugDlg::DeleteHardBP(LONGLONG dwAddress)
{

	if (dwAddress == 0)
	{
		AfxMessageBox("沒輸入斷點地址");
		return;
	}
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(m_tpInfo.hThread, &ct))
	{
		OutputDebugString("EasyDbgDlg.cpp 2583行出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		//輸出錯誤信息
		GetErrorMessage(dwErrorCode);
		return;
	}
	DR7 tagDr7 = { 0 };
	tagDr7.dwDr7 = ct.Dr7;
	//找到對應斷點的調試寄存器
	int nIndex = GetDeletedDrIndex(dwAddress, ct);
	if (nIndex == -1)
	{
		AfxMessageBox("斷點無效");
		return;
	}
	//清0并設置對應標志位為FALSE
	switch (nIndex)
	{
	case 0:
		//地址
		ct.Dr0 = 0;
		//屬性
		tagDr7.DRFlag.rw0 = 0;
		//局部斷點
		tagDr7.DRFlag.L0 = 0;
		//長度
		tagDr7.DRFlag.len0 = 0;

		m_Dr_Use.Dr0 = FALSE;
		break;
	case 1:

		ct.Dr1 = 0;

		tagDr7.DRFlag.rw1 = 0;

		tagDr7.DRFlag.L1 = 0;

		tagDr7.DRFlag.len1 = 0;

		m_Dr_Use.Dr1 = FALSE;
		break;
	case 2:

		ct.Dr2 = 0;

		tagDr7.DRFlag.rw2 = 0;

		tagDr7.DRFlag.L2 = 0;

		tagDr7.DRFlag.len2 = 0;

		m_Dr_Use.Dr2 = FALSE;
		break;
	case 3:

		ct.Dr3 = 0;

		tagDr7.DRFlag.rw3 = 0;

		tagDr7.DRFlag.L3 = 0;

		tagDr7.DRFlag.len3 = 0;

		m_Dr_Use.Dr3 = FALSE;
		break;
	}
	//賦值
	ct.Dr7 = tagDr7.dwDr7;

	if (!SetThreadContext(m_tpInfo.hThread, &ct))
	{
		OutputDebugString("EasyDbgDlg.cpp 2656行出錯");

		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		//輸出錯誤信息
		GetErrorMessage(dwErrorCode);

		return;

	}
	SetDlgItemText(IDC_STATIC1, TEXT("刪除硬件斷點成功"));


}


//獲得要被刪除的硬件斷點的調試寄存器編號 返回-1表示沒找到
int CLeg_DebugDlg::GetDeletedDrIndex(LONGLONG dwAddress, CONTEXT ct)
{
	if (dwAddress == ct.Dr0)
	{
		return 0;
	}
	if (dwAddress == ct.Dr1)
	{
		return 1;
	}
	if (dwAddress == ct.Dr2)
	{
		return 2;
	}
	if (dwAddress == ct.Dr3)
	{
		return 3;
	}

	return -1;

}

//枚舉斷點
void CLeg_DebugDlg::ListBP()
{

	POSITION pos = NULL;
	pos = m_Int3BpList.GetHeadPosition();
	INT3_BP bp = { 0 };
	CString szText;
	if (m_Int3BpList.GetCount() != 0)
	{
		//列舉INT3斷點
		while (pos != NULL)
		{
			bp = m_Int3BpList.GetNext(pos);
			szText.Format("INT3斷點 斷點地址:%08X   斷點處原數據:%2X 是否是永久斷點: %d", bp.dwAddress, bp.bOriginalCode, bp.isForever);
			m_Result.AddString(szText);
			m_Result.SetTopIndex(m_Result.GetCount() - 1);

		}
	}
	else
	{
		szText.Format("當前無INT3斷點");
		m_Result.AddString(szText);
		m_Result.SetTopIndex(m_Result.GetCount() - 1);


	}


	//列舉硬件斷點
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(m_tpInfo.hThread, &ct))
	{
		OutputDebugString("EasyDbgDlg.cpp 2251行出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		//輸出錯誤信息
		GetErrorMessage(dwErrorCode);
		return;
	}

	DR7 tagDr7 = { 0 };
	tagDr7.dwDr7 = ct.Dr7;


	if (m_Dr_Use.Dr0)
	{
		szText.Format("硬件斷點 斷點地址:%08X 斷點類型:%d  斷點長度:%d", ct.Dr0, tagDr7.DRFlag.rw0, tagDr7.DRFlag.len0 + 1);
		m_Result.AddString(szText);
		m_Result.SetTopIndex(m_Result.GetCount() - 1);

	}
	if (m_Dr_Use.Dr1)
	{
		szText.Format("硬件斷點 斷點地址:%08X 斷點類型:%d  斷點長度:%d", ct.Dr1, tagDr7.DRFlag.rw1, tagDr7.DRFlag.len1 + 1);
		m_Result.AddString(szText);
		m_Result.SetTopIndex(m_Result.GetCount() - 1);

	}
	if (m_Dr_Use.Dr2)
	{
		szText.Format("硬件斷點 斷點地址:%08X 斷點類型:%d  斷點長度:%d", ct.Dr2, tagDr7.DRFlag.rw2, tagDr7.DRFlag.len2 + 1);
		m_Result.AddString(szText);
		m_Result.SetTopIndex(m_Result.GetCount() - 1);

	}
	if (m_Dr_Use.Dr3)
	{
		szText.Format("硬件斷點 斷點地址:%08X 斷點類型:%d  斷點長度:%d", ct.Dr3, tagDr7.DRFlag.rw3, tagDr7.DRFlag.len3 + 1);
		m_Result.AddString(szText);
		m_Result.SetTopIndex(m_Result.GetCount() - 1);

	}

	//列舉內存斷點
	pos = NULL;
	pos = m_MemBpList.GetHeadPosition();
	MEM_BP mBP = { 0 };
	if (m_MemBpList.GetCount() != 0)
	{
		while (pos != NULL)
		{
			mBP = m_MemBpList.GetNext(pos);
			switch (mBP.dwNumPage)
			{
			case 1:
			{
					  szText.Format("內存斷點 斷點地址:%08X 斷點類型 %d 斷點長度:%d  斷點所跨分頁:%08X",
						  mBP.dwBpAddress, mBP.dwAttribute, mBP.dwLength, mBP.dwMemPage[0]);
					  m_Result.AddString(szText);
					  m_Result.SetTopIndex(m_Result.GetCount() - 1);
					  break;
			}
			case 2:
			{
					  szText.Format("內存斷點 斷點地址:%08X 斷點類型 %d 斷點長度:%d  斷點所跨分頁:%08X %08X",
						  mBP.dwBpAddress, mBP.dwAttribute, mBP.dwLength, mBP.dwMemPage[0], mBP.dwMemPage[1]);
					  m_Result.AddString(szText);
					  m_Result.SetTopIndex(m_Result.GetCount() - 1);
					  break;
			}
			case 3:
			{
					  szText.Format("內存斷點 斷點地址:%08X 斷點類型 %d 斷點長度:%d  斷點所跨分頁:%08X %08X %08X",
						  mBP.dwBpAddress, mBP.dwAttribute, mBP.dwLength, mBP.dwMemPage[0], mBP.dwMemPage[1],
						  mBP.dwMemPage[2]);
					  m_Result.AddString(szText);
					  m_Result.SetTopIndex(m_Result.GetCount() - 1);


					  break;
			}
			case 4:
			{
					  szText.Format("內存斷點 斷點地址:%08X 斷點類型 %d 斷點長度:%d  斷點所跨分頁:%08X %08X %08X %08X",
						  mBP.dwBpAddress, mBP.dwAttribute, mBP.dwLength, mBP.dwMemPage[0], mBP.dwMemPage[1],
						  mBP.dwMemPage[2], mBP.dwMemPage[3]);
					  m_Result.AddString(szText);
					  m_Result.SetTopIndex(m_Result.GetCount() - 1);
					  break;
			}
			case 5:
			{
					  szText.Format("內存斷點 斷點地址:%08X 斷點類型 %d 斷點長度:%d  斷點所跨分頁:%08X %08X %08X %08X %08X",
						  mBP.dwBpAddress, mBP.dwAttribute, mBP.dwLength, mBP.dwMemPage[0], mBP.dwMemPage[1],
						  mBP.dwMemPage[2], mBP.dwMemPage[3], mBP.dwMemPage[4]);
					  m_Result.AddString(szText);
					  m_Result.SetTopIndex(m_Result.GetCount() - 1);

					  break;
			}
			}



		}

	}
	else
	{
		szText.Format("當前無內存斷點");
		m_Result.AddString(szText);
		m_Result.SetTopIndex(m_Result.GetCount() - 1);

	}






}

//刪除內存斷點
void CLeg_DebugDlg::DeleteMemBP(LONGLONG dwBpAddress)
{
	MEM_BP mBP = { 0 };
	//找到內存斷點并從鏈表中移除
	if (!FindMemBPInformation(mBP, dwBpAddress))
	{
		AfxMessageBox("此地址不是斷點");
		return;
	}

	for (DWORD i = 0; i<mBP.dwNumPage; i++)
	{
		//先判斷有沒有另一個內存斷點在這個分頁上,如果存在就修改為另一個斷點所要求的屬性
		if (!ModifyPageProtect(mBP.dwMemPage[i]))
		{
			//如果沒有其他內存斷點在此內存頁上就直接遍歷內存頁表修改為原來的屬性
			MEMORY_BASIC_INFORMATION mbi = { 0 };
			mbi.BaseAddress = (PVOID)mBP.dwMemPage[i];
			//如果成功返回原屬性
			if (FindMemOriginalProtect(mbi))
			{
				DWORD dwOldProtect = 0;
				//修改
				if (!VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)mBP.dwMemPage[i], 4, mbi.Protect, &dwOldProtect))
				{
					OutputDebugString("EasyDbgDlg.cpp 3299行出錯");
					DWORD dwErrorCode = 0;
					dwErrorCode = GetLastError();
					//輸出錯誤信息
					GetErrorMessage(dwErrorCode);
				}


			}

		}


	}


}

//找到符合的內存斷點信息并返回 參數類型為引用 并從鏈表中刪除此元素
BOOL CLeg_DebugDlg::FindMemBPInformation(MEM_BP& mBP, LONGLONG dwBpAddress)
{

	POSITION pos = NULL;
	pos = m_MemBpList.GetHeadPosition();
	while (pos != NULL)
	{

		mBP = m_MemBpList.GetNext(pos);
		//如果找到返回TRUE
		if (mBP.dwBpAddress == dwBpAddress)
		{

			if (m_MemBpList.GetCount() == 1)
			{
				m_MemBpList.RemoveHead();

				SetDlgItemText(IDC_STATIC1, "內存斷點刪除成功");
				return TRUE;

			}

			if (pos == NULL)
			{
				m_MemBpList.RemoveTail();

				SetDlgItemText(IDC_STATIC1, "內存斷點刪除成功");
				return TRUE;

			}

			m_MemBpList.GetPrev(pos);

			m_MemBpList.RemoveAt(pos);
			SetDlgItemText(IDC_STATIC1, "內存斷點刪除成功");

			return TRUE;
		}

	}
	return FALSE;

}



//先判斷有沒有另一個內存斷點在這個分頁上,如果存在就修改為另一個斷點所要求的屬性
//參數 內存頁的首地址
BOOL CLeg_DebugDlg::ModifyPageProtect(LONGLONG dwBaseAddress)
{
	POSITION pos = NULL;
	pos = m_MemBpList.GetHeadPosition();

	MEM_BP mBP = { 0 };
	BOOL isFind = FALSE;
	//遍歷
	while (pos != NULL)
	{
		mBP = m_MemBpList.GetNext(pos);
		for (DWORD i = 0; i<mBP.dwNumPage; i++)
		{
			//如果找到內存斷點還在此內存頁面上
			if (mBP.dwMemPage[i] == dwBaseAddress)
			{
				isFind = TRUE;
				DWORD dwOldProtect = 0;
				//就把內存保護屬性恢復為他的所需要的
				if (!VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwBaseAddress, 4,
					m_Attribute[mBP.dwAttribute], &dwOldProtect))
				{
					OutputDebugString("EasyDbgDlg.cpp 3387行出錯");
					DWORD dwErrorCode = 0;
					dwErrorCode = GetLastError();

					GetErrorMessage(dwErrorCode);
				}
			}
		}


	}

	return isFind;
}


//找到原始內存頁鏈表的對應屬性并傳出 引用類型
BOOL CLeg_DebugDlg::FindMemOriginalProtect(MEMORY_BASIC_INFORMATION& mbi)
{

	POSITION pos;
	pos = m_MemPageList.GetHeadPosition();
	while (pos != NULL)
	{
		MEM_BP_PAGE mBPage = { 0 };
		mBPage = m_MemPageList.GetNext(pos);
		//如果找到返回TRUE
		if (mBPage.dwBaseAddress == (LONGLONG)mbi.BaseAddress)
		{
			//賦值原始屬性
			mbi.Protect = mBPage.dwProtect;
			return TRUE;

		}
	}
	return FALSE;


}

//設置內存斷點  dwAttribute 1表示寫入斷點 3表示訪問斷點
void CLeg_DebugDlg::SetMemBP(LONGLONG dwBpAddress, LONGLONG dwAttribute, LONGLONG dwLength)
{
	if (dwAttribute != 1 && dwAttribute != 3)
	{
		AfxMessageBox("內存斷點類型弄錯");
		return;
	}

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	MEM_BP mbp = { 0 };

	if (!IsAddressValid(dwBpAddress, mbi))
	{
		AfxMessageBox("斷點地址無效");
		return;
	}
	//判斷地址和長度占了幾個分頁并加入內存分頁表 也把斷點加入斷點表
	if (!AddMemBpPage(dwBpAddress, dwLength, mbi, dwAttribute, mbp))
	{
		AfxMessageBox("斷點添加失敗");
		return;
	}
	//該保護屬性
	for (DWORD i = 0; i<mbp.dwNumPage; i++)
	{
		DWORD dwOldProtect = 0;

		if (!VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)mbp.dwMemPage[i], 4, m_Attribute[dwAttribute], &dwOldProtect))
		{
			OutputDebugString("EasyDbgDlg.cpp 2944行出錯");
			DWORD dwErrorCode = 0;
			dwErrorCode = GetLastError();
			//輸出錯誤信息
			GetErrorMessage(dwErrorCode);
			AfxMessageBox("斷點加入失敗");
			return;

		}


	}

	SetDlgItemText(IDC_STATIC1, "內存斷點設置成功");

}

//判斷地址是否有效
BOOL CLeg_DebugDlg::IsAddressValid(LONGLONG dwAddress, MEMORY_BASIC_INFORMATION& mbi)
{


	DWORD dwRet = 0;

	dwRet = VirtualQueryEx(m_tpInfo.hProcess, (LPVOID)dwAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	//返回值與其緩沖區長度不相同則表示地址無效
	if (dwRet != sizeof(MEMORY_BASIC_INFORMATION))
	{
		return FALSE;
	}
	//MEM_FREE 的不能訪問 MEM_RESERVE的保護屬性未知
	if (mbi.State == MEM_COMMIT)
	{
		return TRUE;
	}

	return FALSE;
}


//判斷地址和長度占了幾個分頁并加入內存分頁表 并把斷點也加入斷點鏈表
BOOL CLeg_DebugDlg::AddMemBpPage(LONGLONG dwBpAddress, LONGLONG dwLength, MEMORY_BASIC_INFORMATION mbi, LONGLONG dwAttribute, MEM_BP& mbp)
{
	//如果在一個分頁中(不跨分頁)
	MEM_BP_PAGE mBPage = { 0 };


	if (dwBpAddress >= (LONGLONG)mbi.BaseAddress && (LONGLONG)mbi.BaseAddress + mbi.RegionSize >= dwBpAddress + dwLength)
	{
		mBPage.dwBaseAddress = (LONGLONG)mbi.BaseAddress;
		mBPage.dwProtect = mbi.Protect;
		//在內存鏈表中沒找到就添加
		if (!FindMemPage((LONGLONG)mbi.BaseAddress))
		{
			m_MemPageList.AddTail(mBPage);
		}
		//添加內存鏈表
		mbp.dwAttribute = dwAttribute;
		mbp.dwBpAddress = dwBpAddress;
		mbp.dwLength = dwLength;
		mbp.dwMemPage[0] = mBPage.dwBaseAddress;
		mbp.dwNumPage = 1;
		//查看該地址處是否已經有內存斷點如果有不能在下斷點
		if (FindMemBP(dwBpAddress))
		{
			AfxMessageBox("該地址已經有內存斷點,不能在下斷點");
			return FALSE;
		}
		else
		{
			//添加到斷點鏈表
			m_MemBpList.AddTail(mbp);
		}
		return TRUE;


	}
	//跨多個分頁的情況 因為跨太多頁屬于腦殘行為,因為就不建立所有的內存頁鏈表了
	//直接比較 其實跨3個頁的就屬于腦殘行為....
	int i = 0;

	mbp.dwAttribute = dwAttribute;
	mbp.dwBpAddress = dwBpAddress;
	mbp.dwLength = dwLength;

	while ((LONGLONG)mbi.BaseAddress + mbi.RegionSize<dwBpAddress + dwLength)
	{
		if (i>4)
		{
			AfxMessageBox("我對你無語下這么多分頁的內存斷點");
			return FALSE;
		}
		mBPage.dwBaseAddress = (LONGLONG)mbi.BaseAddress;
		mBPage.dwProtect = mbi.Protect;
		//在內存鏈表中沒找到就添加
		if (!FindMemPage((LONGLONG)mbi.BaseAddress))
		{
			m_MemPageList.AddTail(mBPage);
		}
		mbp.dwMemPage[i] = mBPage.dwBaseAddress;

		DWORD dwRet = 0;

		//找下一個分頁
		dwRet = VirtualQueryEx(m_tpInfo.hProcess, (LPVOID)((LONGLONG)mbi.BaseAddress + mbi.RegionSize), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		//返回值與其緩沖區長度不相同則表示地址無效
		if (dwRet != sizeof(MEMORY_BASIC_INFORMATION))
		{
			return FALSE;
		}

		i++;


	}

	if (i>4)
	{
		AfxMessageBox("我對你無語下這么多分頁的內存斷點");
		return FALSE;
	}

	mBPage.dwBaseAddress = (LONGLONG)mbi.BaseAddress;
	mBPage.dwProtect = mbi.Protect;
	//在內存鏈表中沒找到就添加
	if (!FindMemPage((LONGLONG)mbi.BaseAddress))
	{
		m_MemPageList.AddTail(mBPage);
	}
	mbp.dwMemPage[i] = mBPage.dwBaseAddress;

	if (FindMemBP(dwBpAddress))
	{
		AfxMessageBox("該地址已經有內存斷點,不能在下斷點");
		return FALSE;
	}
	else
	{
		//添加到斷點鏈表
		m_MemBpList.AddTail(mbp);
	}
	return TRUE;

}


//判斷某一頁首地址是否存在于頁鏈表中
BOOL CLeg_DebugDlg::FindMemPage(LONGLONG dwBaseAddress)
{

	POSITION pos;
	pos = m_MemPageList.GetHeadPosition();
	while (pos != NULL)
	{
		MEM_BP_PAGE mBPage = { 0 };
		mBPage = m_MemPageList.GetNext(pos);
		//如果找到返回TRUE
		if (mBPage.dwBaseAddress == dwBaseAddress)
		{
			return TRUE;

		}
	}
	return FALSE;
}

//判斷地址是否重復下內存斷點
BOOL CLeg_DebugDlg::FindMemBP(LONGLONG dwBpAddress)
{
	POSITION pos = NULL;
	pos = m_MemBpList.GetHeadPosition();
	while (pos != NULL)
	{
		MEM_BP memBp = { 0 };
		memBp = m_MemBpList.GetNext(pos);
		//如果找到返回TRUE
		if (memBp.dwBpAddress == dwBpAddress)
		{
			return TRUE;
		}

	}
	return FALSE;
}

//設置硬件斷點 參數 地址 屬性 長度
//dwAttribute 0表示執行斷點 3表示訪問斷點 1 表示寫入斷點
//dwLength 取值 1 2 4
void CLeg_DebugDlg::SetHardBP(LONGLONG dwBpAddress, LONGLONG dwAttribute, LONGLONG dwLength)
{


	if (dwLength != 1 && dwLength != 2 && dwLength != 4)
	{
		AfxMessageBox("斷點長度設置錯誤");
		return;
	}
	//強制把執行斷點的長度改為1
	if (dwAttribute == 0)
	{
		dwLength = 1;
	}

	int nIndex = 0;
	//獲得當前空閑調寄存器編號
	nIndex = FindFreeDebugRegister();

	if (nIndex == -1)
	{
		AfxMessageBox("當前硬件斷點已滿,請刪除在設置");
		return;
	}
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(m_tpInfo.hThread, &ct))
	{
		OutputDebugString("EasyDbgDlg.cpp 2460行出錯");

		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		//輸出錯誤信息
		GetErrorMessage(dwErrorCode);
		return;

	}
	//賦值我們定義的DR7結構體,這樣省去了位移操作的繁瑣
	DR7 tagDr7 = { 0 };
	tagDr7.dwDr7 = ct.Dr7;

	switch (nIndex)
	{
	case 0:
		//中斷地址
		ct.Dr0 = dwBpAddress;
		//斷點長度
		tagDr7.DRFlag.len0 = dwLength - 1;
		//屬性
		tagDr7.DRFlag.rw0 = dwAttribute;
		//局部斷點
		tagDr7.DRFlag.L0 = 1;
		//設置標志位記錄調試寄存器的使用情況
		m_Dr_Use.Dr0 = TRUE;

		break;
	case 1:
		ct.Dr1 = dwBpAddress;

		tagDr7.DRFlag.len1 = dwLength - 1;

		tagDr7.DRFlag.rw1 = dwAttribute;

		tagDr7.DRFlag.L1 = 1;

		m_Dr_Use.Dr1 = TRUE;


		break;
	case 2:
		ct.Dr2 = dwBpAddress;

		tagDr7.DRFlag.len2 = dwLength - 1;

		tagDr7.DRFlag.rw2 = dwAttribute;

		tagDr7.DRFlag.L2 = 1;

		m_Dr_Use.Dr2 = TRUE;

		break;
	case 3:
		ct.Dr3 = dwBpAddress;

		tagDr7.DRFlag.len3 = dwLength - 1;

		tagDr7.DRFlag.rw3 = dwAttribute;

		tagDr7.DRFlag.L3 = 1;

		m_Dr_Use.Dr3 = TRUE;
		break;
	}

	//賦值回去
	ct.Dr7 = tagDr7.dwDr7;
	if (!SetThreadContext(m_tpInfo.hThread, &ct))
	{
		OutputDebugString("EasyDbgDlg.cpp 2531行出錯");
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		//輸出錯誤信息
		GetErrorMessage(dwErrorCode);
		return;
	}
	SetDlgItemText(IDC_STATIC1, "設置硬件斷點成功");


}

//返回當前可用的調試寄存器
int CLeg_DebugDlg::FindFreeDebugRegister()
{
	if (!m_Dr_Use.Dr0)
	{
		return 0;

	}
	if (!m_Dr_Use.Dr1)
	{
		return 1;
	}
	if (!m_Dr_Use.Dr2)
	{
		return 2;

	}
	if (!m_Dr_Use.Dr3)
	{
		return 3;
	}
	//如果Dr0-Dr3都被使用則返回-1
	return -1;
}

//G命令處理
void CLeg_DebugDlg::ON_G_COMMAND(LONGLONG dwAddress)
{
	//如果不指定地址默認和F9處理一樣
	if (dwAddress == 0)
	{
		m_Result.ResetContent();
		ON_VK_F9();
		return;
	}
	INT3_BP bp = { 0 };
	bp.dwAddress = dwAddress;

	DWORD dwOldProtect = 0;
	DWORD dwRet = 0;

	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);


	if (!ReadProcessMemory(m_tpInfo.hProcess, (LPVOID)dwAddress, &bp.bOriginalCode, sizeof(BYTE), NULL))
	{
		OutputDebugString("EasyDbgDlg.cpp 2392行出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		//向用戶輸出錯誤信息
		GetErrorMessage(dwErrorCode);
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
		return;
	}
	//非永久斷點
	bp.isForever = FALSE;
	//寫入0XCC
	if (!WriteProcessMemory(m_tpInfo.hProcess, (LPVOID)dwAddress, &m_tpInfo.bCC, sizeof(BYTE), NULL))
	{

		OutputDebugString("EasyDbgDlg.cpp 2405行出錯");
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		//向用戶輸出錯誤信息
		GetErrorMessage(dwErrorCode);
		VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
		return;

	}

	VirtualProtectEx(m_tpInfo.hProcess, (LPVOID)dwAddress, 4, dwOldProtect, &dwRet);
	//加入斷點鏈表
	m_Int3BpList.AddTail(bp);

	m_IsGo = TRUE;
	//運行
	ON_VK_F9();



}


void CLeg_DebugDlg::OnEnChangeEdit2()
{
	// TODO:  如果這是 RICHEDIT 控制項，控制項將不會
	// 傳送此告知，除非您覆寫 CDialogEx::OnInitDialog()
	// 函式和呼叫 CRichEditCtrl().SetEventMask()
	// 讓具有 ENM_CHANGE 旗標 ORed 加入遮罩。

	// TODO:  在此加入控制項告知處理常式程式碼
}
