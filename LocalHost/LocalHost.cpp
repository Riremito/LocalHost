#include<ws2spi.h> // this needs to include before including Windows.h
#include"../Share/Simple/Simple.h"
#include"../Share/Hook/SimpleHook.h"
#pragma comment(lib, "ws2_32.lib")


bool useAuthHook = false; // Auth Hook, GMS and MSEA needs to use this method
WSPPROC_TABLE g_ProcTable = { 0 }; // AuthHook
DWORD PrivateServerIP = 0x0100007F; // 127.0.0.1
DWORD OfficialServerIP = 0; // 13.112.241.65, 18.179.64.209

void Redirect(sockaddr_in *name) {
	// port
	WORD wPort = ntohs(name->sin_port);
	// original ip
	OfficialServerIP = name->sin_addr.S_un.S_addr;
	std::wstring server = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);
	// redirect
	*(DWORD *)&name->sin_addr.S_un = PrivateServerIP;
	// private server ip
	std::wstring pserver = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);

	DEBUG(L"[Redirect][" + server + L" -> " + pserver + L"]");
}

void PeerNameBypass(sockaddr_in *name) {
	// port
	WORD wPort = ntohs(name->sin_port);
	// original ip
	std::wstring server = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);
	// fake ip
	*(DWORD *)&name->sin_addr.S_un = OfficialServerIP;
	// official server ip
	std::wstring oserver = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);

	DEBUG(L"[PeerNameBypass][" + server + L" -> " + oserver + L"]");
}

bool IsWebPort(sockaddr_in *name) {
	WORD wPort = ntohs(name->sin_port);

	if (wPort == 80 || wPort == 443) {
		return true;
	}

	return false;
}

// redirector
int (PASCAL *_connect)(SOCKET, sockaddr_in *, int) = NULL;
int PASCAL connect_Hook(SOCKET s, sockaddr_in *name, int namelen) {
	Redirect(name);
	return _connect(s, name, namelen);
}

int WINAPI WSPGetPeerName_Hook(SOCKET s, sockaddr_in *name, LPINT namelen, LPINT lpErrno) {
	int ret = g_ProcTable.lpWSPGetPeerName(s, (sockaddr *)name, namelen, lpErrno);

	if (ret == SOCKET_ERROR) {
		return ret;
	}

	if (IsWebPort(name)) {
		return SOCKET_ERROR;
	}

	PeerNameBypass(name);

	return  ret;
}

int WINAPI WSPConnect_Hook(SOCKET s, sockaddr_in *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno) {

	if (IsWebPort(name)) {
		return SOCKET_ERROR;
	}

	Redirect(name);
	return g_ProcTable.lpWSPConnect(s, (sockaddr *)name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
}

//decltype(WSPStartup) *_WSPStartup = NULL;
decltype(WSPStartup) *_WSPStartup = NULL;
int WINAPI WSPStartup_Hook(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFOW lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable) {
	int ret = _WSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);

	g_ProcTable = *lpProcTable;

	lpProcTable->lpWSPConnect = (decltype(lpProcTable->lpWSPConnect))WSPConnect_Hook;
	lpProcTable->lpWSPGetPeerName = (decltype(lpProcTable->lpWSPGetPeerName))WSPGetPeerName_Hook;
	return ret;
}

bool Hook() {
	// if you get crash after 30 seconds after connecting to login server, you need to use authhook
	if (useAuthHook) {
		HMODULE hDll = GetModuleHandleW(L"mswsock.dll");
		if (!hDll) {
			hDll = LoadLibraryW(L"mswsock.dll");
		}

		if (!hDll) {
			DEBUG(L"failed to load mswsock.dll");
			return false;
		}

		SHookNT(mswsock.dll, WSPStartup);
		return true;
	}
	// Normal Method

	SHook(connect);
	return true;
}

#ifndef _WIN64
#define DLL_NAME L"LocalHost"
#else
#define DLL_NAME L"LocalHost64"
#endif

#define INI_FILE_NAME DLL_NAME".ini"

bool LocalHost(HMODULE hDll) {
	Config conf(INI_FILE_NAME, hDll);
	std::wstring wServerIP, wAuthHook;

	bool check = true;
	check &= conf.Read(DLL_NAME, L"ServerIP", wServerIP);

	if (conf.Read(DLL_NAME, L"AuthHook", wAuthHook)) {
		// not 0
		if (_wtoi(wAuthHook.c_str())) {
			useAuthHook = true;
			DEBUG(L"AuthHook On");
		}
	}

	if (!check) {
		DEBUG(L"use default IP");
		return false;
	}

	DWORD dwIP[4] = { 0 };
	swscanf_s(wServerIP.c_str(), L"%d.%d.%d.%d", &dwIP[0], &dwIP[1], &dwIP[2], &dwIP[3]);

	BYTE *ip_bytes = (BYTE *)&PrivateServerIP;
	for (int i = 0; i < 4; i++) {
		ip_bytes[i] = (BYTE)dwIP[i];
	}

	DEBUG(L"ServerIP = " + wServerIP);
	return true;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		LocalHost(hinstDLL);
		Hook();
	}
	return TRUE;
}