#include"../Share/Simple/Simple.h"
#include"../Share/Hook/SimpleHook.h"
#pragma comment(lib, "ws2_32.lib")

DWORD PrivateServerIP = 0x0100007F; // 127.0.0.1
int (PASCAL *_connect)(SOCKET, sockaddr_in *, int) = NULL;
int PASCAL connect_Hook(SOCKET s, sockaddr_in *name, int namelen) {
	WORD wPort = ntohs(name->sin_port);

	std::wstring server = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);
	*(DWORD *)&name->sin_addr.S_un = PrivateServerIP;
	std::wstring pserver = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);

	DEBUG(L"[connect][" + server + L" -> " + pserver + L"]");

	name->sin_port = htons(wPort);
	return _connect(s, name, namelen);
}

bool Hook() {
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
	std::wstring wServerIP;

	bool check = true;
	check &= conf.Read(DLL_NAME, L"ServerIP", wServerIP);

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
		Hook();
		LocalHost(hinstDLL);
	}
	return TRUE;
}