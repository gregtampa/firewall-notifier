#include "app.h"
#include "resource.h"
#include <ShlObj.h>
#include <shellapi.h>
#include <stdlib.h>
#include <assert.h>

// Application messages.
#define WM_NIMSG (WM_USER + 1)

// Application commands.
#define ID_EXIT 101
#define ID_ENABLE_FIREWALL 102
#define ID_DISABLE_FIREWALL 103
#define ID_RULES 104

App::App() {
}

App::~App() {
}

void App::run() {
	WNDCLASS wc = { 0 };
	wc.hInstance = GetModuleHandleW(nullptr);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
	wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	wc.hIcon = LoadIconW(wc.hInstance, MAKEINTRESOURCEW(IDI_ICON1));
	wc.lpfnWndProc = handle_msg_callback;
	wc.lpszClassName = L"bkth_class_console";
	RegisterClassW(&wc);

	HWND wnd = CreateWindowExW(0, wc.lpszClassName, L"Console", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, 0);
	if (wnd == nullptr) {
		return;
	}

	SetLastError(0);
	SetWindowLongPtrW(wnd, GWLP_USERDATA, (LONG_PTR)this);
	if (GetLastError() == 0) {
		m_is_open = true;

		NOTIFYICONDATA nid = { 0 };
		nid.cbSize = sizeof(nid);
		nid.hWnd = wnd;
		nid.uCallbackMessage = WM_NIMSG;
		nid.uVersion = NOTIFYICON_VERSION;
		nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
		nid.hIcon = (HICON)LoadImageW(wc.hInstance, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON, 16, 16, LR_DEFAULTSIZE | LR_SHARED);

		wcscpy_s(nid.szTip, ARRAYSIZE(nid.szTip), L"Firewall Notifier");
		b32 tray = Shell_NotifyIconW(NIM_ADD, &nid);

		m_monitor.start();
		HANDLE thread = CreateThread(0, 0, notifier_thread_callback, this, 0, 0);

		MSG msg = { 0 };
		while (m_is_open && GetMessageW(&msg, nullptr, 0, 0)) {
			if (IsDialogMessageW(wnd, &msg) == FALSE) {
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
			}
		}

		m_monitor.stop();

		if (m_tray_menu) {
			DestroyMenu(m_tray_menu);
		}

		if (tray) {
			Shell_NotifyIconW(NIM_DELETE, &nid);
		}

		WaitForSingleObject(thread, INFINITE);
	}

	DestroyWindow(wnd);
	UnregisterClassW(wc.lpszClassName, wc.hInstance);
}

LRESULT App::handle_msg(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
	switch (msg) {
		case WM_CLOSE:
		{
			m_is_open = false;
		} break;

		case WM_COMMAND:
		{
			switch (LOWORD(wp)) {
				case ID_EXIT:
				{
					m_is_open = FALSE;
				} break;

				case ID_RULES:
				{
					static wchar_t command[MAX_EXT_PATH + 1];

					if (SHGetFolderPathW(NULL, CSIDL_SYSTEM, NULL, SHGFP_TYPE_DEFAULT, command) == S_OK) {
						if (wcscat_s(command, MAX_EXT_PATH, L"\\mmc.exe wf.msc") == 0) {
							STARTUPINFOW si = { 0 };
							si.cb = sizeof(si);

							PROCESS_INFORMATION pi = { 0 };
							if (CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
								CloseHandle(pi.hThread);
								CloseHandle(pi.hProcess);
							}
						}
					}
				} break;

				case ID_DISABLE_FIREWALL:
				{
					m_firewall.set_filtering(false);
				} break;

				case ID_ENABLE_FIREWALL:
				{
					m_firewall.set_filtering(true);
				} break;
			}
		} break;

		case WM_NIMSG:
		{
			switch (lp) {
				case WM_LBUTTONDOWN:
				{
					SendMessageW(wnd, WM_COMMAND, MAKEWPARAM(ID_RULES, 0), 0);
				} break;

				case WM_RBUTTONDOWN:
				{
					POINT p = { 0 };
					if (GetCursorPos(&p) == FALSE) {
						break;
					}

					if (m_tray_menu) {
						DestroyMenu(m_tray_menu);
					}

					m_tray_menu = CreatePopupMenu();
					if (m_tray_menu == nullptr) {
						break;
					}

					AppendMenuW(m_tray_menu, MF_DEFAULT | MF_STRING, ID_RULES, L"Rules");

					if (m_firewall.is_filtering()) {
						AppendMenuW(m_tray_menu, MF_CHECKED | MF_STRING, ID_DISABLE_FIREWALL, L"Toggle Firewall");
					} else {
						AppendMenuW(m_tray_menu, MF_UNCHECKED | MF_STRING, ID_ENABLE_FIREWALL, L"Toggle Firewall");
					}

					AppendMenuW(m_tray_menu, MF_SEPARATOR, 0, NULL);
					AppendMenuW(m_tray_menu, MF_STRING, ID_EXIT, L"Exit");
					SetMenuDefaultItem(m_tray_menu, ID_RULES, FALSE);

					SetForegroundWindow(wnd);
					TrackPopupMenu(m_tray_menu, TPM_LEFTBUTTON, p.x, p.y, 0, wnd, NULL);
				} break;
			}
		} break;
	}

	return DefWindowProcW(wnd, msg, wp, lp);
}

LRESULT CALLBACK App::handle_msg_callback(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
	App* app = (App*)GetWindowLongPtrW(wnd, GWLP_USERDATA);
	if (app) {
		return app->handle_msg(wnd, msg, wp, lp);
	}

	return DefWindowProcW(wnd, msg, wp, lp);
}

DWORD App::notifier_thread() {
	WCHAR* path;
	while (m_monitor.receive(&path)) {
		if (m_firewall.has_rule(path)) {
			continue;
		}

		NotifierAction action = m_notifier.show(path);
		if (action == NotifierActionSkip) {
			continue;
		}

		if (m_firewall.add_rule(path, (action == NotifierActionAllow)) == false) {
			MessageBoxW(0, L"Error adding rule to firewall.", L"Error", MB_OK);
		}
	}

	return 0;
}

DWORD WINAPI App::notifier_thread_callback(LPVOID context) {
	App* app = (App*)context;
	if (app) {
		return app->notifier_thread();
	}

	return 0;
}
