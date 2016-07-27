#include "notifier.h"
#include "resource.h"
#include <windowsx.h>
#include <shellapi.h>
#include <ShlObj.h>

// Notification window commands.
#define ID_ALLOW 101
#define ID_BLOCK 102
#define ID_SKIP 103
#define ID_OPEN_PATH 104

// Notifier class name.
static WCHAR const CLASS_NAME[] = L"firewall_notifier_class";

// Window element positions.
static RECT INFO_RECT = { 46, 7, 246, 19 };
static RECT PATH_RECT = { 46, 26, 246, 38 };
static RECT ICON_RECT = { 7, 7, 38, 38 };

Notifier::Notifier() {
	INITCOMMONCONTROLSEX icex = {};
	icex.dwSize = sizeof(icex);
	icex.dwICC = ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);

	m_instance = GetModuleHandleW(nullptr);
	m_app_icon = LoadIconW(m_instance, MAKEINTRESOURCEW(IDI_ICON1));

	WNDCLASS wc = { 0 };
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
	wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	wc.hIcon = m_app_icon;
	wc.hInstance = m_instance;
	wc.lpfnWndProc = handle_msg_callback;
	wc.lpszClassName = CLASS_NAME;
	wc.cbWndExtra = sizeof(Notifier*);

	NONCLIENTMETRICS ncm = { 0 };
	ncm.cbSize = sizeof(ncm);
	if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
		m_font = CreateFontIndirectW(&ncm.lfMessageFont);

		ncm.lfMessageFont.lfUnderline = TRUE;
		m_font_underlined = CreateFontIndirectW(&ncm.lfMessageFont);
	}

	m_is_class_registered = (RegisterClassW(&wc) != 0);
}

Notifier::~Notifier() {
	if (m_font_underlined) {
		DeleteObject(m_font_underlined);
	}

	if (m_font) {
		DeleteObject(m_font);
	}

	if (m_app_icon) {
		DestroyIcon(m_app_icon);
	}

	if (m_is_class_registered) {
		UnregisterClassW(CLASS_NAME, m_instance);
	}
}

NotifierAction Notifier::show(WCHAR const * path) {
	NotifierAction action = NotifierActionSkip;

	if (path == nullptr) {
		return action;
	}

	RECT screen = { 0 };
	if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &screen, 0) == FALSE) {
		screen.right = 0;
		screen.bottom = 0;
	}

	DWORD style = WS_POPUP | WS_SYSMENU | WS_BORDER;
	RECT window = { 0, 0, 253, 76 };
	AdjustWindowRect(&window, style, FALSE);

	i32 window_width = (window.right - window.left);
	i32 window_height = (window.bottom - window.top);
	i32 window_x = screen.right - window_width - 11;
	i32 window_y = screen.bottom - window_height - 11;

	HWND wnd = CreateWindowExW(
		WS_EX_TOPMOST, CLASS_NAME, L"Firewall Notification", style,
		window_x, window_y, window_width, window_height,
		nullptr, nullptr, m_instance, nullptr);

	if (wnd == nullptr) {
		return action;
	}

	SetLastError(0);
	SetWindowLongPtrW(wnd, GWLP_USERDATA, (LONG_PTR)this);
	if (GetLastError()) {
		return action;
	}

	m_path = path;
	m_is_open = true;

	m_path_icon = ExtractIconW(nullptr, path, 0);
	if (m_path_icon == nullptr) {
		m_path_icon = (HICON)LoadImageW(nullptr, IDI_APPLICATION, IMAGE_ICON, 32, 32,
			LR_DEFAULTSIZE);
	}

	HWND tooltip = CreateWindowExW(
		WS_EX_TOPMOST, TOOLTIPS_CLASSW,
		nullptr,
		TTS_NOANIMATE | TTS_ALWAYSTIP | TTS_NOPREFIX | WS_POPUP,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		wnd, nullptr, m_instance, nullptr);

	SetWindowPos(tooltip, HWND_TOPMOST, 0, 0, 0, 0,
		SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

	TOOLINFO ti = { 0 };
	ti.cbSize = sizeof(ti);
	ti.uFlags = TTF_SUBCLASS;
	ti.hwnd = wnd;
	ti.lpszText = (LPWSTR)path;
	ti.rect = PATH_RECT;

	SendMessageW(tooltip, TTM_ADDTOOL, 0, (LPARAM)&ti);

	CreateWindowExW(
		0, WC_BUTTONW,
		L"Allow",
		WS_VISIBLE | WS_CHILD,
		7, 46, 75, 23,
		wnd, (HMENU)ID_ALLOW, m_instance, nullptr);

	CreateWindowExW(
		0, WC_BUTTONW,
		L"Block",
		WS_VISIBLE | WS_CHILD,
		89, 46, 75, 23,
		wnd, (HMENU)ID_BLOCK, m_instance, nullptr);

	CreateWindowExW(
		0, WC_BUTTONW,
		L"Skip",
		WS_VISIBLE | WS_CHILD,
		171, 46, 75, 23,
		wnd, (HMENU)ID_SKIP, m_instance, nullptr);

	for (HWND temp = GetTopWindow(wnd); temp; temp = GetWindow(temp, GW_HWNDNEXT)) {
		SendMessageW(temp, WM_SETFONT, (WPARAM)m_font, TRUE);
	}

	ShowWindow(wnd, SW_SHOW);

	FLASHWINFO fi = { 0 };
	fi.cbSize = sizeof(fi);
	fi.hwnd = wnd;
	fi.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
	FlashWindowEx(&fi);

	MSG msg;
	while (m_is_open && GetMessageW(&msg, nullptr, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}

	action = m_action;

	if (m_path_icon) {
		DestroyIcon(m_path_icon);
	}

	DestroyWindow(tooltip);
	DestroyWindow(wnd);

	return action;
}

LRESULT Notifier::handle_msg(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
	switch (msg) {
		case WM_CLOSE:
		{
			m_is_open = false;
		} return 0;

		case WM_COMMAND:
		{
			DWORD id = LOWORD(wp);
			switch (id) {
				case ID_ALLOW:
				{
					m_action = NotifierActionAllow;
					m_is_open = false;
				} break;

				case ID_BLOCK:
				{
					m_action = NotifierActionBlock;
					m_is_open = false;
				} break;

				case ID_SKIP:
				{
					m_action = NotifierActionSkip;
					m_is_open = false;
				} break;

				case ID_OPEN_PATH:
				{
					LPITEMIDLIST idl = ILCreateFromPathW(m_path);
					if (idl) {
						SHOpenFolderAndSelectItems(idl, 0, nullptr, 0);
						ILFree(idl);
					}
				} break;
			}

		} break;

		case WM_LBUTTONDOWN:
		{
			POINT p;
			p.x = GET_X_LPARAM(lp);
			p.y = GET_Y_LPARAM(lp);

			if (PtInRect(&PATH_RECT, p) || PtInRect(&ICON_RECT, p)) {
				SendMessageW(wnd, WM_COMMAND, LOWORD(ID_OPEN_PATH), 0);
			}
		} break;

		case WM_PAINT:
		{
			PAINTSTRUCT ps = { 0 };
			HDC dc = BeginPaint(wnd, &ps);

			SetBkMode(dc, OPAQUE);
			SetBkColor(dc, GetSysColor(COLOR_MENU));

			SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
			SelectObject(dc, m_font);
			DrawTextW(dc, L"Outbound connection was blocked:", -1, &INFO_RECT, DT_SINGLELINE | DT_WORD_ELLIPSIS | DT_NOCLIP);

			SetTextColor(dc, GetSysColor(COLOR_HOTLIGHT));
			SelectObject(dc, m_font_underlined);
			DrawTextW(dc, m_path, -1, &PATH_RECT, DT_SINGLELINE | DT_PATH_ELLIPSIS | DT_NOCLIP);

			if (m_path_icon) {
				DrawIconEx(dc, 7, 7, m_path_icon, 32, 32, 0, nullptr, DI_NORMAL);
			}

			EndPaint(wnd, &ps);
		} break;
	}

	return DefWindowProcW(wnd, msg, wp, lp);
}

LRESULT CALLBACK Notifier::handle_msg_callback(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
	Notifier* notifier = (Notifier*)GetWindowLongPtrW(wnd, GWLP_USERDATA);
	if (notifier) {
		return notifier->handle_msg(wnd, msg, wp, lp);
	}

	return DefWindowProcW(wnd, msg, wp, lp);
}
