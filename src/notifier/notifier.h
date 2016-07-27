#pragma once
#include "core.h"
#include <Windows.h>

// Notify dialog actions that the user can make.
enum NotifierAction {
	NotifierActionSkip,
	NotifierActionBlock,
	NotifierActionAllow
};

// Creates the notifier.
class Notifier {
public:
	// Creates a notifier.
	Notifier();

	// Destroys a notifier.
	~Notifier();

	// Shows a firewall notification for the given path. Reeturns the action that user requested.
	NotifierAction show(WCHAR const* path);

private:
	// Handles a Win32 message.
	LRESULT handle_msg(HWND wnd, UINT msg, WPARAM wp, LPARAM lp);

	// Callback for handling Win32 messages.
	static LRESULT CALLBACK handle_msg_callback(HWND wnd, UINT msg, WPARAM wp, LPARAM lp);

	HINSTANCE m_instance = nullptr;
	HFONT m_font = nullptr;
	HFONT m_font_underlined = nullptr;
	HICON m_app_icon = nullptr;
	HICON m_path_icon = nullptr;
	WCHAR const* m_path = nullptr;
	NotifierAction m_action = NotifierActionSkip;
	b32 m_is_class_registered = false;
	b32 m_is_open = false;
};
