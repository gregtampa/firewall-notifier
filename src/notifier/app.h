#pragma once
#include "core.h"
#include "firewall.h"
#include "monitor.h"
#include "notifier.h"

// Firewall notifier application.
class App {
public:
	// Creates the notifier application.
	App();

	// Destroys the notifier application.
	~App();

	// Runs the notifier application.
	void run();

private:
	// Handles a Win32 message.
	LRESULT handle_msg(HWND wnd, UINT msg, WPARAM wp, LPARAM lp);

	// Callback for handling Win32 messages.
	static LRESULT CALLBACK handle_msg_callback(HWND wnd, UINT msg, WPARAM wp, LPARAM lp);

	// Notification thread routine.
	DWORD notifier_thread();

	// Notification thread routine callback.
	static DWORD WINAPI notifier_thread_callback(LPVOID context);

	Firewall m_firewall;
	Monitor m_monitor;
	Notifier m_notifier;
	HMENU m_tray_menu = nullptr;
	b32 m_is_open = false;
};
