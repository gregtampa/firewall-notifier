#include "app.h"
#include <Windows.h>


// Entry point for the notifier.
int CALLBACK WinMain(_In_ HINSTANCE instance, _In_ HINSTANCE prev, _In_ LPSTR line, _In_ int show) {
	if (FAILED(CoInitializeEx(0, COINIT_MULTITHREADED))) {
		MessageBoxW(0, L"Could not initialize COM.", L"Error", MB_OK);
		return 0;
	}

	App app;
	app.run();

	return 0;
}
