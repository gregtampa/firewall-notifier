#pragma once
#include "core.h"
#include <Windows.h>
#include <fwpmu.h>
#include <fwptypes.h>

// Monitor outbound connection drop event callback. Passes back the device path and the user context data.
typedef void(*MonitorCallback)(WCHAR const* path, void* context);

// Windows firewall outbound connection monitor.
class Monitor {
public:
	// Creates the firewall monitor interface.
	Monitor();

	// Destroys the firewall monitor interface.
	~Monitor();

	// Blocks and receives a drop event notification for a path. Returns true on success, false otherwise.
	b32 receive(WCHAR** path);

	// Starts the firewall monitoring.
	void start();

	// Stops the firewall monitoring.
	void stop();

private:
	// Adds an item to the cache. Returns true if the item was added, false if the cache already contained the item.
	b32 cache(WCHAR const* path);

	// Handles a drop event for the item at the given path.
	void drop_event(WCHAR const* path);

	// Callback from the system to handle a drop event notification event from the firewall.
	static void CALLBACK drop_event_callback(_Inout_ void* context, _In_ const FWPM_NET_EVENT1* ev);

	// An item in the monitor cache.
	struct MonitorItem {
		WCHAR* path;
		ULONGLONG age;
	};

	CONDITION_VARIABLE m_queue_not_full;
	CONDITION_VARIABLE m_queue_not_empty;
	CRITICAL_SECTION m_cache_lock;
	CRITICAL_SECTION m_queue_lock;
	GUID m_session_key;
	HANDLE m_session = nullptr;
	HANDLE m_subscription = nullptr;
	MonitorItem* m_cache = nullptr;
	WCHAR** m_queue = nullptr;
	u32 m_queue_num = 0;
	u32 m_queue_ind = 0;
	b32 m_initialized = false;
};
