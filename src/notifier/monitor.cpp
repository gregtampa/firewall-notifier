#include "monitor.h"
#include "wstr.h"
#include <stdlib.h>
#include <assert.h>
#include <wchar.h>

// Minimum time to wait before deleting a cached rule, in milliseconds.
static const ULONGLONG CACHE_AGE = 60000;

// Maximum number of paths in the cachce.
static const size_t CACHE_SIZE = 32;

// Maximum number of items in the queue.
static const size_t QUEUE_SIZE = 1024;

// Maps the given device path to a real path on the system and returns the resulting path.
static WCHAR* map_path(WCHAR const* path) {
	WCHAR* device = (WCHAR*)calloc(MAX_EXT_PATH + 1, sizeof(*device));
	if (device == nullptr) {
		return nullptr;
	}

	size_t real_size = wcslen(path) + 1;
	WCHAR* real_path = (WCHAR*)calloc(real_size, sizeof(*real_path));
	if (real_path == nullptr) {
		free(device);
		return nullptr;
	}

	DWORD drives = GetLogicalDrives();
	for (DWORD i = 0; i < 26; ++i) {
		if ((drives & (0x1 << i)) == 0) {
			continue;
		}

		WCHAR drive[4];
		drive[0] = L'a' + (wchar_t)i;
		drive[1] = L':';
		drive[2] = L'\0';

		if (QueryDosDeviceW(drive, device, MAX_EXT_PATH) == 0) {
			continue;
		}

		_wcslwr(device);
		drive[2] = L'\\';
		drive[3] = L'\0';

		size_t c = 0;
		while (path[c] && device[c] && towlower(path[c]) == device[c]) {
			c += 1;
		}

		if (path[c] == 0 || device[c]) {
			continue;
		}

		wcsmerge(real_path, real_size, drive, (wchar_t const*)(path + c + 1));
		free(device);

		return real_path;
	}

	free(real_path);
	free(device);

	return nullptr;
}

Monitor::Monitor() {
	m_queue = (WCHAR**)calloc(QUEUE_SIZE, sizeof(*m_queue));
	if (m_queue == nullptr) {
		return;
	}

	m_cache = (MonitorItem*)calloc(CACHE_SIZE, sizeof(*m_cache));
	if (m_cache == nullptr) {
		return;
	}

	FWPM_SESSION0 session_desc = {};
	session_desc.displayData.name = L"Firewall Notifier";
	session_desc.displayData.description = L"Outbound connection monitoring.";

	if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session_desc, &m_session) != ERROR_SUCCESS) {
		return;
	}

	FWP_VALUE0 val = {};
	val.type = FWP_UINT32;
	val.uint32 = 1;

	if (FwpmEngineSetOption0(m_session, FWPM_ENGINE_COLLECT_NET_EVENTS, &val) != ERROR_SUCCESS) {
		return;
	}

	InitializeCriticalSection(&m_cache_lock);
	InitializeCriticalSection(&m_queue_lock);
	InitializeConditionVariable(&m_queue_not_empty);
	InitializeConditionVariable(&m_queue_not_full);

	m_initialized = true;
}

Monitor::~Monitor() {
	stop();

	if (m_session) {
		DeleteCriticalSection(&m_queue_lock);
		DeleteCriticalSection(&m_cache_lock);

		FWP_VALUE0 val = {};
		val.type = FWP_UINT32;
		val.uint32 = 0;

		FwpmEngineSetOption0(m_session, FWPM_ENGINE_COLLECT_NET_EVENTS, &val);
	}

	if (m_cache) {
		for (size_t i = 0; i < CACHE_SIZE; ++i) {
			free(m_cache[i].path);
		}

		free(m_cache);
	}

	if (m_queue) {
		for (size_t i = 0; i < QUEUE_SIZE; ++i) {
			free(m_queue[i]);
		}

		free(m_queue);
	}
}

b32 Monitor::receive(WCHAR** path) {

	EnterCriticalSection(&m_queue_lock);

	while (m_queue_num == 0 && m_subscription) {
		SleepConditionVariableCS(&m_queue_not_empty, &m_queue_lock, INFINITE);
	}

	if (m_subscription == nullptr && m_queue_num == 0) {
		LeaveCriticalSection(&m_queue_lock);
		return false;
	}

	*path = m_queue[m_queue_ind];
	--m_queue_num;
	++m_queue_ind;

	if (m_queue_ind == QUEUE_SIZE) {
		m_queue_ind = 0;
	}

	LeaveCriticalSection(&m_queue_lock);
	WakeConditionVariable(&m_queue_not_full);

	return true;
}

void Monitor::start() {
	if (m_initialized == false) {
		return;
	}

	FWPM_NET_EVENT_SUBSCRIPTION0 sub_desc = {};
	sub_desc.sessionKey = m_session_key;
	FwpmNetEventSubscribe0(m_session, &sub_desc, drop_event_callback, (void*)this, &m_subscription);
}

void Monitor::stop() {
	if (m_session && m_subscription) {
		FwpmNetEventUnsubscribe0(m_session, m_subscription);

		EnterCriticalSection(&m_queue_lock);
		m_subscription = nullptr;
		LeaveCriticalSection(&m_queue_lock);

		WakeAllConditionVariable(&m_queue_not_full);
		WakeAllConditionVariable(&m_queue_not_empty);
	}
}

b32 Monitor::cache(WCHAR const* path) {
	assert(m_initialized);
	assert(path);

	ULONGLONG now = GetTickCount64();
	ULONGLONG oldest_age = MAXUINT64;
	size_t oldest_ind = 0;

	for (size_t i = 0; i < CACHE_SIZE; ++i) {
		MonitorItem* item = m_cache + i;

		if (item->age < oldest_age) {
			oldest_age = item->age;
			oldest_ind = i;
		}

		if (item->path == nullptr) {
			continue;
		}

		if (now - item->age < CACHE_AGE && wcscmp(item->path, path) == 0) {
			return false;
		}
	}

	MonitorItem* item = m_cache + oldest_ind;

	free(item->path);
	item->path = _wcsdup(path);
	item->age = item->path ? now : 0;

	return true;
}

void Monitor::drop_event(WCHAR const* path) {
	EnterCriticalSection(&m_cache_lock);
	b32 cache_result = cache(path);
	LeaveCriticalSection(&m_cache_lock);

	if (cache_result == false) {
		return;
	}

	WCHAR* real_path = map_path(path);
	if (real_path == nullptr) {
		return;
	}

	EnterCriticalSection(&m_queue_lock);

	while (m_queue_num == QUEUE_SIZE && m_subscription) {
		SleepConditionVariableCS(&m_queue_not_full, &m_queue_lock, INFINITE);
	}

	if (m_subscription == nullptr) {
		LeaveCriticalSection(&m_queue_lock);
		return;
	}

	m_queue[(m_queue_ind + m_queue_num) % QUEUE_SIZE] = real_path;
	++m_queue_num;

	LeaveCriticalSection(&m_queue_lock);
	WakeConditionVariable(&m_queue_not_empty);
}

void CALLBACK Monitor::drop_event_callback(_Inout_ void* context, _In_ const FWPM_NET_EVENT1* ev) {
	if (context == nullptr || ev == nullptr) {
		return;
	}

	if (ev->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) {
		return;
	}

	if ((ev->header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) == 0 || ev->header.appId.data == nullptr) {
		return;
	}

	Monitor* monitor = (Monitor*)context;
	monitor->drop_event((WCHAR*)ev->header.appId.data);
}
