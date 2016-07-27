#include "firewall.h"
#include "wstr.h"
#include <assert.h>
#include <stdlib.h>

// Minimum time to wait before rebuilding the cache, in milliseconds.
static const ULONGLONG CACHE_AGE = 300000;

// Maximum numebr of buckets in the block cache hash table.
static const size_t CACHE_SIZE = 257;

// Window firewall built-in profiles.
static NET_FW_PROFILE_TYPE2 const PROFILE_TYPES[] = {
	NET_FW_PROFILE2_PUBLIC,
	NET_FW_PROFILE2_PRIVATE,
	NET_FW_PROFILE2_DOMAIN
};

// Returns true if the rule is valid for the rule cache.
static b32 is_valid_rule(INetFwRule* rule) {
	assert(rule);

	NET_FW_RULE_DIRECTION dir;
	if (FAILED(rule->get_Direction(&dir)) || dir == NET_FW_RULE_DIR_IN) {
		return false;
	}

	VARIANT_BOOL status;
	if (FAILED(rule->get_Enabled(&status)) || status != VARIANT_TRUE) {
		return false;
	}

	bool result = false;

	BSTR ports;
	if (SUCCEEDED(rule->get_LocalPorts(&ports))) {
		NET_FW_ACTION action;
		if (SUCCEEDED(rule->get_Action(&action))) {
			if (action == NET_FW_ACTION_BLOCK || (action == NET_FW_ACTION_ALLOW && (ports == NULL || wcscmp(ports, L"*") == 0))) {
				result = true;
			}
		}

		SysFreeString(ports);
	}

	return result;
}

Firewall::Firewall() {
	m_cache = (FirewallRule**)calloc(CACHE_SIZE, sizeof(*m_cache));
	if (m_cache == nullptr) {
		return;
	}

	if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&m_policy)))) {
		return;
	}

	if (FAILED(m_policy->get_Rules(&m_rules))) {
		return;
	}

	for (size_t i = 0; i < COUNT(PROFILE_TYPES); ++i) {
		m_policy->put_FirewallEnabled(PROFILE_TYPES[i], VARIANT_TRUE);
	}

	set_filtering(true);
	m_is_initialized = true;
}

Firewall::~Firewall() {
	if (m_rules) {
		m_rules->Release();
	}

	if (m_policy) {
		m_policy->Release();
	}

	free(m_cache);
}

b32 Firewall::add_rule(WCHAR const* path, b32 is_allowed) {
	assert(path);

	if (m_is_initialized == false) {
		return false;
	}

	INetFwRule* rule;
	if (FAILED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&rule)))) {
		return false;
	}

	bool result = false;

	BSTR com_path = SysAllocString(path);
	if (com_path) {
		rule->put_Name(com_path);
		rule->put_ApplicationName(com_path);
		rule->put_Profiles(NET_FW_PROFILE2_ALL);
		rule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
		rule->put_Direction(NET_FW_RULE_DIR_OUT);
		rule->put_Enabled(VARIANT_TRUE);
		rule->put_Action(is_allowed ? NET_FW_ACTION_ALLOW : NET_FW_ACTION_BLOCK);

		HRESULT hr = m_rules->Add(rule);
		result = SUCCEEDED(hr);

		SysFreeString(com_path);
	}

	rule->Release();

	if (result == false) {
		cache_add_rule(path);
	}

	return result;
}

b32 Firewall::has_rule(WCHAR const * path) {
	assert(path);

	if (m_is_initialized == false) {
		return false;
	}

	ULONGLONG now = GetTickCount64();
	if (now - m_cache_age > CACHE_AGE) {
		cache_rebuild();
	}

	FirewallRule* rule = m_cache[wcshash(path) % CACHE_SIZE];
	while (rule) {
		if (wcscmp(path, rule->path) == 0) {
			return true;
		}

		rule = rule->next;
	}

	return false;
}

b32 Firewall::is_filtering() {
	if (m_is_initialized == false) {
		return false;
	}

	long profile;
	if (FAILED(m_policy->get_CurrentProfileTypes(&profile))) {
		return false;
	}

	for (size_t i = 0; i < COUNT(PROFILE_TYPES); ++i) {
		NET_FW_PROFILE_TYPE2 profile_type = PROFILE_TYPES[i];
		if ((profile & profile_type) != 0) {
			NET_FW_ACTION action;
			if (FAILED(m_policy->get_DefaultOutboundAction(profile_type, &action)) || action != NET_FW_ACTION_BLOCK) {
				return false;
			}
		}
	}

	return true;
}

b32 Firewall::set_filtering(b32 is_filtering) {
	if (m_is_initialized == false) {
		return false;
	}

	b32 result = true;
	for (size_t i = 0; i < COUNT(PROFILE_TYPES); ++i) {
		if (FAILED(m_policy->put_DefaultOutboundAction(PROFILE_TYPES[i], is_filtering ? NET_FW_ACTION_BLOCK : NET_FW_ACTION_ALLOW))) {
			result = false;
		}
	}

	return result;
}

void Firewall::cache_add_rule(WCHAR const* path) {
	assert(m_is_initialized);
	assert(path);

	size_t i = wcshash(path) % CACHE_SIZE;
	FirewallRule* rule = m_cache[i];

	while (rule) {
		if (wcscmp(path, rule->path) == 0) {
			return;
		}

		rule = rule->next;
	}

	rule = (FirewallRule*)malloc(sizeof(*rule));
	if (rule == nullptr) {
		return;
	}

	rule->path = _wcsdup(path);
	if (rule->path == nullptr) {
		free(rule);
		return;
	}

	rule->next = m_cache[i];
	m_cache[i] = rule;
}

void Firewall::cache_rebuild() {
	assert(m_is_initialized);

	IUnknown* temp;
	if (FAILED(m_rules->get__NewEnum(&temp))) {
		return;
	}

	IEnumVARIANT* enum_var;
	HRESULT hr = temp->QueryInterface(IID_PPV_ARGS(&enum_var));
	temp->Release();

	if (FAILED(hr)) {
		return;
	}

	for (;;) {
		ULONG fetched;
		VARIANT var;

		hr = enum_var->Next(1, &var, &fetched);
		if (FAILED(hr) || hr == S_FALSE) {
			break;
		}

		if (var.vt == VT_DISPATCH && var.pdispVal != NULL) {
			INetFwRule *rule;
			if (SUCCEEDED(var.pdispVal->QueryInterface(IID_PPV_ARGS(&rule)))) {
				if (is_valid_rule(rule)) {
					BSTR path;
					if (SUCCEEDED(rule->get_ApplicationName(&path)) && path) {
						_wcslwr(path);
						cache_add_rule(path);
						SysFreeString(path);
					}
				}

				rule->Release();
			}
		}

		VariantClear(&var);
	}
}
