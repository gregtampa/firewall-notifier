#pragma once
#include "core.h"
#include <netfw.h>

// Windows firewall interface for outbound connection blocking.
class Firewall {
public:
	// Creates the firewall interface.
	Firewall();

	// Destroys the firewall interface.
	~Firewall();

	// Adds a rule into the firewall. Returns true on success.
	b32 add_rule(WCHAR const* path, b32 is_allowed);

	// Returns true if the firewall already contains a rule for the application at the given path.
	b32 has_rule(WCHAR const* path);

	// Returns true if the firewall is currently filtering outbound requests.
	b32 is_filtering();

	// Sets the outbounding filtering state for the firewall.
	b32 set_filtering(b32 is_filtering);

private:
	// Inserts the given rule into the cache.
	void cache_add_rule(WCHAR const* path);

	// Rebuilds the cache.
	void cache_rebuild();

	// A cached firewall rule.
	struct FirewallRule {
		WCHAR* path;
		FirewallRule* next;
	};

	FirewallRule** m_cache = nullptr;
	INetFwPolicy2* m_policy = nullptr;
	INetFwRules* m_rules = nullptr;
	ULONGLONG m_cache_age = 0;
	b32 m_is_initialized = false;
};
