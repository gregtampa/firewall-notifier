# firewall-notifier

![picture alt](https://raw.githubusercontent.com/nkga/firewall-notifier/master/doc/img/notification.png "Notification sample")

Installation and dependency free firewall notification app for Windows 7.1+, written in C++.

### Background
Windows provides notifications for inbound connections that are blocked, but not outbound connections.
The outbound blocking capability is also typically disabled in the stock Windows Firewall.

This application provides an easy mechanism to run the stock firewall with outbound blocking enabled by default,
while providing the convenience of notifications for adding rules to the firewall as applications need them.

### Usage

1. If running a non-standard system configuration, ensure `User Account Control` and `Windows Firewall` are enabled.
2. Run the application.

### Notes

- On application startup, all firewall profiles are set to enabled with outbound connection blocking on.
- Manual modification of firewall rules may take a few minutes to propagate to the application's cache.

### Building

1. Install [Visual Studio 2015](https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx).
2. Open `firewall.sln`.
3. Change solution configuration to `Release`.
4. Build solution.
