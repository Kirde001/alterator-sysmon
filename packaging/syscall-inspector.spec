Name:           syscall-inspector
Version:        1.0
Release:        1
Summary:        eBPF-based syscall data collector
License:        GPL
Group:          System/Base
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz

Requires:       python3-module-bcc

%description
An eBPF-based service for monitoring syscalls

%package -n alterator-sysmon
Summary:        Alterator module for syscall monitoring
Group:          System/Configuration
Requires:       %{name} = %{version}-%{release}
Requires:       alterator

%description -n alterator-sysmon
Alterator module to view data collected by the syscall inspector service

%prep
%setup -q -n %{_builddir_name}

%build

%install
make install DESTDIR=%{buildroot}

%files
/usr/sbin/syscall-inspector.py
/usr/lib/systemd/system/syscall-inspector.service
%config(noreplace) /etc/syscall-inspector/config.conf
%config(noreplace) /etc/syscall-inspector/rules.json

%files -n alterator-sysmon
/usr/share/alterator/applications/sysmon.desktop
/usr/share/applications/sysmon-launcher.desktop
/usr/share/alterator/ui/sysmon/
/usr/lib/alterator/backend3/sysmon
/usr/share/alterator/help/ru_RU/sysmon.html
/usr/share/alterator/help/en_US/sysmon.html

%post
%systemd_post syscall-inspector.service

%preun
%systemd_preun syscall-inspector.service

%postun
%systemd_postun_with_restart syscall-inspector.service
