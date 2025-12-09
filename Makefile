.PHONY: install

install:
	# service
	install -d $(DESTDIR)/usr/sbin/
	install -m 0755 service/syscall-inspector.py $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/usr/lib/systemd/system/
	install -m 0644 service/syscall-inspector.service $(DESTDIR)/usr/lib/systemd/system/
	
	# config
	install -d $(DESTDIR)/etc/syscall-inspector/
	install -m 0644 service/config.conf $(DESTDIR)/etc/syscall-inspector/config.conf
	install -m 0644 service/rules.json $(DESTDIR)/etc/syscall-inspector/rules.json

	# UI
	install -d $(DESTDIR)/usr/share/alterator/ui/sysmon/
	install -m 0644 alterator/ui/*.scm $(DESTDIR)/usr/share/alterator/ui/sysmon/
	
	# backend
	install -d $(DESTDIR)/usr/lib/alterator/backend3/
	install -m 0755 alterator/backend/sysmon $(DESTDIR)/usr/lib/alterator/backend3/sysmon

	# help
	install -d $(DESTDIR)/usr/share/alterator/help/ru_RU/
	install -m 0644 alterator/ui/help/ru_RU/index.html $(DESTDIR)/usr/share/alterator/help/ru_RU/sysmon.html
	install -d $(DESTDIR)/usr/share/alterator/help/en_US/
	install -m 0644 alterator/ui/help/en_US/index.html $(DESTDIR)/usr/share/alterator/help/en_US/sysmon.html

	# desktop
	install -d $(DESTDIR)/usr/share/alterator/applications/
	install -m 0644 alterator/sysmon.desktop $(DESTDIR)/usr/share/alterator/applications/
	
	install -d $(DESTDIR)/usr/share/applications/
	install -m 0644 alterator/sysmon-launcher.desktop $(DESTDIR)/usr/share/applications/
