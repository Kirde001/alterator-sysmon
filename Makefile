install:
	# service
	install -d $(DESTDIR)/usr/sbin/
	install -m 0755 service/syscall-inspector.py $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/usr/lib/systemd/system/
	install -m 0644 service/syscall-inspector.service $(DESTDIR)/usr/lib/systemd/system/
	
	# config defaults
	install -d $(DESTDIR)/etc/syscall-inspector/
	install -m 0644 service/config.conf $(DESTDIR)/etc/syscall-inspector/config.conf
	install -m 0644 service/rules.json $(DESTDIR)/etc/syscall-inspector/rules.json

	# ui & backend
	install -d $(DESTDIR)/usr/share/alterator/ui/syscall-inspector/
	install -m 0644 alterator/ui/*.scm $(DESTDIR)/usr/share/alterator/ui/syscall-inspector/
	
	install -d $(DESTDIR)/usr/lib/alterator/backend3/
	install -m 0755 alterator/backend/syscall-inspector-backend $(DESTDIR)/usr/lib/alterator/backend3/syscall-inspector

	# help
	install -d $(DESTDIR)/usr/share/alterator/help/ru_RU/
	install -m 0644 alterator/ui/help/ru_RU/index.html $(DESTDIR)/usr/share/alterator/help/ru_RU/syscall-inspector.html
	
	install -d $(DESTDIR)/usr/share/alterator/help/en_US/
	install -m 0644 alterator/ui/help/en_US/index.html $(DESTDIR)/usr/share/alterator/help/en_US/syscall-inspector.html

	# desktop files
	install -d $(DESTDIR)/usr/share/alterator/applications/
	install -m 0644 alterator/syscall-inspector.desktop $(DESTDIR)/usr/share/alterator/applications/
	install -d $(DESTDIR)/usr/share/applications/
	install -m 0644 alterator/syscall-inspector-launcher.desktop $(DESTDIR)/usr/share/applications/
