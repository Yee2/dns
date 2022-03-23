all : build install

.PHONY : build
build :
	go get
	go build

.PHONY : install
install :
	cp dns /usr/bin/my-dns
	cp my-dns.service /etc/systemd/system/my-dns.service
	mkdir -p /etc/my-dns/
	cp config.toml /etc/my-dns/config.toml
	systemctl daemon-reload

.PHONY : uninstall
uninstall :
	rm -f /usr/bin/my-dns
	systemctl disable my-dns.service
	rm -f /etc/systemd/system/my-dns.service
	systemctl daemon-reload

.PHONY : clean
clean :
	rm dns

