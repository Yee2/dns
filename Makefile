all : build install

.PHONY : build
build :
    go get
	go build

.PHONY : install
install :
	sudo cp dns /usr/bin/my-dns
	sudo cp my-dns.service /etc/systemd/system/my-dns.service
	- sudo mkdir /etc/my-dns/
	sudo cp config.toml /etc/my-dns/config.toml
	sudo systemctl daemon-reload

.PHONY : uninstall
uninstall :
	- sudo rm /usr/bin/my-dns
	sudo systemctl disable my-dns.service
	- sudo rm /etc/systemd/system/my-dns.service
	sudo systemctl daemon-reload

.PHONY : clean
clean :
	rm dns

