# dns

DNS污染虽然很简单，但是却很管用，国内有很多无污染的DNS服务器，但却应对不了DNS抢答。DNS抢答大都只抢答UDP流量，因此将DNS设置成TCP查询可以缓解DNS抢答，配合国内支持的TCP流量的DNS服务器，可以有较好的上网体验。

## 安装

```sh
git clone https://github.com/Yee2/dns.git
cd dns
make && make install
```

### 快速生成`China IP`列表
```sh
curl https://ftp.apnic.net/stats/apnic/delegated-apnic-latest|grep "|CN|ipv4|" | awk -F '|' '{print $4 "/" 32-log($5)/log(2)}'
```
