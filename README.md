# dns

DNS污染虽然很简单，但是却很管用，国内有很多无污染的DNS服务器，但却应对不了DNS抢答。DNS抢答大都只抢答UDP流量，因此将DNS设置成TCP查询可以缓解DNS抢答，配合国内支持的TCP流量的DNS服务器，可以有较好的上网体验。

## 用法

```sh
git clone https://github.com/Yee2/dns.git
cd dns
make
```
需要安装`Go`，默认配置文件屏蔽了Baidu的网址，推荐使用清华大学的DNS配置文件`dns-list/101.6.6.6.toml`，复制到`/etc/my-dns/config.toml`覆盖。
