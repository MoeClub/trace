# trace
```
case `uname -m` in aarch64|arm64) VER="arm64";; x86_64|amd64) VER="amd64";; *) VER=`read -p "Arch:"`;; esac; wget -qO ./trace "https://raw.githubusercontent.com/MoeClub/trace/main/${VER}/linux/trace" && chmod a+x ./trace

./trace

```

# dest
```
	"北京电信:219.141.136.10:53",
	"北京联通:202.106.46.151:53",
	"北京移动:211.138.30.66:53",

	"上海电信:202.96.209.133:53",
	"上海联通:211.95.1.123:53",
	"上海移动:211.136.150.66:53",

	"广东电信:202.96.128.86:53",
	"广东联通:221.5.88.88:53",
	"广东移动:211.139.163.6:53",

	"湖北电信:202.103.0.68:53",
	"湖北联通:218.104.111.114:53",
	"湖北移动:211.137.58.20:53",

	"四川电信:218.6.200.139:53",
	"四川联通:119.6.6.6:53",
	"四川移动:211.137.82.4:53",

```
