### 查看命令的符号表

如`bash`命令

查看命令位置 `which bash`

查看命令对应某位置的符号表 `nm -D /usr/bin/bash | grep readline`

目标使用 readline 查看用户输入了什么

将`cmd/sys/main.go` 内执行切为`sys.LoadBash()`

### 查看go函数返回

go函数需要有不同返回的可能，如判断，不然写死了查不到这个函数

将`cmd/sys/main.go` 内执行切为`sys.LoadGolangFunc()`

`go build -o http cmd/http/main.go`

查看`nm http | grep main`

运行 `./http`

`go run cmd/sys/main.go`

`curl "http://127.0.0.1:8899?id=12"`


> 截止v1.0

### 监听docker网桥两个 docker 的网络访问

`docker-compose up -d nginx1`
`docker-compose up -d nginx2`
`go run cmd/dockerxdp/main.go`
`docker-compose exec nginx1 bash`
`curl nginx2`


### 使用tc监听网络 
`go run cmd/tc/main.go`
`cat /sys/kernel/debug/tracing/trace_pipe`

这次请求的容器必须是使用了docker0网卡网段的地址`curl 172.17.0.2`

截止v1.1

### 修改转发端口 

`go run cmd/tc/main.go`

必须进入其中一个docker内访问另一个docker,
`docker-compose exec nginx2 bash` 

在`nginx2`内访问`curl 172.18.0.3:8080` ，此时会将8080端口转发到80端口上

以上代码是有一个监听80端口的`nginx`,并且在C代码中写死了，在去向为72.18.0.3，并且端口为8080的请求，转发到端口80上，如果这些ip或者端口不一样要修改C代码

截止v1.2

### arping
`go run cmd/arp/main.go`
`cat /sys/kernel/debug/tracing/trace_pipe`
`docker-compose exec nginx1 arping -i eth0 nginx2`

1请求arp 2相应arp

截止v1.3

### arping提取ip地址
`go run ../cmd/arp/main.go`

`docker-compose exec nginx1 arping -i eth0 nginx2`

截止v1.4

### 使用go实现mac欺骗 

库的依赖 `apt install libpcap-dev`

`go run cmd/arp/main.go`

`docker-compose exec nginx1 arping 172.18.0.9`

实际上 172.18.0.9 并不存在，只是程序接收到 172.18.0.9 的arp请求后，伪装了个返回
截止v1.5
