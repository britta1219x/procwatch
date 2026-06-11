# procwatch

基于 eBPF/CO-RE 的轻量级 Linux 进程行为监控工具，运行于内核态，零侵入、低开销。

## 功能模块

### 模块一：进程创建监控 (execve_monitor)
- Hook `execve` 系统调用，实时捕获系统内所有进程创建事件
- 记录 PID、PPID、UID、进程名、可执行文件路径
- 可用于追踪异常进程启动、排查脚本执行链路

### 模块二：敏感文件访问监控 (openat_monitor)
- Hook `openat` 系统调用，检测对敏感路径的访问行为
- 覆盖 `/etc/passwd`、`/etc/shadow`、`/etc/sudoers`、`.ssh/` 等高风险路径
- 彩色告警输出，按敏感级别分类标注

## 技术栈

- **内核态**：C + eBPF (CO-RE)，使用 BTF + vmlinux.h 实现一次编译到处运行
- **用户态**：C + libbpf，Ring Buffer 异步事件传递
- **构建**：Clang + bpftool skeleton 自动生成加载代码

## 环境要求

- Linux 内核 >= 5.8（需支持 BTF 和 Ring Buffer）
- clang >= 11
- libbpf >= 0.6
- bpftool

## 编译与运行

```bash
# 编译
make

# 进程创建监控
sudo ./procwatch_execve

# 敏感文件访问监控
sudo ./procwatch_openat
```

## 输出示例
procwatch_execve
TIME     PID     PPID    UID   COMM             FILENAME

16:58:43 35468   35445   1000  bash             /usr/bin/su
16:58:44 35481   35468   0     su               /bin/bash
16:58:47 35514   35481   0     bash             /usr/bin/ls
procwatch_openat
ALERT     TIME     PID     UID   COMM             PATH

[PASSWD ] 17:02:01 35578   0     cat              /etc/passwd
[SHADOW ] 17:02:12 35579   0     cat              /etc/shadow

## 已知问题 / TODO

- [ ] openat_monitor 当前仅匹配相对路径前缀，绝对路径的 `.ssh/` 访问需补充完整路径匹配
- [ ] 待增加白名单机制，过滤已知合法进程的误报
- [ ] 待增加日志持久化输出（JSON 格式）
