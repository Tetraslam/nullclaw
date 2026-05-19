# Zig 安装指南

## 优先使用打包好的安装方式

如果你已经在 macOS 或 Linux 上使用 Homebrew，最短路径是直接安装预构建的
NullClaw 包，不需要本地 Zig toolchain：

```bash
brew install nullclaw
```

只有在你想从源码构建 NullClaw，并且需要精确固定的 Zig 0.16.0 toolchain 时，
才需要使用下面的 Debian 步骤。

## Debian

以下步骤用于在全新的 Debian 系统上从官方 x86_64 Linux tar 包安装 Zig 0.16.0。
请以 root 身份执行 `apt` 命令；如果使用普通用户，请在每条命令前加上 `sudo`。

仓库里的 CI 和容器构建通过 `.github/scripts/install-zig.sh` 解析 Zig 下载信息。
本页保留手动 Debian 安装路径，方便用户在第一次源码构建前先装好 Zig。

1. 刷新软件包索引：

   ```bash
   apt update
   ```

2. 安装下载与解压所需的工具：

   ```bash
   apt install -y ca-certificates wget xz-utils
   ```

3. 访问 [ziglang.org/download](https://ziglang.org/download/) 并复制 Zig 0.16.0
   对应的下载链接。在常见的 Debian x86_64 机器上，使用 Linux `x86_64` 变体：

   [https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz](https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz)

4. 下载 tar 包：

   ```bash
   wget https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
   ```

5. 使用官方下载元数据里的校验和验证压缩包：

   ```bash
   printf '%s  %s\n' \
     70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00 \
     zig-x86_64-linux-0.16.0.tar.xz | sha256sum -c -
   ```

6. 解压：

   ```bash
   tar -xf zig-x86_64-linux-0.16.0.tar.xz
   ```

7. 把解压后的目录加入 `PATH`：

   ```bash
   export PATH="$PWD/zig-x86_64-linux-0.16.0:$PATH"
   ```

   如果希望新 shell 也能直接使用 Zig，请把同一条 `export` 命令写入你的 shell
   profile，并使用解压目录的绝对路径。

8. 验证精确版本：

   ```bash
   zig version
   ```

   输出必须是 `0.16.0`。
