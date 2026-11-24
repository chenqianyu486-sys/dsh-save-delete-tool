# dsh-safe-delete-tool

为 **DeepSeek Harness（DSH）** 提供的可恢复删除插件。

它不试图枚举所有危险的 shell 写法。它改变删除这个原语：删除走 `delete_file`，
目标被移动进工作区隔离区并返回 `trash_id`；`restore_file` 可以撤回，
`list_trash` 显示还有什么可恢复。守卫只做一件事——在工具调用进入执行前，
判断它是不是一次不可恢复的删除，并告诉模型改用 `delete_file`。

这里取的是 MiniMax Code CLI 的目标，而不是它的机制。MiniMax 做的是执行层改写：
权限层把 `rm` 的 argv 换成宿主自带的 `mavis-trash`，再在 `PATH` 最前面放一个 `rm`
垫片，所以脚本、`xargs` 里的删除也进宿主回收站，垫片缺失时干脆拒绝启动 bash。
DSH 没有这个钩子——`tools/pre-execute` 明确不能改写 `exec.arguments`，插件也无法
给 shell 注入 `PATH`——所以这里把“可恢复”落在结构化工具上，把“不可恢复的写法”
留给一个纯文本、无文件系统访问的判断层。

## 组成

- 3 个 Host 工具：`delete_file`、`restore_file`、`list_trash`
- 1 个 `tools/pre-execute` 引导式拒绝
- 1 个同步 `tools.guard` 兜底（审批之后仍然生效；三个工具、提示词、pre-execute 和 guard 只在三个工具全部注册成功时安装）
- 1 段系统提示词

没有前端、没有配置项、没有后台清理、没有保留期。

## 安装

本仓库就是一个完整的 DSH bundle（`package.json` 声明了 `dsh.bundle.patch`）：

```text
plugin_manager
  action: install_bundle
  target: <本目录的绝对路径>
```

或在桌面端：**插件管理 → 安装 → 从文件夹安装**。bundle 插入一条进程级条目
（`safe-delete`），所有 agent preset 都会拿到工具与守卫。不要再往某个 preset
里加第二份——工具名是全局的。

要求：DSH `>= 0.2.2-rc.3`（按 `0.2.2-rc.3` 验证），Node `>= 20`。没有 peer 依赖，也没有构建步骤。

## 工具

### `delete_file`

| 参数 | 默认值 | 含义 |
|---|---|---|
| `path` | 必填 | 工作区相对路径；工作区内的绝对路径也接受。 |
| `recursive` | `false` | 非空目录必须显式设为 `true`；空目录不需要。 |
| `reason` | — | 写入隔离区记录，`list_trash` 会显示。 |
| `dry_run` | `false` | 只报告类型、条目数以及是否需要 `recursive`，不移动任何东西。 |

成功返回 `trash_id`，撤销方式写在结果里。拒绝使用稳定错误码：
`RECURSIVE_FLAG_REQUIRED`、`PATH_OUTSIDE_WORKSPACE`、`PATH_PROTECTED`、
`PATH_ALIAS_UNSUPPORTED`、`REFUSE_WORKSPACE_ROOT`、`PATH_IN_TRASH`、`WORKSPACE_IS_FILESYSTEM_ROOT`、
`SANDBOX_READ_ONLY`、`SANDBOX_POLICY_UNAVAILABLE`、`TRASH_SOURCE_REMOVE_FAILED`。拿不到会话工作目录的调用
会被直接拒绝（`WORKSPACE_UNAVAILABLE`），不会拿 Host 进程目录去猜。

永远不可删：工作区根目录、包含受保护路径段（`.git`、`.dsh`、`.env`）的路径、
隔离区本身，以及把磁盘根目录当作工作区的情况。Windows 的 NTFS ADS
（`name:stream`）、末尾点/空格别名（`.git.`、`.env `）和 8.3 短名（`GIT~1`）会以
`PATH_ALIAS_UNSUPPORTED` 拒绝，而不是按字面路径猜测（非 8.3 的常规含 `~` 文件名如
`project~2026.txt` 保持放行）。

### `restore_file`

| 参数 | 默认值 | 含义 |
|---|---|---|
| `trash_id` | 必填 | `delete_file` 返回或 `list_trash` 列出的标识。 |
| `overwrite` | `false` | 原路径已被占用时，把占用者移入隔离区后再恢复。 |

恢复会重新校验记录里的原始路径、重建工作区内缺失的父目录，并拒绝被篡改的记录。
它还会验证 `items/<id>` 是真实目录、`meta.json` 是普通文件，不跟随指向工作区外的
junction/symlink。条目被重定向或损坏时会返回 `TRASH_ITEM_OUTSIDE_WORKSPACE` /
`TRASH_ITEM_INVALID` / `TRASH_ITEM_UNREADABLE`；条目不存在仍是
`TRASH_ITEM_NOT_FOUND`。它不会静默覆盖已有文件：文件载荷会先硬链接到位，恢复过程中被
抢占的路径会以 `DESTINATION_EXISTS` 失败，条目仍留在隔离区；成功恢复会保留原文件
权限（Windows 的只读属性也会恢复）。`overwrite: true` 时被替换下来的文件会得到
新的 `trash_id` 一并返回，两边都可恢复。

### `list_trash`

| 参数 | 默认值 | 含义 |
|---|---|---|
| `query` | — | 对 id、原路径、原因做大小写不敏感过滤。 |
| `trash_id` | — | 只看某一个已知条目。 |
| `limit` | `10` | 返回条数（1–100）。 |
| `offset` | `0` | 跳过条数，用于翻页。 |

默认页故意很小：一次列 20 条的输出比三个工具定义加起来还贵。需要更多时模型会按
结果里的 `Next page` 提示翻页。

### 沙箱模式

`delete_file` 与 `restore_file` 用 `node:fs` 移动文件，不经过 DSH 的文件围栏，
所以它们自己读当次的沙箱策略：只读会话会被拒绝（`SANDBOX_READ_ONLY`）；
`workspace-write` 的牢笼是会话工作区（策略返回的 `workspaceRoot`），不是可变的
shell cwd，`cd` 不能把牢笼移出围栏；`danger-full-access` 行为不变。策略服务
存在但没有 `resolve()`、解析抛错、或返回本插件不认识的模式时 fail-closed
（`SANDBOX_POLICY_UNAVAILABLE`），宿主没有该服务时不设门槛。`dry_run` 预览和
`list_trash` 不做任何变更，始终可用；`list_trash` 不会创建或迁移隔离区；已存在的 1.x 隔离区会从 manifest
列出，由下一次变更操作迁移。

拒绝与工具错误会把稳定错误码写进消息（`[SANDBOX_READ_ONLY] …`），看日志即可
匹配，不必依赖进程内的错误对象。

## 隔离区

```
<workspace>/.dsh/trash/
  .gitignore              # 内容为 *，隔离区永不进 git
  items/
    <id>/
      meta.json           # 原路径、类型、原因、会话、时间、状态
      payload             # 被移动的文件或目录
```

**每个条目自己就是一条日志。** 没有共享 manifest，因此两个并行删除（或两个 dsh
进程）不会互相覆盖记录。删除顺序是：写 `pending` 记录 → 移动 payload → 改写
`trashed`；如果进程在中间崩溃，`pending` + payload 依然是一条可列出、可恢复的
完整条目。恢复前会逐项校验 `items/<id>` 和 `meta.json`，拒绝被 junction/symlink
重定向的条目。

id 形如 `20261114T094442123-abcd1234`：毫秒时间戳 + 随机后缀，同一进程内单调递增，
所以快速连续删除也能稳定按时间排序。

跨卷移动（`EXDEV`）降级为“复制 → 删除源”；复制失败时只清理复制出来的半成品，复制成功但删源失败时保留完整副本并报 `TRASH_SOURCE_REMOVE_FAILED`，
原文件不动。1.x 的 `manifest.json` + `items/<id>__name` 布局会在首次列出时
只读展示，由下一次变更操作迁移。迁移会先写 pending 再移动 archive；失败时
删除空的 item 目录、保留 manifest 和 archive 以便重试；payload 已落盘但 meta 未写时
会把它修成可列出、可恢复的条目，所以升级不会 strand 旧文件。

注意：`realpath` 与逐段 `lstat` 能拒绝路径层面的 junction/symlink，但不能证明
某个目录不是 Linux bind mount 或等价物理挂载；这类 mount point 和检查/使用之间的
竞态仍是已知残余风险，详见 SECURITY #26。

## 守卫

拒绝消息会带上插件版本（`[dsh-safe-delete-tool v2.0.6] …`），升级后旧模块仍在
守卫时一眼能看出来，而不是拿旧规则默默拦命令。

守卫按 **工具 schema 的形状**分类，而不是按工具名：

- 参数里有字符串 `command`（或 `cmd` / `commandLine`）→ shell 工具；
- 参数里有字符串 `code` → 程序工具（PTC 的 `run_code`）。

因此不需要为每个 preset 维护工具名清单：

| Agent 模式 | 该模式提供的相关工具 | 本插件的覆盖 |
|---|---|---|
| `standard`（标准） | `pwsh` / `bash` + `read/write/edit` | shell 守卫 |
| `ptc` | 上面的 shell + `run_code` | shell 守卫 + 程序守卫 |
| `minimal`（极简） | 持久化 `pwsh` | shell 守卫；工具仍全局可用 |
| `cordis`（创造） | `pwsh` + `cordis_inspect_*` | shell 守卫；只读检查工具没有 `command`/`code`，自然跳过 |

shell 工具会扫描**每一个**字符串参数（`description`、`workdir` 等元数据除外），
所以 `wsl(command: "bash", stdin: "rm -rf x")` 也会被看到。

会被拒绝的删除：

- POSIX：`rm`、`rmdir`、`unlink`、`shred`、`srm`，以及 `sudo`、`doas`、`env`
  （含 `env -S`）、`command`、`exec`、`nohup`、`nice`、`timeout`、`stdbuf`、
  `setsid`、`busybox`、`wsl`、`chroot`、`xargs`、`parallel`、`watch` 等包装；
  长选项/分离值、`nohup --`、`runuser --`、`su --session-command`，以及可能喂给
  shell 的进程替换也会覆盖；
- PowerShell：`Remove-Item` 及其别名（`rm`、`del`、`erase`、`rd`、`rmdir`、`ri`），
  `[System.IO.File]::Delete` / `[IO.Directory]::Delete`，实例方法
  `(Get-Item x).Delete()` / `FileInfo.Delete()`，包括管道、`ForEach-Object { ... }`、
  `& 'rm'`、`Start-Process` 启动 shell，以及 `-EncodedCommand`；
- cmd：`del`、`erase`、`rd`、`rmdir`、`cmd /c` 载荷，以及 `d^el` 这类 caret 转义名；
- 原生补丁删除：`apply_patch` 里的 `*** Delete File:` 段；
- 终端输入：可选 terminal bundle 的 `terminal_send`（typed shell text）；
- 整树删除：`find -delete`、`find -exec rm` / `find -exec env|sudo|command|busybox|xargs ...`；
  动态 `-exec` 命令（`$CMD`、`$(...)`）直接 fail-closed；`rsync --delete`、
  `robocopy /MIR|/PURGE`、`git clean -f`、`git rm`（`--cached` 除外）；
- 可读的内联载荷：`bash -c`、`sh -c`、`pwsh -Command`、`cmd /c`、`eval`、
  参数位置的命令替换与反引号、`python -c`（含 `from os import remove; remove(...)`）、
  `node -e`、`perl -e`、`ruby -e`、`php -r`、`lua -e`；载荷会递归分析，
  超过 3 层或超过 64 KB 直接拒绝；
- PTC 程序里调用绑定的 shell 工具执行可识别的删除
  （`pwsh({ command: "rm -rf build" })`）、通过 `Start-Process` 启动 shell，
  或嵌套调用 `run_code`。命令参数按字段读取；元数据和 argv 数据不会被当成命令。
  模块别名（`import`、`require`、`createRequire`、`fs.promises`）、方法别名和
  字面量命令拼接会 fail-closed。

**fail-closed**：解不出的 PowerShell `-EncodedCommand`、未闭合的引号或 heredoc、
从管道或重定向读程序的 shell（`curl … | bash`、`bash < run.sh`）、
喂给 shell 的进程替换（`bash <(…)`）、命令位置的 `$(...)` / 反引号、
动态 `find -exec` 命令、PowerShell `scriptblock::Create` 载荷，以及运行时拼接出来的
命令名（`$CMD`、`%COMSPEC%`）都不会被放行。

**放行的日常写法**：`echo "rm -rf"`、`git commit -m "rm -rf"`、
`grep -r "rm" docs`、`man rm`、`rm --help`、`git clean -n`、
`git rm --cached x`、`npm rm left-pad`、写到文件的 heredoc、
以及 `source venv/bin/activate`。

### 这层守卫不做什么

它**不是安全边界**。它只读命令文本，不读脚本文件：

- `bash deploy.sh`、`pwsh -File build.ps1`、`python main.py` 里的删除不在射程内；
- 运行时拼出来的字符串（`$cmd = 'Remove-Item'; & $cmd x`）、从网络下载的脚本、
  计算属性（`fs['rmSync']`）和二进制同样不在射程内。
- 磁盘擦除（`mkfs`、`dd`）、`git reset --hard` 这类“不是删除文件但会丢数据”的
  命令也不在本插件范围内；
- 终端输入按单次调用检查；拆成多次 `terminal_send` / `wsl-term` 的命令不会被
  重新拼接。

需要硬边界时使用 DSH 的沙箱与审批策略；本插件负责让日常删除可恢复、让明显的
不可恢复删除变得显眼。完整清单见 [SECURITY.md](SECURITY.md)。

## 为什么没有配置

删除原语的语义是固定的：工作区内的目标进 `.dsh/trash`，非空目录必须显式
`recursive`，受保护段和隔离区不可删。把这些做成配置只会增加需要测试的状态，
而不会让删除更安全。需要换隔离区位置时，改代码或提 issue，比加一个没人验证的
开关更诚实。

## 开发

```bash
npm run verify
```

`npm run verify` 会检查所有源码/脚本/测试的语法，校验 `package.json` 与 `exports`
完整性，运行 `npm test`（373 个测试），并执行 `npm run smoke`（四模式与临时工作区
冒烟验证）。

373 个测试，覆盖牢笼（相对/绝对/`..`/符号链接/受保护段/隔离区、Windows ADS/末尾点空格/8.3
别名、常规含 `~` 文件名、`\\?\` 前缀、只读父目录预校验，含被重定向的 `items` 目录和条目目录）、
隔离区（删除、dry-run、递归标志、文件与目录的恢复、覆盖及覆盖失败保留双方 `trash_id` 提示、
分页、过滤、1.x 迁移（含失败重试/崩溃修复/篡改路径拒绝）、并行删除、权限保留、悬空符号链接、
底层 FS 错误码映射）、沙箱门槛（只读下删除与恢复被拒、dry-run 仍可用、策略无法解析时
fail-closed）、shell 判定（直接命令、包装与嵌套上限、内联载荷、包装/find-exec 内命令位置替换、
进程替换、动态 `find -exec`、`git` 全局参数、cmd `if`/开关/caret、PowerShell 反引号转义/
`Delete`/scriptblock/`Start-Process`、编码、heredoc、允许的数据提及）、程序判定（`fs.rm` /
`unlink` / `rimraf` / `Deno.remove` / 静态与动态导入 / 解构与链式别名 / 命令拼接 /
argv 元字符 / `child_process` / `eval`），以及通过伪 Cordis context 的插件装配、
输出 schema 一致性和四模式分类。在 Windows 缺乏符号链接权限或沙箱限制时，符号链接相关用例会跳过。

源码结构：

```
index.js                 插件入口：工具、提示词、pre-execute、guard
lib/paths.js             工作区牢笼、恢复路径校验
lib/trash.js             条目式隔离区：删除、恢复、列表、1.x 迁移
lib/shell.js             感知引号/包装/内联载荷的 shell 删除判定
lib/program.js           PTC 程序的删除判定（含 shell-out）
lib/guard.js             按 schema 形状分类并分派
lib/tools/*.js           delete_file / restore_file / list_trash
```

修改插件源码后需要重载 profile 或重启 DSH：已加载的 ESM 模块不会在进程内刷新。
重启之前旧构建仍在守卫，旧版本的文本策略可能拒绝当前源码允许的命令——拒绝消息里
的版本号就是用来发现这件事的。

## 卸载

在 profile patch 里禁用 `safe-delete` 条目，或移除 bundle。隔离区留在磁盘上；
确认不需要后手动处理 `.dsh/trash`。插件不会自动永久删除任何用户数据。

## 发布

远程仓库、CI、真实宿主 smoke 与 npm 发布步骤见 [RELEASING.md](RELEASING.md)。

## 许可证

MIT，见 [LICENSE](LICENSE)。
