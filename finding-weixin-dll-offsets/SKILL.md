---
name: finding-weixin-dll-offsets
description: >-
  通过 x64dbg-mcp 工具自动查找微信 Weixin.dll 中 MutiWeixinTools 项目所需的 4 个偏移地址
  (mutex_name_offset, hook_offset, global_config_offset, host_redirect_xml_offset)。
  当用户需要为新版本微信查找偏移、更新 config.ini 配置、或分析 Weixin.dll 时使用此技能。
---

# 查找 Weixin.dll 偏移地址

通过 x64dbg-mcp 在已加载的微信进程中搜索特征码和字符串，计算 4 个偏移地址并写入 config.ini。

## 前置条件

- 微信进程已在 x64dbg 中加载并暂停
- x64dbg-mcp 服务已连接
- 一次性授权所有工具: `Action=mcp, Target=x64dbg-mcp/*`

## 工作流程

### Step 0: 获取基址和版本

调用 `module_get`，参数 `{"module": "Weixin.dll"}`。

记录三个值:
- `base` — 基址（后续所有偏移 = 目标地址 - base）
- `path` — 从路径提取版本号
- `size` — 计算搜索结束地址: end = base + size

### Step 1: mutex_name_offset

搜索 UTF-16LE 编码的 `XWeChat_App_Instance_Identity_Mutex_Name`。

调用 `memory_search`:
```json
{
  "pattern": "58 00 57 00 65 00 43 00 68 00 61 00 74 00 5F 00 41 00 70 00 70 00 5F 00 49 00 6E 00 73 00 74 00 61 00 6E 00 63 00 65 00 5F 00 49 00 64 00 65 00 6E 00 74 00 69 00 74 00 79 00 5F 00 4D 00 75 00 74 00 65 00 78 00 5F 00 4E 00 61 00 6D 00 65 00",
  "start": "<base>",
  "end": "<end>"
}
```

计算: `mutex_name_offset = 结果地址 - base`

### Step 2: hook_offset

搜索引用 mutex_name 的代码特征码。

调用 `memory_search`:
```json
{
  "pattern": "0F 10 05 ?? ?? ?? ?? 0F 11 00 0F 10 05 ?? ?? ?? ?? 0F 11 40 10 0F 10 05 ?? ?? ?? ?? 0F 11 40 20 0F 10 05 ?? ?? ?? ?? 0F 11 40 30 0F 10 05 ?? ?? ?? ?? 0F 11 40 40 66 C7 40 50 00 00 31 C9 31 D2 49 89 C0 FF 15 ?? ?? ?? ?? 48 85 C0",
  "start": "<base>",
  "end": "<end>"
}
```

验证与定位:
1. 用 `disassembly_at` 反汇编搜索结果地址，确认第一条指令引用了 Step 1 的 mutex_name 地址
2. 用 `disassembly_function` 获取函数 `end` 地址
3. 用 `memory_search` 在 end 附近搜索 `C3` (ret 字节码): `{"pattern": "C3", "start": "<end>", "end": "<end+0x100>"}`
4. 用 `disassembly_at` 确认 `C3` 是 `ret` 指令，找到 ret 前紧邻的第一个 `call`

⚠️ **陷阱**: `disassembly_function` 的 `end` 可能恰好不含 ret，ret 通常在 end 前几个字节处。典型的函数尾部:
```asm
call xxx        ← 这就是目标地址
mov eax, edi
add rsp, 0x1F0
pop rbx/rdi/rsi/r14/rbp
ret             ← C3
```

计算: `hook_offset = ret前第一个call地址 - base`

### Step 3: global_config_offset

搜索 `global_config` 赋值代码特征码。

调用 `memory_search`:
```json
{
  "pattern": "48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 C7 05 ?? ?? ?? ?? 0D 00 00 00 48 C7 05 ?? ?? ?? ?? 0F 00 00 00 48 B8 67 6C 6F 62 61 6C 5F 63 48 89 05 ?? ?? ?? ?? 48 B8 6C 5F 63 6F 6E 66 69 67 48 89 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ??",
  "start": "<base>",
  "end": "<end>"
}
```

验证与定位:
1. 用 `disassembly_at` 反汇编，找到 `mov rax, 0x6769666E6F635F6C` 指令（即 "l_config"）
2. 该指令机器码为 `48 B8 6C 5F 63 6F 6E 66 69 67`（10字节）
3. 字符 'i' (0x69) 在指令偏移 +8 处

计算: `global_config_offset = (该mov指令地址 + 8) - base`

### Step 4: host_redirect_xml_offset

搜索 ASCII 字符串 `/host-redirect.xml`。

调用 `memory_search`:
```json
{
  "pattern": "2F 68 6F 73 74 2D 72 65 64 69 72 65 63 74 2E 78 6D 6C",
  "start": "<base>",
  "end": "<end>"
}
```

⚠️ 如果搜索无结果，改为搜索不含前导 `/` 的 `host-redirect.xml`:
```json
{
  "pattern": "68 6F 73 74 2D 72 65 64 69 72 65 63 74 2E 78 6D 6C",
  "start": "<base>",
  "end": "<end>"
}
```
然后读取结果地址前 1 字节确认是否为 `2F` (`/`)，如果是则偏移地址从前 1 字节开始计算。

计算: `host_redirect_xml_offset = 结果地址 - base`（含前导 `/` 时为字符串起始地址）


### Step 5: 写入 config.ini

将 4 个偏移值以 `[版本号]` section 追加到 config.ini:
```ini
[x.x.x.x]
mutex_name_offset = 0x...
global_config_offset = 0x...
host_redirect_xml_offset = 0x...
hook_offset = 0x...
```

## 反模式清单

| 不要这样做 | 后果 | 正确做法 |
|-----------|------|---------|
| 在 disassembly_function 结果中搜索 ret | 找不到 ret | 取 end 地址，在附近搜索 C3 字节 |
| 忘记计算搜索范围 end 地址 | 搜索全内存太慢 | end = base + size |
| 手动转换字符串 hex | 容易出错 | 使用本文档中的固定 pattern |
| 不验证特征码搜索结果 | 可能匹配到错误位置 | 反汇编确认引用了目标字符串 |
| 逐个授权 mcp 工具 | 反复打断流程 | 一次性授权 `x64dbg-mcp/*` |

## 已验证版本

| 版本 | mutex_name | global_config | host_redirect_xml | hook |
|------|-----------|---------------|-------------------|------|
| 4.1.8.101 | 0x7EB384E | 0x46A8A | 0x8766C6C | 0x8D932 |
| 4.1.8.107 | 0x7EC284E | 0x46A8A | 0x8776E6C | 0x8D932 |
| 4.1.1.19 | 0x6D50DBE | 0x48A0A | 0x74717D9 | 0x87836 |
