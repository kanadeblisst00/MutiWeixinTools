# 问题排查指南

## disassembly_function 不包含 ret

### 现象
调用 `disassembly_function` 后在 JSON 输出中搜索 `"mnemonic": "ret"` 无结果。

### 原因
x64dbg 的函数分析对大函数或多出口函数的边界检测不准确。返回的 `end` 地址可能指向函数最后一个基本块的末尾，而非包含 epilogue（pop 序列 + ret）的位置。

### 解决步骤

1. 取 `disassembly_function` 返回的 `end` 地址
2. 在 `[end, end+0x100]` 范围搜索 `C3` 字节:
   ```json
   {"pattern": "C3", "start": "<end>", "end": "<end+0x100>"}
   ```
3. 对每个候选 `C3`，用 `disassembly_at` 确认:
   - 该字节确实反汇编为 `ret`（不是其他指令的一部分）
   - ret 后面跟着 `int3` (CC) 或 `nop` 填充（函数边界标志）
4. 确认后向前反汇编 15-20 条指令，找到紧邻 ret 的 `call`

### 4.1.1.19 版本实例

```
disassembly_function end = 0x7FFF75CA784B
实际 ret 位于 0x7FFF75CA784A (end - 1)
ret 前的 call 位于 0x7FFF75CA7836

函数尾部结构:
0x7FFF75CA7836  call 0x7FFF7ACF86F4   ← hook_offset 目标
0x7FFF75CA783B  mov eax, edi
0x7FFF75CA783D  add rsp, 0x1F0
0x7FFF75CA7844  pop rbx
0x7FFF75CA7845  pop rdi
0x7FFF75CA7846  pop rsi
0x7FFF75CA7847  pop r14
0x7FFF75CA7849  pop rbp
0x7FFF75CA784A  ret                   ← 函数结束
0x7FFF75CA784B  call 0x7FFF7B45BCCC   ← end 指向这里
0x7FFF75CA7850  int3                  ← 函数边界
```

## global_config 的 +8 偏移解释

`mov rax, 0x6769666E6F635F6C` 的机器码:
```
48 B8 6C 5F 63 6F 6E 66 69 67
│  │  └─────────────────────── 8 字节立即数 (little-endian)
│  └─── opcode: MOV r64, imm64
└────── REX.W prefix

字节位置:  +0  +1  +2  +3  +4  +5  +6  +7  +8  +9
字节值:    48  B8  6C  5F  63  6F  6E  66  69  67
字符:              l   _   c   o   n   f   i   g
                                             ↑
                                         +8 = 'i' (0x69)
```

所以 `global_config_offset = 指令地址 + 8 - base`，指向的是立即数中 'i' 字符的内存位置。
