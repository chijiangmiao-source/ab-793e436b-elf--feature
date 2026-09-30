# ELF64 重定位载荷审计服务

面向载荷发布前审查的 **ELF64 小端 x86-64 可重定位目标文件（ET_REL）外部符号重定位审计** 服务，支持两种模式：

* **单文件审计**：审查员提交稳定审计标识、Base64 文件、代码装载基址与被引用外部符号地址后，可读取冻结结论、重定位后的代码摘要及按偏移排序的字节补丁；任何违约都会定位到**首个违约位置**并清除该标识下旧的成功结论，**绝不生成部分结果**。
* **联合审计（2–8 个供应商拆分成员）**：提交稳定联合标识、二至八个**具名** Base64 目标文件、整组代码装载基址与剩余外部符号地址；服务端按**成员标识排序**、依据各自 `.text` 的 `sh_addralign` 在同一装载区内确定**连续布局**，确认跨成员引用只解析到同成员局部定义、唯一的其他成员全局定义或显式提供的外部地址。重复导出、未解析引用、非代码节定义均定位到**首个相关重定位**；任何成员 PC32 溢出或补丁重叠都**整组拒绝**，不留下部分联合结论。

纯 Python 3.11 标准库实现，无第三方依赖。两种模式的存储、接口与冻结摘要相互独立；新增联合审计不改变单文件审计的接口与读取结果。

## 审计规则（逐项强校验）

文件必须同时满足：

1. ELF64（`EI_CLASS=2`）、小端（`EI_DATA=1`）、`ET_REL`、`EM_X86_64`，无程序头；
2. 节表/节名字符串表合法，存在**唯一** `.text`（`SHT_PROGBITS`）；
3. 存在唯一 `SHT_SYMTAB` 及其 `SHT_STRTAB`，表项尺寸/`sh_info` 合法；
4. 所有重定位节必须是指向该 `.text` 的 **SHT_RELA**（拒绝 `SHT_REL`、拒绝指向其他节）；
5. 仅处理 `R_X86_64_64`（写 8 字节）与 `R_X86_64_PC32`（写 4 字节有符号）；
6. 逐项校验：符号索引与字符串表、加数、写入范围不得越出 `.text` 节边界；
7. 所有补丁区间两两不得重叠；
8. `R_X86_64_PC32` 的 `S + A − P` 经 64 位补码回绕后必须落在有符号 32 位范围 `[-2^31, 2^31−1]`，越界即整体拒绝。

计算（AMD64 psABI）：

| 类型 | S（符号地址） | 写入值 |
|---|---|---|
| `R_X86_64_64` | 外部符号=用户提供地址；`.text` 内定义符号=基址+st_value | `(S + A) mod 2^64` |
| `R_X86_64_PC32` | 同上 | `(S + A − P) mod 2^64`，按有符号解读，必须 ∈ i32；P = 基址 + 节内偏移 |

流程为两阶段：先做全部结构性/范围性检查（失败即报告首个违约项），再检查补丁重叠，全部通过后才一次性落补丁。

## 联合审计规则（2–8 个成员装入同一连续代码装载区）

每个成员都必须满足上述单文件的全部结构约束（ELF64/小端/ET_REL/EM_X86_64、唯一 `.text`、指向它的 RELA 等）。在此基础上：

1. **连续布局**：不依赖提交次序，一律按 `member_id` 字典序排列；第一个成员从给定 `load_base` 开始（故基址必须满足其 `.text` 的对齐要求），后续成员起始 = 上一成员结尾向上取整到**自己** `.text` 的 `sh_addralign`（0/1 视为 1，其余必须为 2 的幂），区间两两不重叠；
2. **符号解析优先级**（针对每条 `.text` 重定位）：
   - 引用同成员已定义符号（`st_shndx` 指向本成员 `.text`，含局部 STB_LOCAL 与全局）→ 解析到**本成员** `base + st_value`，绝不串到其他成员的同名导出；
   - 引用未定义符号（SHN_UNDEF）：①同名外部地址与全局导出同时存在 → `external_shadows_export`；②恰有一个他成员全局/弱导出且定义在其 `.text` 内 → 跨成员解析为 `该成员基址 + st_value`；③提供了外部地址 → 用该地址；④其余 → `unresolved_symbol`；
   - 引用定义在非代码节（`.rodata` 等普通非 `.text` 节，或保留节索引）的符号 → `non_code_definition`；
3. **重复导出**：同一名字被多个成员全局/弱定义即 `duplicate_export`，定位到全组按（成员序、RELA 序）首个引用该名字的 SHN_UNDEF 重定位；若全组无人引用，则定位到排序在后的导出成员符号表；
4. **整组拒绝条件**：任何成员的 PC32 计算越界（`pc32_overflow`）或成员内补丁写入区间重叠（`patch_overlap`），以及前述解析类违约，都使**整组**成功标志为假——响应/存储中都不出现 `conclusion`、不返回任何成员补丁，且清除同标识旧的联合成功结论；
5. **稳定冻结摘要**：只依赖联合标识、基址、外部地址以及按标识排序后的成员内容与布局；成员提交次序调换但标识与内容相同 ⇒ 同布局、同摘要。

## HTTP 接口

- `GET /` — 审计页面（可切换单文件 / 联合模式）
- `GET /healthz` — 健康状态（含单文件与联合两类已冻结通过/拒绝计数）
- `POST /api/audit` — 提交单文件审计（JSON）
- `GET /api/result/<audit_id>` — 凭稳定标识读回单文件冻结结论或首个违约定位
- `POST /api/group_audit` — 提交联合审计（JSON，2–8 个具名成员）
- `GET /api/group/result/<audit_id>` — 读回联合冻结结论（每成员基址/范围、逐项 S/A/P/前后字节）或首个违约定位

单文件提交示例：

```json
{
  "audit_id": "payload-2026-09-29-001",
  "file_base64": "<Base64 编码的 .o>",
  "load_base": "0x400000",
  "symbols": {"ext_foo": "0x500000", "memcpy": "0x400200"}
}
```

`load_base` 与符号地址接受十进制或 `0x` 十六进制字符串。成功响应逐项给出 `S / A / P / value / before_hex / after_hex`、补丁前后 `.text` 的 SHA-256、按偏移排序的 `patches` 以及 64 字符的冻结结论（对全部输入与补丁结果做规范化哈希，可独立复算）。违约响应给出 `stage / code / message / entry_index / rela_section / rela_index / offset / type / symbol`，服务端同步清除该标识下旧成功记录。

联合审计提交示例（成员数组的**提交次序无关**，服务端按 `member_id` 排序布局）：

```json
{
  "audit_id": "payload-2026-09-29-group",
  "members": [
    {"member_id": "vendor-a", "file_base64": "<Base64 编码的 a.o>"},
    {"member_id": "vendor-b", "file_base64": "<Base64 编码的 b.o>"}
  ],
  "load_base": "0x400000",
  "symbols": {"ext_base": "0x500000"}
}
```

成功响应顶层给出 `load_base / region_range / region_size / member_count / conclusion`，`members[]` 按成员标识升序、每项给出 `member / base / range / base_offset / text_size / text_align / 补丁前后 SHA-256`，并按**成员、节内偏移**稳定排序展示原有 `S、A、P、写入前后字节` 与 `patches`。任何违约都整组失败：请求级问题为 `scope="request"`（如成员数不在 2–8、基址未按首成员 `.text` 对齐、未被引用的外部符号）；可定位问题为 `scope="member"`，给出 `member / rela_section / rela_index / offset / type / symbol`——重复导出（`duplicate_export`）、未解析引用（`unresolved_symbol`）、非代码节定义（`non_code_definition`）均定位到**首个相关重定位**（无人引用的重复导出回退到后导出成员的符号表定义）；PC32 溢出（`pc32_overflow`）与补丁重叠（`patch_overlap`）同样整组拒绝，响应不含 `conclusion`，并清除同标识旧联合结论。

## 本地运行（无需 Docker）

```bash
python3 -m app.server                      # 默认 0.0.0.0:8080
HOST=127.0.0.1 PORT=9090 python3 -m app.server
python3 -m unittest discover -s tests -v   # 75 项测试（47 旧 + 28 联合）
```

## 容器运行（宿主端口可配置）

```bash
docker compose up --build                  # 默认宿主端口 8080
HOST_PORT=9090 docker compose up --build   # 自定义宿主端口
```

## 验收组件 verify（一次运行，退出码结束）

`verify` 服务在同一次运行中依次核对：

1. **测试**：`python3 -m unittest discover` 全量（75 项：47 旧单文件 + 28 联合）；
2. **构建**：全部源码字节编译 + 关键模块导入 + 页面存在；
3. **旧单文件 HTTP 回归**：健康检查、页面、
   - 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   - 重叠写入拒绝（`patch_overlap`，定位 `entry_index=1`，旧成功结论被清除）；
   - PC32 有符号 32 位溢出拒绝（`pc32_overflow`），无部分结果。
4. **联合审计 HTTP**：
   - 跨成员成功解析（他成员全局定义 PC32 + 外部地址 R64），给出每成员基址/范围、逐项 S/A/P 与冻结摘要；提交次序调换得到同一布局与冻结摘要；
   - 重复导出整组拒绝（`duplicate_export`），定位到引用方的首个相关重定位（vendor-b rela#1），旧联合成功结论被清除；
   - 单文件与联合命名空间互相隔离（`GET /api/result` 读不到联合记录）。

```bash
# 以 verify 的退出码作为整条命令退出码
docker compose --profile verify up --build --abort-on-container-exit --exit-code-from verify
echo $?    # 0 表示验收通过
```

或不使用 Docker：

```bash
HOST=127.0.0.1 PORT=8080 python3 -m app.server &
BASE_URL=http://127.0.0.1:8080 python3 scripts/verify.py
```

## 目录结构

```
app/elfaudit.py          ELF 解析 / 校验 / 单文件与联合重定位计算 / 冻结结论核心
app/server.py            页面、单文件与联合审计 API、健康检查
app/static/index.html    审计页面（单文件 / 联合两种模式）
tests/elfbuild.py        内存构造 ELF64 ET_REL 的测试夹具（支持局部符号与自定义对齐）
tests/test_audit.py      47 项单文件单元/集成/HTTP 测试（回归基线，未改动其断言）
tests/test_group_audit.py 28 项联合审计单元/集成/HTTP 测试
scripts/verify.py        Compose verify 验收脚本（单文件回归 + 联合验收）
Dockerfile / docker-compose.yml
```
