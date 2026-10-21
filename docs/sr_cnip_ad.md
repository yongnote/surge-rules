# Surge 国内外分流与广告过滤

来源是 [sr_cnip_ad.conf](https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf)，对应上游的“国内外划分 + 广告”，不是 top500 白名单版。保留上游的手工代理例外、广告拦截、`GEOIP,CN,DIRECT` 和最终代理兜底的先后顺序。

## 两种交付文件

- [`sr_cnip_ad.dconf`](../sr_cnip_ad.dconf)：只有一个有效的 `[Rule]` 段，包含策略和末尾 `FINAL`。供已有配置引用，适合保留现有节点、订阅代理组及 General 设置。它不是 `RULE-SET`，不能通过单条 `RULE-SET,...,PROXY` 引入，也不是模块。
- [`sr_cnip_ad.conf`](../sr_cnip_ad.conf)：单文件、可导入的完整配置模板，规则内嵌，无相对文件依赖。模板不含节点、订阅地址或密码；`PROXY = select, REJECT` 是明确的安全占位。**尚未接入自己的可用代理前，PROXY 流量会被拒绝，不能开箱即用。** `GEOIP,CN,DIRECT` 仍按上游规则允许中国 IP 直连，并非全流量阻断。
- [`sr_cnip_ad.validation.json`](../sr_cnip_ad.validation.json)：输入摘要、规则统计、转换记录和真实客户端测试状态。

稳定 Raw 地址：[完整模板](https://raw.githubusercontent.com/yongnote/surge-rules/main/sr_cnip_ad.conf)、[规则片段](https://raw.githubusercontent.com/yongnote/surge-rules/main/sr_cnip_ad.dconf)。

不创建新的 `.sgmodule`。Surge 模块规则只能使用内置策略，而且插在主规则之前，不能承载这份带自定义 `PROXY` 组与 `FINAL` 的完整有序分流。参见 [Surge 模块说明](https://manual.nssurge.com/profile/module.html)。

## 保留已有节点的最小接入步骤

以下是用户以后手动接入的方法；本次工作没有在任何设备上导入或启用配置。

1. 复制当前 Surge 配置为可编辑的本地副本，保留原有 `[General]`、`[Proxy]`、`[Proxy Group]` 和节点订阅来源。若是不可编辑的托管配置，先在客户端创建本地副本。
2. 让规则中统一使用的 `PROXY` 对接现有可用代理组。已有名为 `PROXY` 的正常代理组时直接复用；否则在现有 `[Proxy Group]` 段内添加 `PROXY = select, 你的现有代理组准确名称`，替换中文示意名，不要另开重复段。引用目标必须存在且最终指向代理节点，不要引用自己或形成组循环，也不要用 `DIRECT` 代替待配置的代理。
3. 把 `sr_cnip_ad.dconf` 放在该本地配置的同一目录，将副本原来的整个 `[Rule]` 段替换为下面两行。片段已经包含唯一的 `FINAL,PROXY`，不要再保留旧 `FINAL`，也不要在它后面追加规则。其他设置和节点保持原样。

```ini
[Rule]
#!include sr_cnip_ad.dconf
```

也可将片段内 `[Rule]` 的内容原序复制到已有 `[Rule]`，取代其原有内容。Surge 的分离段需要被引文件包含相应段声明，详见 [配置格式与分离段](https://manual.nssurge.com/profile/format.html)。

若选择导入完整 `.conf` 模板：它会成为一份独立配置，不会自动继承旧节点。先在本地将旧配置的 `[Proxy]` 和相关代理组复制进去，再把 `PROXY = select, REJECT` 中的占位成员改为实际组名，检查引用和组选择后再自行决定是否启用。不要把含节点或凭据的本地版本传回公开仓库。

已启用的模块仍可能改变最终匹配优先级。尤其旧 `sr_ad_only.sgmodule` 会把 REJECT 规则插在主规则前，可能抢先于新片段的手工代理例外命中；如需严格采用这份上游顺序，应在本地检查并停用重复的旧广告模块。本仓库保留其文件与更新流程不变；本次没有操作客户端模块。

## 转换及匹配差异

- 不排序、不合并、不去重规则，保留原有规则数量、注释和内联说明；General、重写与 MITM 原文作为加了注释前缀的参考附录保留，均不会生效。
- 将 `Proxy` / `proxy` / `PROXY` 统一为 `PROXY`，`Reject` 统一为 `REJECT`。策略引用只允许 `PROXY`、`DIRECT`、`REJECT`，完整模板为 `PROXY` 声明了选择组。
- 五条误标为 `IP-CIDR` 的 IPv6 网络改为 `IP-CIDR6`：`2001:b28:f23d::/48`、`2001:b28:f23f::/48`、`2001:67c:4e8::/48`、`2001:b28:f23c::/48`、`2a0a:f280::/32`。不改变其地址范围或代理策略。
- 三条带主机位的 IPv4 CIDR 规范为同一掩码对应的等价网段：`117.139.18.141/22` → `117.139.16.0/22`；`123.125.117.0/22` → `123.125.116.0/22`；`183.221.247.189/22` → `183.221.244.0/22`。不是缩小成单主机，也不扩大原掩码的覆盖范围。
- 沿用旧广告转换器的 DNS 处理约定：所有 IPv4/IPv6 CIDR 规则各加一次 `no-resolve`，已有同名参数按大小写归一后去重。本快照新增 145 个，原文无重复参数。域名规则不添加此参数。

`no-resolve` 会改变触发 DNS 的时机，**并非完全等价转换**：未解析的域名请求会跳过这些 CIDR 规则；直接 IP 请求或已经解析的域名地址仍可匹配。因此仅靠 IP 拦截的广告，若以未解析域名访问，可能越过早先的 IP REJECT。这一点与旧模块的转换约定相同。[Surge IP 规则说明](https://manual.nssurge.com/rules/ip.html) 解释了此参数的行为。

**`GEOIP,CN,DIRECT` 保持无 `no-resolve`，不改变其国家匹配条件，不添加 `dns-failed`。** 在前面规则未命中时，它仍会对未解析域名触发 DNS，按 Surge 的 GeoIP 数据库决定中国 IP 直连，随后才是唯一的 `FINAL,PROXY`。GEOIP 解析后不会回头重新检查此前跳过的 CIDR。DNS 失败仍可能使请求失败，而非自动走 FINAL。这保留了上游 GEOIP/FINAL 约定；Shadowrocket 与 Surge 使用的数据库、DNS 结果仍可能不同。

## General 设置审查

规则片段不修改任何 General 设置；完整模板只启用 `ipv6 = false` 和 `dns-server = system`。模板没有主动添加绕过路由；唯一的 DIRECT 规则是上游保留的 `GEOIP,CN,DIRECT`。系统 DNS 选择与上游的 DoH 不同，建议已有用户使用片段来保留自己的 DNS 设置。

| 上游设置 | 本次处理及原因 |
| --- | --- |
| `ipv6 = false` | Surge 支持，完整模板保留；这主要影响 AAAA 查询，不等于绝对禁止所有 IPv6 字面地址请求，也没有自动启用 `ipv6-vif`。 |
| `bypass-system = true` | 当前 Surge General 文档未列出这个 Shadowrocket 设置，不移植。 |
| `bypass-tun = ...` | 不复制，也不机械改成 Surge 的 `tun-excluded-routes`。后者改变 VIF 接管范围，上游还包含 `198.18.0.0/15` 等特殊地址，不能作为普通分流规则直接套用。 |
| `skip-proxy = ...` | Surge 虽有同名设置，但在 iOS/macOS 的接管含义不同，不是规则中 DIRECT 的同义词；不将上游长列表直接应用。 |
| `dns-server = https://...` | 不把 DoH URL 直接放进此键。模板显式使用 `system`；上游两条 DoH 仅以注释示例放在 `encrypted-dns-server` 下，未启用。Surge 当前可兼容迁移旧写法，但新配置采用其明确的键名。 |

依据：[Surge General 文档](https://manual.nssurge.com/profile/general.html)。系统 DNS 不承诺加密或经代理；即使以后自行启用 DoH，Surge 的加密 DNS 默认也走直连出口，是否遵循出站模式需另行配置，不应把“使用 DoH”理解为“DNS 必然通过 PROXY”。

Google `.cn` → `.com` 的 302 URL 重写不是分流或广告拦截所需，故只留在注释附录。HTTP 重定向与对 HTTPS 解密后重写是两回事；HTTPS 重写通常需要 MITM。上游 `hostname = *.google.cn,*.googlevideo.com` 仅为参考文字。本次未启用 MITM、创建或安装证书，也未更改任何真实设备网络设置。

## 输入版本、复现与验证

准备日期：2026-10-21 UTC。指定 Pages 地址通过浏览工具可读，显示构建时间 `2026-10-20 23:03:52 UTC`；命令行直接下载该 Pages URL 返回 HTTP 403。因此转换输入取自官方 `release` 分支的**同名文件**，浏览核对其构建时间及头尾规则一致，未对 Pages 响应做完整的逐字节比对。

- 输入版本：[Johnshall release 提交 d82763e65227deab1c66760e3416b1c981cf57c3](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/commit/d82763e65227deab1c66760e3416b1c981cf57c3)。
- [固定版本的输入 Raw 文件](https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/d82763e65227deab1c66760e3416b1c981cf57c3/sr_cnip_ad.conf)。Git blob：`068369d3b97396b8a5264a6f1fe950bb1798bdcc`。
- 输入为 2,384,112 字节；SHA-256：`562326734fcaf24a4ba2f8ec25c4225a7f6c9bc87998e08608e27d881af5d29a`。通过 Git 克隆与 Raw 下载取得的文件摘要一致。

| 有效规则类型 | 数量 |
| --- | ---: |
| DOMAIN-SUFFIX | 59,856 |
| DOMAIN-KEYWORD | 2 |
| IP-CIDR | 140 |
| IP-CIDR6 | 5 |
| GEOIP | 1 |
| FINAL | 1 |
| 合计 | 60,005 |

策略计数：`REJECT` 59,613，`PROXY` 391（含 FINAL），`DIRECT` 1。

下载后的文本仅当作数据读取，不运行上游脚本。新转换器不下载数据，不执行命令；遇到未知规则类型、参数、策略、配置指令、额外配置段、异常数量或改变此版本结构的规则会停止，需人工审查。所有内容先转换及验证，再准备临时文件并逐个原子替换三个新产物；三文件不是跨文件事务。转换器不写旧模块、旧转换器或 workflow。

在仓库根目录复现（`/tmp/sr_cnip_ad.source.conf` 是自己已下载并核对摘要的原始文本）：

```sh
python3 scripts/convert_cnip.py --source /tmp/sr_cnip_ad.source.conf
python3 scripts/convert_cnip.py --source /tmp/sr_cnip_ad.source.conf --check
python3 -m unittest discover -s tests -v
```

本次 17 项测试通过，包括 14 项新测试及 3 项旧测试回归。检查覆盖规则类型、策略引用、IPv4/IPv6 与 CIDR 规范化、no-resolve 去重及 DNS 差异、原顺序与注释、FINAL 唯一且末尾、危险配置指令拒绝、失败不覆盖、生成一致性，以及两份已生成配置的静态验证。**没有在真实 Surge 客户端加载，也没有实际流量、连通性、广告效果或性能测试。**

现有 `sr_ad_only.sgmodule`、`scripts/update_rules.py`、旧测试及每周一 00:30 UTC workflow 保持不变。新 CNIP 文件由这个独立离线转换器生成，**没有接入现有定时更新**，不会因旧 workflow 的每周执行而刷新。

## 署名与许可证

感谢 Moshel、Johnshall、h2y 及来源项目的贡献者。此转换基于 [Johnshall / Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever)，上游延续 [h2y / Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules)。规则及其改编沿用 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)，参见仓库 [LICENSE](../LICENSE)。上述兼容改动不代表来源作者认可或担保。
