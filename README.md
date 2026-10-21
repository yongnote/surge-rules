# Surge 广告拦截模块

此项目由 OpenAI Dots 创建。

`sr_ad_only.sgmodule` 是 [Johnshall / Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) 的 [sr_ad_only.conf](https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf) 自动同步转换版本。

来源项目延续了 [h2y / Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules) 的工作。规则与来源项目一样，按 [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/) 许可分发，详见 LICENSE；本转换不代表原作者认可。

## 转换说明

- 初始转换日期：2026-10-19 UTC。上游文件注明规则刷新时间为 2026-10-18 23:03:50。
- 初始版本保留 58,913 条规则（58,785 条 DOMAIN-SUFFIX、128 条 IP-CIDR）和原始注释。
- 添加 Surge 模块元数据，将策略名称 Reject 规范为 REJECT。
- 将三条 IPv4 CIDR 规范为等价网段：117.139.18.141/22 → 117.139.16.0/22；123.125.117.0/22 → 123.125.116.0/22；183.221.247.189/22 → 183.221.244.0/22。
- IP-CIDR / IP-CIDR6 规则添加一次 no-resolve，并保留其他参数，避免为了匹配 IP 规则而提前触发 DNS 查询。尚未解析的域名请求会跳过这些 IP 规则；直接 IP 请求或已经解析的地址仍可匹配。没有脚本、MITM 或重写功能。

## 使用与限制

在 Surge 的模块管理中添加此文件的 Raw 链接并启用。模块规则会插入主规则列表前部，可能覆盖主配置中的放行规则；遇到正常服务被拦截时可先停用模块排查。不保证去除所有广告。已经完成静态格式检查，未在真实 Surge 客户端加载测试。

GitHub Actions 每周一北京时间 08:30（UTC 周一 00:30）下载、校验并转换上游规则，成功后自动提交；也可在 Actions 页面选择 Update Surge rules → Run workflow 手动运行。模块链接保持不变。测试、下载或校验失败不会覆盖现有规则。GitHub 定时运行可能延迟，公开仓库连续 60 天无活动时可能停用定时任务。

请通过 URL 在 Surge 中安装远程模块，以保留远程更新来源。Surge 支持自动检查模块更新，设备检查时间不保证与仓库同步。

参考：[Surge 官方模块文档](https://manual.nssurge.com/profile/module.html)。

## 新增：国内外分流 + 广告过滤

另提供上游 `sr_cnip_ad.conf` 的 Surge 转换，源自国内外分流版，不是 top500 白名单版：

- [`sr_cnip_ad.dconf`](sr_cnip_ad.dconf)：保留上游顺序的 `[Rule]` 分离段，适合接入已有节点配置。
- [`sr_cnip_ad.conf`](sr_cnip_ad.conf)：可导入的独立模板，不含节点或凭据；`PROXY = select, REJECT` 是待配置的安全占位，接入实际代理前无法正常代理上网。
- [接入步骤、兼容差异与验证记录](docs/sr_cnip_ad.md)：包括 IPv6、CIDR、no-resolve、General、可选重写/MITM 的说明及输入来源记录。

新文件带自定义代理组引用和末尾 FINAL，不是模块。旧广告模块、原转换脚本及上述每周更新流程均保持原样；新增 CNIP 文件尚未接入定时更新。已完成静态检查与新旧测试，未在真实 Surge 客户端加载。
