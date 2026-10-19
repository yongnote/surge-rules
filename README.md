# Surge 广告拦截模块

`sr_ad_only.sgmodule` 是 [Johnshall / Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) 的 [sr_ad_only.conf](https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf) 静态转换版本。

来源项目延续了 [h2y / Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules) 的工作。规则与来源项目一样，按 [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/) 许可分发，详见 LICENSE；本转换不代表原作者认可。

## 转换说明

- 下载日期：2026-10-19 UTC。上游文件注明规则刷新时间为 2026-10-18 23:03:50。
- 保留 58,913 条规则（58,785 条 DOMAIN-SUFFIX、128 条 IP-CIDR）和原始注释。
- 添加 Surge 模块元数据，将策略名称 Reject 规范为 REJECT。
- 将三条 IPv4 CIDR 规范为等价网段：117.139.18.141/22 → 117.139.16.0/22；123.125.117.0/22 → 123.125.116.0/22；183.221.247.189/22 → 183.221.244.0/22。
- 未添加 no-resolve，保留原 IP 匹配行为；没有脚本、MITM 或重写功能。

## 使用与限制

在 Surge 的模块管理中添加此文件的 Raw 链接并启用。模块规则会插入主规则列表前部，可能覆盖主配置中的放行规则；遇到正常服务被拦截时可先停用模块排查。不保证去除所有广告。已经完成静态格式检查，未在真实 Surge 客户端加载测试。

这是静态快照，没有自动同步上游的流程。Surge 重新下载同一链接不会自动转换上游新规则。

参考：[Surge 官方模块文档](https://manual.nssurge.com/profile/module.html)。
