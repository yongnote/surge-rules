# Surge 广告拦截模块

此项目由 OpenAI Dots 创建。

`sr_ad_only.sgmodule` 是 [Johnshall / Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) 的 [sr_ad_only.conf](https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf) 自动同步转换版本。

来源项目延续了 [h2y / Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules) 的工作。规则与来源项目一样，按 [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/) 许可分发，详见 LICENSE；本转换不代表原作者认可。

## 转换说明

- 初始转换日期：2026-10-19 UTC。上游文件注明规则刷新时间为 2026-10-18 23:03:50。
- 初始版本保留 58,913 条规则（58,785 条 DOMAIN-SUFFIX、128 条 IP-CIDR）和原始注释。
- 添加 Surge 模块元数据，将策略名称 Reject 规范为 REJECT。
- 将三条 IPv4 CIDR 规范为等价网段：117.139.18.141/22 → 117.139.16.0/22；123.125.117.0/22 → 123.125.116.0/22；183.221.247.189/22 → 183.221.244.0/22。
- IP-CIDR / IP-CIDR6 规则添加一次 no-resolve，并保留其他参数，避免为了匹配 IP 规则而提前触发 DNS 查询。尚未解析的域名请求会跳过这些 IP 规则；直接 IP 请求或已经解析的地址仍可匹配。模块不包含脚本，也不会自动启用 HTTPS 解密。

## 误拦截例外

- `ogads-pa.googleapis.com` 不纳入本模块的拦截名单，避免 Gmail 的 Google 存储用量无法显示。此例外由转换脚本保留，后续每周同步不会重新加回。该请求继续按 Surge 配置的原有规则路由，本模块不指定直连或代理。

## 知乎 App 开屏广告

自动更新版只对知乎主 API 下的两个开屏广告路径做 URL Rewrite 拦截，不拦整个域名、首页、回答或信息流。要让规则生效，需在自己的 Surge 配置中启用 HTTPS 解密，并将 `api.zhihu.com` 加入解密主机列表。模块不会替用户开启解密或添加主机。仅在需要时为该主机开启，无需添加通配符；如遇证书校验或正常功能异常，移除该解密主机即可。

## 内联版（静态）

`sr_ad_only_inline.sgmodule` 是拆分为外部规则集之前的独立模块。规则直接写在 `[Rule]` 内，只去掉了 `ogads-pa.googleapis.com` 的拦截；不随每周任务更新。需要使用时，在 Surge 里与自动更新版二选一，不要同时启用。内联规则较多，载入可能较慢。

## 使用与限制

模块通过一条 `RULE-SET` 引用独立的 `sr_ad_only.list`，而不是注入数万条内联规则。规则顺序、统一的 `REJECT` 策略和 IP 规则的 `no-resolve` 保留。已安装的用户更新原模块即可。

在 Surge 的模块管理中添加此文件的 Raw 链接并启用。模块规则会插入主规则列表前部，可能覆盖主配置中的放行规则；遇到正常服务被拦截时可先停用模块排查。不保证去除所有广告。已经完成静态格式检查，未在真实 Surge 客户端加载测试。

GitHub Actions 每周六北京时间 08:30（UTC 周六 00:30）下载、校验并转换上游规则，成功后自动提交；也可在 Actions 页面选择 Update Surge rules → Run workflow 手动运行。模块链接保持不变。测试、下载或校验失败不会覆盖现有规则。GitHub 定时运行可能延迟，公开仓库连续 60 天无活动时可能停用定时任务。

请通过 URL 在 Surge 中安装远程模块，以保留远程更新来源。Surge 支持自动检查模块更新，设备检查时间不保证与仓库同步。

参考：[Surge 官方模块文档](https://manual.nssurge.com/profile/module.html)。
