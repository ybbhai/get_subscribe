# 本仓库是依据这个仓库进行修改的：https://github.com/ermaozi/get_subscribe.git

## 节点筛选与客户端要求

- Google、YouTube、ChatGPT 使用手动选择组，优先列出对应网页实测成功的节点，其后追加“节点选择”、“自动选择”以及全部导出节点作为兜底。不按节点名称或地区猜测；兜底选项不代表已通过该服务测试。
- ChatGPT 首页失败时，额外检查认证端点 `/api/auth/providers` 是否返回 OpenAI 认证提供方 JSON；防护 HTML、403、429 和地区拒绝响应不算成功。网页测试超时至少 6 秒，不随 TCP 快筛缩短至 2 秒。
- 在测速机器上实测后，按延时和统一 1 MiB 下载目标的速度综合评分（延时、速度均归一化到 0–100 后按 7:3 加权），最多保留 50 个节点；不足 50 个时不补入失败节点。GLOBAL 按模板顺序列出**全部代理组**，其后追加全部导出节点。
- 分组顺序严格保留 `clash/base_template.yaml` 的定义；模板没有 GLOBAL 时，将 GLOBAL 追加到末尾。“节点选择”默认选“自动选择”；漏网之鱼、电报、微软、国内媒体等通用业务组保留原默认策略，同时提供自动选择和全部导出节点。直连、拦截组不追加代理节点。
- GLOBAL 必须包含全部代理组，不能只列“节点选择”和“自动选择”：OpenClash 内置面板（metacubexd）是按各分组在 `GLOBAL.all` 里的下标来排序展示的，不在 `GLOBAL.all` 中的组会被排到最前面，导致“节点选择”“自动选择”被挤到列表末尾。
- GLOBAL 为手动 `select`，启用 `profile.store-selected` 保存选择。直接选具体节点不会因测速定时切换；选“自动选择”，或选当前指向自动组的“节点选择”，实际出口仍会自动变化。客户端自身的配置覆写及订阅更新恢复策略可能与 YAML 不同。
- 下载速度单位为 kbit/s；网页耗时包含下载时间，不是纯网络 RTT。统一测速目标不可用时速度记为 0。
- Windows 请使用支持 Clash Meta/Mihomo 内核的客户端。旧版 Clash 内核不支持部分 VLESS、Reality、Hysteria2 等配置，不能保证兼容。
- 测试结果只代表运行时、测速机器网络下的网页 HTTP 可用性，不保证 Windows 本地网络、后续时刻、视频播放或 ChatGPT 登录/对话可用。HTTP 403、429、跨站重定向等不会视为成功。
- 修改逻辑后需重新执行订阅生成流程，已有订阅文件不会自动更新。
- 离线回归测试：`python3 -m unittest discover -s tests -v`（CI 每次运行前也会执行）。

## 规则模式与输出文件

- 规则模式从上到下匹配 `rules`，走首条命中规则指定的节点或分组，不取第一个分组，也不统一走 GLOBAL。例如 Google、YouTube、ChatGPT 分别走各自服务组；未命中其他规则时，`MATCH` 走“漏网之鱼”，其默认走“节点选择”。国内 IP 则默认直连。
- 全局模式走 GLOBAL。规则模式下修改 GLOBAL 不会改变规则指定的服务组；应在实际命中的组中选节点，或选择“节点选择”统一跟随主组。
- 原逻辑会把无实测节点的服务组设为 REJECT，导致规则模式相关网站被直接拒绝。新逻辑允许回退，但节点在客户端本地仍需可用；可在客户端连接日志中查看命中规则和最终代理链。
- 生成入口 `python3 main.py -p prod -d ./subscribe` 为**单次执行**：脚本自身不做定时调度，更新频率由外部调度器决定（本仓库的 GitHub Actions 使用 cron 触发，也可用系统 cron）。成功后写入 `subscribe/clash.yaml`，不是仓库已有的 `subscribe/clash.yml`，请导入或订阅正确文件。默认 dev 模式不导出最终配置，会在日志中给出提示。
- 导出时还会在 `clash/proxy_generated.yaml` 写一份同样的配置副本（内含真实节点凭据，已在 `.gitignore` 中忽略，请勿提交）。
- 采集订阅前会先用本地 Clash 内核起一个代理，配置选择顺序为：①`clash/proxy_generated.yaml`（上次生成的真实节点，最长等 60 秒，首次启动需联网下载 geoip.metadb）；②`clash/proxy.yaml`（默认直连兜底，最长等 10 秒）。两者都不可用时才直连拉取。因此本地反复运行时，第二次起就能借上次的有效节点访问被墙的订阅源；CI 每次都是干净环境，通常会回退到 `proxy.yaml`。


# 以下是原仓库的readme
#######################################################################

# ⏰ 免费机场 免费梯子 翻墙VPN

## ⚠️ 注意

- 链接来自网络，仅作学习使用
- 使用页面所提供的任意资源时，请务必遵守当地法律

## 🚀 每12小时更新一次

- clash订阅链接
  ```
  https://git.io/emzclash
  ```

- v2ray订阅链接
  ```
  https://git.io/emzv2ray
  ```

## 📘 客户端使用方法

- 📱 [Android](https://www.ermao.net/article/eh8f4n86/)
- 🖥 [Windows](https://www.ermao.net/article/0gematwc/)
- 🍎 [iOS](https://www.ermao.net/article/z747kgjd/)

## 💸 付费订阅

我搜罗的一些比较便宜好用的机场，觉得免费订阅不好使的朋友们可以在这里面找找。

[https://www.ermao.net/posts/vpn](https://www.ermao.net/posts/vpn)

[https://www.pyjichang.com](https://www.pyjichang.com)

## 📷 使用截图

低峰期可以看视频，高峰期可能会有点卡顿。

![alt text](https://www.ermao.net/assets/image-St_c8wNW.png)

![alt text](https://www.ermao.net/assets/image-1-D1lHRY7Y.png)

