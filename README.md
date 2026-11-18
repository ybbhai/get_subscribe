# 本仓库是依据这个仓库进行修改的：https://github.com/ermaozi/get_subscribe.git

## 节点筛选与客户端要求

- Google、YouTube、ChatGPT 使用 `url-test` 自动选择组，只包含对应服务实测成功的节点，不混入其他节点或通用自动组。无实测成功节点时使用 `REJECT`，避免误选未经验证的出口。
- 自动组每 120 秒主动健康检查（`lazy: false`），超时 6 秒，切换容差 50ms。通用组使用 HTTPS 204 探测；服务组分别检查 Google 204、YouTube 200、ChatGPT 认证端点 200，避免把 HTTP 错误页当作健康节点。客户端的状态码检查不能校验认证 JSON，也不能保证登录或对话可用。
- ChatGPT 始终检查认证端点 `/api/auth/providers` 是否返回 OpenAI 认证提供方 JSON；首页返回 200 不作为成功依据。防护 HTML、403、429 和地区拒绝响应不算成功。网页测试超时至少 6 秒，不随 TCP 快筛缩短至 2 秒。
- 节点至少通过一个目标服务才会导出，并进入对应服务组。Google 在生成时与客户端均检查 `https://www.google.com/generate_204` 的 204 响应。gstatic 健康检查与 Cloudflare 1 MiB 下载不作为服务组准入条件；下载失败或短响应时速度记为 0，只影响排序，不清除已通过的服务资格。
- TCP 快筛只用于适用的协议；Hysteria、Hysteria2、TUIC 跳过 TCP 快筛，仍必须通过 Mihomo 的真实代理请求测试才能导出。
- 在测速机器上实测后，按延时和统一 1 MiB 下载目标的速度综合评分（延时、速度均归一化到 0–100 后按 7:3 加权），最多保留 50 个节点；先为全局及各服务保留最佳候选，再按性能补齐，避免唯一合格节点被截断。单个服务通过仅获得对应服务组资格；Google、YouTube、ChatGPT 三项全部通过，才获得通用节点资格。
- 三项全通过指生成时的检测结果。客户端通用自动组只周期检查 gstatic，不能持续验证三项服务；服务可用性变化后需要重新生成订阅。原生单 URL 的 `url-test` 不能表达三个目标同时成功，当前未引入客户端多目标检测守护进程。
- 分组顺序保留 `clash/base_template.yaml` 的定义；模板没有 GLOBAL 时，将 GLOBAL 追加到末尾。“自动选择”和“节点选择”只纳入通用节点，“节点选择”默认跟随“自动选择”。其他业务组保留原默认策略，只追加通用节点；服务专用节点保留在各自服务组。
- GLOBAL 只包含“节点选择”、“自动选择”和三项全部通过的节点，不引用服务专用组或直连组，避免绕过全局资格限制。没有通用节点时自动组使用 REJECT。部分 OpenClash 面板按 `GLOBAL.all` 排序，因而显示顺序可能不同于模板；不能为面板排序将不合格出口放入 GLOBAL。
- GLOBAL 为手动 `select`，启用 `profile.store-selected` 保存选择。直接选具体节点不会因测速定时切换；选“自动选择”，或选当前指向自动组的“节点选择”，实际出口仍会自动变化。客户端自身的配置覆写及订阅更新恢复策略可能与 YAML 不同。
- 下载速度单位为 kbit/s；网页耗时包含下载时间，不是纯网络 RTT。统一测速目标不可用时速度记为 0。
- Windows 请使用支持 Clash Meta/Mihomo 内核的客户端。旧版 Clash 内核不支持部分 VLESS、Reality、Hysteria2 等配置，不能保证兼容。
- 测试结果只代表运行时、测速机器网络下的网页 HTTP 可用性，不保证 Windows 本地网络、后续时刻、视频播放或 ChatGPT 登录/对话可用。HTTP 403、429、跨站重定向等不会视为成功。
- 修改逻辑后需重新执行订阅生成流程，已有订阅文件不会自动更新。
- 离线回归测试：`python3 -m unittest discover -s tests -v`（CI 每次运行前也会执行）。

## 规则模式与输出文件

- 规则模式从上到下匹配 `rules`，走首条命中规则指定的节点或分组，不取第一个分组，也不统一走 GLOBAL。例如 Google、YouTube、ChatGPT 分别走各自服务组；未命中其他规则时，`MATCH` 走“漏网之鱼”，其默认走“节点选择”。国内 IP 则默认直连。
- 全局模式走 GLOBAL。规则模式下修改 GLOBAL 不会改变规则指定的服务组；应在实际命中的组中选节点，或选择“节点选择”统一跟随主组。
- 无实测节点的服务组会明确拒绝连接；需要重新生成订阅获得该服务的可用节点。可在客户端连接日志中查看命中规则和最终代理链。
- OpenClash 的流媒体解锁检测独立于本项目的网页连通性测试。“不支持解锁”表示地区或服务授权未通过；“解锁检测失败”也可能来自超时或检测接口变化。若日志出现 `GLOBAL`，说明检测正在遍历全局候选，可能遍历到苹果服务等直连组。应在 OpenClash 中将 HBO Max 的检测目标设为实际承载规则的“国外媒体”组，Netflix 设为“NETFLIX”组，并使用规则模式。项目没有实测这些服务的播放解锁能力，节点名称中的地区或电视图标不能作为解锁凭证。
- 生成入口 `python3 main.py -p prod -d ./subscribe` 默认为**常驻定时循环**：启动后立即执行一轮，之后每隔 `--interval` 小时（默认 12）自动重复，直到收到 SIGINT/SIGTERM。单轮失败只记录日志，不会中断循环。成功后写入 `subscribe/clash.yaml`，不是仓库已有的 `subscribe/clash.yml`，请导入或订阅正确文件。默认 dev 模式不导出最终配置，会在日志中给出提示。
- 若交给外部调度器（系统 cron、GitHub Actions 等）每分钟/每小时触发，请加 `--once` 只跑一次并退出，否则进程会一直驻留：`python3 main.py -p prod -d ./subscribe --once`。此时无可用节点会以退出码 2 结束，便于调度器判失败。
- 循环模式示例：`python3 main.py -p prod -d ./subscribe --interval 6`（每 6 小时一轮）。
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

