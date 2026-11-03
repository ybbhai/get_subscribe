# 本仓库是依据这个仓库进行修改的：https://github.com/ermaozi/get_subscribe.git

## 节点筛选与客户端要求

- Google、YouTube、ChatGPT 使用手动选择组，优先列出对应网页实测成功的节点，并提供“节点选择”和“自动选择”作为回退。不按节点名称或地区猜测；回退选项不代表已通过该服务测试。
- ChatGPT 首页失败时，额外检查认证端点 `/api/auth/providers` 是否返回 OpenAI 认证提供方 JSON；防护 HTML、403、429 和地区拒绝响应不算成功。网页测试超时至少 6 秒，不随 TCP 快筛缩短至 2 秒。
- 在测速机器上实测后，按延时和统一 1 MiB 下载目标的速度综合评分，最多保留 50 个节点；不足 50 个时不补入失败节点。GLOBAL 包含“节点选择”、“自动选择”和全部导出节点。
- 分组顺序严格保留 `clash/base_template.yaml` 的定义；模板没有 GLOBAL 时，将 GLOBAL 追加到末尾。“节点选择”默认选“自动选择”；漏网之鱼、电报、微软、国内媒体等通用业务组保留原默认策略，同时提供自动选择和全部导出节点。直连、拦截组不追加代理节点。
- GLOBAL 为手动 `select`，启用 `profile.store-selected` 保存选择。直接选具体节点不会因测速定时切换；选“自动选择”，或选当前指向自动组的“节点选择”，实际出口仍会自动变化。客户端自身的 GLOBAL 展示位置、配置覆写及订阅更新恢复策略可能与 YAML 不同。
- 下载速度单位为 kbit/s；网页耗时包含下载时间，不是纯网络 RTT。统一测速目标不可用时速度记为 0。
- Windows 请使用支持 Clash Meta/Mihomo 内核的客户端。旧版 Clash 内核不支持部分 VLESS、Reality、Hysteria2 等配置，不能保证兼容。
- 测试结果只代表运行时、测速机器网络下的网页 HTTP 可用性，不保证 Windows 本地网络、后续时刻、视频播放或 ChatGPT 登录/对话可用。HTTP 403、429、跨站重定向等不会视为成功。
- 修改逻辑后需重新执行订阅生成流程，已有订阅文件不会自动更新。
- 离线回归测试：`python -m unittest discover -s tests -v`。

## 规则模式与输出文件

- 规则模式从上到下匹配 `rules`，走首条命中规则指定的节点或分组，不取第一个分组，也不统一走 GLOBAL。例如 Google、YouTube、ChatGPT 分别走各自服务组；未命中其他规则时，`MATCH` 走“漏网之鱼”，其默认走“节点选择”。国内 IP 则默认直连。
- 全局模式走 GLOBAL。规则模式下修改 GLOBAL 不会改变规则指定的服务组；应在实际命中的组中选节点，或选择“节点选择”统一跟随主组。
- 原逻辑会把无实测节点的服务组设为 REJECT，导致规则模式相关网站被直接拒绝。新逻辑允许回退，但节点在客户端本地仍需可用；可在客户端连接日志中查看命中规则和最终代理链。
- 生成入口 `python main.py -p prod -d ./subscribe` 会立即执行并每三小时更新一次，实际写入 `subscribe/clash.yaml`，不是仓库已有的 `subscribe/clash.yml`。请导入或订阅正确文件；默认 dev 模式不导出最终配置。


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

