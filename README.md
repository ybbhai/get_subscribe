# 本仓库是依据这个仓库进行修改的：https://github.com/ermaozi/get_subscribe.git

## 节点筛选与客户端要求

- Google、YouTube、ChatGPT 分组仅收录对应网页实测成功的节点，不按节点名称或地区猜测。无通过节点时设为 REJECT，不回退到其他节点。
- 在测速机器上实测后，按延时和统一 1 MiB 下载目标的速度综合评分，最多保留 50 个节点；不足 50 个时不补入失败节点。GLOBAL 仅包含其中前 10 个。
- 下载速度单位为 kbit/s；网页耗时包含下载时间，不是纯网络 RTT。统一测速目标不可用时速度记为 0。
- Windows 请使用支持 Clash Meta/Mihomo 内核的客户端。旧版 Clash 内核不支持部分 VLESS、Reality、Hysteria2 等配置，不能保证兼容。
- 测试结果只代表运行时、测速机器网络下的网页 HTTP 可用性，不保证 Windows 本地网络、后续时刻、视频播放或 ChatGPT 登录/对话可用。HTTP 403、429、跨站重定向等不会视为成功。
- 修改逻辑后需重新执行订阅生成流程，已有订阅文件不会自动更新。
- 离线回归测试：`python -m unittest discover -s tests -v`。


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

