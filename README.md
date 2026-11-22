# 本仓库是依据这个仓库进行修改的：https://github.com/ermaozi/get_subscribe.git

## 节点筛选与客户端要求

- Google、YouTube、ChatGPT 使用 `url-test` 自动选择组，只包含对应服务实测成功的节点，不混入其他节点或通用自动组。无实测成功节点时使用 `REJECT`，避免误选未经验证的出口。
- 自动组每 120 秒主动健康检查（`lazy: false`），超时 6 秒，切换容差 50ms。通用组使用 HTTPS 204 探测；服务组分别检查 Google 204、YouTube 200、ChatGPT 认证端点 200，避免把 HTTP 错误页当作健康节点。客户端的状态码检查不能校验认证 JSON，也不能保证登录或对话可用。
- ChatGPT 始终检查认证端点 `/api/auth/providers` 是否返回 OpenAI 认证提供方 JSON；首页返回 200 不作为成功依据。防护 HTML、403、429 和地区拒绝响应不算成功。网页测试超时至少 6 秒，不随 TCP 快筛缩短至 2 秒。
- 节点至少通过一个目标服务才会导出，并进入对应服务组。Google 在生成时与客户端均检查 `https://www.google.com/generate_204` 的 204 响应。gstatic 健康检查与 Cloudflare 1 MiB 下载不作为服务组准入条件；下载失败或短响应时速度记为 0，只影响排序，不清除已通过的服务资格。
- TCP 快筛只用于适用的协议；Hysteria、Hysteria2、TUIC、OpenVPN 和完整代理链跳过 TCP 快筛，仍必须通过 Mihomo 的真实代理请求测试才能导出。
- 在测速机器上实测后，先按“优质低风险家宽候选 → 其他低风险节点 → 性能兜底”选择等级，再按延时和统一 1 MiB 下载目标的速度综合评分（延时、速度均归一化到 0–100 后按 7:3 加权），最多保留 50 条实测路径。先为全局及各服务保留最佳候选，再从各组最高等级候选中补齐，避免唯一合格节点被截断。单个服务通过仅获得对应服务组资格；Google、YouTube、ChatGPT 三项全部通过，才获得通用节点资格。
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
- 生成入口 `python3 main.py -p prod -d ./subscribe` 默认为**常驻定时循环**：启动后立即执行一轮，之后每隔 `--interval` 小时（默认 2）自动重复，直到收到 SIGINT/SIGTERM。单轮失败只记录日志，不会中断循环。成功后写入权限为 `0777` 的 `subscribe/clash.yaml`，不是仓库已有的 `subscribe/clash.yml`，请导入或订阅正确文件；`prod` 本轮没有合格节点时会删除同名旧配置，避免误用过期结果。默认 dev 模式不写出 `subscribe/clash.yaml`，但会刷新 `clash/proxy_generated.yaml` 采集缓存，并在日志中给出提示。
- 若交给外部调度器（系统 cron、GitHub Actions 等）每分钟/每小时触发，请加 `--once` 只跑一次并退出，否则进程会一直驻留：`python3 main.py -p prod -d ./subscribe --once`。此时无可用节点会以退出码 2 结束，便于调度器判失败。
- 循环模式示例：`python3 main.py -p prod -d ./subscribe --interval 6`（每 6 小时一轮）。
- 导出时还会在 `clash/proxy_generated.yaml` 写一份同样的配置副本（内含真实节点凭据，已在 `.gitignore` 中忽略，请勿提交）。
- 节点名称在测速前统一避开内置代理及模板分组名称，冲突时自动加序号，Cloudflare 的 `-cf` 后缀仍位于末尾。导出前检查重名、缺失引用与引用循环；正式配置和采集缓存分别通过临时文件原子替换，写入失败保留各自的旧文件。
- 默认无需 Cloudflare 账号、Worker、Secret 或单独配置。采集完成并关闭采集 Clash 后，程序读取 Cloudflare 官方 IPv4 网段，在网上抓取的节点中寻找原服务器为 Cloudflare 官方网段内 IPv4 地址、且满足 VLESS + WS + TLS + 443、有效 SNI、WebSocket Host 和 Path 的模板。程序使用 CloudflareSpeedTest 抽样测速，替换模板地址后把候选与抓取节点合并，送入原有统一连通性、服务可达性、下载测速和排序流程。官方网段或测速程序下载不可用时仍会继续筛选已抓取节点；测速程序下载到本机 `.cache/cloudflare-speedtest`，并按 Release SHA-256 校验。
- 自动 Cloudflare 候选默认最多 40 个，可用 `--cloudflare-max-candidates` 调整（1–500）。每轮最多下载测试 40 个入口、每个下载 5 秒，总超时随下载数量增加；节点组合数量与实际扫描数量独立。只扫描 443 和官方 IPv4 网段的抽样 `/24`，不会启用 CloudflareSpeedTest 的 `-allip` 全量扫描。先验证官方网段再限制模板数量，最多选取 10 个模板，优先覆盖不同主机，再按入口排名轮流组合。输出目录的 cloudflare_diagnostics.json 会记录实际模板数、测速入口数和组合数；cloudflare_speedtest.csv 保留测速结果。无法证明候选节点出口 IP 为纯净 IP 或家宽。
- 节点测速会关闭 Python 环境中的 HTTP/HTTPS/ALL proxy 设置，并经独立测试用 Clash 实例显式走当前被测节点，避免请求串入用户日常代理。CloudflareSpeedTest 使用直连 TCP 测速，执行时也会移除代理环境变量。运行前请关闭本机代理软件的系统代理或 TUN 模式，否则底层流量仍可能被透明转发，影响测速结果。
- CloudflareSpeedTest 上游 README 明确提示 Cloudflare CDN 禁止以代理方式使用，使用者需自行评估并遵守适用条款。此工具只筛测 Cloudflare CDN 入口 IP，不代表该入口可用于任何代理协议，也不保证节点可用。
- 原有 EdgeTunnel 订阅和地址文件选项仍可作为额外来源。需要时可保存订阅配置：先把 VLESS 订阅保存到 `subscription.txt`，然后在 `get_subscribe` 目录运行 `conda run -n python310 python main.py --configure-cloudflare --cloudflare-subscription-file ../subscription.txt`。配置保存在本机忽略文件 `config/cloudflare.yaml`，可与自动优选结果一同进入筛选。配置中的订阅文件路径相对配置文件解析，含令牌时建议使用本地文件，避免令牌进入命令历史。
- 也可在首次配置时加入 `--cloudflare-addresses-file ../results.csv --cloudflare-addresses-format cloudflare-speedtest-csv`，并用 `--cloudflare-template-index` 选择订阅中的 VLESS 模板。地址文件需要由 CloudflareSpeedTest 或其他流程更新，保存路径不会自动刷新文件。
- Cloudflare 入口 IP 不能证明节点出口是纯净或家宽。现在会经当前被测节点查询实际出口风险；`prod` 环境自动启用家宽识别模式，读取已配置的 ipapi.is key 后结合 ISP/ASN、网络类型和滥用评分判断家宽候选。未配置 key 时明确记录家宽识别不可用，住宅属性保持未知。数据库分类只能作为证据，不能保证 100% 纯净或 100% 家宽，具体规则见下文。
- 外部计划任务应每次执行 `conda run -n python310 python main.py -p prod --once`。未带 `--once` 时程序会常驻运行，启动后立即更新并默认每 2 小时执行一次。自动 Cloudflare 优选不依赖自建 EdgeTunnel 服务或订阅。
- 采集订阅前会先用本地 Clash 内核起一个代理，配置选择顺序为：①`clash/proxy_generated.yaml`（上次生成的真实节点，控制台就绪最长等 30 秒，首次启动需联网下载 geoip.metadb）；②`clash/proxy.yaml`（默认直连兜底，最长等 15 秒）。两者都不可用时才直连拉取。所有订阅采集完成后会先关闭该采集实例，再执行 Cloudflare 优选和节点状态验证。因此本地反复运行时，第二次起就能借上次的有效节点访问被墙的订阅源；CI 每次都是干净环境，通常会回退到 `proxy.yaml`。
- 节点是否可用按**真实抓取订阅数据**判定：切换到该节点后，用它的本地出口去请求 RSS 源和不同主机的 `config/urls.txt` 订阅源，必须真的拿到可解析内容（RSS 源还要能解析出条目）才算通过。让节点访问 `generate_204` 返回 204 不算通过，那只能证明它能上网，不能证明它抓得到订阅站。每个节点有独立探测预算：普通协议 24 秒；OpenVPN 35 秒，短暂失败后保持同一节点重试，以等待握手完成。最多依次尝试 12 个节点，全部失败才判定“无可用采集节点”。
- 采集实例与测速实例的端口全部动态分配（`find_free_port_block`，区间 17000-18000 及 18000+），不写死 7890/7891/9090，避免与本机代理客户端抢端口。访问本机 Clash REST API 的请求强制 `trust_env=False`，不会被 `HTTP_PROXY`/`HTTPS_PROXY` 转发到外部代理。


## Cloudflare Worker 与家宽链式订阅

两种视频方案对应不同的订阅格式，本项目在客户端订阅的导入、测速和导出阶段接入：

| 来源 | 输入本项目的内容 | 处理方式 |
| --- | --- | --- |
| EdgeTunnel + gate / CheckSocks5 | EdgeTunnel 生成的最终 VLESS URI、Base64 或 Clash YAML 订阅 | 完整保留 WS Path（包括出口参数）、Host、SNI 和 early-data；可选替换独立节点的入口地址 |
| CFnew v3.1 家宽 | `target=vg` 返回的 Clash YAML，含 OpenVPN 与 `dialer-proxy` | 解析前置节点/静态 select、url-test、fallback 组，展开为具体 OpenVPN → Worker 链路，逐条测完整链路 |
| VPN Gate 官方出口池 | 官方 API 的 CSV 与内嵌 OpenVPN 配置，prod 默认自动获取 | 转为原生 OpenVPN 候选，走统一性能、出口风险和家宽识别流程 |

`-p prod` 无需配置 Worker 即会采集 VPN Gate，默认每轮最多取 100 条候选；dev 等其他环境默认关闭。可用 `--vpngate`、`--no-vpngate` 覆盖本次开关，或在本地配置中设置 `vpngate.enabled`。源站标注的速度、Ping、国家、住宅名称仅用于候选排序与命名，不算本机测速或出口信誉证据。支持 Windows/Linux；TCP 和 UDP OpenVPN 都由 Mihomo 实际连接测试。API 默认通过 HTTPS，单次采集有共享总超时、响应大小和行数限制；不支持的脚本、外部文件引用或无法保留的 TLS 校验指令会被拒绝。

复制 `config/cloudflare.example.yaml` 为 `config/cloudflare.yaml`，可以同时配置多份 Worker、EdgeTunnel、CFnew **最终订阅**（最多 32 个），各来源独立失败、独立计数：

```yaml
automatic_enabled: true
automatic_max_candidates: 40
max_total_candidates: 500
sources:
  - id: gate-edgetunnel
    subscription_file: ./my-edgetunnel.txt
    max_candidates: 150
  - id: cfnew-home
    subscription_url: https://your-worker.example/your-uuid/sub?target=vg
    max_candidates: 100
vpngate:
  max_candidates: 100
```

相对路径按配置文件所在目录解析；示例域名、文件路径需替换为自己的最终订阅。旧的单个 `subscription_url` / `subscription_file` 配置与 `--configure-cloudflare` 继续有效，保存旧 CLI 参数不会删除已配置的多个来源。每源预算为 1–500；`max_total_candidates`（默认 500，最大 2000）仅限制额外的 Worker/VPN Gate 来源，按来源轮流取候选、合并重复路径的来源后再截断，不限制普通 RSS 和 URLs 总池。自动入口优化另受 `automatic_max_candidates` 限制，默认 40，可设至 500。

保存配置时会检查启用的本地文件是否存在；运行时文件被移动或删除，只将该来源记为失败并继续采集其余来源。远程 Worker/CFnew 订阅最多读取 4 MiB，默认连接超时 5 秒、读取空闲超时 10 秒，并在 15 秒总截止时间内完成连接、响应头和正文读取；持续少量发送数据也不能延长总截止时间。请求保留采集会话选择的 HTTP/HTTPS 代理、请求头和 CA 设置。

自动 Cloudflare 优选使用已采集的有效传输模板替换入口 IP；入口组合增加不等于独立出口增加。VPN Gate 与 gate/CFnew 也可能使用相同上游出口。报告分别给出每源候选数量、各测试阶段数量、选中路径数，以及实际查询所得的独立出口 IP 数；未知出口单独计数，不把 server 地址或入口地址当成已确认出口。相同路径只测一次并合并来源；同出口但服务覆盖不同的路径可继续保留。已通过性能门槛的多个来源会公平分配有限的出口检查名额。

一个路径可归属多个来源，因此各来源数量之和可能大于全局总数。额外来源预算统计候选路径，不保证产生同等数量的新出口；与普通订阅重复的候选在全局去重时继续合并。

自动 Cloudflare 优选和 Worker/CFnew 订阅来源的节点名称统一以 `-cf` 结尾，例如 `香港-cf`；重名时使用 `香港-1-cf`。与普通订阅重复时仍保留此后缀，重复处理不会反复追加。独立 VPN Gate 来源不加此后缀。

`node_selection_report.json` 的计数含义：

| 字段 | 含义 |
| --- | --- |
| `diagnostics.stage_counts.tcp_tested` | 实际执行直连 TCP 快筛的候选 |
| `diagnostics.stage_counts.tcp_skipped` | 跳过快筛、交由内核测试的 OpenVPN、QUIC 和完整代理链 |
| `diagnostics.stage_counts.tcp_passed` | 实际 TCP 快筛成功者，不含跳过者 |
| `diagnostics.stage_counts.tcp_retained` | 快筛成功者与跳过者之和，进入下一阶段 |
| `test_input_count` | 传入内核测试流程的候选数量；是否成功需看后续计数与失败原因 |
| `service_passed_count` / `measured_count` | 至少通过一个目标服务的实测节点；`measured_count` 保留兼容旧报告 |
| `selected_count` | 满足筛选条件并被选中的路径数，不等于独立出口 IP 数 |

全局和每个来源分别给出测试输入、服务通过与选中数量。服务通过为 0 不代表没有执行测试；旧报告若将跳过快筛的节点计入 `tcp_passed`，也不能据此认定 TCP 连接成功。

gate 的 `nodes.txt`（例如 `入口:443#备注$sstp://…`）需要先交给 EdgeTunnel 生成订阅。不能把它作为 `--cloudflare-addresses-file`：程序会明确拒绝，避免把出口链接误当备注，生成实际上没有指定家宽出口的节点。程序不会替你创建 Worker、生成 UUID 或部署检测服务。

CFnew 家宽订阅示例（域名和 UUID 替换为自己的；普通版通常为 `/{UUID}/sub?target=vg`，经典版为 `/{UUID}?target=vg`）：

```powershell
# 在 get_subscribe 目录，将客户端的“CLASH 家宽”订阅保存为 cfnew.yaml 后：
python main.py --configure-cloudflare --cloudflare-subscription-file ./cfnew.yaml --no-cloudflare-optimize
python main.py -p prod --once
```

也可以用 `--cloudflare-subscription-url` 保存自己的 HTTPS 订阅地址，后续每轮重新请求，适合出口池自动更新；本地文件不会自动刷新。URL 可能含 UUID/令牌，配置文件已忽略提交，避免把真实地址粘贴到公开日志或提交中。

链式订阅的行为：

- **运行本项目和导入生成订阅的客户端需要 Mihomo ≥ 1.19.30**，以支持导入所需的 CBC、独立握手预算、数据加密协商、TLS 密钥和会话过渡窗口字段。检测到 OpenVPN 候选时，如现有内核过旧，程序会按当前 Windows/Linux 平台下载官方稳定版到 `.cache/mihomo/`，核对官方 SHA-256 并验证版本，后续复用缓存。仓库随附二进制不被替换。设置了 `MIHOMO_BINARY` 时尊重该路径，过旧则明确失败；下载或验证失败会记录 `openvpn_runtime` 与 `unsupported_core` 原因，普通节点继续筛选。使用生成配置的客户端需自行更新兼容内核。
- 每个出口最多展开 3 个静态前置候选，先覆盖不同出口，再分配备用入口；`--cloudflare-max-candidates` 限制完整链路数量。动态 provider、缺失引用、循环引用、直连 OpenVPN、缺少内联 CA/cert/key 的节点不导入。上游只含不可解析的家宽链路时，不会悄悄改成直接使用 CF 入口。
- 不沿用上游前置组的自动选择状态；每条候选固定到一个前置节点，以保证测试与导出的链路一致。完整链路也参与出口风险查询、家宽优先和服务实测分组。只提取节点数据，不导入订阅的 DNS、规则、控制端口等全局设置。
- OpenVPN 出口跳过本机直连 TCP 快筛，由 Mihomo 验证；服务探测在同一节点的 35 秒总预算内重试，避免外层 5 秒拨号超时提前否定仍在进行的握手。重试不更换出口，随后独立测延时和完整下载；包含家宽节点的客户端自动组也使用 35 秒检查超时。
- OpenVPN 在测速、导出和采集配置中默认启用隧道内 DNS 解析；未指定 DNS 或 `dns: []` 时使用 `1.1.1.1`、`8.8.8.8`，查询经过该 OpenVPN 节点，避免本机 DNS 或 TUN 返回的 fake-IP 被当成公网目标拨号。上游非空 DNS 列表和 `remote-dns-resolve: false` 会保留；`dns: null` 原样保留，由内核校验。普通协议不因此改变解析方式。
- 前置节点在每个测试批次、最终导出和采集缓存中随出口一起保留；只作为拨号依赖，不因出口通过测试而获得独立的 Google、YouTube、ChatGPT 或通用组资格。最多 50 个实测出口之外，YAML 可以另含必要的前置节点。
- 家宽链式订阅不能同时使用地址文件覆盖出口。前置地址应在 CFnew 配置；`--no-cloudflare-optimize` 可跳过本项目的独立入口扫描，仍导入、验证 Worker 订阅，并可随订阅配置持久保存。
- 订阅中的“住宅/纯净”名称只是上游标签，本项目根据实际出口的检测证据分类，不据名称认定住宅属性或信誉。公共出口可能变化，需要重新生成订阅。

参考资料（2026-11-21 核对）：第一个视频 `_YeepOEKQKU` 未能提取字幕，采用作者配套教程 `blog.imxiaohe.com/2026/11/123_0411195847.html`；第二个视频 `FfVstgssKaQ` 已读取完整字幕及说明，并对照 `byJoey/cfnew` 的 `v3.1` 源码核实 OpenVPN/前置组字段。离线回归覆盖链式导入、批次配置、最终导出、内核版本检查和自动入口优选；未连接真实自建 Worker 验证出口。

## 出口风险与家宽优先

prod 自动执行两阶段筛选：先测所有候选的服务可达性和下载速度，再按性能、服务覆盖、来源覆盖分批复测；复测失败时继续补位，每轮最多对 200 个复测合格节点查询出口。来源预留总名额最多占预算一半，其中合格的自动 Cloudflare 候选优先名额最多 10 个，其余按性能补足。复测仍通过时，在测试实例选中该节点的状态下查询实际出口。没有复测通过的节点不导出，避免输入顺序消耗查询预算，也避免一次偶然成功被当作稳定可用。

prod 所有层级默认要求完整下载 1 MiB、速度至少 **5000 kbit/s（5 Mbps）**、204 响应耗时不超过 **1500ms**；家宽优先还要求不超过 **1000ms**。延时使用 gstatic 的空响应请求，失败时可用 Google 的 204 请求，不再把完整网页下载耗时当作延时。多个测试实例的下载测速串行执行，减少本机下载任务互相争抢带宽。dev 未配置时保留较宽门槛。普通节点与 Cloudflare 链式节点使用同一套策略，各服务组和通用组在性能合格者中分别执行以下优先级：

1. **优质低风险家宽候选**：通过低风险检查，并有 ISP 类型证据；完整下载实测至少 **5000 kbit/s**，204 响应耗时不超过 **1000ms**。
2. **其他低风险节点**：没有第一层候选时使用；包括速度或延时未达到第一层门槛的低风险家宽候选。
3. **性能兜底**：前两层都没有时，从已通过对应服务测试的剩余节点中按速度和延时评分选择。此层可能包含风险已知或风险未知的节点，不带“纯净”保证。

每个自动组仅包含当前最高可用等级，客户端随后在同等级内测速选取。最多导出 50 条合格路径，不为凑数放宽门槛。整轮没有合格节点时更新诊断报告、保留旧配置，`--once` 返回失败；请检查报告时间和数量。等级回退发生在**重新生成订阅时**；如果本轮家宽节点导出后全部失效，需要重新生成，客户端不会自动恢复本轮未纳入的低等级节点。没有通过服务测试的候选仍使用 `REJECT`。

默认通过 IPQuery 查询当前节点实际出口。风险分数必须不高于 10，VPN、代理、Tor 标记必须明确为 false，其他必需字段也必须完整，才记为低风险。数据中心低风险出口可以进入第二层，不能进入家宽层。“非数据中心”本身不足以证明家宽。

`-p prod` 自动启用家宽识别模式。ipapi.is 凭据优先读取环境变量 `IPAPI_IS_KEY`，其次读取本地 `config/exit_quality.yaml` 的 `ipapi_is_key`；可复制 `config/exit_quality.example.yaml` 后填入 key，也可通过 `EXIT_QUALITY_CONFIG` 指定配置文件路径。配置中的 key 不会写入生成的订阅或检测报告，本地默认配置已忽略提交。其他环境在配置 key 后也会执行家宽识别。prod 未配置 key 时仍检查 IPQuery 出口风险，但家宽识别状态为“已启用、不可用”（`missing_api_key`），不会把未知住宅属性当作家宽；自动启用不会代为申请 API 凭据。GitHub Actions 可使用仓库 Secrets 中的同名 `IPAPI_IS_KEY`。

家宽候选要求 company 与 ASN 类型均为 `isp`，两者滥用评分不高于 0.01，风险标记、数据中心、移动、卫星、Anycast 标记明确为 false，且没有托管出口服务标记。即使满足这些条件也只代表 **ISP/家宽候选**，不能证明物理家庭线路。

IPQuery 查询失败或缺失必需风险字段时，出口风险为未知。可选的 ipapi.is 查询超时、传输失败或额度受限时，保留 IPQuery 已取得的风险结果，家宽属性保持未知，并以 `reputation_reason` 记录原因；不会仅因辅助查询不可用就丢掉已确认的低风险证据。ipapi.is 实际返回风险信号时会覆盖低风险判断；返回 IP 不一致或缺失必需信誉字段时则保守标记风险未知。请求仅经当前被测节点发出，不切换直连。每次查询的总超时覆盖连接、响应头及完整响应读取，持续慢速响应也会被取消。key 放在 HTTPS POST JSON 中，不写入请求 URL、生成的订阅或报告。prod 每轮最多对 200 个复测合格节点查询出口，复测失败时继续用下一批性能合格候选补位；超额且未经复测的节点不导出。相同出口的 ipapi.is 结果短时复用。IPQuery 的 403/429 仅影响当前节点，其他出口继续检测；ipapi.is 的 403/429 则停止本轮后续账户查询。额度按实际 API 账户限制管理，定时频繁运行时可降低每轮预算。

复制 `config/node_policy.example.yaml` 为 `config/node_policy.yaml` 即可调整风险分数、滥用评分、所有层级与家宽层的速度/延时门槛、查询超时及每轮预算；也可用 `NODE_POLICY_CONFIG` 指定文件路径。错误字段或非法数值会报错，避免配置无效却继续运行。

每次进入节点测试流程后，在输出目录写入 `node_selection_report.json`，包含检测时间、策略门槛、各组选择等级、出口 IP、风险证据、复测结果、家宽检测启用状态，以及 Cloudflare 从采集、TCP、服务、性能、复测到导出的数量与失败阶段。`performance_eligible` 只表示性能达标，`export_eligible` 还要求有可用服务且在 prod 中复测通过；两者均有对应的总数量，最终导出仍受等级优先级和数量上限约束。批次因无效配置提前退出时会拆分重试，隔离问题节点。报告不写代理密码、UUID、订阅地址或 API key，且已忽略提交。若本轮在采集阶段失败，报告可能仍属于上一轮，请核对 `generated_at`。导出的 Clash YAML 会移除内部检测字段。

## Windows 与 Linux 运行

使用 Python 3.10 或更高版本，在 `get_subscribe` 目录安装依赖并运行。Windows PowerShell：

```powershell
python -m pip install -r requirements.txt
# prod 自动启用家宽识别；填入 key 后才可验证，也可改用本地配置文件
$env:IPAPI_IS_KEY = '你的 key'
python main.py -p prod -d ./subscribe --once
```

Linux：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
chmod +x clash/linux-compatible
# prod 自动启用家宽识别；填入 key 后才可验证，也可改用本地配置文件
export IPAPI_IS_KEY='你的 key'
python main.py -p prod -d ./subscribe --once
```

默认优先使用已验证的缓存内核，再按平台选择随附的 Windows `clash/windows-compatible.exe` 或 Linux `clash/linux-compatible`（随附文件为 x86_64）。有 OpenVPN 候选时会按需获取官方兼容内核，支持 Windows/Linux 的 amd64/arm64；也可以通过 `MIHOMO_BINARY` 指定匹配当前平台与架构的文件。Linux 文件必须有执行权限。这个覆盖同时用于采集代理、能力检查和节点测试，路径可含空格。OpenVPN 需要 ≥ 1.19.30，例如：

```powershell
$env:MIHOMO_BINARY = 'D:\tools\mihomo.exe'
```

```bash
export MIHOMO_BINARY='/opt/mihomo/mihomo'
```

离线验证命令为 `python -m unittest discover -s tests -v`。新增工作流覆盖 Ubuntu/Windows 与 Python 3.10/3.12；本地 Windows 测试不能代替 Linux 实际运行或真实出口联网验证。

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

