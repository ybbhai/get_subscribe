import argparse
import os
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import feedparser
import requests
import schedule
import yaml
from matplotlib.style.core import available

from utils.utils import test_nodes, v2ray_2_clash, SSLAdapter, clean_yaml_content, parse_special_clash, filter_proxies, \
    test_proxy_telnet

requests.packages.urllib3.disable_warnings()

ok_code = [200, 201, 202, 203, 204, 205, 206]

# 邮箱域名过滤列表
blackhole_list = ["cnr.cn", "cyberpolice.cn", "gov.cn", "samr.gov.cn", "12321.cn"
                                                                       "miit.gov.cn", "chinatcc.gov.cn"]


def write_log(content, level="INFO"):
    date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    update_log = f"[{date_str}] [{level}] {content}\n"
    print(update_log)
    with open(f'./log/{time.strftime("%Y-%m", time.localtime(time.time()))}-update.log', 'a', encoding="utf-8") as f:
        f.write(update_log)


def get_subscribe_proxies():
    dirs = './subscribe'
    if not os.path.exists(dirs):
        os.makedirs(dirs)
    log_dir = "./log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    rss = feedparser.parse('https://www.cfmem.com/feeds/posts/default?alt=rss')
    entries = rss.get("entries")
    if not entries:
        write_log("更新失败！无法拉取原网站内容", "ERROR")
        return
    update_list = []
    summary = entries[0].get("summary")
    if not summary:
        write_log("暂时没有可用的订阅更新", "WARN")
        return
    v2ray_list = re.findall(r">V2Ray/XRay -&gt; (.*?)</span>", summary)
    proxies = []
    # 获取普通订阅链接
    if any(v2ray_list):
        v2ray_url = v2ray_list[-1].replace('amp;', '')
        v2ray_req = requests.request("GET", v2ray_url, verify=False)
        v2ray_code = v2ray_req.status_code
        if v2ray_code not in ok_code:
            write_log(f"获取 v2ray 订阅失败：{v2ray_url} - {v2ray_code}", "WARN")
        else:
            update_list.append(f"v2ray: {v2ray_code}")
            proxies.extend(v2ray_2_clash(content=v2ray_req.text))
    clash_list = re.findall(r">clash -&gt; (.*?)</span>", summary)
    # 获取clash订阅链接
    if any(clash_list) and not clash_list[-1].startswith("订阅地址生成失败"):
        clash_url = clash_list[-1].replace('amp;', '')
        clash_req = requests.request("GET", clash_url, verify=False)
        clash_code = clash_req.status_code
        if clash_code not in ok_code:
            write_log(f"获取 clash 订阅失败：{clash_url} - {clash_code}", "WARN")
        else:
            update_list.append(f"clash: {clash_code}")
            clash_content = clash_req.content.decode("utf-8")
            # 获取clash_content里的proxies
            proxies.extend(yaml.safe_load(clash_content)["proxies"])
    print("结果: ", update_list)
    return proxies


def get_clash_proxies():
    # 获取当前时间，并转换成yyyyMMdd格式的字符串
    now = time.localtime(time.time())
    year = time.strftime('%Y', now)
    month = time.strftime('%m', now)
    stamp = time.strftime('%Y%m%d', now)

    urls = [
        "https://free.datiya.com/uploads/{stamp}-clash.yaml",
        "https://node.openclash.cc/uploads/{year}/{month}/2-{stamp}.yaml",
        "https://node.openclash.cc/uploads/{year}/{month}/4-{stamp}.yaml",
        # "https://oneclash.cc/wp-content/uploads/{year}/{month}/{stamp}.yaml",
        "https://raw.githubusercontent.com/free-nodes/clashfree/refs/heads/main/clash{stamp}.yml",
        "https://clashgithub.com/wp-content/uploads/rss/{stamp}.yml",
        "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
        # "https://fastly.jsdelivr.net/gh/freenodes/freenodes@main/ClashPremiumFree.yaml",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml"
    ]

    proxies = []
    # 创建session并配置SSL适配器、超时、重试策略
    session = requests.Session()
    session.mount("https://", SSLAdapter())
    # 设置超时时间（连接超时5秒，读取超时10秒）
    timeout = (5, 10)
    for url in urls:
        url = url.format(stamp=stamp, year=year, month=month)
        # 获取链接文件内容
        content = None
        try:
            req = session.get(url,
                              verify=False,
                              timeout=timeout,
                              headers={
                                  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
            print("获取yaml文件结果: ", req)
            if req.status_code in ok_code:
                content = req.content.decode("utf-8")
                content = clean_yaml_content(content)
                content = yaml.safe_load(content)
                proxies.extend(content["proxies"])
        except Exception as e:
            if content:
                try:
                    tmp = parse_special_clash(content)
                    proxies.extend(tmp)
                except Exception as e:
                    print("获取proxy失败：", url, e)
            else:
                print("获取proxy失败：", url, e)
    return proxies


def main(env, dirs):
    proxies = get_subscribe_proxies()
    proxies.extend(get_clash_proxies())
    proxies = filter_proxies(proxies)
    # 并发调用方法test_proxy_telnet测试proxies的连通性
    available_proxies = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(test_proxy_telnet, proxies))
        # print(results)
        for i, result in enumerate(results):
            if result:
                available_proxies.append(proxies[i])
    # 测试proxies的可用性
    if available_proxies:
        available_proxies = test_nodes(available_proxies, env, dirs)
    print("可用代理: ", len(available_proxies))


def parse_command_args():
    """
    解析命令行参数，支持 -p/--profile 和 -d/--directory 参数，顺序不限
    返回：解析后的参数字典
    """
    # 1. 创建参数解析器
    parser = argparse.ArgumentParser(
        description="解析命令行参数示例：支持-p（环境，可选）和-d（目录，可选）参数，顺序不限",
        formatter_class=argparse.RawTextHelpFormatter  # 保持帮助文本格式
    )

    # 2. 添加需要的参数（-p/--profile 是短参数/长参数，required=True 表示必传）
    parser.add_argument(
        '-p', '--profile',  # 参数名：短参数-p，长参数--profile
        type=str,          # 参数类型：字符串
        required=False,     # 是否必传：是
        help='运行环境标识，例如 dev/prod/test'
    )

    parser.add_argument(
        '-d', '--directory',  # 参数名：短参数-d，长参数--directory
        type=str,
        required=False,
        help='目标目录路径，例如 ./data 或 /home/user/dir'
    )

    # 3. 解析参数（自动处理参数顺序，忽略顺序差异）
    args = parser.parse_args()

    # 4. 转换为字典（方便使用）
    return {
        'profile': args.profile,
        'directory': args.directory
    }


# 主函数入口
if __name__ == '__main__':
    # 接收运行时用参数-p/-d指定的参数
    # 解析命令行参数
    args = parse_command_args()

    env = "dev"
    if "profile" in args and args["profile"]:
        env = args["profile"]
    dirs = os.path.join(os.path.dirname(__file__), "clash")
    if "directory" in args and args["directory"]:
        dirs = args["directory"]

    # 定时任务，每三小时执行一次，初次运行时也启动
    schedule.every(3).hours.do(main, env, dirs).run()
    # dirs = './subscribe'
    # v2ray_2_clash(dirs + '/v2ray.txt')

    # get_clash_proxies()

    # dirs = "./clash/test_config.yaml"
    # with open(dirs, encoding="utf-8") as f:
    #     base_config = yaml.safe_load(f)
    # result = test_nodes(base_config["proxies"])
    # print(result)
