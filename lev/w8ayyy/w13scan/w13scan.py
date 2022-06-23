"""
w13scan漏洞扫描器
GitHub: https://github.com/w-digital-scanner/w13scan
"""
import levrt
from levrt import Cr, annot, ctx
from levrt.annot.cats import Attck
from urllib.parse import urlparse


def _spider(target: str, cookies: str = "", thread_num: int = 20, max_count: int = 10086) -> list:
    import json
    import subprocess
    import logging
    logger = logging.getLogger("lev")
    logger.setLevel(logging.INFO)

    # 爬虫文件路径
    Excvpath = "/usr/bin/crawlergo"
    # Chrome 路径
    Chromepath = "/usr/bin/chromium-browser"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3945.0 Safari/537.36",
        "Spider-Name": "Baidu.Inc",
        "Cookie": cookies,
    }
    if target == "":
        return
    elif "://" not in target:
        target = "http://" + target
    logger.info("Target:{}".format(target))

    cmd = [Excvpath, "-c", Chromepath, "--fuzz-path", "--robots-path", "-t", str(thread_num), "--custom-headers",
           json.dumps(
               headers), "--max-crawled-count", str(max_count), "-i", "-o", "json",
           target]
    rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = rsp.communicate()
    try:
        result = json.loads(output.decode().split("--[Mission Complete]--")[1])
    except IndexError:
        return
    all_req_list = result["req_list"]
    return all_req_list


@annot.meta(
    desc="对单个url进行漏洞扫描",
    params=[annot.Param("url", "目标URL"),
            annot.Param("cookies", "Cookies", holder="debug=1;w13scan=1;"),
            annot.Param("threads", "线程数"),
            annot.Param("timeout", "超时时间"),
            annot.Param("sql", "是否启用sql注入扫描"),
            annot.Param("command", "是否启用命令执行扫描"),
            annot.Param("xss", "是否启用xss扫描"),
            annot.Param("backup", "是否启用备份文件扫描"),
            ],
)
def single_scan(url: str, cookies: str = 'w13scan=1;', threads: int = 30, timeout: int = 30, sql: bool = True, command: bool = True, xss: bool = True, backup: bool = True) -> Cr:
    """
    单个漏洞扫描

    ```
    await single_scan(url,cookies,threads,timeout,sql,command,xss,backup)
    ```
    """

    @levrt.remote
    def entry():
        import sys
        sys.path.append("/usr/local/lib/python3.10/site-packages")
        sys.path.append("/w13scan")
        root = "/w13scan/W13SCAN"
        sys.path.append(root)

        import requests
        from W13SCAN.api import init, FakeReq, FakeResp, HTTPMETHOD, task_push_from_name, start, KB
        disable_plugins = ['poc_fastjson', 'struts2_032', 'struts2_045']
        sql_plugins = [
            'sqli_bool',
            'sqli_error',
            'sqli_time'
        ]
        if not sql:
            disable_plugins.extend(sql_plugins)
        command_plugins = [
            'command_asp_code',
            'command_php_code',
            'command_system'
        ]
        if not command:
            disable_plugins.extend(command_plugins)
        xss_plugins = [
            'xss'
            'net_xss',
            'swf_files'
        ]
        if not xss:
            disable_plugins.extend(xss_plugins)
        backup_plugins = [
            'backup_file',
            'backup_folder',
            'backup_domain',
        ]
        if not backup:
            disable_plugins.extend(backup_plugins)

        configure = {
            "debug": True,  # debug模式会显示更多信息
            "level": 2,
            "timeout": timeout,
            "retry": 3,
            "json": "",  # 自定义输出json结果路径,
            "html": False,
            "threads": threads,  # 线程数量,
            "disable": disable_plugins,
            "able": [],
            "excludes": ["google", "lastpass", '.gov.cn']  # 不扫描的网址
        }
        print("[*] 启动w13scan")
        init(root, configure)
        headers = {}
        req = requests.get(url, headers=headers)
        fake_req = FakeReq(req.url, headers, HTTPMETHOD.GET)
        fake_resp = FakeResp(req.status_code, req.content, req.headers)
        task_push_from_name('loader', fake_req, fake_resp)
        start()
        count = len(KB["output"].collect)
        print('[*] 漏洞扫描完毕，漏洞数量:{}'.format(count))
        if count>0:
            ctx.set(callback=KB["output"].collect)
            filename = KB["output"].get_html_filename()
            with open(filename,'rb') as f:
                data = f.read()
                ctx.set(result={"results.html":data})
    return Cr(".w8ayyy.w13scan:v0.1", entry=entry())


@annot.meta(
    desc="chromium动态爬虫",
    params=[annot.Param("url", "目标URL"),
            annot.Param("cookies", "Cookies", holder="debug=1;w13scan=1;"),
            annot.Param("thread_num", "线程数"),
            annot.Param("max_count", "爬虫爬取最大数量"),
            ],
)
def spider(url: str, cookies: str = "w13scan=1;", thread_num: int = 20, max_count: int = 10086) -> Cr:
    """
    爬虫模式

    ```
    await spider(url,cookies,thread_num,max_count)
    ```
    """

    @levrt.remote
    def entry():
        import logging
        logger = logging.getLogger("lev")
        logger.setLevel(logging.INFO)
        callback = _spider(url, cookies, thread_num, max_count)
        logger.info("爬虫爬取数量:{}".format(len(callback)))
        ctx.set("callback", callback)
    return Cr(".w8ayyy.w13scan:v0.1", entry=entry())


@annot.meta(
    desc="标准模式，爬虫+漏洞扫描",
    params=[annot.Param("url", "目标URL"),
            annot.Param("cookies", "Cookies", holder="debug=1;w13scan=1;"),
            annot.Param("thread_num", "线程数"),
            annot.Param("max_count", "爬虫爬取最大数量"),
            annot.Param("timeout", "超时时间"),
            annot.Param("sql", "是否启用sql注入扫描"),
            annot.Param("command", "是否启用命令执行扫描"),
            annot.Param("xss", "是否启用xss扫描"),
            annot.Param("backup", "是否启用备份文件扫描"),
            ],
)
def fullscan(url: str, cookies: str = "w13scan=1;", thread_num: int = 20, max_count: int = 10086, timeout: int = 30, sql: bool = True, command: bool = True, xss: bool = True, backup: bool = True) -> Cr:
    """
    漏洞扫描标准模式
    ```
    await fullscan(url,cookies,thread_num,max_count,timeout,sql,command,xss,backup)
    ```
    """

    @levrt.remote
    def entry():
        import logging
        logger = logging.getLogger("lev")
        logger.setLevel(logging.INFO)
        callback = _spider(url, cookies, thread_num, max_count)
        print("爬虫爬取数量:{}".format(len(callback)))

        import sys
        sys.path.append("/usr/local/lib/python3.10/site-packages")
        sys.path.append("/w13scan")
        root = "/w13scan/W13SCAN"
        sys.path.append(root)

        import requests
        from W13SCAN.api import init, FakeReq, FakeResp, HTTPMETHOD, task_push_from_name, start, KB
        disable_plugins = ['poc_fastjson', 'struts2_032', 'struts2_045']
        sql_plugins = [
            'sqli_bool',
            'sqli_error',
            'sqli_time'
        ]
        if not sql:
            disable_plugins.extend(sql_plugins)
        command_plugins = [
            'command_asp_code',
            'command_php_code',
            'command_system'
        ]
        if not command:
            disable_plugins.extend(command_plugins)
        xss_plugins = [
            'xss'
            'net_xss',
            'swf_files'
        ]
        if not xss:
            disable_plugins.extend(xss_plugins)
        backup_plugins = [
            'backup_file',
            'backup_folder',
            'backup_domain',
        ]
        if not backup:
            disable_plugins.extend(backup_plugins)

        configure = {
            "debug": True,  # debug模式会显示更多信息
            "level": 2,
            "timeout": timeout,
            "retry": 3,
            "json": "",  # 自定义输出json结果路径,
            "html": True,
            "threads": thread_num,  # 线程数量,
            "disable": disable_plugins,
            "able": [],
            "excludes": ["google", "lastpass", '.gov.cn']  # 不扫描的网址
        }
        print("[*] 启动w13scan")
        init(root, configure)
        for item in callback:
            url1 = item["url"]
            method = item["method"]
            headers = item["headers"]
            data = item["data"]

            try:
                if method.lower() == 'post':
                    req = requests.post(url1, data=data, headers=headers)
                    http_model = HTTPMETHOD.POST
                else:
                    req = requests.get(url1, headers=headers)
                    http_model = HTTPMETHOD.GET
            except Exception as e:
                logger.error(
                    "request method:{} url:{} faild,{}".format(method, url1, e))
                continue

            fake_req = FakeReq(req.url, {}, http_model, data)
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push_from_name('loader', fake_req, fake_resp)
            logger.info("加入扫描目标:{}".format(req.url))

        start()
        count = len(KB["output"].collect)
        print('[*] 漏洞扫描完毕，漏洞数量:{}'.format(count))
        if count>0:
            ctx.set(callback=KB["output"].collect)
            filename = KB["output"].get_html_filename()
            with open(filename,'rb') as f:
                data = f.read()
                ctx.set(result={"results.html":data})

    return Cr(".w8ayyy.w13scan:v0.1", entry=entry())


__lev__ = annot.meta([fullscan, spider, single_scan],
                     cats={
    Attck: [Attck.Reconnaissance, Attck.InitialAccess, Attck.Discovery]  # ATT&CK
},
    tags=['w13scan', 'web漏洞扫描'],
)
