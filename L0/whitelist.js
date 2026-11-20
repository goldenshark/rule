// Loon 插件参数 po0Url 和独立脚本参数均接收完整的 HTTPS 加白链接。
const argument = typeof $argument === "undefined" ? null : $argument;
const input = typeof argument === "string" ? argument : argument && argument.po0Url;
const url = typeof input === "string" ? input.trim() : "";
const addUrl = /^https:\/\/[^\s/?#@\\]+\/api\/firewall\/pgnfw_[a-zA-Z0-9_-]+\/add(?:\?slot=[0-4])?$/;
const ipv4OrSubnet = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}(?:\/24)?$/;

function finish(message) {
  console.log("[po0 白名单] " + message);
  $done({ title: "po0 白名单", content: message });
}

function checkWhitelist(body) {
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    return "接口返回了无法解析的响应";
  }

  if (data && data.enabled === false) return "服务器防火墙尚未启用";
  if (!data || data.enabled !== true || !Array.isArray(data.whitelist)) {
    return "接口响应缺少防火墙状态或白名单";
  }

  const currentIp = data.currentIp;
  const current = typeof currentIp === "string" && ipv4OrSubnet.exec(currentIp);
  if (!current) return "接口未返回有效的出口 IPv4 或网段";

  const listed = data.whitelist.some((entry) => {
    const ip = typeof entry === "string" ? entry : entry && entry.ip;
    const network = typeof ip === "string" && ipv4OrSubnet.exec(ip);
    if (!network) return false;
    return ip === currentIp || (network[1] === current[1] &&
      (ip.endsWith("/24") || currentIp.endsWith("/24")));
  });

  return listed ? `${currentIp} 已在白名单中` : `${currentIp} 尚未出现在白名单中`;
}

function register(canRetry) {
  $httpClient.post({
    url,
    node: "DIRECT",
    timeout: 8000,
    insecure: false,
    "auto-redirect": false,
    "auto-cookie": false,
    headers: { "Content-Type": "application/json" },
    body: ""
  }, (error, response, body) => {
    const status = Number(response && (response.status || response.statusCode));
    if (canRetry && (status >= 500 || !status)) {
      setTimeout(() => register(false), 1500);
      return;
    }

    if (!status) {
      finish("连接失败，请检查网络、接口地址或 HTTPS 证书");
    } else if (status < 200 || status >= 300) {
      finish(`登记请求失败（HTTP ${status}）`);
    } else if (error) {
      finish("读取接口响应失败");
    } else {
      finish(checkWhitelist(body));
    }
  });
}

if (addUrl.test(url)) {
  register(true);
} else {
  finish("请在 Loon 中填写完整的 po0 HTTPS 加白链接");
}
