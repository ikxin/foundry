# ikxin/caddy

使用官方 Caddy 2.11.7 构建镜像和本目录的 `static_rules` 模块编译，运行环境为 Alpine，支持静态站点服务、自定义响应头和重定向规则。最终镜像仅声明 `8080/tcp` 端口。

## 构建和运行

在仓库根目录执行：

```sh
docker buildx build --load -t ikxin/caddy:latest docker/caddy
docker run --rm -p 8080:8080 \
  -v "$PWD/dist:/usr/share/caddy:ro" ikxin/caddy:latest
```

默认监听 `8080`，站点目录为 `/usr/share/caddy`。默认关闭管理 API，不监听 `2019` 端口；默认关闭访问日志，启动和运行日志仍输出到 stderr，便于由反向代理统一记录网站访问。

将镜像用于站点构建的最终阶段：

```dockerfile
FROM ikxin/caddy:latest
COPY dist/ /usr/share/caddy/
```

发布前先执行 `docker login`；以下命令构建并推送 amd64、arm64 镜像，统一使用 `ikxin/caddy:latest` 标签：

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ikxin/caddy:latest \
  --push docker/caddy
```

升级 Caddy 时同步修改 `Dockerfile` 的 `CADDY_VERSION` 和 `go.mod` 的依赖版本，再运行 `go mod tidy` 并重新构建。

## 静态文件行为

- 优先匹配原路径、追加 `.html` 的路径、目录下的 `index.html`。
- 缺失的非 HTML 资源直接返回纯文本 404，不回退到 HTML。
- 站点根目录存在 `404.html` 时，缺失页面返回该文件和 404；否则回退到 `index.html`，正常返回 200，并保留 304、206 等 HTTP 行为。
- 启用 gzip、zstd 压缩，禁止访问路径中的 `.git`、`node_modules`、`vendor`、`.venv`、`_headers` 和 `_redirects`。
- 末段带非 HTML 扩展名的路径被视为资源，例如 `/api/v1.2` 不会进入 SPA 回退。

## 站点规则

在站点根目录放置可选的 `_headers`、`_redirects` 文件，启动时读取，修改后重启容器使其生效。统一支持各平台的规则语法，不需要选择平台；语义冲突时以 Cloudflare 为准。不支持或格式错误的声明静默跳过，不输出警告，也不会阻止其他规则生效；规则文件无法读取等文件系统错误仍会阻止启动。

| 行为 | 统一语义 |
| --- | --- |
| 省略重定向状态码 | 302 |
| 规则顺序 | 按文件顺序执行首个满足路径、查询和条件的规则；同来源的条件规则可依次回退 |
| 已有文件 | 重定向、重写优先；兼容状态码后的 `!`，无需靠它覆盖文件 |
| 路径匹配 | 区分大小写，严格区分末尾斜杠；`/docs/*` 匹配 `/docs/`，不匹配 `/docs` |
| 响应头 | 叠加所有匹配规则，同名头以逗号合并；支持头值变量和 `! Header-Name` 删除头 |
| 内部重写 | `200` 读取目标文件，只执行一次；4xx/5xx 可指定错误页面 |
| 外部代理 | `200` 指向外部 HTTP(S) 地址，保留请求方法、请求体和编码路径，超时 26 秒 |

支持空行和整行 `#` 注释，`_redirects` 还支持行尾注释。路径支持命名占位符 `:name` 和通配符 `*`；重定向允许一个 `*`，可在路径中间使用。响应头额外支持 Netlify 的多个 `*`；只有单个 `*` 时才提供 `:splat` 捕获值。命名占位符与通配符可以组合，但捕获名称不得重复。

捕获值可以用于重定向目标的路径、域名、查询串、片段或响应头值，编码路径不会重复解码。目标自带非空查询串时替换原查询串，否则保留；通过查询条件捕获的参数不会额外转发。独立镜像不套用 SaaS 的规则数量和部署配额。

`_headers` 示例：

```text
/*
  X-Frame-Options: DENY
/assets/*
  Cache-Control: public, max-age=31536000, immutable
/assets/*/*.js
  X-Asset-Type: javascript
/movies/:title
  X-Movie-Name: :title
/*.jpg
  ! X-Frame-Options
```

响应头可按路径或 HTTPS 域名模式匹配，例如 `https://:project.pages.dev/*`；域名模式忽略请求协议和端口。多个规则按顺序先删除、再合并该规则声明的头。响应头在发送前应用，匹配原始请求路径；内部重写不会改为匹配目标路径。重定向响应和外部代理响应不应用普通 `_headers` 规则。

`_redirects` 示例，可混合使用 Cloudflare 和 Netlify 的语法：

```text
/old /new 301
/old-docs/* /docs/:splat 302
/posts/:year/:slug /news/:slug?year=:year 307
/app/* /index.html 200
/store id=:id /blog/:id 301
/products /zh/products 302 Language=zh
/ /cn 302 Country=cn
/preview/* /draft/:splat 200! Cookie=preview
/admin/* /admin/:splat 200! Role=admin
/admin/* /login.html 401!
/api/* https://api.example.com/:splat 200
https://old.example.com/* https://example.com/:splat 301
```

来源为完整 HTTP(S) URL 时同时匹配协议、域名和路径。查询条件必须匹配完整参数集合；`Country`、`Language`、`Cookie`、`Role` 支持逗号分隔的候选值，多种条件必须同时满足。未知条件会使整条规则被忽略，不会退化为无条件跳转。按 Cloudflare 语义，每次请求只执行首个匹配规则，不自动合并后续重定向链。

同站重写保留 HEAD、Range、ETag 和条件请求，自定义错误页面使用声明的错误状态码。目标文件缺失时尝试根目录 `404.html`，否则返回纯文本 404。

### 条件与认证的配置

国家和语言优先使用 `nf_country`、`nf_lang` cookie。语言否则读取 `Accept-Language` 的第一个值，忽略质量权重，支持区域语言回退。Cookie 条件只检查名称是否存在，名称不区分大小写。条件响应添加对应的 `Vary` 字段。

容器不自带 GeoIP 数据库。需要按真实国家匹配时，设置 `STATIC_RULES_COUNTRY_HEADER`（例如 `CF-IPCountry`），并在 Caddy 的 `servers { trusted_proxies ... }` 中配置实际可信代理；只有可信代理提供的地理信息头会参与匹配。国家 cookie 可覆盖地理信息。

`Role` 读取 `nf_jwt` cookie，使用 `STATIC_RULES_JWT_SECRET` 校验 HS256 签名、JWT 类型、有效期和 `nbf`，支持 `app_metadata.roles` 与 `app_metadata.authorization.roles`。无权限且没有后续匹配规则时返回 404。

兼容 Netlify 的 Basic Auth，在 `_headers` 中配置：

```text
/protected/*
  Basic-Auth: user:password second:other-password
```

认证在跳转、重写和代理前执行，凭证不作为响应头输出；更后面的匹配认证规则覆盖之前的规则。

支持 `/* 200! Role=admin` 转发简写，以及外部代理后的 `Sign=ENV_VAR` / `signed=ENV_VAR` 签名声明。签名通过 `x-nf-sign` 发送有效期 5 分钟的 HS256 JWT，密钥来自对应环境变量；`CONTEXT`、`SITE_ID`、`URL` 可提供部署上下文。缺少签名密钥时请求失败，不发送无签名代理请求。

可在 `static_rules` 的 Caddyfile 块中设置 `country_header`、`jwt_secret`，优先于环境变量。兼容范围为 `_headers` 和 `_redirects` 文件；`netlify.toml`、平台 Functions、CDN 缓存和 Identity 服务不由本模块实现。

参考：[Cloudflare 重定向](https://developers.cloudflare.com/workers/static-assets/redirects/)、[Cloudflare 响应头](https://developers.cloudflare.com/workers/static-assets/headers/)、[Netlify 重定向](https://docs.netlify.com/manage/routing/redirects/redirect-options/)、[Netlify 响应头](https://docs.netlify.com/manage/routing/headers/)。
