# ikxin/caddy

使用官方 Caddy 2.11.7 镜像和本目录的 `static_rules` 模块构建，支持静态站点服务、自定义响应头和重定向规则。

## 构建和运行

在仓库根目录执行：

```sh
docker buildx build --load -t ikxin/caddy:latest docker/caddy
docker run --rm -p 8080:8080 \
  -v "$PWD/dist:/usr/share/caddy:ro" ikxin/caddy:latest
```

默认监听 `8080`，站点目录为 `/usr/share/caddy`，访问日志输出到 stderr。

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

在站点根目录放置可选的 `_headers`、`_redirects` 文件，启动时读取。修改后重启容器，或执行 `caddy reload --force --config /etc/caddy/Caddyfile --adapter caddyfile`。

`_headers` 示例：

```text
/about
  Cache-Control: no-cache
  X-Frame-Options: DENY
/assets/app.js
  Cache-Control: public, max-age=3600
```

`_redirects` 示例：

```text
/old /new 301
/docs https://example.com/docs 302
/gateway https://example.com
/old-docs/* /docs/:splat 301
```

`_headers` 按请求路径精确匹配，忽略查询参数和末尾斜杠，同一路径重复定义时最后一条生效。

`_redirects` 优先匹配精确路径，再按文件顺序匹配末尾 `/*` 通配符，忽略末尾斜杠，相同来源路径重复定义时最后一条覆盖原定义。目标路径中的 `:splat` 替换为捕获的剩余路径；通配符也匹配不带末尾斜杠的空路径，例如 `/old-docs` 和 `/old-docs/`。状态码可省略，默认为 302，支持显式指定 301、302、303、307、308。目标未指定查询参数时保留请求的查询参数；目标自带查询参数或以 `?` 结尾时使用目标设置。

重定向优先于响应头规则和文件服务。支持空行和整行 `#` 注释，暂不支持其他通配符、条件规则和 200 内部重写；无效规则会报出文件及行号并阻止启动。
