# Build context is this scanner-core/ directory. The sibling tool scripts
# it wraps (e.g. ../../ssl_tls_scanner) live outside this project, so they
# are reached via a second named build context ("tools_root", see
# docker-compose.yml's build.additional_contexts) instead of widening this
# context to the whole shared tools/ directory.
#
# spec §53 Docker 책임 + §63 버전 관리: ffuf/gobuster are pinned Linux
# release binaries (not apt packages) so the exact tool version used in a
# scan is reproducible, matching how ssl_tls_scanner's openssl dependency
# is a known system package version.
FROM python:3.11-slim

ARG FFUF_VERSION=2.1.0
ARG GOBUSTER_VERSION=3.6.0
# spec review finding (2026-09-06): this Dockerfile hardcoded linux_amd64
# release assets, so it never actually ran natively on Apple Silicon (spec
# §52 requires macOS Apple Silicon as a first-class supported host, not just
# "works under amd64 emulation"). BuildKit (the default builder since Docker
# 23) auto-populates TARGETARCH to match the actual build platform -- no
# docker-compose.yml change needed for this to resolve correctly on either host.
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl nmap curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && case "${TARGETARCH}" in \
         amd64) FFUF_ARCH=amd64; GOBUSTER_ARCH=x86_64 ;; \
         arm64) FFUF_ARCH=arm64; GOBUSTER_ARCH=arm64 ;; \
         *) echo "unsupported TARGETARCH: '${TARGETARCH}' (expected amd64 or arm64)" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${FFUF_ARCH}.tar.gz" \
       -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm /tmp/ffuf.tar.gz \
    && curl -fsSL "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_${GOBUSTER_ARCH}.tar.gz" \
       -o /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm /tmp/gobuster.tar.gz

WORKDIR /app/tools/security_toolkit/scanner-core

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY --from=tools_root ssl_tls_scanner /app/tools/ssl_tls_scanner
COPY --from=tools_root site_depth_crawler /app/tools/site_depth_crawler
COPY --from=tools_root default_content_scanner /app/tools/default_content_scanner
COPY --from=tools_root infra_vuln_scanner /app/tools/infra_vuln_scanner
COPY --from=tools_root ffuf_scanner /app/tools/ffuf_scanner
COPY --from=tools_root gobuster_scanner /app/tools/gobuster_scanner
COPY --from=tools_root xss_reflected_scanner /app/tools/xss_reflected_scanner
COPY --from=tools_root xss_stored_scanner /app/tools/xss_stored_scanner
COPY --from=tools_root jwt_analyzer /app/tools/jwt_analyzer
COPY --from=tools_root crypto_identifier /app/tools/crypto_identifier
COPY --from=tools_root security_toolkit/safe_http_checks /app/tools/security_toolkit/safe_http_checks

# Runtime-offline data set.  Only the files used by the registered wrappers
# are embedded; the much larger upstream repositories and their unreviewed
# payloads are intentionally not copied into the runnable image.
COPY --from=tools_root SecLists-master/Discovery/Web-Content/common.txt /app/tools/SecLists-master/Discovery/Web-Content/common.txt
COPY --from=tools_root SecLists-master/Discovery/Web-Content/Web-Servers /app/tools/SecLists-master/Discovery/Web-Content/Web-Servers
COPY --from=tools_root SecLists-master/Passwords/scraped-JWT-secrets.txt /app/tools/SecLists-master/Passwords/scraped-JWT-secrets.txt
COPY --from=tools_root SecLists-master/Passwords/Common-Credentials/10k-most-common.txt /app/tools/SecLists-master/Passwords/Common-Credentials/10k-most-common.txt
COPY --from=tools_root ["PayloadsAllTheThings-master/Directory Traversal/Intruder", "/app/tools/PayloadsAllTheThings-master/Directory Traversal/Intruder"]

# spec review finding (2026-09-05): default_content_scanner/ffuf_scanner/
# gobuster_scanner/jwt_analyzer/crypto_identifier all resolve their default
# wordlists against ../SecLists-master and ../PayloadsAllTheThings-master
# relative to their own script (i.e. /app/tools/SecLists-master here) --
# without these, path_traversal always fails (no CLI override exists for
# its payload dir) and ffuf/gobuster/crack features fail whenever no
# explicit --wordlist is passed.  The exact required subsets are copied
# above so runtime never depends on host wordlists or Internet access.
RUN mkdir -p /app/tools/SecLists-master /app/tools/PayloadsAllTheThings-master

ENV SCANNER_DATA_DIR=/app/tools/security_toolkit/scanner-data
ENV NO_PROXY=*
ENV no_proxy=*
EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
