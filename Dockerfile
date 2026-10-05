#
# Multi-stage Dockerfile for Pentest Agent
# Uses Chainguard Wolfi for minimal attack surface and supply chain security

# Pinned security tooling used by opt-in assessment modules.
FROM cgr.dev/chainguard/wolfi-base:latest AS security-tools

RUN apk update && apk add --no-cache curl ca-certificates unzip

ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=10.4.8
ARG GITLEAKS_VERSION=8.30.1
ARG K6_VERSION=2.2.0

RUN set -eux; \
    case "$(uname -m)" in \
      x86_64) NUCLEI_ARCH=amd64; GITLEAKS_ARCH=x64; K6_ARCH=amd64 ;; \
      aarch64) NUCLEI_ARCH=arm64; GITLEAKS_ARCH=arm64; K6_ARCH=arm64 ;; \
      *) echo "unsupported security-tool architecture: $(uname -m)"; exit 1 ;; \
    esac; \
    mkdir -p /security-tools/bin /security-tools/opt /tmp/security-tools; \
    cd /tmp/security-tools; \
    curl -fsSLO "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"; \
    echo "${ZAP_SHA256}  ZAP_${ZAP_VERSION}_Linux.tar.gz" | sha256sum -c -; \
    tar -xzf "ZAP_${ZAP_VERSION}_Linux.tar.gz"; \
    mv "ZAP_${ZAP_VERSION}" /security-tools/opt/zap; \
    curl -fsSLO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_checksums.txt"; \
    curl -fsSLO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip"; \
    grep "nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" "nuclei_${NUCLEI_VERSION}_checksums.txt" | sha256sum -c -; \
    unzip -q "nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" nuclei; \
    mv nuclei /security-tools/bin/nuclei; \
    curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
    curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"; \
    grep "gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" gitleaks; \
    mv gitleaks /security-tools/bin/gitleaks; \
    curl -fsSLO "https://github.com/grafana/k6/releases/download/v${K6_VERSION}/k6-v${K6_VERSION}-checksums.txt"; \
    curl -fsSLO "https://github.com/grafana/k6/releases/download/v${K6_VERSION}/k6-v${K6_VERSION}-linux-${K6_ARCH}.tar.gz"; \
    grep "k6-v${K6_VERSION}-linux-${K6_ARCH}.tar.gz" "k6-v${K6_VERSION}-checksums.txt" | sha256sum -c -; \
    tar -xzf "k6-v${K6_VERSION}-linux-${K6_ARCH}.tar.gz"; \
    mv "k6-v${K6_VERSION}-linux-${K6_ARCH}/k6" /security-tools/bin/k6; \
    chmod +x /security-tools/bin/* /security-tools/opt/zap/zap.sh

RUN set -eux; \
    root=/security-tools/opt/nuclei-templates; \
    mkdir -p "$root/http/misconfiguration" "$root/http/exposures/configs" "$root/http/technologies"; \
    base="https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/v${NUCLEI_TEMPLATES_VERSION}"; \
    curl -fsSL "$base/http/misconfiguration/http-missing-security-headers.yaml" -o "$root/http/misconfiguration/http-missing-security-headers.yaml"; \
    curl -fsSL "$base/http/exposures/configs/nextjs-vite-public-env.yaml" -o "$root/http/exposures/configs/nextjs-vite-public-env.yaml"; \
    curl -fsSL "$base/http/exposures/configs/git-config.yaml" -o "$root/http/exposures/configs/git-config.yaml"; \
    curl -fsSL "$base/http/exposures/configs/package-json.yaml" -o "$root/http/exposures/configs/package-json.yaml"; \
    curl -fsSL "$base/http/technologies/tech-detect.yaml" -o "$root/http/technologies/tech-detect.yaml"

# Builder stage - Install tools and dependencies
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

# Install system dependencies available in Wolfi
RUN apk update && apk add --no-cache \
    # Core build tools
    build-base \
    git \
    curl \
    wget \
    ca-certificates \
    # Language runtimes
    nodejs-22 \
    npm \
    # Additional utilities
    bash

# Install pnpm
RUN npm install -g --ignore-scripts pnpm@10.33.0

# Build Node.js application in builder to avoid QEMU emulation failures in CI
WORKDIR /app

# Copy workspace manifests for install layer caching
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./
COPY apps/worker/package.json ./apps/worker/
COPY apps/cli/package.json ./apps/cli/

RUN pnpm install --frozen-lockfile

COPY . .

# Build worker. CLI not needed in Docker
RUN pnpm --filter @shannon/worker run build
RUN test -f apps/worker/dist/ai/extensions/bash-timeout/index.js

# Production-only deps (pnpm recommends install --prod over prune in monorepos)
RUN rm -rf node_modules apps/*/node_modules && pnpm install --frozen-lockfile --prod

# Runtime stage - Minimal production image
FROM cgr.dev/chainguard/wolfi-base:latest AS runtime

# Install only runtime dependencies
USER root
RUN apk update && apk add --no-cache \
    # Core utilities
    git \
    bash \
    curl \
    ca-certificates \
    shadow \
    # Typst release archive decompression
    xz \
    # Language runtimes (minimal)
    nodejs-22 \
    npm \
    python3 \
    openjdk-21-jre \
    # Chromium browser and dependencies for Playwright
    chromium \
    # Additional libraries Chromium needs
    nss \
    freetype \
    harfbuzz \
    # X11 libraries for headless browser
    libx11 \
    libxcomposite \
    libxdamage \
    libxext \
    libxfixes \
    libxrandr \
    mesa-gbm \
    # Font rendering
    fontconfig

# Pin the PDF compiler and select the musl release for the runtime architecture.
ARG TYPST_VERSION=0.14.2
RUN case "$(uname -m)" in \
      x86_64) TYPST_ARCH=x86_64-unknown-linux-musl ;; \
      aarch64) TYPST_ARCH=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture for Typst: $(uname -m)" && exit 1 ;; \
    esac && \
    mkdir -p /tmp/typst-install /usr/local/bin && \
    cd /tmp/typst-install && \
    curl -fsSL "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-${TYPST_ARCH}.tar.xz" -o typst.tar.xz && \
    xz -d typst.tar.xz && \
    tar -xf typst.tar && \
    mv "typst-${TYPST_ARCH}/typst" /usr/local/bin/typst && \
    chmod +x /usr/local/bin/typst && \
    cd / && rm -rf /tmp/typst-install && \
    typst --version

# Create non-root user
RUN addgroup -g 1001 pentest && \
    adduser -u 1001 -G pentest -s /bin/bash -D pentest

# System-level git config (survives UID remapping in entrypoint)
RUN git config --system user.email "agent@localhost" && \
    git config --system user.name "Pentest Agent" && \
    git config --system --add safe.directory '*'

# Set working directory
WORKDIR /app

# Copy only what the worker needs (skip CLI source, infra, tsdown artifacts)
COPY --from=builder /app/package.json /app/pnpm-workspace.yaml /app/pnpm-lock.yaml /app/.npmrc /app/
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/apps/worker /app/apps/worker
COPY --from=builder /app/apps/cli/package.json /app/apps/cli/package.json
COPY --from=security-tools /security-tools/bin/ /usr/local/bin/
COPY --from=security-tools /security-tools/opt/zap/ /opt/zap/
COPY --from=security-tools /security-tools/opt/nuclei-templates/ /opt/nuclei-templates/

RUN ln -s /opt/zap/zap.sh /usr/local/bin/zap.sh

RUN npm install -g --ignore-scripts pnpm@10.33.0 @playwright/cli@0.1.1
RUN mkdir -p /tmp/.pi/agent/skills && \
    playwright-cli install --skills && \
    cp -r .claude/skills/playwright-cli /tmp/.pi/agent/skills/ && \
    rm -rf .claude

# Symlink CLI tools onto PATH
RUN ln -s /app/apps/worker/dist/scripts/save-deliverable.js /usr/local/bin/save-deliverable && \
    chmod +x /app/apps/worker/dist/scripts/save-deliverable.js && \
    ln -s /app/apps/worker/dist/scripts/generate-totp.js /usr/local/bin/generate-totp && \
    chmod +x /app/apps/worker/dist/scripts/generate-totp.js

# Create directories for session data and ensure proper permissions
RUN mkdir -p /app/sessions /app/repos /app/workspaces && \
    mkdir -p /tmp/.cache /tmp/.config /tmp/.npm && \
    chmod 777 /app && \
    chmod 777 /tmp/.cache && \
    chmod 777 /tmp/.config && \
    chmod 777 /tmp/.npm && \
    chown -R pentest:pentest /app /tmp/.pi

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set environment variables
ENV NODE_ENV=production
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH="${JAVA_HOME}/bin:/usr/local/bin:$PATH"
ENV SHANNON_DOCKER=true
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_MCP_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV PLAYWRIGHT_CLI_SKILL_PATH=/tmp/.pi/agent/skills/playwright-cli/SKILL.md
ENV npm_config_cache=/tmp/.npm
ENV HOME=/tmp
ENV XDG_CACHE_HOME=/tmp/.cache
ENV XDG_CONFIG_HOME=/tmp/.config

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["node", "apps/worker/dist/temporal/worker.js"]
