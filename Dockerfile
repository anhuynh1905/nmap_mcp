# ─── Builder Stage ──────────────────────────────────────────────────────────────
FROM alpine:3.18 AS builder

# 1) Install Nmap core + NSE support + build deps
RUN apk add --no-cache \
      nmap \
      nmap-scripts \
      lua5.3-libs \
      git \
      ca-certificates

ENV NMAP_SCRIPTS_DIR=/usr/share/nmap/scripts

# 2) Clone the latest master of your two script collections
RUN git clone --depth 1 https://github.com/vulnersCom/nmap-vulners.git \
      ${NMAP_SCRIPTS_DIR}/vulners \
 &&  git clone --depth 1 https://github.com/scipag/vulscan.git \
      ${NMAP_SCRIPTS_DIR}/vulscan

# 3) Rebuild the script database (now that nse_main.lua is present)
RUN nmap --datadir /usr/share/nmap --script-updatedb

# ─── Runtime Stage ──────────────────────────────────────────────────────────────
FROM alpine:3.18

# 4) Pull in only the runtime bits (no git, no build deps)
RUN apk add --no-cache \
      nmap \
      nmap-scripts \
      lua5.3-libs \
      ca-certificates \
 && update-ca-certificates

# 5) Copy the fully-populated Nmap share dir
COPY --from=builder /usr/share/nmap /usr/share/nmap

ENTRYPOINT ["nmap"]
CMD ["--help"]