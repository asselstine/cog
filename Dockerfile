FROM node:22-bookworm-slim AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./
RUN npm run build

FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY frontend ./frontend
COPY --from=frontend /src/frontend/dist ./frontend/dist
COPY src ./src
RUN COG_FRONTEND_PREBUILT=1 cargo build --locked --release
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/cog /usr/local/bin/cog
RUN useradd --system --uid 10001 --home /data cog && mkdir /data && chown cog:cog /data
USER cog
VOLUME /data
EXPOSE 4788
ENV COG_DATA_DIR=/data COG_LISTEN=0.0.0.0:4788
ENTRYPOINT ["cog"]
