################
##### Builder
FROM rust:1.71.1-alpine3.17 as chef
RUN apk add --no-cache musl-dev gcc
RUN cargo install cargo-chef
WORKDIR app

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release

################
##### Runtime
FROM alpine:3.17 AS runtime
RUN addgroup -S myuser && adduser -S myuser -G myuser
WORKDIR app
COPY --from=builder /app/target/release/webexampleopenidc /usr/local/bin
EXPOSE 8080
USER myuser
CMD ["/usr/local/bin/webexampleopenidc"]

