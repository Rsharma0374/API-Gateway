# API Gateway — Project Summary

## Overview

A **production-grade reactive API Gateway** built with **Spring Boot 3.5.11** and **Java 21**,
designed to serve as the single entry point for all inbound HTTP traffic to the
Guardian Services backend microservices ecosystem.

The gateway handles **authentication**, **authorisation**, **rate limiting**,
**request correlation**, **structured logging**, **circuit breaking**, and
**observability** — all in a fully non-blocking reactive pipeline powered by
**Project Reactor** and **Netty**.

---

## Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Language | Java | 21 (LTS) |
| Framework | Spring Boot | 3.5.11 |
| Reactive Runtime | Project Reactor + Netty | BOM managed |
| Identity Provider | Keycloak | 26.x |
| JWT Library | Nimbus JOSE+JWT | 9.37.3 |
| Rate Limiting | Bucket4j | 8.10.0 |
| Caching | Caffeine | BOM managed |
| Circuit Breaker | Resilience4j | 2.3.0 |
| Metrics | Micrometer + Prometheus | BOM managed |
| Tracing | Micrometer Tracing + Brave | BOM managed |
| Logging | SLF4J + Logback + Logstash | BOM managed |
| Build Tool | Maven | 3.9+ |
| Container | Distroless Java 21 (Jib) | nonroot |

---

## Project Structure

api-gateway/
│
├── pom.xml                                          # Maven build — all dependencies locked
│
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── in/guardianservices/api_gateway/
│   │   │       │
│   │   │       ├── ApiGatewayApplication.java       # Spring Boot entry point
│   │   │       │                                    # Beans: WebClient, Clock
│   │   │       │
│   │   │       ├── config/
│   │   │       │   └── RouteConfig.java             # Functional router — all routes defined here
│   │   │       │                                    # Circuit breaker on /api/**
│   │   │       │                                    # Fallback, health, public routes
│   │   │       │
│   │   │       ├── security/
│   │   │       │   ├── JwksCache.java               # Async JWKS cache (Caffeine AsyncLoadingCache)
│   │   │       │   │                                # Circuit breaker on JWKS fetch
│   │   │       │   │                                # Cache stampede protection
│   │   │       │   │                                # invalidate() for key rotation
│   │   │       │   │
│   │   │       │   ├── JwtVerifier.java             # Full JWT verification pipeline
│   │   │       │   │                                # Parse → JWKS fetch → Signature → Claims
│   │   │       │   │                                # RSA (RS256/384/512) + EC (ES256/384/512)
│   │   │       │   │                                # exp, nbf, iss, aud, sub validation
│   │   │       │   │                                # Algorithm rejection (none, HS*)
│   │   │       │   │                                # Auto key rotation (kid not found → retry)
│   │   │       │   │
│   │   │       │   └── PublicPathRegistry.java      # Single source of truth for public paths
│   │   │       │                                    # Ant-style pattern matching (/public/**)
│   │   │       │                                    # Config-driven via application.yml
│   │   │       │                                    # @PostConstruct startup validation
│   │   │       │
│   │   │       └── filter/                          # WebFilter chain (ordered 1 → 4)
│   │   │           │
│   │   │           ├── RequestIdFilter.java         # Order 1 — Request correlation ID
│   │   │           │                                # UUID validation on incoming header
│   │   │           │                                # Reactor Context propagation (not MDC)
│   │   │           │                                # Log injection prevention (CWE-117)
│   │   │           │                                # X-Request-ID on request + response
│   │   │           │
│   │   │           ├── JwtVerificationFilter.java   # Order 2 — JWT authentication
│   │   │           │                                # PublicPathRegistry bypass (Ant patterns)
│   │   │           │                                # Bearer token extraction + validation
│   │   │           │                                # Claims → Reactor Context + exchange attrs
│   │   │           │                                # RFC 7807 Problem+JSON error responses
│   │   │           │                                # Tiered errors: 401 vs 503
│   │   │           │
│   │   │           ├── RateLimitFilter.java         # Order 3 — Per-IP rate limiting
│   │   │           │                                # Bucket4j token bucket algorithm
│   │   │           │                                # Caffeine-backed bounded bucket map
│   │   │           │                                # IP spoof-resistant (last X-Forwarded-For)
│   │   │           │                                # Retry-After + X-RateLimit-* headers
│   │   │           │                                # Micrometer counters (allowed/rejected)
│   │   │           │
│   │   │           └── RequestLoggingFilter.java    # Order 4 — Structured access logging
│   │   │                                            # SLF4J (never System.out)
│   │   │                                            # Reactor Context for requestId
│   │   │                                            # Request + response + latency logging
│   │   │                                            # Status-based log levels (INFO/WARN/ERROR)
│   │   │                                            # Authenticated subject in response log
│   │   │                                            # Safe header allowlist (no Auth leakage)
│   │   │
│   │   └── resources/
│   │       ├── application.yml                      # Base/dev configuration (fully documented)
│   │       └── application-prod.yml                 # Production overrides (Keycloak, hardened)
│   │
│   └── test/
│       └── java/
│           └── in/guardianservices/api_gateway/
│               ├── filter/
│               │   ├── RequestIdFilterTest.java      # Unit tests
│               │   ├── JwtVerificationFilterTest.java
│               │   └── RateLimitFilterTest.java
│               └── security/
│                   ├── JwksCacheTest.java
│                   └── JwtVerifierTest.java
│
├── docker-compose.yml                               # Keycloak 26 local dev setup
└── owasp-suppressions.xml                           # OWASP CVE scan suppressions

---

## Request Lifecycle

Every inbound HTTP request passes through the following pipeline in order:

Client Request
│
▼
┌─────────────────────────────────────────────────────┐
│  Filter 1 — RequestIdFilter (@Order 1)              │
│  • Read or generate X-Request-ID (UUID)             │
│  • Validate incoming UUID format                    │
│  • Write to Reactor Context + mutate request header │
│  • Echo X-Request-ID on response                    │
└─────────────────────┬───────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│  Filter 2 — JwtVerificationFilter (@Order 2)        │
│  • Check PublicPathRegistry (Ant pattern match)     │
│  • Public path? ──YES──▶ skip to Filter 3           │
│  • Extract Bearer token from Authorization header   │
│  • Delegate to JwtVerifier:                         │
│      1. Parse JWT + reject bad algorithms           │
│      2. Fetch JWKS from Keycloak (cached)           │
│      3. Verify RSA/EC signature                     │
│      4. Validate exp, nbf, iss, aud, sub            │
│  • Write JWTClaimsSet to Reactor Context            │
│  • On failure → 401 Problem+JSON                    │
│  • On JWKS down → 503 Problem+JSON                  │
└─────────────────────┬───────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│  Filter 3 — RateLimitFilter (@Order 3)              │
│  • Resolve client IP (X-Forwarded-For last hop)     │
│  • Get or create Bucket4j token bucket for IP       │
│  • tryConsumeAndReturnRemaining(1)                  │
│  • Token available? ──YES──▶ set rate-limit headers │
│  • Token exhausted? ──NO───▶ 429 + Retry-After      │
│  • Increment Micrometer allowed/rejected counters   │
└─────────────────────┬───────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│  Filter 4 — RequestLoggingFilter (@Order 4)         │
│  • Log inbound: method, path, IP, userAgent         │
│  • Read requestId from Reactor Context              │
│  • Delegate to route handler                        │
│  • Log outbound: status, latency, subject           │
│  • Log level based on status (INFO/WARN/ERROR)      │
└─────────────────────┬───────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│  RouteConfig (RouterFunction)                       │
│  GET  /health        → Health check (public)        │
│  GET  /fallback/**   → Circuit breaker fallback     │
│  GET  /public/**     → Public resources             │
│  GET  /api/**        → Authenticated API routes     │
│  POST /api/**        → Authenticated API routes     │
│  *                   → 404 Not Found                │
│                                                     │
│  /api/** wrapped in Resilience4j CircuitBreaker     │
│  Open → redirect to /fallback/**                   │
└─────────────────────────────────────────────────────┘

---

## Filter Chain Summary

| Order | Filter | Responsibility |
|---|---|---|
| 1 | `RequestIdFilter` | Assigns `X-Request-ID` to every request via Reactor Context |
| 2 | `JwtVerificationFilter` | Authenticates JWT via Keycloak JWKS, propagates claims |
| 3 | `RateLimitFilter` | Enforces per-IP token bucket rate limiting |
| 4 | `RequestLoggingFilter` | Structured access logging with latency + authenticated subject |

---

## Security Features

| Feature | Implementation |
|---|---|
| JWT Authentication | Nimbus JOSE+JWT — full RSA + EC JWKS support |
| Algorithm Rejection | `none`, `HS256`, `HS384`, `HS512` explicitly blocked |
| Claims Validation | `exp`, `nbf`, `iss`, `aud`, `sub` all validated |
| Clock Skew Tolerance | 30 seconds tolerance on `exp` and `nbf` |
| Key Rotation | Auto-invalidate JWKS cache on unknown `kid` + retry once |
| Rate Limiting | Per-IP token bucket — Caffeine bounded map (no OOM) |
| IP Spoof Resistance | Last `X-Forwarded-For` hop (edge proxy trusted) |
| Log Injection Prevention | Strip `\r\n\t` from all user-supplied header values (CWE-117) |
| Error Response Hardening | RFC 7807 Problem+JSON — never exposes internals |
| Authorization Header | Never logged — safe header allowlist enforced |
| Request Correlation | `X-Request-ID` on every request + response |

---

## Observability

| Signal | Endpoint | Details |
|---|---|---|
| **Health** | `http://localhost:8081/actuator/health` | Liveness + readiness probes |
| **Metrics** | `http://localhost:8081/actuator/metrics` | All Micrometer metrics |
| **Prometheus** | `http://localhost:8081/actuator/prometheus` | Prometheus scrape endpoint |
| **Loggers** | `http://localhost:8081/actuator/loggers` | Runtime log level changes |
| **Circuit Breakers** | `http://localhost:8081/actuator/circuitbreakers` | CB state + stats |
| **Tracing** | Zipkin at `localhost:9411` | Distributed trace export |

### Custom Micrometer Metrics

| Metric | Description |
|---|---|
| `gateway.ratelimit.allowed` | Requests that passed rate limiting |
| `gateway.ratelimit.rejected` | Requests rejected with 429 |

---

## Keycloak Integration

| Property | Value |
|---|---|
| **Server** | `https://keycloak.guardianservices.in` |
| **Realm** | `guardian-services` |
| **Client ID** | `api-gateway` |
| **JWKS URL** | `https://keycloak.guardianservices.in/realms/guardian-services/protocol/openid-connect/certs` |
| **Issuer** | `https://keycloak.guardianservices.in/realms/guardian-services` |
| **Audience** | `api-gateway` |
| **Token Endpoint** | `https://keycloak.guardianservices.in/realms/guardian-services/protocol/openid-connect/token` |
| **Discovery Doc** | `https://keycloak.guardianservices.in/realms/guardian-services/.well-known/openid-configuration` |

---

## Configuration Properties Reference

# Server
server.port                          # API port (default: 8080)
management.server.port               # Actuator port (default: 8081)

# JWT / Keycloak
auth.jwt.jwks-url                    # Keycloak JWKS endpoint
auth.jwt.issuer                      # Must match 'iss' claim in token
auth.jwt.audience                    # Must match 'aud' claim in token

# Public Paths
gateway.public-paths                 # Ant-style list of paths that skip JWT auth

# Rate Limiting
ratelimit.capacity                   # Max burst tokens per IP
ratelimit.refill-tokens              # Tokens added per period
ratelimit.refill-period-ms           # Refill interval in milliseconds
ratelimit.cache-max-size             # Max unique IPs tracked
ratelimit.cache-ttl-hours            # Idle eviction TTL

# Resilience4j
resilience4j.circuitbreaker.instances.jwksFetch.*
resilience4j.circuitbreaker.instances.downstreamService.*
resilience4j.retry.instances.jwksFetch.*

---

## Environment Variables (Production)

Spring Boot automatically maps these env vars to config properties:

AUTH_JWT_JWKS_URL=https://keycloak.guardianservices.in/realms/guardian-services/protocol/openid-connect/certs
AUTH_JWT_ISSUER=https://keycloak.guardianservices.in/realms/guardian-services
AUTH_JWT_AUDIENCE=api-gateway
SERVER_PORT=8080

---

## Build Commands

# Development build
mvn clean install

# Force re-download (fix cached failures)
mvn clean install -U

# Run locally
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Run with production profile
mvn spring-boot:run -Dspring-boot.run.profiles=prod

# Build Docker image (Jib — no Docker daemon needed)
mvn jib:build

# Build Docker image to local Docker daemon
mvn jib:dockerBuild

# OWASP CVE scan
mvn dependency-check:check

# Run tests with coverage
mvn verify

# View coverage report
open target/site/jacoco/index.html

---

## Known Issues Fixed During Development

| # | Error | Fix |
|---|---|---|
| 1 | `ClassNotFoundException: RxJava3OnClasspathCondition` | Added `resilience4j-rxjava3` dependency |
| 2 | `bucket4j-core:8.14.0` not on Maven Central | Downgraded to `8.10.0` |
| 3 | `Compilation failure: warnings found and -Werror` | Replaced `-Xlint:all -Werror` with targeted lint flags |
| 4 | `No qualifying bean of type Clock` | Added `Clock.systemUTC()` bean in `GatewayApplication` |
| 5 | MDC dropping `requestId` on thread switches | Replaced thread-local MDC with Reactor Context |
| 6 | Cache stampede on JWKS expiry | Replaced `Cache` with `AsyncLoadingCache` |
| 7 | `ConcurrentHashMap` unbounded memory growth | Replaced with Caffeine bounded cache |
| 8 | Bucket4j deprecated API (`Bucket4j.builder()`) | Updated to v8 `Bucket.builder()` API |
| 9 | NPE on `getRemoteAddress()` behind proxy | Added 4-layer null-safe IP resolution |
| 10 | Duplicate public path lists diverging | Centralised into `PublicPathRegistry` |

---

## Files Delivered

| # | File | Package |
|---|---|---|
| 1 | `pom.xml` | Root |
| 2 | `ApiGatewayApplication.java` | `in.guardianservices.api_gateway` |
| 3 | `JwksCache.java` | `...security` |
| 4 | `JwtVerifier.java` | `...security` |
| 5 | `PublicPathRegistry.java` | `...security` |
| 6 | `RequestIdFilter.java` | `...filter` |
| 7 | `JwtVerificationFilter.java` | `...filter` |
| 8 | `RateLimitFilter.java` | `...filter` |
| 9 | `RequestLoggingFilter.java` | `...filter` |
| 10 | `RouteConfig.java` | `...config` |
| 11 | `application.yml` | `resources` |
| 12 | `application-prod.yml` | `resources` (pending) |