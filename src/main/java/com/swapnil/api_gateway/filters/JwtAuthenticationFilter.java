package com.swapnil.api_gateway.filters;

import com.swapnil.api_gateway.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    // JwtUtil is used to validate JWT and extract claims like userId and email
    private final JwtUtil jwtUtil;

    /**
     * This method is executed for EVERY request that comes to the API Gateway.
     *
     * Flow:
     * Client -> Gateway -> (this filter runs) -> Question/Auth Service
     *
     * We use this filter to:
     * 1. Skip authentication for public endpoints (login/register)
     * 2. Validate JWT for protected endpoints
     * 3. Extract user information from JWT
     * 4. Forward that information to downstream services as headers
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }
        // Get the request path
        // Example:
        // /api/v1/auth/login
        // /questions
        String path = exchange.getRequest().getURI().getPath();


        /**
         * Public endpoints:
         * Login and Register should be accessible without JWT.
         *
         * If request path starts with /api/v1/auth,
         * simply forward the request to Auth Service.
         */
        if (path.startsWith("/api/v1/auth")) {
            return chain.filter(exchange);
        }

        /**
         * Read Authorization header.
         *
         * Example:
         * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
         */
        String authHeader =
                exchange.getRequest()
                        .getHeaders()
                        .getFirst(HttpHeaders.AUTHORIZATION);

        /**
         * If Authorization header is missing
         * OR does not start with "Bearer ",
         * reject the request with 401 Unauthorized.
         */
        String token = authHeader.substring(7);

        System.out.println("Gateway received Authorization header");
        System.out.println("Gateway token valid: " + jwtUtil.validateToken(token));
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Remove "Bearer " prefix
//        String token = authHeader.substring(7);

        /**
         * Validate JWT.
         *
         * Checks:
         * - Signature is correct
         * - Token is not expired
         * - Token is well-formed
         */
        if (!jwtUtil.validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        /**
         * Extract information from JWT claims.
         *
         * Example JWT payload:
         * {
         *   "userId": 1,
         *   "email": "swapnil@example.com",
         *   "roles": ["USER"]
         * }
         */
        Long userId = jwtUtil.extractUserId(token);
        String email = jwtUtil.extractEmail(token);

        /**
         * Add user information as request headers.
         *
         * These headers will be available inside Question Service.
         *
         * X-User-Id: 1
         * X-User-Email: swapnil@example.com
         */
        ServerHttpRequest request = exchange.getRequest()
                .mutate()
                .header("X-User-Id", userId.toString())
                .header("X-User-Email", email)
                .build();

        /**
         * Forward the modified request to the next filter
         * and eventually to the target microservice.
         */
        return chain.filter(
                exchange.mutate()
                        .request(request)
                        .build()
        );
    }

    /**
     * Filter order.
     *
     * Lower value = higher priority.
     *
     * -1 ensures this filter runs BEFORE routing happens.
     */
    @Override
    public int getOrder() {
        return -1;
    }


}
