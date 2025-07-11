package com.realive.security.customer;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.realive.dto.customer.member.MemberLoginDTO;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

// [Customer] JWT 토큰을 이용한 인증 필터

@Component
@RequiredArgsConstructor
@Log4j2
public class CustomerJwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        log.info("[CustomerJwtAuthenticationFilter] doFilterInternal 호출, URI: {}", request.getRequestURI());
        String token = resolveToken(request);
        log.info("JWT 토큰 추출: {}", token);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            String email = jwtTokenProvider.getUsername(token);
            log.info("토큰에서 추출한 사용자명(email): {}", email);

            // DB에서 유저 정보 로드 (MemberLoginDTO는 UserDetails를 구현해야 함)
            MemberLoginDTO memberDTO = (MemberLoginDTO) customUserDetailsService.loadUserByUsername(email);

            // 인증 객체 생성 및 SecurityContext에 등록
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(memberDTO, null, memberDTO.getAuthorities());
            //log.info("로드한 MemberLoginDTO: {}", memberDTO);

            SecurityContextHolder.getContext().setAuthentication(auth);
            log.info("SecurityContextHolder에 인증 객체 등록 완료");
        }else {
            log.info("토큰이 없거나 유효하지 않음");
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        log.info("Authorization 헤더: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7); // "Bearer " 이후 토큰만 추출
            log.info("추출된 토큰: {}", token);
            return token;
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String uri = request.getRequestURI();
        log.info("shouldNotFilter 호출 - URI: {}", uri);
        boolean result = uri.startsWith("/api/admin") || uri.startsWith("/api/seller") || uri.startsWith("/api/public");
        log.info("필터 제외 여부: {}", result);
        return result;
    }

}