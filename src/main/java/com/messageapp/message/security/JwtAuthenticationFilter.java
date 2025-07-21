package com.messageapp.message.security;

import com.messageapp.message.config.MessageUserPrincipal;
import com.messageapp.message.entity.User;
import com.messageapp.message.session.UserSessionService;
import com.messageapp.message.session.UserSession;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Autowired
    private UserSessionService userSessionService;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Get JWT token from HTTP request
        String token = getTokenFromRequest(request);

        // Validate Token
        if (StringUtils.hasText(token) && jwtUtil.validateToken(token)) {
            // get username from token
            String username = jwtUtil.getEmailFromToken(token);
            String sessionIdFromToken = jwtUtil.getSessionIdFromToken(token);

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            Long userId = null;
            if (userDetails instanceof MessageUserPrincipal principal) {
                userId = principal.getId();
            }

            if (userId != null) {
                Optional<UserSession> sessionOpt = userSessionService.getSessionByUserId(userId);

                if (sessionOpt.isEmpty() || !sessionOpt.get().getSessionId().equals(sessionIdFromToken)) {
                    filterChain.doFilter(request, response);
                    return;
                }
            }

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );

            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }

        filterChain.doFilter(request, response);
    }

    public String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}