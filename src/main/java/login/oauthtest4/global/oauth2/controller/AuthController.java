package login.oauthtest4.global.oauth2.controller;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import login.oauthtest4.global.jwt.service.JwtService;
import login.oauthtest4.global.redis.RedisService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final JwtService jwtService;
    private final RedisService redisService;

    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refreshToken(
        HttpServletRequest request,
        HttpServletResponse response,
        @CookieValue(value = "refreshToken", required = false) String refreshToken) {

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("RefreshToken이 없습니다.");
        }

        try {
            // 1. RefreshToken 유효성 검증
            if (!jwtService.isRefreshTokenValid(refreshToken)) {
                throw new IllegalArgumentException("유효하지 않은 RefreshToken");
            }

            // 2. RefreshToken에서 이메일 추출
            String email = jwtService.extractEmail(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("토큰에서 이메일 추출 실패"));

            // 3. Redis에서 저장된 토큰과 비교
            String storedToken = redisService.getValues("RF-" + email);
            if (!refreshToken.equals(storedToken)) {
                throw new IllegalArgumentException("저장된 토큰과 불일치");
            }

            // 4. 새로운 AccessToken 생성
            String newAccessToken = jwtService.createAccessToken(email);

            return ResponseEntity.ok()
                .header(jwtService.getAccessHeader(), "Bearer " + newAccessToken)
                .body("토큰 갱신 성공");

        } catch (Exception e) {
            log.error("토큰 갱신 실패", e);

            // RefreshToken 쿠키 제거
            clearRefreshTokenCookie(response);

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("토큰 갱신 실패 - 재로그인 필요");
        }
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(
        HttpServletResponse response,
        @CookieValue(value = "refreshToken", required = false) String refreshToken,
        @RequestHeader(value = "Authorization", required = false) String accessToken) {

        try {
            // RefreshToken이 있으면 Redis에서 제거
            if (refreshToken != null) {
                jwtService.extractEmail(refreshToken)
                    .ifPresent(email -> {
                        redisService.deleteValues("RF-" + email);
                        log.info("Redis에서 RefreshToken 제거 완료 - 사용자: {}", email);
                    });
            }

            // RefreshToken 쿠키 제거
            clearRefreshTokenCookie(response);

            return ResponseEntity.ok("로그아웃 성공");

        } catch (Exception e) {
            log.error("로그아웃 처리 중 오류", e);
            return ResponseEntity.ok("로그아웃 처리 완료");
        }
    }

    /**
     * RefreshToken 쿠키 제거
     */
    private void clearRefreshTokenCookie(HttpServletResponse response) {
        ResponseCookie expiredCookie = ResponseCookie.from("refreshToken", "")
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(0)  // 즉시 만료
            .sameSite("Strict")
            .build();

        response.addHeader("Set-Cookie", expiredCookie.toString());
        log.info("RefreshToken 쿠키 제거 완료");
    }
}