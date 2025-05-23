package login.oauthtest4.global.oauth2.handler;

import javax.servlet.http.Cookie;
import login.oauthtest4.domain.user.Role;
import login.oauthtest4.domain.user.User;
import login.oauthtest4.domain.user.repository.UserRepository;
import login.oauthtest4.global.jwt.service.JwtService;
import login.oauthtest4.global.oauth2.CustomOAuth2User;
import login.oauthtest4.global.redis.RedisService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.io.IOException;
import org.springframework.web.util.UriComponentsBuilder;
@Slf4j
@Component
@RequiredArgsConstructor
@Transactional
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RedisService redisService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");
        try {
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

            if(oAuth2User.getRole() == Role.GUEST) {
                log.info("신규 사용자 회원가입 처리");
                handleGuestUser(response, oAuth2User);
            } else {
                log.info("기존 사용자 로그인 처리");
                loginSuccess(response, oAuth2User);
            }
        } catch (Exception e) {
            log.error("OAuth2 로그인 처리 중 오류 발생", e);
            throw e;
        }
    }

    private void handleGuestUser(HttpServletResponse response, CustomOAuth2User oAuth2User) throws IOException {
        String oAuth2UserEmail = oAuth2User.getEmail();
        log.info("oAuth2UserEmail : {}", oAuth2UserEmail);

        String accessToken = jwtService.createAccessToken(oAuth2UserEmail);
        String refreshToken = createOrReuseRefreshToken(oAuth2UserEmail);

        // HttpOnly 쿠키로 RefreshToken 설정
        setRefreshTokenCookie(response, refreshToken);

        // AccessToken은 헤더로 전달
        response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);

        // Redis에 RefreshToken 저장
        redisService.setRefreshTokenValues("RF-" + oAuth2UserEmail, refreshToken);

        User findUser = userRepository.findByEmail(oAuth2User.getEmail())
            .orElseThrow(() -> new IllegalArgumentException("이메일에 해당하는 유저가 없습니다."));
        findUser.authorizeUser();

        response.sendRedirect("/oauth2/sign-up");
    }

    private void loginSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User) throws IOException {
        String email = oAuth2User.getEmail();
        String accessToken = jwtService.createAccessToken(email);
        String refreshToken = createOrReuseRefreshToken(email);

        // HttpOnly 쿠키로 RefreshToken 설정
        setRefreshTokenCookie(response, refreshToken);

        // AccessToken은 헤더로 전달
        response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);

        log.info("로그인 성공 - 사용자: {}", email);
    }

    /**
     * 기존 RefreshToken 검증하고, 유효하면 재사용, 아니면 새로 생성
     */
    private String createOrReuseRefreshToken(String email) {
        String redisKey = "RF-" + email;
        String existingRefreshToken = redisService.getValues(redisKey);

        // 기존 토큰이 있고 유효한지 검증
        if (existingRefreshToken != null && jwtService.isTokenValid(existingRefreshToken)) {
            log.info("기존 RefreshToken 재사용 - 사용자: {}", email);
            return existingRefreshToken;
        }

        // 기존 토큰이 없거나 만료된 경우 새로 생성
        log.info("새로운 RefreshToken 생성 - 사용자: {}", email);
        String newRefreshToken = jwtService.createRefreshToken(email);
        redisService.setRefreshTokenValues(redisKey, newRefreshToken);

        return newRefreshToken;
    }

    /**
     * RefreshToken HttpOnly 쿠키 설정
     */
    private void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
            .httpOnly(true)                    // XSS 공격 방지
            .secure(true)                     // HTTPS 에서만 전송
            .path("/")                        // 전체 도메인에서 사용
            .maxAge(7 * 24 * 60 * 60)         // 7일 (초 단위)
            .sameSite("Strict")               // CSRF 공격 방지
            .build();

        response.addHeader("Set-Cookie", refreshTokenCookie.toString());
        log.info("RefreshToken 쿠키 설정 완료");
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