package login.oauthtest4.global.oauth2.controller;

import login.oauthtest4.global.jwt.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Slf4j
@Controller
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class OAuth2RedirectController {

    private final JwtService jwtService;

    /**
     * OAuth2 로그인 성공 후 리다이렉트되는 엔드포인트
     *
     * @param token JwtToken (OAuth2LoginSuccessHandler에서 리다이렉트 시 전달)
     * @param model View에 데이터 전달
     * @return 로그인 성공 페이지
     */
    @GetMapping("/redirect")
    public String redirect(@RequestParam(name = "token", required = false) String token,
        Model model) {

        log.info("OAuth2 로그인 리다이렉트 - 토큰: {}", token != null ? "발급됨" : "NULL");

        if (token != null) {
            model.addAttribute("token", token);
            // 토큰을 뷰에 전달
        }

        // oauth2_redirect.html로 이동 (resources/templates 폴더에 생성해야 함)
        return "oauth2_redirect";
    }

    /**
     * API 호출용 토큰 검증 엔드포인트 (선택사항)
     */
    @GetMapping("/validate-token")
    @ResponseBody
    public String validateToken(@RequestParam String token) {
        // JWT 토큰 검증 로직 (선택적)
        boolean isValid = jwtService.isTokenValid(token);
        return "{\"isValid\": " + isValid + "}";
    }
}