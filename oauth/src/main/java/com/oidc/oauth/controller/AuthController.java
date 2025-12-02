package com.oidc.oauth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Slf4j
@Controller
public class AuthController {

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "logout", required = false) String logout,
                        Model model) {
        if (error != null) {
            model.addAttribute("error", "아이디 또는 비밀번호가 올바르지 않습니다.");
        }
        if (logout != null) {
            model.addAttribute("message", "로그아웃되었습니다.");
        }

        return "login";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    // 회원가입 처리
    @PostMapping("/signup")
    public String signup(@RequestParam String username,
                         @RequestParam String email,
                         @RequestParam String password,
                         @RequestParam String passwordConfirm,
                         @RequestParam(required = false) String terms,
                         RedirectAttributes redirectAttributes) {

        // 기본 검증
        if (!password.equals(passwordConfirm)) {
            redirectAttributes.addFlashAttribute("error", "비밀번호가 일치하지 않습니다.");
            return "redirect:/signup";
        }

        if (terms == null) {
            redirectAttributes.addFlashAttribute("error", "이용약관에 동의해주세요.");
            return "redirect:/signup";
        }

        // TODO: 실제 회원가입 로직 구현
        // userService.registerUser(username, email, password);

        redirectAttributes.addFlashAttribute("success", "회원가입이 완료되었습니다. 로그인해주세요.");
        return "redirect:/login";
    }

    @GetMapping("/forgot-password")
    public String forgotPassword() {
        return "forgot-password";
    }

    // 인증 코드 발송
    @PostMapping("/forgot-password/send-code")
    public String sendVerificationCode(@RequestParam String email,
                                       RedirectAttributes redirectAttributes) {

        // TODO: 이메일로 인증 코드 발송 로직
        // emailService.sendVerificationCode(email);

        redirectAttributes.addFlashAttribute("success", "인증 코드가 이메일로 발송되었습니다.");
        redirectAttributes.addFlashAttribute("email", email);
        return "redirect:/forgot-password";
    }

    // 인증 코드 확인
    @PostMapping("/forgot-password/verify-code")
    public String verifyCode(@RequestParam String code1,
                             @RequestParam String code2,
                             @RequestParam String code3,
                             @RequestParam String code4,
                             @RequestParam String code5,
                             @RequestParam String code6,
                             RedirectAttributes redirectAttributes) {

        String code = code1 + code2 + code3 + code4 + code5 + code6;

        // TODO: 인증 코드 검증 로직
        // if (!verificationService.verifyCode(code)) {
        //     redirectAttributes.addFlashAttribute("error", "인증 코드가 올바르지 않습니다.");
        //     return "redirect:/forgot-password";
        // }

        redirectAttributes.addFlashAttribute("success", "인증이 완료되었습니다. 새 비밀번호를 설정하세요.");
        return "redirect:/forgot-password";
    }

    // 비밀번호 재설정
    @PostMapping("/forgot-password/reset")
    public String resetPassword(@RequestParam String newPassword,
                                @RequestParam String confirmPassword,
                                RedirectAttributes redirectAttributes) {

        if (!newPassword.equals(confirmPassword)) {
            redirectAttributes.addFlashAttribute("error", "비밀번호가 일치하지 않습니다.");
            return "redirect:/forgot-password";
        }

        // TODO: 비밀번호 변경 로직
        // userService.updatePassword(userId, newPassword);

        redirectAttributes.addFlashAttribute("success", "비밀번호가 성공적으로 변경되었습니다.");
        return "redirect:/login";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }


    //callback test
    @GetMapping("/callback")
    public ResponseEntity<String> callback(@RequestParam("code") String code) {

        System.out.println("받은 Authorization Code = " + code);

        // 1. Token 요청 준비
        RestTemplate rest = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("redirect_uri", "http://localhost:40001/callback");   // 반드시 동일해야 함
        params.add("client_id", "test-client");
        params.add("client_secret", "secret");                      // 네 Authorization Server 설정

        HttpEntity<MultiValueMap<String, String>> request =
                new HttpEntity<>(params, headers);

        // 2. 토큰 엔드포인트 호출
        ResponseEntity<String> response = rest.postForEntity(
                "http://localhost:40001/oauth2/token",
                request,
                String.class
        );

        System.out.println("Token Response = " + response.getBody());

        // 3. 결과 반환
        return response;
    }
}
