package com.sparta.springsecurity.config;


import com.sparta.springsecurity.security.CustomAccessDeniedHandler;
import com.sparta.springsecurity.security.CustomAuthenticationEntryPoint;
import com.sparta.springsecurity.security.CustomSecurityFilter;
import com.sparta.springsecurity.security.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity // 스프링 Security 지원을 가능하게 함
@EnableGlobalMethodSecurity(securedEnabled = true) // @Secured 어노테이션 활성화
public class WebSecurityConfig {

    private final UserDetailsServiceImpl userDetailsService;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Bean // 비밀번호 암호화 기능 등록
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() { //아래 SFC보다 우선적으로 걸리는 설정이다.
        // h2-console 사용 및 resources 접근 허용 설정
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toH2Console())
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
                // 아래 경로들을 한번에 무시하도록 설정한 것. 아래 것은 주석처리.
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // CSRF 설정
        http.csrf().disable();

        http.authorizeRequests().antMatchers("/api/user/**").permitAll()
//                .antMatchers("/h2-console/**").permitAll()
//                .antMatchers("/css/**").permitAll()
//                .antMatchers("/js/**").permitAll()
//                .antMatchers("/images/**").permitAll() // CSS, JS, 이미지 파일등 일일히 인증하지 않게 설정
//                // permitAll() 해당 경로의 URL들은 인증을 하지않아도 실행 가능
//                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()

                //.antMatchers() 내에 다양한 설정들이 있기 때문에 구글링이나 레퍼런스를 참고할 것.
                .anyRequest().authenticated(); // 그 이외의 요청들은 모두 Authentication 인증을 하겠다는 표시.

        // 로그인 사용
//        http.formLogin(); //Security에서 제공하는 디폴트 Form Login을 사용하겠다는 표시.
        // Custom 로그인 페이지 사용
        http.formLogin().loginPage("/api/user/login-page").permitAll();
        //해당 요청을 받아줄 Controller 도 필요하다.

        // Custom Filter 등록하기
        http.addFilterBefore(new CustomSecurityFilter(userDetailsService, passwordEncoder()), UsernamePasswordAuthenticationFilter.class);
        // 필터를 추가하겠다. 어떠한 필터 이전에.
        // 기본적으로 UsernamePasswordAuthenticationFilter. username/password 방식에서 처리가 되지만, 이전에 custom한 필터를 넣어 추가 검증하도록 적용하는 것.
        // 먼저 필터가 통해 인증 객체를 만들고 컨택스트에 추가하면, 인증이 완료되었기 때문에 뒤의 필터를 거쳐도 다음 필터로 넘어갈 수 있다.

//        // 접근 제한 페이지 이동 설정. 우선적으로 페이지가 이동이 되어서 주석 처리
//        http.exceptionHandling().accessDeniedPage("/api/user/forbidden");

        // 401 Error 처리, Authorization 즉, 인증과정에서 실패할 시 처리
        http.exceptionHandling().authenticationEntryPoint(customAuthenticationEntryPoint);

        // 403 Error 처리, 인증과는 별개로 추가적인 권한이 충족되지 않는 경우
        http.exceptionHandling().accessDeniedHandler(customAccessDeniedHandler);


        return http.build();
    }

}
