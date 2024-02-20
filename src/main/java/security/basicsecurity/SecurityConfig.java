package security.basicsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    @Autowired
//    UserDetailsService userDetailService;

    @Bean
    public UserDetailsManager users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();
        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, sys, admin);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/user").hasRole("USER")
                .requestMatchers("/admin/pay").hasRole("ADMIN")
                .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                .anyRequest().authenticated()
        ).formLogin(Customizer.withDefaults());
        return http.build();
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((form) -> form
//                .anyRequest().authenticated()
//        ).formLogin(form -> form
//                //.loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication : " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception : " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll()
//        );
//
//        http.logout(form -> form
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember-me")
//        );
//
//        http.rememberMe(form -> form
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailService)
//        );
//
//        http.sessionManagement(form -> form
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false)
//        );
//
//        http.sessionManagement(form -> form
//                .sessionFixation().changeSessionId()
//        );
//
//        return http.build();
//    }
}
