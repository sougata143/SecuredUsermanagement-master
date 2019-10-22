package com.easybusiness.usermanagement.security;

import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	public static final String REALM_NAME = "sls comptech";
	
	@Autowired
	DataSource dataSource;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	/*@Autowired
	private PasswordEncoder passwordEncoder;*/
	
	/*@Autowired
	PasswordEncoderFactories passwordEncoderFactory;*/
    
    public SecurityConfig(UserDetailsService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }
    
    /*@Bean
    public static PasswordEncoder passwordEncoder() {
          return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }*/
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
		.and()
		.authorizeRequests()
	        .antMatchers("/easybusiness/user/deleteUser/**").hasRole("ADMIN")
	        .antMatchers("/easybusiness/user/activateUser/**").hasRole("ADMIN")
	        .antMatchers("/easybusiness/user/deactivateUser/**").hasRole("ADMIN")
	        .antMatchers("/easybusiness/user/getAllUsers/**").hasRole("ADMIN")
	    .anyRequest().permitAll()
        .and()
        	.httpBasic()
        		.realmName(REALM_NAME)
        		.authenticationEntryPoint(new RestAuthenticationEntryPoint())
        		.and()
//        .addFilter(new JWTAuthenticationFilter(authenticationManager()))
//        .addFilter(new JWTAuthorizationFilter(authenticationManager()))
        .formLogin()
        	.defaultSuccessUrl("/easybusiness/user/getAllUsers")
        	.permitAll();
        	//.successHandler(customAuthenticationSuccessHandler)
//        .and()
//        	.logout().permitAll();
        //.and()
        	//.exceptionHandling().accessDeniedHandler(new MyAccessDeniedHandler());
		
	}
	
	
	@Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
		auth.authenticationProvider(authenticationProvider());
    }
	
	/*@Bean
	public static PasswordEncoder passwordEncoder() {
			
		String idForEncode = "bcrypt";
		
		Map encoders = new HashMap<>();
		encoders.put(idForEncode, new BCryptPasswordEncoder());
		encoders.put("noop", NoOpPasswordEncoder.getInstance());
		encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
		encoders.put("scrypt", new SCryptPasswordEncoder());
		encoders.put("sha256", new StandardPasswordEncoder());

		PasswordEncoder passwordEncoder =
		    new DelegatingPasswordEncoder(idForEncode, encoders);
		
	    return passwordEncoder;
	}*/
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	 @Bean
	 public DaoAuthenticationProvider authenticationProvider() {
	      DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
	      authenticationProvider.setUserDetailsService(userDetailsService);
	      authenticationProvider.setPasswordEncoder(passwordEncoder());
	      
	      return authenticationProvider;
	 }
	 
	
	 
	
}
