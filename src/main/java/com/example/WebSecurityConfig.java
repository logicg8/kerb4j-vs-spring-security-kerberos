package com.example;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.kerb4j.server.spring.SpnegoAuthenticationProcessingFilter;
import com.kerb4j.server.spring.SpnegoAuthenticationProvider;
import com.kerb4j.server.spring.SpnegoEntryPoint;
import com.kerb4j.server.spring.SpnegoMutualAuthenticationHandler;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;

@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${app.service-principal}")
	private String servicePrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

	   http.exceptionHandling()
	   		.authenticationEntryPoint(spnegoEntryPoint())
	   		.and()
            .authorizeRequests().antMatchers("/", "/home").permitAll()
            //kerb4j .antMatchers("/hello").access("hasRole('ROLE_USER')")
            .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .logout().permitAll().and() //spring
                .addFilterBefore(spnegoAuthenticationProcessingFilter(authenticationManagerBean()), 
                		BasicAuthenticationFilter.class);
    }
    
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean(); //authenticationManager(); //spring
	}

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(kerberosServiceAuthenticationProvider());
    }

    @Bean
    public SpnegoEntryPoint spnegoEntryPoint() {
        return new SpnegoEntryPoint(); ///login spring
    }

    @Bean
    public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
            AuthenticationManager authenticationManager) {
        SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();

        SpnegoMutualAuthenticationHandler successHandler = new SpnegoMutualAuthenticationHandler();//kerb4j only
        filter.setAuthenticationSuccessHandler(successHandler);//kerb4j only

        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public SpnegoAuthenticationProvider kerberosServiceAuthenticationProvider() {
        SpnegoAuthenticationProvider provider = new SpnegoAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setExtractGroupsUserDetailsService(dummyUserDetailsService());
        provider.setServerSpn(servicePrincipal);
        return provider;
    }

    //replace bean above with this bean and re-organize imports to test spring-security-kerberos 
//	@Bean
//	public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
//		KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
//		provider.setTicketValidator(sunJaasKerberosTicketValidator());
//		provider.setUserDetailsService(dummyUserDetailsService());
//		return provider;
//	}

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator = new SunJaasKerberosTicketValidator();
        sunJaasKerberosTicketValidator.setServicePrincipal(servicePrincipal);
        sunJaasKerberosTicketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
        return sunJaasKerberosTicketValidator;
    }

    @Bean
    public DummyUserDetailsService dummyUserDetailsService() {
        return new DummyUserDetailsService();
    }
    

}