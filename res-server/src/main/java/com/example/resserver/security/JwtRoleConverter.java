package com.example.resserver.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JwtRoleConverter implements Converter<Jwt, Collection<GrantedAuthority> > {
    @Override 
    public Collection convert (Jwt jwt)  {
        List<String> roles =  (ArrayList)  jwt.getClaims().get("roles") ;
        if  ( roles ==  null  || roles.isEmpty ())  {
            return  new  ArrayList <>() ;
        }
        List<GrantedAuthority> authorityList = new ArrayList<>();
        for(String role : roles){
            authorityList.add(new SimpleGrantedAuthority(role));
        }
        return authorityList;
    }
}