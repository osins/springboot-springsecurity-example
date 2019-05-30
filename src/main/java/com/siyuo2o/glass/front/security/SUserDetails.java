package com.siyuo2o.glass.front.security;

import com.siyuo2o.glass.db.album.tables.pojos.UserInfo;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class SUserDetails extends UserInfo implements org.springframework.security.core.userdetails.UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
