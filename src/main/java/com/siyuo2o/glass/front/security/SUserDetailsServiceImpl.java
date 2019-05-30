package com.siyuo2o.glass.front.security;

import org.jooq.DSLContext;
import org.jooq.Record;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class SUserDetailsServiceImpl implements UserDetailsService {
    private static final Logger log = LoggerFactory.getLogger(SUserDetailsServiceImpl.class);

    @Autowired
    DSLContext dsl;

    com.siyuo2o.glass.db.album.tables.UserInfo userTable = com.siyuo2o.glass.db.album.tables.UserInfo.USER_INFO.as("u");

    @Override
    public SUserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Record result = dsl.select().from(userTable).where(userTable.USERNAME.eq(s)).fetchAny();
        if(result == null){
            return null;
        }

        return result.into(SUserDetails.class);
    }
}
