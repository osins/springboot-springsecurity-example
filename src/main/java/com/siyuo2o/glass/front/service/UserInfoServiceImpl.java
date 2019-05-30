package com.siyuo2o.glass.front.service;

import com.siyuo2o.glass.db.album.tables.pojos.SysRole;
import com.siyuo2o.glass.db.album.tables.pojos.UserInfo;
import com.siyuo2o.glass.db.album.tables.records.UserInfoRecord;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserInfoServiceImpl implements UserInfoService {
    @Autowired
    DSLContext dsl;

    com.siyuo2o.glass.db.album.tables.UserInfo userTable = com.siyuo2o.glass.db.album.tables.UserInfo.USER_INFO.as("u");
    com.siyuo2o.glass.db.album.tables.SysUserRole userRoleTable = com.siyuo2o.glass.db.album.tables.SysUserRole.SYS_USER_ROLE.as("ur");
    com.siyuo2o.glass.db.album.tables.SysRole roleTable = com.siyuo2o.glass.db.album.tables.SysRole.SYS_ROLE.as("r");

    @Override
    public UserInfo findByUsername(String username) {
        Record result = dsl.select().from(userTable).where(userTable.USERNAME.eq(username)).fetchAny();
        if(result == null){
            return null;
        }

        return result.into(UserInfo.class);
    }

    public void addUser(UserInfo userInfo) {
        if(userInfo.getName()== null || userInfo.getName().isEmpty()){
            userInfo.setName(userInfo.getUsername());
        }

        if(userInfo.getUsername()== null || userInfo.getUsername().isEmpty()){
            return;
        }

        if(userInfo.getPassword()== null || userInfo.getPassword().isEmpty()){
            return;
        }

        BCryptPasswordEncoder encoder =new BCryptPasswordEncoder();
        userInfo.setPassword(encoder.encode(userInfo.getPassword().trim()));

        UserInfoRecord record = dsl.newRecord(userTable, userInfo);
        record.store();
    }

    public List<SysRole> getRoleList(String username){
        return dsl.select().from(roleTable).join(userRoleTable)
                .on(roleTable.ID.eq(userRoleTable.ROLE_ID))
                .join(userTable).on(userTable.UID.eq(userRoleTable.UID))
                .where(userTable.USERNAME.eq(username))
                .fetch().into(SysRole.class);
    }
}