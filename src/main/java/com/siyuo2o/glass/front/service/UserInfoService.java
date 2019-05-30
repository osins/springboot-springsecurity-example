package com.siyuo2o.glass.front.service;

import com.siyuo2o.glass.db.album.tables.pojos.SysRole;
import com.siyuo2o.glass.db.album.tables.pojos.UserInfo;

import java.util.List;

public interface UserInfoService {
    /**通过username查找用户信息;*/
    public UserInfo findByUsername(String username);
    public void addUser(UserInfo userInfo);
    public List<SysRole>  getRoleList(String username);
}