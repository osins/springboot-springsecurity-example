package com.siyuo2o.glass.front.service;

import com.siyuo2o.glass.db.album.tables.pojos.SysPermission;

import java.util.List;

public interface SysPermissionsService {
    public List<SysPermission> getListByRoleId(int roleId);
}
