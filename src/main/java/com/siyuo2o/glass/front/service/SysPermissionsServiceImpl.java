package com.siyuo2o.glass.front.service;

import com.siyuo2o.glass.db.album.tables.pojos.SysPermission;
import org.jooq.DSLContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SysPermissionsServiceImpl implements SysPermissionsService {
    @Autowired
    DSLContext dsl;

    com.siyuo2o.glass.db.album.tables.SysRolePermission sysRolePermissionTable = com.siyuo2o.glass.db.album.tables.SysRolePermission.SYS_ROLE_PERMISSION.as("rp");
    com.siyuo2o.glass.db.album.tables.SysPermission sysPermissionTable = com.siyuo2o.glass.db.album.tables.SysPermission.SYS_PERMISSION.as("p");

    @Override
    public List<SysPermission> getListByRoleId(int roleId) {
        return dsl.select().from(sysPermissionTable)
                .join(sysRolePermissionTable).on(sysRolePermissionTable.PERMISSION_ID.eq(sysPermissionTable.ID))
                .where(sysRolePermissionTable.ROLE_ID.eq(roleId))
                .fetch().into(SysPermission.class);
    }
}
