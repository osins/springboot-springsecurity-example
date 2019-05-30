/*
 * This file is generated by jOOQ.
 */
package com.siyuo2o.glass.db.album.tables.pojos;


import com.siyuo2o.glass.db.album.enums.SysPermissionResourceType;

import java.io.Serializable;

import javax.annotation.Generated;


/**
 * This class is generated by jOOQ.
 */
@Generated(
    value = {
        "http://www.jooq.org",
        "jOOQ version:3.11.9"
    },
    comments = "This class is generated by jOOQ"
)
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class SysPermission implements Serializable {

    private static final long serialVersionUID = 1897706859;

    private Integer                   id;
    private Boolean                   available;
    private String                    name;
    private Long                      parentId;
    private String                    parentIds;
    private String                    permission;
    private SysPermissionResourceType resourceType;
    private String                    url;

    public SysPermission() {}

    public SysPermission(SysPermission value) {
        this.id = value.id;
        this.available = value.available;
        this.name = value.name;
        this.parentId = value.parentId;
        this.parentIds = value.parentIds;
        this.permission = value.permission;
        this.resourceType = value.resourceType;
        this.url = value.url;
    }

    public SysPermission(
        Integer                   id,
        Boolean                   available,
        String                    name,
        Long                      parentId,
        String                    parentIds,
        String                    permission,
        SysPermissionResourceType resourceType,
        String                    url
    ) {
        this.id = id;
        this.available = available;
        this.name = name;
        this.parentId = parentId;
        this.parentIds = parentIds;
        this.permission = permission;
        this.resourceType = resourceType;
        this.url = url;
    }

    public Integer getId() {
        return this.id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Boolean getAvailable() {
        return this.available;
    }

    public void setAvailable(Boolean available) {
        this.available = available;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Long getParentId() {
        return this.parentId;
    }

    public void setParentId(Long parentId) {
        this.parentId = parentId;
    }

    public String getParentIds() {
        return this.parentIds;
    }

    public void setParentIds(String parentIds) {
        this.parentIds = parentIds;
    }

    public String getPermission() {
        return this.permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }

    public SysPermissionResourceType getResourceType() {
        return this.resourceType;
    }

    public void setResourceType(SysPermissionResourceType resourceType) {
        this.resourceType = resourceType;
    }

    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("SysPermission (");

        sb.append(id);
        sb.append(", ").append(available);
        sb.append(", ").append(name);
        sb.append(", ").append(parentId);
        sb.append(", ").append(parentIds);
        sb.append(", ").append(permission);
        sb.append(", ").append(resourceType);
        sb.append(", ").append(url);

        sb.append(")");
        return sb.toString();
    }
}