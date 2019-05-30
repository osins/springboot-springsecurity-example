/*
 * This file is generated by jOOQ.
 */
package com.siyuo2o.glass.db.album.tables.pojos;


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
public class Image implements Serializable {

    private static final long serialVersionUID = 1691546158;

    private Integer id;
    private Integer albumId;
    private String  name;
    private String  src;
    private String  url;

    public Image() {}

    public Image(Image value) {
        this.id = value.id;
        this.albumId = value.albumId;
        this.name = value.name;
        this.src = value.src;
        this.url = value.url;
    }

    public Image(
        Integer id,
        Integer albumId,
        String  name,
        String  src,
        String  url
    ) {
        this.id = id;
        this.albumId = albumId;
        this.name = name;
        this.src = src;
        this.url = url;
    }

    public Integer getId() {
        return this.id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getAlbumId() {
        return this.albumId;
    }

    public void setAlbumId(Integer albumId) {
        this.albumId = albumId;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSrc() {
        return this.src;
    }

    public void setSrc(String src) {
        this.src = src;
    }

    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Image (");

        sb.append(id);
        sb.append(", ").append(albumId);
        sb.append(", ").append(name);
        sb.append(", ").append(src);
        sb.append(", ").append(url);

        sb.append(")");
        return sb.toString();
    }
}