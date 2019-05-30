/*
 * This file is generated by jOOQ.
 */
package com.siyuo2o.glass.db.album.tables.daos;


import com.siyuo2o.glass.db.album.tables.Image;
import com.siyuo2o.glass.db.album.tables.records.ImageRecord;

import java.util.List;

import javax.annotation.Generated;

import org.jooq.Configuration;
import org.jooq.impl.DAOImpl;


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
public class ImageDao extends DAOImpl<ImageRecord, com.siyuo2o.glass.db.album.tables.pojos.Image, Integer> {

    /**
     * Create a new ImageDao without any configuration
     */
    public ImageDao() {
        super(Image.IMAGE, com.siyuo2o.glass.db.album.tables.pojos.Image.class);
    }

    /**
     * Create a new ImageDao with an attached configuration
     */
    public ImageDao(Configuration configuration) {
        super(Image.IMAGE, com.siyuo2o.glass.db.album.tables.pojos.Image.class, configuration);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Integer getId(com.siyuo2o.glass.db.album.tables.pojos.Image object) {
        return object.getId();
    }

    /**
     * Fetch records that have <code>id IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Image> fetchById(Integer... values) {
        return fetch(Image.IMAGE.ID, values);
    }

    /**
     * Fetch a unique record that has <code>id = value</code>
     */
    public com.siyuo2o.glass.db.album.tables.pojos.Image fetchOneById(Integer value) {
        return fetchOne(Image.IMAGE.ID, value);
    }

    /**
     * Fetch records that have <code>album_id IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Image> fetchByAlbumId(Integer... values) {
        return fetch(Image.IMAGE.ALBUM_ID, values);
    }

    /**
     * Fetch records that have <code>name IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Image> fetchByName(String... values) {
        return fetch(Image.IMAGE.NAME, values);
    }

    /**
     * Fetch records that have <code>src IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Image> fetchBySrc(String... values) {
        return fetch(Image.IMAGE.SRC, values);
    }

    /**
     * Fetch records that have <code>url IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Image> fetchByUrl(String... values) {
        return fetch(Image.IMAGE.URL, values);
    }
}
