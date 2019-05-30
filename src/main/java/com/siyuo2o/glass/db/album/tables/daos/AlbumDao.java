/*
 * This file is generated by jOOQ.
 */
package com.siyuo2o.glass.db.album.tables.daos;


import com.siyuo2o.glass.db.album.tables.Album;
import com.siyuo2o.glass.db.album.tables.records.AlbumRecord;

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
public class AlbumDao extends DAOImpl<AlbumRecord, com.siyuo2o.glass.db.album.tables.pojos.Album, Integer> {

    /**
     * Create a new AlbumDao without any configuration
     */
    public AlbumDao() {
        super(Album.ALBUM_, com.siyuo2o.glass.db.album.tables.pojos.Album.class);
    }

    /**
     * Create a new AlbumDao with an attached configuration
     */
    public AlbumDao(Configuration configuration) {
        super(Album.ALBUM_, com.siyuo2o.glass.db.album.tables.pojos.Album.class, configuration);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Integer getId(com.siyuo2o.glass.db.album.tables.pojos.Album object) {
        return object.getId();
    }

    /**
     * Fetch records that have <code>id IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Album> fetchById(Integer... values) {
        return fetch(Album.ALBUM_.ID, values);
    }

    /**
     * Fetch a unique record that has <code>id = value</code>
     */
    public com.siyuo2o.glass.db.album.tables.pojos.Album fetchOneById(Integer value) {
        return fetchOne(Album.ALBUM_.ID, value);
    }

    /**
     * Fetch records that have <code>parent_id IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Album> fetchByParentId(Integer... values) {
        return fetch(Album.ALBUM_.PARENT_ID, values);
    }

    /**
     * Fetch records that have <code>name IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Album> fetchByName(String... values) {
        return fetch(Album.ALBUM_.NAME, values);
    }

    /**
     * Fetch records that have <code>src IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Album> fetchBySrc(String... values) {
        return fetch(Album.ALBUM_.SRC, values);
    }

    /**
     * Fetch records that have <code>url IN (values)</code>
     */
    public List<com.siyuo2o.glass.db.album.tables.pojos.Album> fetchByUrl(String... values) {
        return fetch(Album.ALBUM_.URL, values);
    }
}
