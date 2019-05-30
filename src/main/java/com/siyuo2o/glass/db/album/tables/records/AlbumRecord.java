/*
 * This file is generated by jOOQ.
 */
package com.siyuo2o.glass.db.album.tables.records;


import com.siyuo2o.glass.db.album.tables.Album;

import javax.annotation.Generated;

import org.jooq.Field;
import org.jooq.Record1;
import org.jooq.Record5;
import org.jooq.Row5;
import org.jooq.impl.UpdatableRecordImpl;


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
public class AlbumRecord extends UpdatableRecordImpl<AlbumRecord> implements Record5<Integer, Integer, String, String, String> {

    private static final long serialVersionUID = 4230153;

    /**
     * Setter for <code>album.album.id</code>.
     */
    public void setId(Integer value) {
        set(0, value);
    }

    /**
     * Getter for <code>album.album.id</code>.
     */
    public Integer getId() {
        return (Integer) get(0);
    }

    /**
     * Setter for <code>album.album.parent_id</code>.
     */
    public void setParentId(Integer value) {
        set(1, value);
    }

    /**
     * Getter for <code>album.album.parent_id</code>.
     */
    public Integer getParentId() {
        return (Integer) get(1);
    }

    /**
     * Setter for <code>album.album.name</code>.
     */
    public void setName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>album.album.name</code>.
     */
    public String getName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>album.album.src</code>.
     */
    public void setSrc(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>album.album.src</code>.
     */
    public String getSrc() {
        return (String) get(3);
    }

    /**
     * Setter for <code>album.album.url</code>.
     */
    public void setUrl(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>album.album.url</code>.
     */
    public String getUrl() {
        return (String) get(4);
    }

    // -------------------------------------------------------------------------
    // Primary key information
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Record1<Integer> key() {
        return (Record1) super.key();
    }

    // -------------------------------------------------------------------------
    // Record5 type implementation
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Row5<Integer, Integer, String, String, String> fieldsRow() {
        return (Row5) super.fieldsRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Row5<Integer, Integer, String, String, String> valuesRow() {
        return (Row5) super.valuesRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Integer> field1() {
        return Album.ALBUM_.ID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Integer> field2() {
        return Album.ALBUM_.PARENT_ID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field3() {
        return Album.ALBUM_.NAME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field4() {
        return Album.ALBUM_.SRC;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field5() {
        return Album.ALBUM_.URL;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Integer component1() {
        return getId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Integer component2() {
        return getParentId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component3() {
        return getName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component4() {
        return getSrc();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component5() {
        return getUrl();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Integer value1() {
        return getId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Integer value2() {
        return getParentId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value3() {
        return getName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value4() {
        return getSrc();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value5() {
        return getUrl();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AlbumRecord value1(Integer value) {
        setId(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AlbumRecord value2(Integer value) {
        setParentId(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AlbumRecord value3(String value) {
        setName(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AlbumRecord value4(String value) {
        setSrc(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AlbumRecord value5(String value) {
        setUrl(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AlbumRecord values(Integer value1, Integer value2, String value3, String value4, String value5) {
        value1(value1);
        value2(value2);
        value3(value3);
        value4(value4);
        value5(value5);
        return this;
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached AlbumRecord
     */
    public AlbumRecord() {
        super(Album.ALBUM_);
    }

    /**
     * Create a detached, initialised AlbumRecord
     */
    public AlbumRecord(Integer id, Integer parentId, String name, String src, String url) {
        super(Album.ALBUM_);

        set(0, id);
        set(1, parentId);
        set(2, name);
        set(3, src);
        set(4, url);
    }
}
