/*
 * This file is generated by jOOQ.
 */
package com.siyuo2o.glass.db.album.tables.records;


import com.siyuo2o.glass.db.album.tables.Image;

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
public class ImageRecord extends UpdatableRecordImpl<ImageRecord> implements Record5<Integer, Integer, String, String, String> {

    private static final long serialVersionUID = -1740518476;

    /**
     * Setter for <code>album.image.id</code>.
     */
    public void setId(Integer value) {
        set(0, value);
    }

    /**
     * Getter for <code>album.image.id</code>.
     */
    public Integer getId() {
        return (Integer) get(0);
    }

    /**
     * Setter for <code>album.image.album_id</code>.
     */
    public void setAlbumId(Integer value) {
        set(1, value);
    }

    /**
     * Getter for <code>album.image.album_id</code>.
     */
    public Integer getAlbumId() {
        return (Integer) get(1);
    }

    /**
     * Setter for <code>album.image.name</code>.
     */
    public void setName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>album.image.name</code>.
     */
    public String getName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>album.image.src</code>.
     */
    public void setSrc(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>album.image.src</code>.
     */
    public String getSrc() {
        return (String) get(3);
    }

    /**
     * Setter for <code>album.image.url</code>.
     */
    public void setUrl(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>album.image.url</code>.
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
        return Image.IMAGE.ID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Integer> field2() {
        return Image.IMAGE.ALBUM_ID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field3() {
        return Image.IMAGE.NAME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field4() {
        return Image.IMAGE.SRC;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field5() {
        return Image.IMAGE.URL;
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
        return getAlbumId();
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
        return getAlbumId();
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
    public ImageRecord value1(Integer value) {
        setId(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ImageRecord value2(Integer value) {
        setAlbumId(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ImageRecord value3(String value) {
        setName(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ImageRecord value4(String value) {
        setSrc(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ImageRecord value5(String value) {
        setUrl(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ImageRecord values(Integer value1, Integer value2, String value3, String value4, String value5) {
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
     * Create a detached ImageRecord
     */
    public ImageRecord() {
        super(Image.IMAGE);
    }

    /**
     * Create a detached, initialised ImageRecord
     */
    public ImageRecord(Integer id, Integer albumId, String name, String src, String url) {
        super(Image.IMAGE);

        set(0, id);
        set(1, albumId);
        set(2, name);
        set(3, src);
        set(4, url);
    }
}