package com.siyuo2o.glass.front.service;

import com.siyuo2o.glass.db.album.tables.pojos.Image;

import java.util.List;

public interface ImageService {
    public List<Image> selectAll();
}
