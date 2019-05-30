package com.siyuo2o.glass.front.service;

import com.siyuo2o.glass.db.album.tables.pojos.Image;
import org.jooq.DSLContext;
import org.jooq.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ImageServiceImpl implements ImageService{

    @Autowired
    DSLContext dsl;

    com.siyuo2o.glass.db.album.tables.Image img = com.siyuo2o.glass.db.album.tables.Image.IMAGE.as("img");

    @Override
    public List<Image> selectAll() {
        Result result = dsl.select().from(img).fetch();

        return result.into(Image.class);
    }
}
