package com.siyuo2o.glass.front.api;

import com.siyuo2o.glass.db.album.tables.pojos.Image;
import com.siyuo2o.glass.front.service.ImageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/album")
public class AlbumRestController {

    @Autowired
    private ImageService imageService;

    @RequestMapping(value = "list", method = RequestMethod.GET)
    public List<Image> list(){
        List<Image> result = imageService.selectAll();

        return result;
    }
}
