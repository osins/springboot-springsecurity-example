package com.siyuo2o.glass.front.controller;

import com.siyuo2o.glass.db.album.tables.pojos.Image;
import com.siyuo2o.glass.front.service.ImageService;
import com.siyuo2o.glass.front.service.ImageServiceImpl;
import com.siyuo2o.glass.front.utils.AlbumTool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller
@RequestMapping("/album")
public class AlbumController {
    @Autowired
    private Environment env;

    @Autowired
    private ImageService imageService;

    @GetMapping("list")
    public ModelAndView list(){

//        String album_path = env.getProperty("album.path");
//        List<String> photos = AlbumTool.getInstance().getPhotoByAlbum(album_path);

        List<Image> result = imageService.selectAll();

        ModelAndView model = new ModelAndView("album/list");
        model.addObject("photos", result);
        return model;
    }
}
