package com.siyuo2o.glass.front.utils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class AlbumTool {
    private AlbumTool(){

    }

    private static class AlbumToolSingleton {
        private static AlbumTool singleton = new AlbumTool();
    }

    public static AlbumTool getInstance(){
        return AlbumToolSingleton.singleton;
    }

    public List<String> getPhotoByAlbum(String path){
        File f = new File(path);
        File[] list = f.listFiles();
        if(list == null){
            return null;
        }

        List<String> photos = new ArrayList<String>();
        for (int i=0; i<list.length; i++) {
            photos.add(list[i].getName());
        }

        return photos;
    }
}
