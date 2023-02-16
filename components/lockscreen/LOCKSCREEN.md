# Custom lockscreen
Add a lockscreen file in this directory. Preferably use a 4K image. If there is only one jpg or png in this directory, this file will be used. If there are multiple image files, the function will look for "img0.jpg".

If SetCustomLockScreen function is triggered, but no file is found in lockscreen directory, it will look for components\wallpaper\img0.jpg and use this file instead if it exists.