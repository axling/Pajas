Pajas!
=====

[Pajas](http://apps.facebook.com/pajaspoint) is a simple facebook app for keeping track of your friends clownery(Yes! it is a word). The app is written in python and uses Google Appengine for the hosting. The webapp framework(which is very similar to Django) is used for simplicity. 

The app is based on an example app that Facebook has that is called [Run with Friends](http://apps.facebook.com/runwithfriends/). I recommend the [tutorial](http://developers.facebook.com/docs/samples/canvas/) that explains how Run with Friends was made. 

For security reasons I haven't included the file conf.py which contains the API secret codes that you need for the Facebook interaction. Create the file and add the following(and replacing the stuff inside <> of course):
> # Facebook Application ID and Secret.
> FACEBOOK_APP_ID = '<Facebook App Id>'
> FACEBOOK_APP_SECRET = 'Facebook App Secret'
> # Canvas Page name.
> FACEBOOK_CANVAS_NAME = 'Facebook App Name'


