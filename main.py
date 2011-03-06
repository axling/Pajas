#!/usr/bin/env python
# coding: utf-8
# Copyright 2011 Facebook, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import os
# dummy config to enable registering django template filters
os.environ[u'DJANGO_SETTINGS_MODULE'] = u'conf'

from google.appengine.dist import use_library
use_library('django', '1.2')

from django.template.defaultfilters import register
from django.utils import simplejson as json
from functools import wraps
from google.appengine.api import urlfetch, taskqueue
from google.appengine.ext import db, webapp
from google.appengine.ext.webapp import util, template
from google.appengine.runtime import DeadlineExceededError
from random import randrange
from uuid import uuid4
from operator import itemgetter
import Cookie
import base64
import cgi
import conf
import datetime
import hashlib
import hmac
import logging
import time
import traceback
import urllib


def htmlescape(text):
    """Escape text for use as HTML"""
    return cgi.escape(
        text, True).replace("'", '&#39;').encode('ascii', 'xmlcharrefreplace')


@register.filter(name=u'get_name')
def get_name(dic, index):
    """Django template filter to render name"""
    return dic[index].name


@register.filter(name=u'get_picture')
def get_picture(dic, index):
    """Django template filter to render picture"""
    return dic[index].picture

class User(db.Model):
    user_id = db.StringProperty(required=True)
    access_token = db.StringProperty(required=True)
    name = db.StringProperty(required=True)
    picture = db.StringProperty(required=True)
    friends = db.StringListProperty()
    dirty = db.BooleanProperty()
    pajas_friends = db.StringListProperty()
    def refresh_data(self):
        """Refresh this user's data using the Facebook Graph API"""
        me = Facebook().api(u'/me',
            {u'fields': u'picture,friends', u'access_token': self.access_token})
        self.dirty = False
        self.name = me[u'name']
        self.picture = me[u'picture']
        self.friends = [user[u'id'] for user in me[u'friends'][u'data']]
        return self.put()

class Point(db.Model):
    """The Pajas Point model"""
    issuer_id = db.StringProperty(required=True)
    pajas_id = db.StringProperty(required=True)
    description = db.StringProperty(required=True)
    submit_time = db.DateTimeProperty(auto_now_add=True)
    

class FacebookApiError(Exception):
    def __init__(self, result):
        self.result = result

    def __str__(self):
        return self.__class__.__name__ + ': ' + json.dumps(self.result)


class Facebook(object):
    """Wraps the Facebook specific logic"""
    def __init__(self, app_id=conf.FACEBOOK_APP_ID,
            app_secret=conf.FACEBOOK_APP_SECRET):
        self.app_id = app_id
        self.app_secret = app_secret
        self.user_id = None
        self.access_token = None
        self.signed_request = {}

    def api(self, path, params=None, method=u'GET', domain=u'graph'):
        """Make API calls"""
        if not params:
            params = {}
        params[u'method'] = method
        if u'access_token' not in params and self.access_token:
            params[u'access_token'] = self.access_token
        result = json.loads(urlfetch.fetch(
            url=u'https://' + domain + u'.facebook.com' + path,
            payload=urllib.urlencode(params),
            method=urlfetch.POST,
            headers={
                u'Content-Type': u'application/x-www-form-urlencoded'})
            .content)
        if isinstance(result, dict) and u'error' in result:
            raise FacebookApiError(result)
        return result

    def load_signed_request(self, signed_request):
        """Load the user state from a signed_request value"""
        try:
            sig, payload = signed_request.split(u'.', 1)
            sig = self.base64_url_decode(sig)
            data = json.loads(self.base64_url_decode(payload))

            expected_sig = hmac.new(
                self.app_secret, msg=payload, digestmod=hashlib.sha256).digest()

            # allow the signed_request to function for upto 1 day
            if sig == expected_sig and \
                    data[u'issued_at'] > (time.time() - 86400):
                self.signed_request = data
                self.user_id = data.get(u'user_id')
                self.access_token = data.get(u'oauth_token')
        except ValueError, ex:
            pass # ignore if can't split on dot

    @property
    def user_cookie(self):
        """Generate a signed_request value based on current state"""
        if not self.user_id:
            return
        payload = self.base64_url_encode(json.dumps({
            u'user_id': self.user_id,
            u'issued_at': str(int(time.time())),
        }))
        sig = self.base64_url_encode(hmac.new(
            self.app_secret, msg=payload, digestmod=hashlib.sha256).digest())
        return sig + '.' + payload

    @staticmethod
    def base64_url_decode(data):
        data = data.encode(u'ascii')
        data += '=' * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def base64_url_encode(data):
        return base64.urlsafe_b64encode(data).rstrip('=')


class CsrfException(Exception):
    pass


class BaseHandler(webapp.RequestHandler):
    facebook = None
    user = None
    csrf_protect = True
    
    def initialize(self, request, response):
        """General initialization for every request"""
        super(BaseHandler, self).initialize(request, response)

        try:
            self.init_facebook()
            self.init_csrf()
            self.response.headers[u'P3P'] = u'CP=HONK'  # iframe cookies in IE
        except Exception, ex:
            self.log_exception(ex)
            raise

    def handle_exception(self, ex, debug_mode):
        """Invoked for unhandled exceptions by webapp"""
        self.log_exception(ex)
        self.render(u'error',
                    trace=traceback.format_exc(), debug_mode=debug_mode)

    def log_exception(self, ex):
        """Internal logging handler to reduce some App Engine noise in errors"""
        msg = ((str(ex) or ex.__class__.__name__) +
                u': \n' + traceback.format_exc())
        if isinstance(ex, urlfetch.DownloadError) or \
           isinstance(ex, DeadlineExceededError) or \
           isinstance(ex, CsrfException) or \
           isinstance(ex, taskqueue.TransientError):
            logging.warn(msg)
        else:
            logging.error(msg)

    def set_cookie(self, name, value, expires=None):
        """Set a cookie"""
        if value is None:
            value = 'deleted'
            expires = datetime.timedelta(minutes=-50000)
        jar = Cookie.SimpleCookie()
        jar[name] = value
        jar[name]['path'] = u'/'
        if expires:
            if isinstance(expires, datetime.timedelta):
                expires = datetime.datetime.now() + expires
            if isinstance(expires, datetime.datetime):
                expires = expires.strftime('%a, %d %b %Y %H:%M:%S')
            jar[name]['expires'] = expires
        self.response.headers.add_header(*jar.output().split(u': ', 1))

    def render(self, name, **data):
        """Render a template"""
        if not data:
            data = {}
        data[u'js_conf'] = json.dumps({
            u'appId': conf.FACEBOOK_APP_ID,
            u'canvasName': conf.FACEBOOK_CANVAS_NAME,
            u'userIdOnServer': self.user.user_id if self.user else None,
        })
        data[u'logged_in_user'] = self.user
        data[u'message'] = self.get_message()
        data[u'csrf_token'] = self.csrf_token
        data[u'canvas_name'] = conf.FACEBOOK_CANVAS_NAME
        self.response.out.write(template.render(
            os.path.join(
                os.path.dirname(__file__), 'templates', name + '.html'),
            data))

    def init_facebook(self):
        """Sets up the request specific Facebook and User instance"""
        facebook = Facebook()
        user = None

        # initial facebook request comes in as a POST with a signed_request
        if u'signed_request' in self.request.POST:
            facebook.load_signed_request(self.request.get('signed_request'))
            # we reset the method to GET because a request from facebook with a
            # signed_request uses POST for security reasons, despite it
            # actually being a GET. in webapp causes loss of request.POST data.
            self.request.method = u'GET'
            self.set_cookie(
                'u', facebook.user_cookie, datetime.timedelta(minutes=1440))
        elif 'u' in self.request.cookies:
            facebook.load_signed_request(self.request.cookies.get('u'))

        # try to load or create a user object
        if facebook.user_id:
            user = User.get_by_key_name(facebook.user_id)
            if user:
                # update stored access_token
                if facebook.access_token and \
                        facebook.access_token != user.access_token:
                    user.access_token = facebook.access_token
                    user.put()
                # restore stored access_token if necessary
                if not facebook.access_token:
                    facebook.access_token = user.access_token

            if not user and facebook.access_token:
                me = facebook.api(u'/me', {u'fields': u'name,picture,friends'})
                try:
                    friends = [user[u'id'] for user in me[u'friends'][u'data']]
                    user = User(key_name=facebook.user_id,
                                user_id=facebook.user_id, friends=friends,
                                access_token=facebook.access_token, 
                                name=me[u'name'],
                                picture=me[u'picture'])
                    user.put()
                except KeyError, ex:
                    pass # ignore if can't get the minimum fields

        self.facebook = facebook
        self.user = user

    def init_csrf(self):
        """Issue and handle CSRF token as necessary"""
        self.csrf_token = self.request.cookies.get(u'c')
        if not self.csrf_token:
            self.csrf_token = str(uuid4())[:8]
            self.set_cookie('c', self.csrf_token)
        if self.request.method == u'POST' and self.csrf_protect and \
                self.csrf_token != self.request.POST.get(u'_csrf_token'):
            raise CsrfException(u'Missing or invalid CSRF token.')

    def set_message(self, **obj):
        """Simple message support"""
        self.set_cookie('m', base64.b64encode(json.dumps(obj)) if obj else None)

    def get_message(self):
        """Get and clear the current message"""
        message = self.request.cookies.get(u'm')
        if message:
            self.set_message()  # clear the current cookie
            return json.loads(base64.b64decode(message))


def user_required(fn):
    """Decorator to ensure a user is present"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        handler = args[0]
        if handler.user:
            return fn(*args, **kwargs)
        handler.redirect(u'/')
    return wrapper

class UserPage(BaseHandler):
    def get(self, uid):
        if self.user:
            if (uid in self.user.friends) or uid == self.user.user_id:
                rec_points = Point.all().filter("pajas_id =", 
                                                uid).order("-submit_time")
                issued_points = Point.all().filter("issuer_id =", 
                                                   uid).order("-submit_time")
                self.render(u'user_page', points = rec_points, 
                            user_name = self.user.name, 
                            iss_points = issued_points, 
                            user = uid)
            else:
                self.redirect(u"/")
        else:
            self.redirect(u"/")
    def post(self, uid):
        if uid:
            if u'point_tag' in self.request.POST:
                key = self.request.POST[u'point_tag']
                the_point = Point.get(key)
                the_point.delete()
                self.redirect(u'/user_page/' + uid)
            else:
                description = self.request.POST[u'description']
                point = Point(issuer_id = self.user.user_id, pajas_id = uid,
                              description = description)
                point.put()
                self.redirect(u'/user_page/' + uid)
        else:
            self.redirect(u'/user_page/' + uid)

class FriendListHandler(BaseHandler):
    def get(self):
        if self.user:
            pajas_friends = []
            for friend in self.user.friends:
                q = db.GqlQuery("SELECT * FROM Point " + 
                                "WHERE pajas_id = :1 " +
                                "ORDER BY submit_time DESC", 
                                friend)
                first = True
                count=0
                temp_point = None
                for point in q:
                    if first:
                        temp_point = point
                        count= 1
                        first=False
                    else:
                        count += 1
                if count > 0:
                    pajas_friends.append((friend, temp_point, count))
            if pajas_friends:
                pajas_friends = sorted(pajas_friends, key=lambda k: k[2],
                                       reverse=True)
            self.render(u'friend_list', friendlist=pajas_friends)
        else:
            self.redirect(u'/')

class ListPointsHandler(BaseHandler):
    def get(self):
        if self.user:
            summary = {}
            the_points = Point.all()
            for point in the_points:
                if(point.pajas_id in summary):
                    summary[point.pajas_id] += 1
                else:
                    summary[point.pajas_id] = 1
            summary = sorted(summary.iteritems(), key=itemgetter(1), 
                             reverse=True) 
            self.render(u'list_points', summary=summary, points=the_points)
        else:
            self.redirect(u'/')

class AddPointsHandler(BaseHandler):
    def get(self):
        if self.user:
            self.render(u'add_points', friends = self.user.friends)
        else:
            self.redirect(u'/')
    def post(self):
        description = self.request.POST[u'description']
        friend = self.request.POST[u'friend']
        point = Point(issuer_id = self.user.user_id, pajas_id = friend, 
                      description = description)
        point.put()
        self.redirect(u'/friend_list')
        

class MainHandler(BaseHandler):
    def get(self):
        if self.user:
            self.redirect(u'/user_page/' + self.user.user_id)
        else:
            self.render(u'main')

def main():
    routes = [
        (r'/', MainHandler),
        (r'/add_point', AddPointsHandler),
        (r'/list_points', ListPointsHandler),
        (r'/friend_list', FriendListHandler),
        (r'/user_page/(.*)', UserPage)
        ]
    application = webapp.WSGIApplication(routes,
        debug=os.environ.get('SERVER_SOFTWARE', '').startswith('Dev'))
    util.run_wsgi_app(application)


if __name__ == u'__main__':
    main()
