#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
from google.appengine.ext import db
from google.appengine.api import memcache
import re
import hashlib
import hmac
import string
import random
from datetime import datetime

secret = 'hunter2'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
BLANK_RE = re.compile(r"^[\s]*$")

def valid_username(username):
    return USER_RE.match(username)

def valid_pass(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

def blank(text):
    return BLANK_RE.match(text)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class TopicPage(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    snippet = db.StringProperty(required = True)
    ver = db.IntegerProperty(required = True)

class Users(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def hmac_str(string):
    return hmac.new(secret, string).hexdigest()

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt=make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

def hash_str(s):
        return hashlib.sha256(s).hexdigest()

def make_secure_val(s):
        return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
        val = h.split('|')[0]
        if h == make_secure_val(val):
                return val

class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        user = self.request.get('username')
        password = self.request.get('password')
        password2 = self.request.get('verify')
        email = self.request.get('email')
        isNewUser = True
        oldUsers = db.GqlQuery("SELECT * FROM Users")
        for userc in oldUsers:
            if userc.username == user:
                isNewUser = False
                break
        if (valid_username(user) and (valid_email(email) or blank(email))
            and valid_pass(password) and password == password2 and isNewUser):
            salt = make_salt()
            hashedPass = make_pw_hash(user, password, salt)
            newUser = Users(username = user, password = hashedPass, email = email)
            newUser.put()
            userId = str(newUser.key().id())
            hashedId = make_secure_val(userId)
            self.response.headers.add_header('Set-Cookie', 'userId=%s; Path=/' % hashedId)    
            self.redirect("/welcome")
        else:
            if not isNewUser:
                userError = "Username is not available"
            elif valid_username(user):
                userError = ""
            else:
                userError = "Invalid username"
            if valid_email(email) or blank(email):
                emailError = ""
            else:
                emailError = "Invalid email"
            if not valid_pass(password):
                passError = "Invalid password"
                matchError = ""
            elif password != password2:
                matchError = "Passwords do not match"
                passError = ""
            else:
                passError = ""
                matchError = ""
            self.render('signup.html', user = user, email = email, userError = userError, passError = passError,
                        matchError = matchError, emailError = emailError)

class LoginPage(Handler):
    def get(self):
        self.render('login.html')
    def post(self):
        user = self.request.get('username')
        password = self.request.get('password')
        thisUser = Users.all().filter('username =', user).get()
        # there are get parameters.
        if thisUser:
            if valid_pw(user, password, thisUser.password):
                userId = str(thisUser.key().id())
                hashedId = make_secure_val(userId)
                self.response.headers.add_header('Set-Cookie', 'userId=%s; Path=/' % hashedId)
                self.redirect("/welcome")
        self.render("login.html", passError = "Invalid Login")

class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'userId=; Path=/')
        self.redirect('/signup')

class WikiPage(Handler):
	# checks cookie, gets topicName from url
    # checks get parameters for version info and acts accordingly
	# uses wikiLOut.html if logged out
	# uses wikiLin.html if logged in
	# passes topicName and topicArticle in both cases
    def get(self, topicName):
        # pageVersions = TopicPage.all().filter('title =', topicName).get()
        # hashedId = self.request.cookies.get('userId')
        # userIdStr = check_secure_val(hashedId)
        # if check_secure_val(hashedId):
        #     userId = int(userIdStr)
        #     aUser = Users.get_by_id(userId)
        #     self.render('wikiLin.html', user = aUser.username, topicName = )
        # else:
        #     self.redirect('/signup')
        pass

class HistoryPage(Handler):
	# get topicName from url, checks cookie
	# uses historyLIn.html if logged in
	# uses historyLOut.html if logged out
	# pass topicName
	# pass all the versions to be looped
	pass

class EditPage(Handler):
	# get topicName from url
	# check cookie, redirect to WikiPage view as needed
    #checks for get parameters with version info and acts accordingly
	# pass topicName to editWiki.html
	# populate textarea with topicArticle
    #accepts edited page and adds it to database with
    #   title and content from the form
    #   created, courtesy of GAE and
    # snippet and ver, computed here
    def get(self, topicName):
        hashedId = self.request.cookies.get('userId')
        userIdStr = check_secure_val(hashedId)
        if check_secure_val(hashedId):
            ver = self.request.get('ver')
            if ver:
                topicPages = TopicPage.all().filter('ver =', ver,' AND title =', topicName).get()
            else:
                topicPages = TopicPage.all().filter('title =', topicName).order('-created').get()
            if topicPages:
                topicArticle = topicPages.content
            else:
                topicArticle = ''
            userId = int(userIdStr)
            aUser = Users.get_by_id(userId)
            self.render('editWiki.html', user = aUser.username, topicName = topicName[1:], topicArticle = topicArticle)
        elif topicPages:
            self.redirect('/' + topicName[1:])
        else:
            self.redirect('/login?ref=' + topicName[1:])

    def post(self, topicName):
        hashedId = self.request.cookies.get('userId')
        userIdStr = check_secure_val(hashedId)
        if check_secure_val(hashedId):
            topicArticle = self.request.get('content')
            topicPages = TopicPage.all().filter('title =', topicName)
            topicList = list(topicPages)
            ver = len(topicList)
            snippet = topicArticle[:100]
            newVersion = TopicPage(title = topicName, ver= ver, snippet = snippet, content = topicArticle)
            newVersion.put()
            self.redirect('/_edit' + topicName)
        else:
            self.redirect('/login?ref=' + topicName[1:])




PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)