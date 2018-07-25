'use strict';

var loopback = require('loopback');
var passport = require('passport');
var _ = require('underscore');
var fs = require('fs');

var debug = require('debug')('@rula:cas-configurator');

module.exports = CasConfigurator;

/**
 * @class
 * @classdesc The CAS configurator
 * @param {Object} app The LoopBack app instance
 * @returns {CasConfigurator}
 */
function CasConfigurator(app) {
  if (!(this instanceof CasConfigurator)) {
    return new CasConfigurator(app);
  }
  this.app = app;
};

/**
 * Set up data models for CAS users.
 * @options {Object} options Options for models
 * @property {Model} [userModel] The user model class
 * @end
 */
CasConfigurator.prototype.setupModels = function(options) {
  options = options || {};
  // Set up relations
  this.userModel = options.casUserModel || 
    loopback.getModelByType(this.app.models.CasUser);
};

/**
 * Initialize the CAS configurator
 * @returns {Passport}
 */
CasConfigurator.prototype.init = function(noSession) {
  var self = this;
  self.app.middleware('session:after', passport.initialize());

  return passport;
};

CasConfigurator.prototype.configureProvider = function(name, options) {
  var self = this;
  options = options || {};
  var link = options.link;
  var AuthStrategy = require(options.module)[options.strategy || 'Strategy'];

  if (!AuthStrategy) {
    AuthStrategy = require(options.module);
  }

  var authScheme = 'cas';
  var provider = options.provider || name;
  var authPath = options.authPath || ('/auth/' + name);
  var callbackPath = options.callbackPath || ('/auth/' + name + '/callback');
  var callbackHTTPMethod = options.callbackHTTPMethod !== 'post' ? 'get' : 'post';

  // remember returnTo position, set by ensureLoggedIn
  var successRedirect = function(req, accessToken) {
    if (!!req && req.session && req.session.returnTo) {
      var returnTo = req.session.returnTo;
      delete req.session.returnTo;
      return appendAccessToken(returnTo, accessToken);
    }
    return appendAccessToken(options.successRedirect, accessToken) || '/auth/account';
  };

  var appendAccessToken = function(url, accessToken) {
    if (!accessToken) {
      return url;
    }
    return url + '?access-token=' + accessToken.id + '&user-id=' + accessToken.userId;
  };

  var failureRedirect = options.failureRedirect || '/login.html';

  var session = !!options.session;

  var loginCallback = options.loginCallback || function(req, done) {
    return function(err, user, identity, token) {
      var authInfo = {
        identity: identity,
      };
      if (token) {
        authInfo.accessToken = token;
      }
      done(err, user, authInfo);
    };
  };

  var strategy = new AuthStrategy(_.defaults({
    passReqToCallback: true,
  }, options),
    // This is the Passport verify function.
    function(req, profile, done) {
      if (profile) {
        var casAttrForUsername = options.casAttrForUsername || 'user';
        var username = profile[casAttrForUsername];

        var query = {
          where: {
            username: username
          }
        };

        self.userModel.findOne(query, function(err, user) {
          var defaultError = new Error('Login failed');
          defaultError.statusCode = 401;
          defaultError.code = 'LOGIN_FAILED';

          if (err) {
            debug('An error is reported from User.findOne: %j', err);
            done(defaultError);
          }

          if (user) {
            // At this point, a user with the matching CAS username exists
            // and should be allowed.
            var u = user.toJSON();
            var userProfile = {
              provider: 'cas',
              id: u.id,
              username: u.username,
              status: u.status,
              accessToken: null,
            };

            user.createAccessToken(u.ttl, u, function(err, token) {
              if (err) {
                debug('Error creating accessToken: %j', err);
                done(defaultError);
              }

              if (token) {
                userProfile.accessToken = token;
                done(null, userProfile, {accessToken: token});
              } else {
                done(defaultError);
              }
            });
          } else {
            var authError = new Error('CAS user not authorized!');
            authError.statusCode = 401;
            authError.code = 'LOGIN_FAILED';

            done(authError);
          }
        });
      } else {
        done(null);
      }
    }
  );

  passport.use(name, strategy);

  var defaultCallback = function(req, res, next) {
    // The default callback
    passport.authenticate(name, _.defaults({session: session},
      options.authOptions), function(err, user, info) {
      if (err) {
        return next(err);
      }
      if (!user) {
        if (!!options.json) {
          return res.status(401).json('Authentication error.');
        }
        if (options.failureQueryString && info) {
          return res.redirect(appendErrorToQueryString(failureRedirect, info));
        }
        return res.redirect(failureRedirect);
      }
      if (session) {
        req.logIn(user, function(err) {
          if (err) {
            return next(err);
          }
          if (info && info.accessToken) {
            if (!!options.json) {
              return res.json({
                'access_token': info.accessToken.id,
                userId: user.id,
              });
            } else {
              res.cookie('access_token', info.accessToken.id,
                {
                  signed: req.signedCookies ? true : false,
                  // maxAge is in ms
                  maxAge: 1000 * info.accessToken.ttl,
                  domain: (options.domain) ? options.domain : null,
                });
              res.cookie('userId', user.id.toString(), {
                signed: req.signedCookies ? true : false,
                maxAge: 1000 * info.accessToken.ttl,
                domain: (options.domain) ? options.domain : null,
              });
            }
          }
          return res.redirect(successRedirect(req));
        });
      } else {
        if (info && info.accessToken) {
          if (!!options.json) {
            return res.json({
              'access_token': info.accessToken.id,
              userId: user.id,
            });
          } else {
            res.cookie('access_token', info.accessToken.id, {
              signed: req.signedCookies ? true : false,
              maxAge: 1000 * info.accessToken.ttl,
            });
            res.cookie('userId', user.id.toString(), {
              signed: req.signedCookies ? true : false,
              maxAge: 1000 * info.accessToken.ttl,
            });
          }
        }
        return res.redirect(successRedirect(req, info.accessToken));
      }
    })(req, res, next);
  };

  var casCallback = options.customCallback || defaultCallback;
  self.app.get(authPath, casCallback);

  var customCallback = options.customCallback || defaultCallback;
  // Register the path and the callback.
  self.app[callbackHTTPMethod](callbackPath, customCallback);

  return strategy;
};