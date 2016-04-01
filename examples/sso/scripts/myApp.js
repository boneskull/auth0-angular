var myApp = angular.module('myApp', [
  'ngCookies', 'auth0', 'ngRoute', 'angular-jwt', 'angular-storage'
]);



myApp.config(function ($routeProvider, authProvider, $httpProvider, jwtInterceptorProvider) {
  $routeProvider
  .when('/logout',  {
    templateUrl: 'views/logout.html',
    controller: 'LogoutCtrl'
  })
  .when('/login',   {
    templateUrl: 'views/login.html',
    controller: 'LoginCtrl',
  })
  .when('/secure',   {
    templateUrl: 'views/secure.html',
    controller: 'SecureCtrl',
    requiresLogin: true
  })
  .when('/', {
    templateUrl: 'views/root.html',
    controller: 'RootCtrl',
    /* isAuthenticated will prevent user access to forbidden routes */
    requiresLogin: true
  });

  authProvider.init({
    domain: 'samples.auth0.com',
    clientID: 'BUIJSW9x60sIHBw8Kd9EmCbj8eDIFxDC',
    sso: true,
    loginUrl: '/login'
  });

  authProvider.on('loginSuccess', function($location, profilePromise, idToken, refreshToken, store) {
    $location.path('/');
    store.set('token', idToken);
    store.set('refreshToken', refreshToken);
    profilePromise.then(function(profile) {
      store.set('profile', profile);
    });
  });

  // Add a simple interceptor that will fetch all requests and add the jwt token to its authorization header.
  // NOTE: in case you are calling APIs which expect a token signed with a different secret, you might
  // want to check the delegation-token example

  jwtInterceptorProvider.tokenGetter = function(store, jwtHelper, auth) {
    var idToken = store.get('token');
    var refreshToken = store.get('refreshToken');
    if (!idToken || !refreshToken) {
      return null;
    }
    if (jwtHelper.isTokenExpired(idToken)) {
      return auth.refreshIdToken(refreshToken).then(function(idToken) {
        store.set('token', idToken);
        return idToken;
      });
    } else {
      return idToken;
    }
  }

  // Add a simple interceptor that will fetch all requests and add the jwt token to its authorization header.
  // NOTE: in case you are calling APIs which expect a token signed with a different secret, you might
  // want to check the delegation-token example
  $httpProvider.interceptors.push('jwtInterceptor');
}).run(function($rootScope, auth, store, jwtHelper, $location) {
  function checkForToken() {
    if (!auth.isAuthenticated) {
      var token = store.get('token');
      var refreshToken = store.get('refreshToken');
      if (token) {
        if (!jwtHelper.isTokenExpired(token)) {
          auth.authenticate(store.get('profile'), token);
        } else {
          if (refreshToken) {
            return auth.refreshIdToken(refreshToken).then(function(idToken) {
              store.set('token', idToken);
              auth.authenticate(store.get('profile'), idToken);
            });
          } else {
            $location.path('/login');
          }
        }
      }
    }
  }
  
  checkForToken();

  $rootScope.$on('$locationChangeStart', checkForToken);
});
