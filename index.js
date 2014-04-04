//
// includes
//
var accessTokenCache = {} 
  , responseCache = {}
  , metadataCache = {};

var DEBUG_HEADERS = false;

//
// module defines
//

function createReverseProxy(configurationFile){

//
// read configuration file
//
  var fs = require("fs");
  var aConfigFile = configurationFile || "./proxy.conf";
console.log("");
  fs.exists(aConfigFile, function(exists) {
    if (!exists) {
console.log("Configuration file " + aConfigFile + " missing");
console.log("");
      process.exit(0);
    } else {
console.log("Using configuration file " + aConfigFile);
      var contents = fs.readFileSync(aConfigFile).toString().split("\n");
      var i;
      var userConfig = {};
      for(i in contents) {
        var line = contents[i];
        var data = line.split(":");
        if (data.length != 1) {
          if (line.substring(0,1) != "#") {
            var aValue = data[1].trim().toUpperCase();
            switch (aValue) {
              case "false":
                aValue = false;
                break;
              case "FALSE":
                aValue = false;
                break;
              case "true":
                aValue = true;
                break;
              case "TRUE":
                aValue = true;
                break;
              default:
                aValue = data[1].trim();
            }
            userConfig[data[0]] = aValue;
          }
        }
      }

      var getIPAddress = function() {
        var interfaces = require('os').networkInterfaces();
        for (var devName in interfaces) {
          var iface = interfaces[devName];
          for (var i = iface.length; i--;) {
            var alias = iface[i];
            if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal) {
                return alias.address;
            }
          }
        }

        return '0.0.0.0';
      }

      if (!userConfig["LISTENING_DOMAIN"]) {
        userConfig["LISTENING_DOMAIN"] = getIPAddress();
      }
      startReverseProxy(userConfig);
    }
  });
}; // createReverseProxy

function startReverseProxy(userConfig) {

  var btoa = require("btoa")
    , crypto = require("crypto")
    , http = require("http")
    , https = require("http")
    , randomstring = require("just.randomstring")
    , cnonce = randomstring(16);

//
// banner processing
//
  var bannerWidth = 78;
  function bannerTop() {
    var bannerText = ".";
    for (var i = bannerWidth; i--;) {
      bannerText += "-";
    }
    bannerText += ".";
console.log(bannerText);
  }
  function bannerSpacer() {
    var bannerText = "|";
    for (var i = bannerWidth; i--;) {
      bannerText += "-";
    }
    bannerText += "|";
console.log(bannerText);
  }
  function bannerLine(text) {
    if (!text) {
      text = "";
    }
    var bannerText = "| " + text;
    for (var i = (bannerWidth-text.length-1); i--;) {
      bannerText += " ";
    }
    bannerText += "|";
console.log(bannerText);
  }
  function bannerBottom() {
    var bannerText = "'";
    for (var i = bannerWidth; i--;) {
      bannerText += "-";
    }
    bannerText += "'";
console.log(bannerText);
  }
  
  http.createServer(function(request, response) {

    var startTime = new Date();

//
// items to keep around during the proxy
//
    var post_body;
    var uri;

//
// timers
//
    var timeout;
    var fn;
    function timeout_wrapper(req) {
      return function( ) { req.abort(); };
    };

//
// error processor
//
    function errorResponse(text) {
      var tempHeaders = {
        "host": userConfig["LISTENING_DOMAIN"] + ":" + userConfig["LISTENING_PORT"],
        "connection": "close"
      };
      if (request.headers["origin"]) {
        tempHeaders["access-control-allow-origin"] = request.headers["origin"];
      } else {
        tempHeaders["access-control-allow-origin"] = request.connection.remoteAddress;
      }
      response.writeHead(503, tempHeaders);
      response.write(text);
      response.end();
      bannerTop();
      bannerLine(text);
      bannerBottom();
    }

    function constructDigestResponse(realm, method, nonce, nc, qop) {
/*
      var md5 = function (str, encoding){
        var crypto = require("crypto");
        return crypto.createHash('md5').update(str, 'utf8').digest(encoding || 'hex');
      };
      var A1 = userConfig["ACCOUNT"] + ":" + realm + ":" + userConfig["PASSWORD"];
      var HA1 = md5(A1);
      var A2 = method + ":" + uri;
      var HA2 = md5(A2);
      var response_text = HA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HA2;
      var response = md5(response_text);
*/

      var HA1 = crypto.createHash("md5").update(userConfig["ACCOUNT"] + ":" + realm + ":" + userConfig["PASSWORD"], "utf8").digest("hex");
      var HA2 = crypto.createHash("md5").update(method + ":" + uri, "utf8").digest("hex");
      var response = crypto.createHash("md5").update(HA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HA2, "utf8").digest("hex");

//
// keep a copy to replay while incrementing nc
//
      responseCache[uri] = {
        "realm": realm,
        "qop": qop,
        "nonce": nonce,
        "nc": nc
      } 

      return 'Digest username="' + userConfig["ACCOUNT"] + '", realm="' + realm + '", nonce="' + nonce + '", uri="' + uri + '", response="' + response + '", qop=' + qop + ', nc=' + nc + ', cnonce="' + cnonce + '"';
    } // constructDigestRespnse 

    function doTransfer(authHeader) {
      var tempHeaders = {
        "host": userConfig["LISTENING_DOMAIN"] + ":" + userConfig["LISTENING_PORT"],
        "user-agent": userConfig["USER_AGENT"] + "/1.0", 
        "x-forwarded-for": request.connection.remoteAddress,
        "accept": request.headers["accept"]
      }
      if (request.headers["content-type"]) {
        tempHeaders["content-type"] = request.headers["content-type"];
      }
      if (request.headers["origin"]) {
        tempHeaders["x-forwarded-host"] = request.headers["origin"];
      }
      if (request.headers["accept-language"]) {
        tempHeaders["accept-language"] = request.headers["accept-language"];
      }
      if (userConfig["COMPRESSION"]) {
        if (request.headers["accept-encoding"]) {
          tempHeaders["accept-encoding"] = request.headers["accept-encoding"];
        }
//        headers["accept-encoding"] = "deflate";
//        headers["accept-encoding"] = "gzip";
      }
      if (authHeader) {
        tempHeaders["authorization"] = authHeader;
      } else {
        tempHeaders["authorization"] = "Basic " + btoa(userConfig["ACCOUNT"] + ":" + userConfig["PASSWORD"]);
      }
      if (post_body) {
        if (post_body.length > 0) {
          tempHeaders["content-length"] = post_body.length;
        }
      }
if (DEBUG_HEADERS) {
console.log("SENT_TO_SERVER");
console.dir(tempHeaders);
}
      var options = {
        host: userConfig["API_DOMAIN"],
        port: userConfig["API_PORT"],
        path: request.url,
        headers: tempHeaders, 
        method: request.method 
      };

      var clientRequest;
      if (userConfig["API_PROTOCOL"] == "https") {
       clientRequest = https.request(options, function(clientResponse) {
if (DEBUG_HEADERS) {
console.log("RECEIVED_FROM_SERVER");
console.dir(clientResponse.headers);
}
          processBody(clientResponse, authHeader);
        });
      } else {
        clientRequest = http.request(options, function(clientResponse) {
if (DEBUG_HEADERS) {
console.log("RECEIVED_FROM_SERVER");
console.dir(clientResponse.headers);
}
          processBody(clientResponse, authHeader);
        });
      }
      if (post_body) {
        if (post_body.length > 0) {
          clientRequest.write(post_body);
        }
      }
      clientRequest.end();
      clientRequest.on('error', function(e) { 
        errorResponse("MLS Connection Problem") 
      });
      fn = timeout_wrapper(clientRequest);
      timeout = setTimeout(fn,userConfig["LISTENING_TIMEOUT"]);

    } // doTransfer

    function processBody(clientResponse, forceBasic) {
      var authType = userConfig["AUTH_TYPE"];
      if (forceBasic) {
        authType = "Basic";
      }
 
      var msg = "";

      var useGzip = false; 
      var useInflate = false; 
      if (clientResponse.headers["content-encoding"]) {
        if (clientResponse.headers["content-encoding"].indexOf("gzip") > -1 ) useGzip = true;
        if (clientResponse.headers["content-encoding"].indexOf("deflate") > -1 ) useInflate = true;
      }

      function digestResponseFromHeader(cnonce) {
        if (clientResponse.headers["www-authenticate"]) {
          var authorization = clientResponse.headers["www-authenticate"];
//
// Determine if server is configured for Digest authorization
//
          if (authorization.split(" ")[0] !== "Digest") {
console.log("Server is not configured for Digest");
          } else {
            var parts = authorization.substring(authorization.indexOf(" ")).split(",");
//
// determine if the correct number of arguments is in the Digest header
//
            if (parts.length !== 3) {
console.log("Server responded to Digest with an unexpected number of arguments");
            } else {
              var realm;
              var nonce;
              var qop;
              for (var i = parts.length; i--;) {
                var pieces = parts[i].split("=");
                switch(pieces[0].trim()) {
                  case "realm":
                    realm = pieces[1].replace(/["']/g, "");
                    break;
                  case "nonce":
                    nonce = pieces[1].replace(/["']/g, "");
                    break;
                  case "qop":
                    qop = pieces[1].replace(/["']/g, "");
                    break;
                }
              }
              return constructDigestResponse(realm, request.method, nonce, 0, qop);
            }
          }
        }

        return false;

      } // digestResponseFromHeader

      function completeTransfer() {
        clearTimeout(timeout);
        switch (authType) {
          case "Basic":

            if (clientResponse.headers["www-authenticate"]) {
              errorResponse("Bad MLS Credentials");
            } else {

              var headers = {
                "access-control-allow-origin": (request.headers["origin"] || request.connection.remoteAddress),
                "access-control-max-age": userConfig["CACHE_LATENCY"],
                "cache-control": "max-age=" + userConfig["CACHE_LATENCY"],
                "connection": clientResponse.headers["connection"]
              };
              if (clientResponse.headers["content-type"]) {
                headers["content-type"] = clientResponse.headers["content-type"];
              }

              var writeResultWithLength = function(returnedResult, encoding) {
                if (encoding) {
                  headers["content-encoding"] = encoding;
                }
                if (returnedResult.length > 0) {
                  headers["content-length"] = returnedResult.length;
                }
                response.writeHead(clientResponse.statusCode, headers);
                response.write(returnedResult);
                response.end();
                var aURL = unescape(request.url);
if (DEBUG_HEADERS) {
console.log("RETURN_TO_BROWSER");
console.dir(headers);
console.log(request.method + " " + aURL + " received from " + request.connection.remoteAddress + " consuming " + ((new Date().getTime()) - startTime.getTime()) + " ms");
} else {
                if (aURL.indexOf("$metadata") !== -1) {
                  if (userConfig["CACHE_METADATA"]) {
//
// cache metadata requests and don't display the transfer
//
                    var anOrigin = headers["access-control-allow-origin"];
                    metadataCache[anOrigin]["headers"] = headers;
                    metadataCache[anOrigin]["response"] = returnedResult;
                  }
                } else {
//
// display the transfer
//
                  var methodName = "Unknown";
                  switch (request.method) {
                    case "DELETE":
                      methodName = "Delete";
                      break;
                    case "GET":
                      methodName = "Query";
                      break;
                    case "PATCH":
                      methodName = "Update";
                      break;
                    case "POST":
                      methodName = "Add";
                      break;
                  }
console.log((new Date()) + " " + methodName + " from " + request.connection.remoteAddress + " consuming " + ((new Date().getTime()) - startTime.getTime()) + " ms");
                }
}
              } // writeResultWithLength

              if (useGzip || useInflate) {
                headers["vary"] = "Accept-Encoding";
                var zlib = require('zlib');
                if (useGzip) {
                  zlib.gzip(msg, function(err, result) {
                    if (!err) {
                      writeResultWithLength(result, "gzip");
                    }
                  });
                } else {
                  zlib.deflate(msg, function(err, result) {
                    if (!err) {
                      writeResultWithLength(result, "deflate");
                    }
                  });
                }
              } else {
                writeResultWithLength(msg);
              }

            }
            break;
          case "Digest":
            var authHeader = digestResponseFromHeader(cnonce);
            if (authHeader) {
              doTransfer(authHeader);
            } else {
              errorResponse("MLS Credentialing is failing");
            }
            break;
        } // authType switch
      } // completeTransfer

      var clientMethod;
      if (useGzip || useInflate) {
        if (useGzip) {
          clientMethod = require('zlib').createGunzip();
        } else {
          clientMethod = require('zlib').createInflate();
        }
        clientResponse.pipe(clientMethod);
      } else {
        clientMethod = clientResponse;
      }
      clientMethod.on("data", function (chunk) {
        msg += chunk;
        clearTimeout(timeout);
        timeout = setTimeout(fn, userConfig["LISTENING_TIMEOUT"]);
      });
      clientMethod.on("end", function () {
        completeTransfer();
      });
      clientMethod.on("error", function () {
        clearTimeout(timeout);
        errorResponse("RESPONSE ERROR");
      });
    } // processBody

    switch (request.method) {
      case "OPTIONS":
        var headers = {
          "access-control-allow-origin": request.headers["origin"],
          "access-control-allow-credentials": "false",
          "access-control-max-age": userConfig["CACHE_LATENCY"],
          "cache-control": "max-age=" + userConfig["CACHE_LATENCY"],
          "access-control-allow-methods": request.headers["access-control-request-method"],
          "access-control-allow-headers": request.headers["access-control-request-headers"]
        };
        response.writeHead(200, headers);
        response.end();
        break;

      case "DELETE":
      case "GET":
        if (userConfig["CACHE_METADATA"]) {
          if (unescape(request.url).indexOf("$metadata") !== -1) {
            var anOrigin = request.headers["origin"] || request.connection.remoteAddress;
            if (metadataCache[anOrigin]) {
              if (((new Date().getTime()) - metadataCache[anOrigin]["age"]) < (userConfig["CACHE_LATENCY"] * 1000)) { 
                response.writeHead(200, metadataCache[anOrigin]["headers"]);
                response.write(metadataCache[anOrigin]["response"]);
                response.end();
                break;
              }
            }
            metadataCache[anOrigin] = {
              "age": (new Date().getTime())
            }
          }
        }
      case "PATCH":
      case "POST":

        var request_body = "";
        request.on("data", function (chunk) {
          request_body += chunk;
          if (request_body.length > 1e6) { 
// FLOOD ATTACK OR FAULTY CLIENT, NUKE REQUEST
            request.connection.destroy();
          }
        });
        request.on('end', function () {
          post_body = request_body;

          delete request.headers["host"];

if (DEBUG_HEADERS) {
console.log("RECEIVED_FROM_BROWSER");
console.dir(request.headers);
}

          switch (userConfig["AUTH_TYPE"]) {

            case "Basic":
                doTransfer();
              break;

            case "Digest":

              function uriFromRequest() {
                var pos = request.url.indexOf("/$");
                if (pos == -1) {
                  pos = request.url.indexOf("?$");
                }
                if (pos == -1) {
                  pos = request.url.indexOf("('");
                  if (pos == -1) {
                    return request.url;
                  }
                }
                return request.url.substring(0,pos);
              }
              uri = uriFromRequest();
              if (responseCache[uri]) {
                doTransfer(
                  constructDigestResponse(
                    responseCache[uri]["realm"], 
                    request.method, 
                    responseCache[uri]["nonce"], 
                    responseCache[uri]["nc"] + 1, 
                    responseCache[uri]["qop"]
                  )
                );
              } else {
                doTransfer();
              }
              break;
/*
          case "OAuth2":
            var uri = uriFromRequest(request);
//console.log("--------------");
//console.log(request.url);
//console.log(uri);
//console.log("--------------");

            var cachedAccessToken = accessTokenCache[uri];
            if (cachedAccessToken != null) {
console.dir(cachedAccessToken);
//              var tokenHeader = tokenResponseFromCache(tokenCache, uri);
//console.dir("--------------");
//console.log(tokenHeader);
//console.dir("--------------");
//              if (tokenHeader !== false) {
//                completeToken(tokenHeader, request, response);
//              }
            } else {

    function constructProxyHeaders() {
      var headers = {
        "host": userConfig["LISTENING_DOMAIN"] + ":" + userConfig["LISTENING_PORT"],
        "user-agent": userConfig["USER_AGENT"] + "/1.0", 
        "x-forwarded-for": request.connection.remoteAddress,
        "accept": request.headers["accept"]
      }
      if (request.headers["content-type"]) {
        headers["content-type"] = request.headers["content-type"];
      }
      if (request.headers["origin"]) {
        headers["x-forwarded-host"] = request.headers["origin"];
      }
      if (request.headers["accept-language"]) {
        headers["accept-language"] = request.headers["accept-language"];
      }
      if (userConfig["COMPRESSION"]) {
        if (request.headers["accept-encoding"]) {
          headers["accept-encoding"] = request.headers["accept-encoding"];
        }
//            headers["accept-encoding"] = "deflate";
//            headers["accept-encoding"] = "gzip";
      }
      return headers;
    }

              var tempHeaders = constructProxyHeaders(request);
              var options = {
                host: userConfig["AUTH_DOMAIN"],
                port: userConfig["AUTH_PORT"],
                path: request.url,
                headers: tempHeaders, 
                method: request.method 
              };
              var msg = "";
              var clientHeaders;
              if (userConfig["API_PROTOCOL"] == "https") {
                var clientRequest = https.request(options, function(clientResponse) {
                  clientHeaders = clientResponse.headers;
                  clientResponse.on("data", function (chunk) {
                    msg += chunk;
                  });
                  clientResponse.on("end", function () {
console.dir(clientHeaders);
                  });
                });
              } else {
                var clientRequest = http.request(options, function(clientResponse) {
                  clientHeaders = clientResponse.headers;
                  clientResponse.on("data", function (chunk) {
                    msg += chunk;
                  });
                  clientResponse.on("end", function () {
console.dir(clientHeaders);
                  });
                });
              }
              clientRequest.end();
            }
            break;
*/
          } // AUTH_TYPE switch
        }); // request on end
        break; // DELETE, GET, PATCH, PUT 
      default:
        errorResponse("Unhandled Reqest Type: " + request.method);
    } // method.type switch
  }).listen(userConfig["LISTENING_PORT"], userConfig["LISTENING_DOMAIN"]); // createServer

  var projectName = "RESO API Reverse Proxy";
  var serverName = userConfig["SERVER_NAME"] || projectName;

  bannerTop();
  var packageName = projectName + " Version " + require('./package').version;
  if (serverName == projectName ) {
    bannerLine(packageName);
  } else {
    bannerLine(serverName);
    bannerLine("(" + packageName + ")");
  }
  bannerSpacer();

  bannerLine("- Using " + userConfig["AUTH_TYPE"] + " Authentication Scheme");
  switch (userConfig["AUTH_TYPE"]) {
    case "Basic":
      break;
    case "Digest":
      bannerLine("  > Digest cnonce: " + cnonce);
      break;
    case "OAuth2":
      break;
    default:
      bannerLine("- Unrecognized Authentication Scheme '" + userConfig["AUTH_TYPE"] + "' specified in the configuration file");
      process.exit(0);
  }

  if (userConfig["COMPRESSION"] == null) {
    userConfig["COMPRESSION"] = true;
    bannerLine("- Configuration value for COMPRESSION not found");
    bannerLine("  > Using default of " + userConfig["COMPRESSION"]);
  }
  if (userConfig["COMPRESSION"]) {
    bannerLine("- Output compression will ALWAYS be attempted");
  } else {
    bannerLine("- Output will NEVER be compressed");
  }
  if (!userConfig["LISTENING_TIMEOUT"] == null) {
    userConfig["LISTENING_TIMEOUT"] = 10000;
    bannerLine("- Configuration value for LISTENING_TIMEOUT not found");
    bannerLine("  > Using default of 1" + userConfig["LISTENING_TIMEOUT"] + " ms");
  }
  if (userConfig["USER_AGENT"] == null) {
    userConfig["USER_AGENT"] = serverName;
    bannerLine("- Configuration value for USER_AGENT not found");
    bannerLine("  > Using default of \"" + userConfig["USER_AGENT"] + "\"");
  }
  if (userConfig["CACHE_LATENCY"]) {
    bannerLine("- Recipient information is only current for " + userConfig["CACHE_LATENCY"] + " seconds");
    if (userConfig["CACHE_METADATA"]) {
      bannerLine("  > Metadata requests will be cached");
    } else{
      bannerLine("  > Metadata requests are processed even if information is still current");
    }
  }

  bannerLine();
  bannerLine("Listening for requests on http://" + userConfig["LISTENING_DOMAIN"] + ":" + userConfig["LISTENING_PORT"]);
  bannerLine("Passing requests to " + userConfig["API_PROTOCOL"] + "://" + userConfig["API_DOMAIN"] + ":" + userConfig["API_PORT"]);
  bannerBottom();

}; // startReverseProxy

module.exports = createReverseProxy;

