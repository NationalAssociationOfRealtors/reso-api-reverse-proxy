
reso-api-reverse-proxy
=======

The RESO API Reverse Proxy connects a website with a RESO API Server.  It overcomes Cross-Origin Resource Sharing (CORS) restrictions that are now being enforced by commercial web browsers.  CORS restrictions limit the use of API-based packages that are not served from the same website that the page is served from.

Most RESO API Servers have security functions that require account and password credentials for each subscriber.  This RESO API Reverse Proxy keeps subscriber credentials from being exposed to consumers. 

### Operation 

The RESO API Reverse Proxy can be run from a script with the following:

```javascript
 var resoReverseProxy=require("reso-api-reverse-proxy");
 resoReverseProxy();
```

The resoReverseProxy() function takes an optional argument to specify the configuration file.  The default for this argument is "./proxy.conf".  An
example of overriding the default name is:

```javascript
var resoReverseProxy=require("reso-api-reverse-proxy");
resoReverseProxy("./mySpecial.configuration");
```

### Configuration 

A text configuration file should be located in the root directory of your project.  The default name of the file is "proxy.conf", but this name can be overriden when calling the resoReverseProxy() method.  

A sample of a configuration file called "proxy.conf" can be found in the samples directory of this distribution.  

Some of the configuration values used in the file need to be obtained from the operator of the RESO API Server that you will be using.  The following parameters are found in the configuration file:

+ Listener Service (consumer facing parameters)

 CACHE\_LATENCY: The number for seconds that the browser will retain query results.  If you have a high volume site, you can set this to something like 3600 to to only hit the RESO API Server hourly.  Setting this to a low number, such as 1, would provide near real time access to listing data.  

 CACHE\_METADATA: A boolean value that controls the caching of metadata requests for the time period specified in the CACHE\_LATENCY parameter.  Some OData clients send Metadata requests eventhough the previous Metadata request specified that the request was not needed.  This reduced the burden on the RESO API Server for all requests, ensuring that the policy set by the CACHE\_LATENCY parameter is universally applied.  This value was made configurable because it is possible you would like Metadata requests to act as a "heatbeat" to the RESO API Server.  

 COMPRESSION: A boolean value that controls whether information is compressed to the consumer.  Compressed is much smaller than normal data.  If the parameter is set to "true", them data will be compressed even the API Server does not support compression.  If the browser does not support compression, no compression will be attempted even if the COMPRESSION parameter is set to "true".
 
 LISTENING\_DOMAIN: The dns name of the the computer that will be running the RESO API Reverse Proxy. If not supplied, the IP Adress of the computer will be used.  

 LISTENING\_PORT: The port that the RESO API Reverse Proxy will be listening on.

 SERVER\_NAME: The name to display in the console at startup.  Useful for private labelling.

+ API Service (data supplier parameters)

 API\_DOMAIN: The dns name of the the computer that will be running the RESO API Server.

 API\_PORT: The port that the RESO API Server will be listening on.

 API\_PROTOCOL: The protocol that the RESO API Server is using.  Valid values are "http" or "https".

 API\_TYPE: The authentication type protocol that the RESO API Server is using.  Valid values are "Basic" or "Digest".

 LISTENING\_TIMEOUT: How long to wait for RESO API Server responses before returning an error.

 USER\_AGENT: The name of the account as it is passed in HTTP headers to the API server.  If this parameter is not included, the SERVER\_NAME parameter value will be used.

+ Authentication

 AUTH\_TYPE: The type of authentication supported by the RESP API Server.  Valid values are "Basic" and "Digest".  

+ Credentials 

 ACCOUNT: The name of the subscriber account to use with the RESO API Server.  

 PASSWORD: The secret value to be used the subscriber account when accessing the RESO API Server.  

### License

>The MIT License (MIT)
>
>Copyright (c) 2014 National Association of REALTORS 
>
>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

