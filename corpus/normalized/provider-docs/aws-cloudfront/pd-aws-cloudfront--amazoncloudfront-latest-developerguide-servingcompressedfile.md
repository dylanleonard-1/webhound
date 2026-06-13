# AWS CloudFront caching behavior

Source: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html
Provider: AWS CloudFront | Authority: Tier A
Ingested: 2026-06-13 | Terms: AWS docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Serve compressed files - Amazon CloudFront
View a markdown version of this page              Serve compressed files - Amazon CloudFront                   Documentation  Amazon CloudFront  Developer Guide    Configure CloudFront to compress objects  How CloudFront compression works  Conditions for compression  File types that CloudFront compresses  ETag header conversion       Serve compressed files        When requested objects are compressed, downloads can be faster because the objects are
smaller—in some cases, less than a quarter the size of the original. Faster downloads
can result in faster rendering of webpages for your viewers, especially for JavaScript and
CSS files. In addition, the cost of CloudFront data transfer is based on the total amount of data
served. Serving compressed objects can be less expensive than serving them
uncompressed.   Topics     Configure CloudFront to compress objects      How CloudFront compression works      Conditions for compression      File types that CloudFront compresses      ETag header conversion
Configure CloudFront to compress objects
To configure CloudFront to compress objects, update the cache behavior that you want to
serve the compressed objects.
To configure CloudFront to compress objects (console)
Sign in to the   CloudFront
console    .
Choose your distribution and then choose the  Behavior  to
edit.
For the  Compress objects automatically  setting, choose
Yes .
Use a  cache policy  to specify
the caching settings, and enable both  Gzip  and
Brotli  compression formats.
Notes
You must use  cache
policies  to use Brotli compression. Brotli doesn't support legacy
cache settings.
To enable compression by using  CloudFormation  or the  CloudFront  API, set
the  Compress ,  EnableAcceptEncodingGzip ,
EnableAcceptEncodingBrotli  parameters to
true .
To understand how CloudFront compresses objects, see the following section.
How CloudFront compression works
A viewer requests an object. The viewer includes the
Accept-Encoding  HTTP header in the request, and the header
value includes  gzip ,  br , or both. This indicates that
the viewer supports compressed objects. When the viewer supports both Gzip and
Brotli, CloudFront uses Brotli.
Note    Chrome and Firefox web browsers support Brotli compression only when the
request is sent using HTTPS. They don't support Brotli with HTTP
requests.
At the edge location, CloudFront checks the cache for a compressed copy of the
requested object.
Depending whether the compressed object is in the cache or not, CloudFront does one
of the following:
If the compressed object is already in the cache, CloudFront sends the
object to the viewer and skips the remaining steps.
If the compressed object isn't in the cache, CloudFront forwards the request
to the origin.
Note    If an uncompressed copy of the object is already in the cache, CloudFront might
send it to the viewer without forwarding the request to the origin. For
example, this can happen when CloudFront  previously skipped compression . When this happens, CloudFront caches
the uncompressed object and continues to serve it until the object expires,
is evicted, or is invalidated.
If the origin returns a compressed object, (as indicated by the
Content-Encoding  header in the HTTP response), CloudFront sends the
compressed object to the viewer, adds it to the cache, and skips the remaining
steps. CloudFront doesn’t compress the object again.
If the origin returns an uncompressed object to CloudFront without the
Content-Encoding  header in the HTTP response, CloudFront then
determines whether the object can be compressed. For more information, see  Conditions for compression .
If the object can be compressed, CloudFront compresses it, sends it to the viewer,
and then adds it to the cache.
If there are subsequent viewer requests for the same object, CloudFront returns the
first cached version. For example, if a viewer requests a specific cached object
that uses Gzip compression, and the viewer  accepts  the Gzip
format, subsequent requests to the same object will always return the Gzip
version, even if the viewer accepts both Brotli and Gzip.
Some custom origins can also compress objects. Your origin might be able to compress
objects that CloudFront doesn’t compress. For more information, see  File types that CloudFront compresses .
Conditions for compression
The following list provides more information about scenarios in which CloudFront doesn't compress
objects.
Request uses HTTP 1.0
If a request to CloudFront uses HTTP 1.0, CloudFront removes the
Accept-Encoding  header and doesn't compress the object in
the response.
Accept-Encoding  request header
If the  Accept-Encoding  header is missing from the viewer
request, or if it doesn’t contain  gzip  or  br  as a
value, CloudFront doesn't compress the object in the response. If the
Accept-Encoding  header includes additional values such as
deflate , CloudFront removes them before forwarding the request to
the origin.
When CloudFront is  configured to compress objects , it includes the
Accept-Encoding  header in the cache key and in origin
requests automatically.
Content is already cached when you configure CloudFront to compress objects
CloudFront compresses objects when it gets them from the origin. When you
configure CloudFront to compress objects, CloudFront doesn’t compress objects that are
already cached in edge locations. In addition, when a cached object expires
in an edge location and CloudFront forwards another request for the object to your
origin, CloudFront doesn’t compress the object when your origin returns an HTTP
status code 304. This means that the edge location already has the latest
version of the object. If you want CloudFront to compress objects that are already
cached in edge locations, you need to invalidate those objects. For more
information, see  Invalidate files to remove content .
Origin is already configured to compress objects
If you configure CloudFront to compress objects and the o
