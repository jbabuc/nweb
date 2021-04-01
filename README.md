# nweb
<html>
  <body>
    <ul>
      <li>nweb.c, simple http server with directory listing</li>
        <ul>
          <li>url decode support to allow spaces and other chars in file names</li>
          <li>keep live support to allow multiple file transfer on same socket</li>
          <li>log to console client ip and time</li>
          <li>simplified error handling code</li>
          <li>logging improvements</li>
          <li>support for default favicon.ico</li>
          <li>support for range headers, for better streaming</li>
        </ul>
      <li>nwebs, statically compiled binary for alpine</li>
      <li>sslserver.c & sslclient.c, sample ssl socket code</li>
    </ul>
  </body>
</html>
