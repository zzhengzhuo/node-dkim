var DKIM = require( './dkim' )

const isDKIM = v => /^(DKIM-Signature|X-Google-DKIM-Signature)/.test(v);

/**
 * Fix a email body to pass dkim body hash check
 * @memberOf DKIM
 * @param {Buffer} message
 * @throws {Error} If input is not a buffer
 * 
 * @returns {Buffer} fixed email body
 */
function fixBody( message ) {

  if( !Buffer.isBuffer( message ) ) {
    throw new Error( 'Message must be a Buffer' )
  }

  var boundary = message.indexOf( '\r\n\r\n' )
  if( boundary === -1 ) {
    throw new Error( 'No header boundary found' )
  }

  var header = message.toString( 'utf8', 0, boundary )
  var body = message.slice( boundary + 4 )

  var results = []
  var signatures = []

  header.split(/\r\n(?=[^\x20\x09]|$)/g).forEach(function(h, i, headers) {
    // ISSUE: executing line below, may result in including a different 'DKIM-Signature' header
    // signatures.push( headers.slice( i ) )
    // FIX: after slicing, remove any included 'DKIM-Signature' header that differ from "oneHeader"
    if (isDKIM(h)) {
      // remove DKIM headers
      const sigHeaders = headers.filter(v => !isDKIM(v));
      // add one DKIM header
      sigHeaders.unshift(h);

      signatures.push(sigHeaders);
    }
  });

  var headers = signatures.pop()
  if( headers == null ) {
    return callback( null, results )
  }

  if( !/^(DKIM-Signature|X-Google-DKIM-Signature)/i.test( headers[0] ) ) {
    throw new Error( 'Missing DKIM-Signature' )
  }
  const signature =  DKIM.Signature.parse( headers[0].slice( headers[0].indexOf(':') + 1 ) )
  body = signature.length != null ?  body.slice( 0, signature.length ) : body

  // process body and header
  var message = DKIM.processBody( body, signature.canonical.split( '/' ).pop() )
  const boundaryHeader = headers.find(x=>x.includes('boundary="'));
  if(boundaryHeader){
  // console.log('boundaryHeader', boundaryHeader);
  const found = boundaryHeader.match(/boundary="?([.=0-9A-Za-z_-]+)"?/);
  // console.log('headers', found);
  const boundary = found[1];

  message = message.replace(new RegExp(`^--${boundary}\n`, 'g'), `--${boundary}\r\n`)
  // console.log('message.length1', message.length);
  message = message.replace(new RegExp(`\n--${boundary}\n`, 'g'), `\r\n--${boundary}\r\n`)
  // console.log('message.length2', message.length);
  message = message.replace(new RegExp(`\n--${boundary}--\n`, 'g'), `\r\n--${boundary}--\r\n`)

  }
  if(!message.endsWith('\r\n')){
    // console.log("append newline");
    // console.dir(message.slice(-2))
    message = message + '\r\n';
  }

  // return fixed email buffer
  const fixedMail = header + "\r\n\r\n" + message;
  return Buffer.from(fixedMail, 'utf8');
}

module.exports = fixBody
