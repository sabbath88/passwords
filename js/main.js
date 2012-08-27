dojox = { encoding: { ascii85: {} } };

// Also shim in the PRNG required by the bCrypt constructor - fake it out since we don't need the PRNG.
Clipperz = { Crypto: { PRNG: { 
	defaultRandomGenerator: function(){}, 
	isReadyToGenerateRandomValues: function(){ throw 'PRNG not defined'; }
} } };

requirejs.config( {
    shim: {
		'bCrypt': {},
		'ascii85': {}
    }
} );

$( document ).ready( function() {

	require( [ 'jquery-ui', 'bCrypt', 'ascii85' ], function() {

		var bcrypt = new bCrypt(),
            $output = $('#Output'),
			$salt = $('#inputUser'),
			$secret = $('#inputPassword'),
			$passwd = $('#inputPhrase');
			
		function b85_hash ( s ) {
			return dojox.encoding.ascii85.encode( $.map( b64_sha512( s ).split(''), function( val ) { return val.charCodeAt( 0 ); } ) );
		}
		
		function validate_b85_password ( password ) {
			return (
				password.search(/[0-9]/) >= 0 && 
				password.search(/[A-Z]/) >= 0 && 
				password.search(/[a-z]/) >= 0 && 
				password.search(/[\x21-\x2F\x3A-\x40\x5B-\x60]/) >= 0 
				) ? true : false;
		}

               $('input').on('keydown change', function (event) {
                      var key=event.which;
                       if( event.type == 'change' || key == 8 || key == 32 || ( key > 45 && key < 91 ) || ( key > 95 && key < 112 ) || ( key > 185 && key < 223 ) ) {
                               $output.progressbar( 'destroy' );
                       }
               });
		
		$salt.on( 'change', function( e ) {
		  $passwd.trigger( 'change' );
		}).trigger( 'change' );
		
		window.gp2_generate_passwd = function( password, len ) {
                        var User=$salt.val().replace(/\s/g, '').toLowerCase();
		
			var salt = '$2a$10$' + hex_sha512( $('#inputDomain').val() + User + 'ed6abeb33d6191a6acdc7f55ea93e0e2' ).substr( 0, 21 ) + '.';
                        var i = 0;

                        $output.html('').progressbar({
                                value: 0
                        });

			
			bcrypt.hashpw( password, salt, function( result ) {
				var hashed = b85_hash( result.slice( ( result.length - 31 ) , result.length ) ).substring( 0, len );

				while( !validate_b85_password( hashed ) ) {
					hashed = b85_hash( hashed ).substring( 0, len );
				}
                               $output.progressbar( 'value' , 100 );
                               $output.progressbar( 'destroy');
                               $secret.text(hashed).show();

                        }, function( ){
                               $output.progressbar( 'value' , i++ );
			} );

			return undefined;
		};		
	} );
} );