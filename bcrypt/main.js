
// shim in the dojo objects expected by the ascii85 include
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

require( [ 'jquery-ui', 'bCrypt', 'ascii85' ], function() {

	var bcrypt = new bCrypt(),
		Source, Origin;
		
	function b85_hash ( s ) {
		// What we're doing is hashing the incoming string, 
		// then splitting it into an array, 
		// then applying charCodeAt to each element of the array, 
		// and then passing that result back to ascii85.encode
		return dojox.encoding.ascii85.encode( $.map( b64_sha512( s ).split(''), function( val ) { return val.charCodeAt( 0 ); } ) );
	}
	
	// removed rule that first character must be lower-case letter
	// added rule that password must contain at least one non-alphanumeric character (from ascii85)
	function validate_b85_password ( password ) {
		return (
			password.search(/[0-9]/) >= 0 && 
			password.search(/[A-Z]/) >= 0 && 
			password.search(/[a-z]/) >= 0 && 
			password.search(/[\x21-\x2F\x3A-\x40\x5B-\x60]/) >= 0 
			) ? true : false;
	}
	
	function validate_cost ( cost ) {
		// floor should normalize to either a number or NaN, then min/max it to between 4 an 31
		// then left pad it with zeros - can assume that it will only have a length of 1 or 2
		var default_cost = 10;
		return ( '0' + Math.min( 31, Math.max( 4, Math.floor( cost ) || default_cost ) ) ).slice( -2 );
	}	
		
	$(document).ready(function() {
		var $output = $('#Output'),
			$salt = $('#Salt'),
			$passwd = $('#Passwd'),
			$canvas = $('#Canvas'), 
			$cost, $saltcanvas; // don't exist yet
		
		// Clear the background image on the same events that clear the password text
		$('input').on('keydown change', function (event) {
			var key=event.which;
			if(event.type=='change'||key==8||key==32||(key>45&&key<91)||(key>95&&key<112)||(key>185&&key<223)) {
				$output.progressbar( 'destroy' );
			} 
		});
		
		// move canvas to inside PasswdField fieldset, so that it can be positioned absolutely inside password box
		$canvas.appendTo('#PasswdField');
		
		// Instantiate a canvas for the salt identicon ( for validating the bookmarklet )
		$saltcanvas = $('<canvas id="SaltCanvas" width="16" height="16"></canvas>').prependTo( 'h1' );
		
		// Then update both the salt and password icons and the jstorage value
		// whenever it's changed and also when the page is loaded
		$salt.on('change', function( e ) {
			update_identicon( this.value, $saltcanvas );
			$passwd.trigger( 'change' );
			$.jStorage.set('Salt',this.value);
		} ).trigger('change');
		
		// Also update the password identicon when it's changed, rather than waiting for generate
		$passwd.on( 'change', function( e ) {
			update_identicon( ( this.value ) ? this.value + $salt.val() : '' , $canvas );
		} ).trigger('change');
		
		function update_identicon( value, $target ) {
			if( value !== '') {
				$target.identicon5( { hash: gp2_generate_hash( value ), size: 16 } );
			} else {
				$target[0].getContext('2d').clearRect(0, 0, 16, 16);
			}		
		}
		
		// Because we're using a salt identicon, we don't also need the word "Salt"
		$('#SaltHUD').html('');
		
		// Add a new set of advanced settings for bcrypt, including the Cost field
		$( '#MethodField' ).after( '<fieldset id="BcryptField"><label for="Cost">Cost</label><input id="Cost" type="text" placeholder="Cost"></fieldset>' );
		
		// Grab the Cost from localstorage, and also validate the Cost on change
		$cost = $('#Cost')
			.val( parseInt( validate_cost( $.jStorage.get( 'Cost', 10 ) ), 10 ) )
			.on( 'change', function ( e ){
				this.value = parseInt( validate_cost( this.value ), 10 );
				$.jStorage.set( 'Cost', this.value );
			});
			
		// Listen for the bookmarklet (evoked from the domain of the target site)
		// so that I also have access to Source, Origin - they're in a closure on index.html
		$( window ).on( 'message', function( event ) {
			Source = event.originalEvent.source;
			Origin = event.originalEvent.origin;
		});			
		
		// Validate against b85 hash rather than b64 hash - should result in length of 108
		window.gp2_validate_length = function ( n ) {
			var default_length = parseInt( $('#Len').val(), 10 ) || 10;
			return parseInt( n, 10 ) ? Math.max( 4, Math.min( parseInt( n, 10 ), b85_hash( 'test' ).length ) ) : default_length;
		};
		
		// Overwrite both of the global window functions in the document.ready 
		// ensuring that the sgp.core.js ones have already been defined.
		window.gp2_generate_passwd = function( password, len ) {
		
			// prepend + cost + delimiter + salt
			var salt = '$2a$' + validate_cost( $cost.val() ) + '$' 
					// salt is made up of first 21 character of sha512 hash of (domain + user supplied salt + application salt)
					+ hex_sha512( gp2_process_uri( $('#Domain').val() || 'localhost' ) + $salt.val() + 'ed6abeb33d6191a6acdc7f55ea93e0e2' ).substr( 0, 21 ) + '.'
				,
				i = 0;
			
			$output.html('').progressbar({
				value: 0
			});			
			
			bcrypt.hashpw( password, salt, function( result ) {
				// bcrypt returns the original salt and cost, but we calc those, so we don't need to store them.  
				// So we just throw them out, and then trim that down to the user-defined length
				var hashed = b85_hash( result.slice( ( result.length - 31 ) , result.length ) ).substring( 0, len );

				// Tests to make sure that the password meets the qualifications
				while( !validate_b85_password( hashed ) ) {
					hashed = b85_hash( hashed ).substring( 0, len );
				}
				
				// add the hashed result within the div appended by the progress bar plugin
				$output.progressbar( 'value' , 100 ).children( '.ui-progressbar-value' ).text( hashed );
				
				if( Source && Origin ) {
					Source.postMessage( hashed, Origin );
				}			
				
			}, function( ){
				$output.progressbar( 'value' , i++ );
			} );

			// Explicitly return undefined because things break if we return anything else.
			// Could just not do a return, but this serves as a reminder.
			return undefined;
			
		};		
		
	} );
	
} );