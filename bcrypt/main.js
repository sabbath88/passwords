
// shim in the dojo objects expected by the ascii85 include
dojox = {encoding: { ascii85: {}}};

// Also shim in the PRNG required by the bCrypt constructor - fake it out since we don't need the PRNG.
Clipperz = { Crypto: { PRNG: { 
	defaultRandomGenerator: function(){}, 
	isReadyToGenerateRandomValues: function(){ throw "PRNG not defined"; }
} } };

requirejs.config({
    shim: {
		'bCrypt': {},
		'ascii85': {}
    }
});

require([ 'jquery-ui-1.8.22.custom.min', 'bCrypt', 'ascii85' ], function( ) {

	var bcrypt = new bCrypt(),
		string2Bin = function(str) {
			var result = [];
			for (var i = 0; i < str.length; i++) {
				result.push(str.charCodeAt(i));
			}
			return result;
		}, bin2String = function (array) {
			return String.fromCharCode.apply(String, array);
		};
	
	/**
	* 
	* hex_hash and gp2_generate_hash are only used for generating the identity icons, we'll leave those alone
	* b64_hash is used by gp2_generate_passwd and gp2_validate_length the max password length is undefined
	*
	*/

	// clear the background image on the same events that clear the password text
	$(document).ready(function() {
		var $output = $('#Output');
	
		$('input').on('keydown change', function (event) {
			var key=event.which;
			if(event.type=='change'||key==8||key==32||(key>45&&key<91)||(key>95&&key<112)||(key>185&&key<223)) {
				$output.progressbar( 'destroy' );
			} 
		});
		
		$('#MethodField').hide().after('<fieldset id="BcryptField"><label for="Cost">Cost</label><input id="Cost" type="text" placeholder="Cost"></fieldset>');

	});
	
	// removed rule that first character must be lower-case letter
	// added rule that password must contain at least one non-alphanumeric character (from ascii85)
	window.gp2_check_passwd = function (Passwd) {
		return (
			Passwd.search(/[0-9]/) >= 0 && 
			Passwd.search(/[A-Z]/) >= 0 && 
			Passwd.search(/[a-z]/) >= 0 && 
			Passwd.search(/[\x21-\x2F\x3A-\x40\x5B-\x60]/) >= 0 
			) ? true : false;
	};
	
	// overwrite the base64 hash with an ascii85 hash
	window.b64_hash = function( s ) {
		return dojox.encoding.ascii85.encode( string2Bin ( b64_sha512( s ) ) );
	};
	
	// reset the LenMax so that the next time gp2_validate_length is called it will use the new b64_hash to calculate it.
	delete LenMax;
	
	window.gp2_generate_passwd = function( password, len ) {
		// salt here is the password and domain concatenated
		var domain = ( $('#Domain').val() ) ? gp2_process_uri( $('#Domain').val(), false ) : 'localhost',
			iterations = '10',
			salt = '$2a$' + iterations + '$' + hex_hash( domain + $('#Salt').val() ).substr( 0, 21 ) + '.',
			$output = $('#Output'),
			i = 0;

		// height is 28px on my screen because of a 14px font (plus 2px top/bottom font-padding) plus 10px padding.
		// I reproduce this with a 26px height plus 2px of top/bottom border
		$output.html('').progressbar({
			value: 0
		});			
		
		bcrypt.hashpw( password, salt, function( result ) {
			var j = 0;
			
			// get only the password hash (not the salt) from the result, 
			// and then trim that down to the user-defined length
			result = b64_hash( result.substr(-31) ).substring( 0, len );

			// Tests to make sure that the password meets the qualifications
			// I'm not entirely convinced this is a good idea.  
			// On the one hand it decreases entropy.
			// On the other hand, password attacks will tend to search in 
			//   order of alpha only, then alpha+numeric then all three
			while( !gp2_check_passwd( result ) ) {
				result = b64_hash( result ).substring( 0, len );
				j++;
			}
			
			//the child div isn't part of the original html, it's appended by the progress bar plugin
			$output.progressbar( "value" , 100 ).children('div').html( result );
			
		}, function( ){
			$output.progressbar( "value" , i++ )
		} );		
		
	};
	
} );
