
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
		strToArray = function(str) {
			var result = [];
			for (var i = 0; i < str.length; i++) {
				result.push(str.charCodeAt(i));
			}
			return result;
		}, 
		b85_hash = function ( s ) {
			return dojox.encoding.ascii85.encode( strToArray ( b64_sha512( s ) ) );
		},
		validate_cost = function( cost ){
			// floor should normalize to either a number or NaN, then mix/max it to between 4 an 31
			// then left pad it with zeros - can assume that it will only have a length of 1 or 2
			var default_cost = 10,
				raw_cost = Math.floor( cost ),
				valid_cost = isNaN( raw_cost ) ? default_cost : Math.min( 31, Math.max( 4, raw_cost ) ),
				padded_cost = "00".slice( 0, 2 - (valid_cost + "").length ) + valid_cost;
				
			return padded_cost;
		
		};
		
	
	/**
	* 
	* hex_hash and gp2_generate_hash are only used for generating the identity icons, we'll leave those alone
	* b64_hash is used by gp2_generate_passwd and gp2_validate_length the max password length is undefined
	*
	*/

	$(document).ready(function() {
		var $output = $('#Output');
		
		// clear the background image on the same events that clear the password text
		$('input').on('keydown change', function (event) {
			var key=event.which;
			if(event.type=='change'||key==8||key==32||(key>45&&key<91)||(key>95&&key<112)||(key>185&&key<223)) {
				$output.progressbar( 'destroy' );
			} 
		});
		
		// add a new set of advanced settings for bcrypt
		$('#MethodField').hide().after('<fieldset id="BcryptField"><label for="Cost">Cost</label><input id="Cost" type="text" placeholder="Cost"></fieldset>');
		
		$('#Cost').on('change', function ( e ){
			this.value = parseInt( validate_cost( this.value ), 10 );
		});
		
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
	
	// the only reason we need to overwrite the b64_hash is because gp2_validate_length uses it. therefore:
	// todo: instead of overwriting b64_hash with b85_hash:
	//	add new "Method" to advanced setting for bcrypt+base85,
	//  duckpunch gp2_validate_length to look for a b85_hash function, and use it if it exists
	window.b64_hash = function( s ) {
		return b85_hash( s );
	};
	
	// reset the LenMax so that the next time gp2_validate_length is called it will use the new b64_hash to calculate it.
	delete LenMax;
	
	window.gp2_generate_passwd = function( password, len ) {
		// salt here is the password and domain concatenated
		var application_salt = 'ed6abeb33d6191a6acdc7f55ea93e0e2',
			raw_domain = $('#Domain').val(),
			domain = ( raw_domain ) ? gp2_process_uri( raw_domain, false ) : 'localhost',
			padded_cost = validate_cost( $('#Cost').val() ),
			
			// salt is made up of domain ("per-user" salt) + user supplied salt (optional) + application salt
			salt = '$2a$' + padded_cost + '$' + hex_sha512( domain + $('#Salt').val() + application_salt ).substr( 0, 21 ) + '.',
			
			$output = $('#Output'),
			i = 0;
		
		// height is 28px on my screen because of a 14px font (plus 2px top/bottom font-padding) plus 10px padding.
		// I reproduce this with a 26px height plus 2px of top/bottom border
		$output.html('').progressbar({
			value: 0
		});			
		
		bcrypt.hashpw( password, salt, function( result ) {
			var j = 0,
				key = result.slice( (result.length - 31) , result.length );

			// get only the password hash (not the salt) from the result, 
			// and then trim that down to the user-defined length
			result = b85_hash( key ).substring( 0, len );

			// Tests to make sure that the password meets the qualifications
			// I'm not entirely convinced this is a good idea.  
			// On the one hand it decreases entropy.
			// On the other hand, password attacks will tend to search in 
			//   order of alpha only, then alpha+numeric then all three
			while( !gp2_check_passwd( result ) ) {
				result = b85_hash( result ).substring( 0, len );
				j++;
			}
			
			//add the result within the div appended by the progress bar plugin
			$output.progressbar( "value" , 100 ).children('.ui-progressbar-value').html( result );
			
		}, function( ){
			$output.progressbar( "value" , i++ )
		} );		
		
	};
	
} );
