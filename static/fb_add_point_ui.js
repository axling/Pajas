$(document).ready(function() {
	$('#add_point').submit(function() {
		FB.ui({
			method: 'feed',
			    name: 'Pajas!',
			    caption: 'Added a pajas point',
			    description: 'Pajas points are for fools',
			    message: 'I have given a pajas point'
			    });		
	    });
    });