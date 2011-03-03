function fbLogin() {
    $('.fb_uid').each(function() {
	    var uid = this.id;
	    var string = "";
	    // We must save this so we can use it inside FB.api
	    var selected = $(this);
	    FB.api("/" + uid, function(response) {
		    string = "<img src='http://graph.facebook.com/" +
			uid + "/picture' /><a href='/user_page/" + uid
			+ "'>" + response.name +"</a>";
		    selected.html(string);
		});
	    
	});
    $('.fb_uid_name').each(function() {
	    var uid = this.id;
	    // We must save this so we can use it inside FB.api
	    var selected = $(this);
	    FB.api("/" + uid, function(response) {
		    selected.replaceWith(response.name);
		});
	});
}