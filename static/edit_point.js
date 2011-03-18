$(document).ready(function() {
	$('.edit-point-img').click(function (){
		var tr = $(this).parent().parent().parent();
		var description = tr.children().first().children().first().html();
		var csrf = $(this).parent().children().first().children().first().val();
		var point = $(this).parent().children().first().children().first().next().val();
		
		var url = window.location.pathname;
		tr.html("<td colspan='4'><form method='post' id='edit-point' action=" +
			url + "><textarea rows='2' cols='30' name=" + 
			"'description'>" + description +"</textarea>" +
			"<input type='hidden' name=" + 
			"'_csrf_token' value='" + csrf + "'>" + 
			"<input type='hidden' name='edit_point_tag' value='" + 
			point +"'><input type='submit' " +
			"value='Edit Pajas Point' /></form></td>");
	    });
    });