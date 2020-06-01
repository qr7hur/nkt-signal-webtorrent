$.plugin({
    
    name: 'NewMsgTitle',
	init: function() {
		$.chat.focusBool = true;
		$.chat.focusCount = 0;
        $(window).focus(this.focus).blur(this.blur);
    },
	focus: function(){
		$(window).blur(this.blur);
		$.chat.focusBool = true;
		$.chat.focusCount = 0;
		document.title="Home";
	},
	blur: function(){
		$(window).focus(this.focus);
		$.chat.focusBool = false;
	},
    onWrite: function(msg, nick) {
		if(!$.chat.focusBool){
			$.chat.focusCount++;
			document.title=$.chat.focusCount+" Home";
		}
		return msg;
    }
});
