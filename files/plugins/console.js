var ConsoleTheme = function () {
    
    var _self = this ;
    
    var _initMargin;
    var _interval;
    
    
    _self.init = function () {
        // to be able to disable the plugin
        $.pluginApi.loadPlugin('IRCcmd');
        $.irc.reversed = false;
        
        $('.plugins').hide();
        $('#list').hide();
        $('#chat').hide();
        
        
        $('<div id="console-chat"></div>')
            .append('<pre></pre>')
            .insertAfter('#chat')
        ;
        
        $('#typing')
            .css('margin', '0')
            .appendTo('#console-chat')
        ;
        
        
        moveToConsole();
    } ;
    
    _self.stop = function() {
        $.irc.reversed = true;
        $('.plugins').show();
        $('#list').show();
        $('#chat').show();
        
        $('#typing')
            .css('margin', '20px auto 0')
            .appendTo('#toggle')
        ;
        
        moveToChat();
        $('#console-chat').remove();

        $(document).scrollTop(0);
    }
    
    
    var moveToConsole = function(nick) {
        
        var last = $('#console-chat > pre:last()');
        
        $('#chat > *').each(function() {
            var tag = $(this);
            last.after(tag);
			if(($.chat.docScroll + $.chat.winHeight) == $.chat.docHeight || !nick || nick==$.chat.myNick()) $(document).scrollTop($(document).height() - $(window).height());
        });
    };
    
    var moveToChat = function() {
        
        $('#console-chat > *').each(function() {
            var tag = $(this);
            $('#chat').prepend(tag);
        });
    };

	_self.moveToConsole = moveToConsole;
};

var consoleTheme = new ConsoleTheme();
    
$.plugin({
    name: 'console',
    init: consoleTheme.init,
    stop: consoleTheme.stop,
	onWrite: function(msg, nick) {
		$.chat.docScroll = $(document).scrollTop();
		$.chat.winHeight = $(window).height();
		$.chat.docHeight = $(document).height();
		setTimeout(function(){
			consoleTheme.moveToConsole(nick);
		}, 200);
		return msg;
	}
});
