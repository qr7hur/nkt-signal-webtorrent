var IRCcmd = function () {
    
    var _self = this;
    var _awayList = new Array();
    var _cmdList = {};
    var _who = [];
	var _history = [], _historyPtr = 0;
    
    _self.reversed = true;
	
	$('textarea').on('keydown', function (e) {
		if(e.keyCode == 38) // UP
			if(_historyPtr > -1 && _history.length > _historyPtr)
				$('textarea').val(_history[_history.length-(++_historyPtr)]);
		if(e.keyCode == 40) // DOWN
			if(_historyPtr > 0 && _history.length > _historyPtr - 1)
				$('textarea').val(_history[_history.length-(--_historyPtr)]);

	});
	
	$('body').on( 'change keyup paste cut', 'textarea', function (){
		if($(this).val().indexOf('\n') == 0) $(this).val($(this).val().substring(1));
		$(this).height(0).height(this.scrollHeight);
	}).find( 'textarea' ).change();
    
    var parseCmd = function(msg) {
		_history.push(msg);
		_historyPtr = 0;
        if (msg.charAt(0) != '/') {
            return msg;
        }
        var origMsg = msg;
        msg = msg.substring(1);
        var cmd, params;
        
        if (msg.indexOf(' ') >= 0) {
            cmd = msg.substring(0, msg.indexOf(' '));
            params = msg.substring(msg.indexOf(' ')+1);
        } else {
            cmd = msg ;
            params = '';
        }
        if (_cmdList[cmd]) {
            $.chat.write( $.chat.escape(origMsg), $.chat.myNick(), true);
            return _cmdList[cmd].func(cmd, params, null) ;
        } else {
            $.chat.write( '/' + cmd + ' : command not found', '');
            return '';
        }
    }
    
    var parseRecivedCmd = function(msg, nick) {
        if (msg.charAt(0) != '/') {
            checkNotAway(nick);
            return msg;
        }
        var origMsg = msg;
        msg = msg.substring(1);
        var cmd, params;
        
        if (msg.indexOf(' ') >= 0) {
            cmd = msg.substring(0, msg.indexOf(' '));
            params = msg.substring(msg.indexOf(' ')+1);
        } else {
            cmd = msg ;
            params = '';
        }
        
        if (_cmdList[cmd]) {
            return _cmdList[cmd].func(cmd, params, nick) ;
        } else {
            return origMsg;
        }
    }
    
    
    var onUsersRefresh = function (tag) {
        for (var i in _awayList) {
            if (! $.chat.isMuted(_awayList[i]) ) {
                $('#list a:contains('+_awayList[i]+')')
                    .css('font-style', 'italic')
                    .css('color', '#dddddd')
                ;
            }
        }
    }
    
    /**
     * Add a command to the chat
     * @param object cmdInfos :
     * cmdInfos = { func: callback, description: 'string', proto: 'string'}
     * @param string name Command name
     */
    _self.addCmd = function (cmdInfos, name) {
        _cmdList[name] = cmdInfos;
    };
    
    
    
    /**
     * Action of command /away
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var away = function (cmd, params, source) {
        if (source) {
            $.chat.write( source + ' est maintenant absent (' + params + ')', '');
            _awayList.push(source);
            return '';
        } else {
            return '/' + cmd + ' ' + params;
        }
    };
    
    /**
     * Check if an user is nto away any more
     * @param string nick
     */
    var checkNotAway = function (nick) {
        if (_awayList) {
            var index = _awayList.indexOf(nick);
            if (index >= 0) {
                _awayList.splice(index, 1);
            }
        }
    }
    
    /**
     * Action of commands /exit and /quit
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var exit = function (cmd, params, source) {
        if (source) {
            return '/'+cmd+' '+params
        }
        document.location = 'http://www.9gag.com';
        return '';
    };
    
    /**
     * Action of command /hrlp
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var help = function (cmd, params, source) {
        
        // /!\ reversed chat 
        if (source) {
            return '/'+cmd+' '+params
        }
        
        if (! _self.reversed) {
            $.chat.write('Liste des commandes : ', '', true);
        }
        
        for ( var name in _cmdList) {
            obj = _cmdList[name];
            if (obj.proto && obj.description ) {
                if (_self.reversed) {
                    $.chat.write("\t" + obj.description, '', true);
                    $.chat.write(obj.proto, '', true);
                } else {
                    $.chat.write(obj.proto, '', true);
                    $.chat.write("\t" + obj.description, '', true);
                }
            }
        }
        
        if (_self.reversed) {
            $.chat.write('Liste des commandes : ', '', true);
        }
        
        return '';
    };
    
    /**
     * Action of commands /ignore and /unignore
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var toggleIgnore = function (cmd, params, source) {
        
        if (source) {
            return '/'+cmd+' '+params
        }
        
        var user = params;
        if (! user ) {
            var obj = _cmdList[cmd];
            $.chat.write('Usage : ' + obj.proto, '', true);
            return '';
        }

        if ($.inArray(user, $.chat.nicks()) < 0) {
            $.chat.write( user + ' does not exist.', '');
            return '';
        }
        
        var muted = $.chat.isMuted(user);
        
        if ((muted && cmd == 'unignore') || ( !muted && cmd == 'ignore' )){
            $.chat.mute(user);
        }
        return '';
    };
    
    /**
     * Action of command /logout and /leave
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var logout = function (cmd, params, source) {
        // TODO
        if (source) {
            return '/'+cmd+' '+params
        }
        
        location.reload();
    };
    
    /**
     * Action of command /nick
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var nick = function (cmd, params, source) {
        
        if(! source ) {
            if (params) {
                var lastNick = $.chat.myNick();
                $.chat.login(params);
                return '/' + cmd + ' '+ lastNick;
            } else {
                var obj = _cmdList[cmd];
                $.chat.write('Usage : ' + obj.proto, '', true);
                return '';
            }
        } else if (params) {
            $.chat.write(params + " s'appelle maintenant " + source, '');
            return '';
        }
    };
    
    /**
     * Action of command /me
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var me = function (cmd, params, source) {
        if (! source) {
            return '/' + cmd + ' ' + params;
        } else {
            $.chat.write( source + ' ' + params, '');
            return '';
        }
    };
    
    /**
     * Action of command /who
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var who = function (cmd, params, source) {
        
        if (source) {
            return '/'+cmd+' '+params
        }
        
        var nicks = $.chat.nicks();
		if(! _self.reversed) $.chat.write('Connected users:', '');
        for (var i in  nicks) {
            var msg = nicks[i];
            msg += (_who[nicks[i]]) ? ': '+_who[nicks[i]] : '';
            $.chat.write(msg, '');
        }
		if(_self.reversed) $.chat.write('Connected users:', '');
        return '';
    };
    
    /**
     * Action of command /saywho
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var saywho = function (cmd, params, source) {
        
        if (params && params.indexOf(' ') >= 0) {
            var user = params.substring(0, params.indexOf(' '));
            var msg = params.substring(params.indexOf(' ')+1);
            _who[user] = msg;
            return (source) ? '' : '/' + cmd + ' ' + params;
        }
        return '';
    };
    
	/**
     * Action of command /clear
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var clear = function (cmd, params, source) {
        if (source) {
            return '/'+cmd+' '+params
        }
        
		setTimeout(function(){
			$('pre:not(:first)').remove();
			$('br:not(:first)').remove();
		}, 500);
        return '';
    };
	
    /**
     * Action of command /mp /w /notice 
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var mp = function (cmd, params, source) {
        if (source) {
            return '/'+cmd+' '+params
        }
        
        if (params && params.indexOf(' ') >= 0) {
            var user = params.substring(0, params.indexOf(' '));
            var msg = params.substring(params.indexOf(' ')+1);
            
            try {
                $.chat.sendPrivate(user, msg);
            } catch (e) {
                $.chat.write(e, '', true)
            }
            return '';
        } else {
            var obj = _cmdList[cmd];
            $.chat.write('Usage : ' + obj.proto, '', true);
        }
        return '';
    };
    
    /**
     * Action of command /plugin
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    var plugin = function (cmd, params, source) {
        if (source) {
            return '/'+cmd+' '+params
        }
        
        
        if (!params) {
            params = 'list';
        }
        
        var action, pluginName;
        if (params.indexOf(' ') >= 0) {
            action = params.substring(0, params.indexOf(' '));
            pluginName = params.substring(params.indexOf(' ')+1);
        } else {
            action = params;
            pluginName = '';
        }
        
        switch (action) {
            
			case 'ls':
            case 'list':
                var list = $.pluginApi.pluginList(),
					loaded_str, unloaded_str;
				for(var i in list.loaded){
					var style = $('#plugin-container').find('#'+list.loaded[i]+' span').css('font-style');
					loaded_str=(loaded_str)?loaded_str+'</span> <span style="font-style:'+style+'">'+list.loaded[i]:'<span style="font-style:'+style+'">'+list.loaded[i];
					if(i == list.loaded.length-1) loaded_str+='</span>';
				}
				for(var i in list.unloaded){
					var style = $('#plugin-container').find('#'+list.unloaded[i]+' span').css('font-style');
					unloaded_str=(unloaded_str)?unloaded_str+'</span> <span style="font-style:'+style+'">'+list.unloaded[i]:'<span style="font-style:'+style+'">'+list.unloaded[i];
					if(i == list.unloaded.length-1) unloaded_str+='</span>';
				}
                
                if (_self.reversed) {
                    $.chat.write("\t" + unloaded_str, '', true);
                    $.chat.write('Unloaded : ', '', true);
                    $.chat.write("\t" + loaded_str, '', true);
                    $.chat.write('Loaded : ', '', true);
                } else {
                    $.chat.write('Loaded : ', '', true);
                    $.chat.write("\t" + loaded_str, '', true);
                    $.chat.write('Unloaded : ', '', true);
                    $.chat.write("\t" + unloaded_str, '', true);
                }
                break;
            
			case 'ad':
            case 'add':
				var tempName = $.trim(params);
				var afterName = tempName.substring(tempName.indexOf(' ')+1);
				var name = afterName.split(' ')[0].replace(/\W/g, '');
				var file = afterName.substring(afterName.indexOf(' ')+1);
				var sendPlugin = {};
				sendPlugin.pluginName = name;
				sendPlugin.pluginFile = file;
				try{
					if(afterName.split(' ')[0].charAt(0) == '$') $.chat.write("Don't forget the plugin name ! Command is /plugin add MyPluginName MyPluginCode",'');
					else if(file.split('name')[1].split(',')[0].indexOf("'"+name+"'") <0 && file.split('name')[1].split(',')[0].indexOf('"'+name+'"') < 0) $.chat.write('Plugin names mismatch. Declared: '+name+', Coded'+file.split('name')[1].split(',')[0],'');
					else{
						$.ajax({
							type: 'POST',
							data: JSON.stringify(sendPlugin),
							contentType: 'application/json',
							url: '/plugin-add',						
							success: function(data) {
								$('<iframe src="/PluginManager.js" />').css('display','none').appendTo($('body')).on('load', function(){
									$.chat.send('<script>'+file+'</script>');
									$.chat.send('/me uploaded plugin '+name+', click previous message to actuate changes, then load it if unloaded.');
								});
							}
						});
					}
				}catch(e){$.chat.write("Invalid syntax ! Command is /plugin add MyPluginName MyPluginCode",'');}
				break;
				
			case 'rm':
            case 'remove':
				var tempName = $.trim(params);
				var afterName = tempName.substring(tempName.indexOf(' ')+1);
				var name = afterName.split(' ')[0];
				var sendPlugin = {};
				sendPlugin.pluginName = name;
				
				$.ajax({
					type: 'POST',
					data: JSON.stringify(sendPlugin),
					contentType: 'application/json',
					url: '/plugin-remove',						
					success: function(data) {
						$.chat.send('/me removed plugin '+name);
					}
				});
				break;
				
			case 'rs':
            case 'restore':
				var tempName = $.trim(params);
				var afterName = tempName.substring(tempName.indexOf(' ')+1);
				var name = afterName.split(' ')[0];
				var sendPlugin = {};
				sendPlugin.pluginName = name;
				
				$.chat.send('/plugin ud '+name);
				
				$.ajax({
					type: 'POST',
					data: JSON.stringify(sendPlugin),
					contentType: 'application/json',
					url: '/plugin-rollback',						
					success: function(data) {
						$('<iframe src="/PluginManager.js" />').css('display','none').appendTo($('body')).on('load', function(){
							$.get( $.pluginApi.getPath(name, false), function( data ) {
								$.chat.send('<script>'+data+'</script>');
								$.chat.send('/me rolled plugin '+name+' back, click previous message to actuate changes, then load it if unloaded.');
							});
						});
					}
				});
				break;
				
			case 'ld':
            case 'load':
				try {
                    $.pluginApi.loadPlugin(pluginName);
                    $.chat.write(pluginName+ ' loaded !', '', true);
                } catch(s) {
                    $.chat.write(s, '', true);
                }
                break;
                
			case 'ud':
            case 'unload':
				try {
                    $.pluginApi.unloadPlugin(pluginName);
                    $.chat.write(pluginName+ ' unloaded !', '', true);
                } catch(s) {
                    $.chat.write(s, '', true);
                }
                break;
				
			case 'vi':
            case 'view':
				var url = false;
				$('#plugin-container').find('a').each(function() {
					if($(this).attr('href').indexOf(pluginName+'.js') > -1) url = $(this).attr('href');
				});
				if(url)
					$('<iframe src="/PluginManager.js" />').css('display','none').appendTo($('body')).on('load', function(){
						$.get( url, function( data ) {
							$.chat.write($.chat.escape(data),'', true);
						});
					});
				else $.chat.write('Plugin '+pluginName+' not found !', '');
				
                break;
                
            
            default:
                var obj = _cmdList[cmd];
                $.chat.write('Usage : ' + obj.proto, '', true);
                break;
        }
        
        return '';
    }
    
    
    
    _cmdList = {
		clear: { func: clear, description: 'Clears all messages', proto:'/clear'},
        away: { func: away, description: 'Indique une absence', proto:'/away &lt;message&gt;'},
        exit: { func: exit, description:'Ferme le chat', proto:'/exit ou /quit'},
        quit: { func: exit },
        help: { func: help, description:'Affiche l\'aide', proto:'/help'},
        ignore: { func: toggleIgnore, description:'Ignore totalement un user (de préférence dagoulas)', proto:'/ignore &lt;pseudo&gt;'},
        unignore: { func: toggleIgnore, description:'Desactive l\'ignore', proto:'/unignore &lt;pseudo&gt;'},
        leave: { func: logout, description:'Se déconnecte du chat', proto:'/logout ou /leave'},
        logout: { func: logout },
        nick: { func: nick, description:'Change de pseudo', proto:'/nick &lt;pseudo&gt;'},
        me: { func: me, description:'Affiche un message en mode "action"', proto:'/me [message]'},
        who: { func: who, description:'Affiche des infos sur les utilisateurs du chat', proto:'/who'},
        saywho: { func: saywho },
        mp : { func: mp, description:'Envoie un message privé', proto:'(/w|/mp|/notice) &lt;pseudo&gt; [message]'},
        notice : {func: mp, proto:'(/w|/mp|/notice) &lt;pseudo&gt; [message]'},
        w : {func: mp, proto:'(/w|/mp|/notice) &lt;pseudo&gt; [message]'},
        plugin : { 
            func: plugin, 
            description:'Plugins management. Only plugins in <i>italic</i> can be added/removed/replaced/restored. "restore" restores a plugin to a random backup version', 
            proto:'/plugin (list|load|unload|add|remove|restore|view) | (ls|ld|ud|ad|rm|rs|vi) [plugin name] [plugin code]'
        },
    }
    
    // listeners
    _self.name = 'IRCcmd' ;
    _self.onSend = parseCmd;
    _self.onReceived = parseRecivedCmd;
    _self.onUsersRefresh = onUsersRefresh;
}


var irc = new IRCcmd();
$.irc = irc;
$.plugin({
    name: irc.name,
    onSend: irc.onSend,
    onReceived: irc.onReceived,
    onUsersRefresh: irc.onUsersRefresh
});
