var unsafe = [], showHide = [], disclaimer = [], nkt_ready = 0, nkt_checkReady = null;
var launch = function() {

	var swit = false;
	var nosubmit = false;
	
	var port = $('#port').html();
	var pubKeys = [], cutLink = [], as = [];
	var nicks = [];
	
	var ticks = 0, userTicks1 = [], userTicks2 = [], switchTicks = [];
	var emptyList = 0;
	var lastaction = 0;
	
	var key, pubKey, socket;
	var listener = [];
	
	var myNick="";
    
    /**
     * Escape an html string
     * @param string string String to escape
     * @return string Escped string
     */
	var escapeHTML = function(string) {
		var pre = document.createElement('pre');
		var text = document.createTextNode(string);
		pre.appendChild(text);
		return pre.innerHTML;
	};
	
	
	var escapeAndAddWarning = function(msg) {
	    var escaped = escapeHTML(msg);
	    var disp = msg;
	    
		if(escaped != msg) {
			disclaimer[unsafe.length] = 'This message ('+escaped+') may be unsafe, click to show';
			showHide[unsafe.length]  =true;
			disp='<span id="'+unsafe.length+'" onmouseover="this.style.cursor=\'pointer\';" onclick="$(this).html(showHide[this.id]?\'Unsafe content (click to hide):<br />\'+unsafe[this.id]:disclaimer[this.id]);showHide[this.id]=!showHide[this.id];">'+disclaimer[unsafe.length]+'</span>';
			unsafe.push(msg);
		}
		return disp;
	}
	
	
	/**
	 * Display a rceived message
	 * @param object data received data
	 */
	var disp_msg=function(data){
		if(typeof data !== 'object' || !data.pubKeySrc || !data.nickSrc || !data.msg
		//|| !data.pubKeyDest
		) return;
		if(myNick){
			save_key(data.pubKeySrc, atob(data.nickSrc));
			if(
				//data.pubKeyDest == pubKey && 
				!cutLink[pubKeys.indexOf(data.pubKeySrc)]){
				//var msg = cryptico.decrypt(data.msg, key), disp, escaped;
				
				// call plugin functions
				//msg.nickName = atob(data.nickSrc);
				data.nickName = atob(data.nickSrc);
				data.plaintext = data.msg;
				//launchEvent('received', msg);
				launchEvent('received', data);
				
				// write on window
				//write_msg(msg.plaintext, atob(data.nickSrc));
				write_msg(data.msg,  atob(data.nickSrc));
			}
			//data.nickSrc = btoa(myNick);
			//data.pubKeySrc = pubKey;
			//socket.emit('ping2',data);
			window.nkt.sendClearMessage({
				ping: true,
				nickSrc: btoa(myNick),
				pubKeySrc: pubKey
			});
		}
	};
	
	
	/**
	 * Write a message on the window
	 * @param string msg Message to display
	 * @param string nickName Source of the message (nickname)
	 * @param bollean notEscape set to true to not escape HTML (optional)
	 */
	var write_msg = function (msg, nickName, notEscape) {
	    
	    var escaped = msg ;
	    if (! notEscape){
	        escaped = escapeAndAddWarning(msg);
	    }
	    var event = {
	        msg: escaped,
	        nickName: nickName
	    };
	    launchEvent('write', event);
	    
	    if (!event.msg) {
	        return ;
	    }
	    
	    // new line
		$('#chat').prepend(
			$(document.createElement('br'))
		);
		
		// display the text
		$('#chat').prepend(
			$(document.createElement('pre'))
			.css('font-family','Courier New')
			.css('display','inline')
			.css('font-weight','bold')
			.css('word-break','break-all')
			.css('word-wrap','break-word')
			.css('white-space','-moz-pre-wrap')
			.css('white-space','pre\9')
			.css('white-space','pre')
			.css('white-space','pre-wrap')
			.css('font-size','90%')
			.css('color','#C0C0C0')
			.html(event.nickName+'&gt; '+event.msg)
		);
	};
	
	
	/**
	 * Toggle mute an user
	 * @param (integer|string) Nickname or id of the user
	 * @return boolean muted
	 */
	var mute = function( id ) {
	    
	    if (typeof id == 'string') {
	        id = parseInt( $('#list a:contains('+id+')').attr('id') );
	    }
	    
	    if ( id == undefined || !pubKeys[id]) {
		    throw "User does not exist.";
	    }
	    
	    var elmt = $('#list a#'+id);
	    elmt.css('color', (cutLink[id]) ? 'white' : 'gray');
	    cutLink[id] = (cutLink[id]) ? false : true ;
	    return cutLink[id];
	};
	
	/**
	 * Get if an user is muted
	 * @param (integer|string) Nickname or id of the user
	 * @return boolean muted
	 */
	var isMuted = function (id) {
	    if (typeof id == 'string') {
	        id = parseInt( $('#list a:contains('+id+')').attr('id') );
	    }
	    return cutLink[id];
	}
	
	
	/**
	 * Send a message to the others
	 * @param string msg
	 */
	var send_msg = function (msg) {
	    var data = {};
	    var event = {
	        msg: msg
	    }
	    launchEvent('send', event);
	    msg = event.msg;
	    
	    if (!msg) {
	        return ;
		}
		data.nickSrc = btoa(myNick);
		data.pubKeySrc = pubKey;
		data.msg = msg;
		window.nkt.sendEncryptedMessage(data);
	    /*
		
		for(var i in pubKeys){
			if(pubKeys[i] && !cutLink[i]){
				var encrypted = cryptico.encrypt(msg,pubKeys[i]);
				data.msg = encrypted.cipher;
				data.pubKeyDest = pubKeys[i];
				socket.emit('new_msg2',data);
			}
		}
		var encrypted = cryptico.encrypt(msg,pubKey);
		data.msg = encrypted.cipher;
		data.pubKeyDest = pubKey;
		*/
		disp_msg(data);
	};
	
	/**
	 * Send a private msg to an user
	 * @param (integer|string) Nickname or id of the user
	 */
	var send_private = function (id, msg) {
	    
	    var nick ;
	    if (typeof id == 'string') {
	        nick = id;
	        id = parseInt( $('#list a:contains('+id+')').attr('id') );
	    } else {
	        nick = $('#list a#' + id).text();
	    }
	    
   	    if ( id == undefined || !pubKeys[id]) {
   			throw "User does not exist.";
	    }

	    //var encrypted = cryptico.encrypt( '(private) ' + msg, pubKeys[id]);
		
	    var data = {
	        nickSrc : btoa(myNick),
	        pubKeySrc : pubKey,
	        msg : '(private - ' + nick + ') ' + msg,
	        pubKeyDest : pubKeys[id]
		};
		disp_msg(data);
		data.msg = '(private) ' + msg;
		window.nkt.sendEncryptedMessage(data, pubKeys[id]);


		/*
	    socket.emit('new_msg2',data);
	    
	    encrypted = cryptico.encrypt( '(private - ' + nick + ') ' + msg, pubKey);
	    data.msg = encrypted.cipher;
		data.pubKeyDest = pubKey;
		*/
		//data.msg = '(private - ' + nick + ') ' + msg;
	    //disp_msg(data);
	}
	
	
	
	/**
	 * Loggin on the chat
	 * @param string nickname
	 */
	var login = function (nickname) {
	    var data = {};
	    //var prevNick = myNick;
	    var debug = true;
	    
	    nickname = nickname.replace(/\n/g,'');
		nickname = escapeHTML(nickname);
		nickname = nickname.replace(/ /g,'');

		if(nickname.match(/@debug$/)) {
			nickname = nickname.substr(0,nickname.length - 6);
		} else debug = false;

		data.nickSrc = nickname;
		data.pubKeySrc = pubKey;
		myNick=nickname;
		$('input:last').attr('value','Send');
		$('#nick').html(myNick+'&gt; ');

        if(!debug) {
			setTimeout(function(){
				nosubmit = true;
				$('textarea').val('Loading default plugins...');
			}, 50);
			setTimeout(function(){
				$.pluginApi.loadPlugin('seed');
				$('textarea').val('');
				nosubmit = false;
			}, 100);
        }
	};
	
	/**
	 * Refresh the userList
	 * using public keys received
	 */
	var userList=function(cancelEvent){
		var empty=true;
		for(var i in pubKeys){
			if(pubKeys[i] && pubKeys[i]!=pubKey){
				if(empty) $('#list').html('<font color="white">Plugged/</font><font color="gray">Unplugged</font> : ');
				empty=false;
				as[i]=document.createElement('a');
				as[i].id=i;
				as[i].innerHTML=nicks[i];
				if(!cutLink[i]) as[i].style.color='white';
				else as[i].style.color='gray';
				as[i].style.cursor='pointer';
				as[i].style.textDecoration='underline';
				document.getElementById('list').appendChild(as[i]);
				document.getElementById('list').appendChild(document.createTextNode(' '));
			}
		}
		/*
		if(!socket.connected) {
			$('#list').html('<font color="white">Plugged/</font><font color="gray">Unplugged</font> : No network.');
			setTimeout(function(){userList(true);}, 50);
		}
		else */
		if(empty) {
			emptyList++;
			if(emptyList > 50) {
				$('#list').html('<font color="white">Plugged/</font><font color="gray">Unplugged</font> : No other users.');
				emptyList = 0;
			}
			setTimeout(function(){userList(true);}, 50);
		}
		
		if(!cancelEvent) launchEvent('userListRefreshed', $('#list'));
	};
	
	/**
	 * Saved a received public key
	 * @param string pubKeySrc Public key received
	 * @param string nickName NickName of the sender
	 */
	var save_key=function(pubKeySrc, nickName){
		if(pubKeySrc){
			if(pubKeys.indexOf(pubKeySrc)==-1){
				pubKeys.push(pubKeySrc);
				var index = pubKeys.indexOf(pubKeySrc);
				nicks[index] = nickName;
				userTicks1[index] = ticks;
				userTicks2[index] = ticks;
				switchTicks[index] = true;
				
	            launchEvent('newUser', nickName);
			}else{
				var index = pubKeys.indexOf(pubKeySrc);
				nicks[index] = nickName;
				if(switchTicks[index]) userTicks1[index] = ticks;
				else userTicks2[index] = ticks;
				switchTicks[index] = !switchTicks[index];
			}
			lastaction = ticks;
			userList();
		}
	};
	
	/**
	 * Initialise the crypto stuff
	 */
	var initialize_crypto=function(){
	    //key = cryptico.generateRSAKey(Math.random().toString(),2048);
	    //pubKey = cryptico.publicKeyString(key);
		pubKey = window.nkt.mySwarm.address();
	};
	
	var socket_connect = function() {
		/*
	    var host = $(location).attr('protocol').replace(/^http/, 'ws')+'//'+$(location).attr('hostname');
	    if($(location).attr('protocol:')!='http' && $(location).attr('protocol')!='https:')
		    host='ws://' + $(location).attr('hostname');
	    if($(location).attr('hostname')=='localhost')
		    host='http://'+$(location).attr('hostname')+':'+port;
	    
		socket = io(host);
		*/
		socket = window.nkt.websocket;
	};
	
	/**
	 * Subscribe on chat events
	 * @param function callback
	 */
	var subscribe = function (callback) {
        listener.push(callback);
    }
	
	/**
	 * Launch an event for listeners
	 * @param string name Name of the event
	 * @param object data
	 */
	var launchEvent = function(name, data) {
	    for (var i = 0; i < listener.length; i++) {
	        listener[i](name, data);
	    }
	}
	
	
	// submit on enter pressed
	$('textarea').first().keydown(function(e){
		var code = e.which || e.keyCode || 0;
		if(code == 13 || (code == 229 && $('textarea').val().slice(-1) == '\n')){
			if(!nosubmit) $('form').submit();
		}
	});
	$('textarea').first().keyup(function(e){
		var code = e.which || e.keyCode || 0;
		if(code == 13 || (code == 229 && $('textarea').val().slice(-1) == '\n')){
			if(!nosubmit) $('form').submit();
		}
	});
	/**
	 * On submitting the textarea
	 */
	$('form').submit(function(){
		var msg=$('textarea').val();
		var data = {};
		msg = $.trim(msg);
		if(msg){
			if(!myNick){
				$('textarea').css('width','80%');
				login(msg);
			}else{
				send_msg(msg);
			}
		}
		$('textarea').val('').focus();
		return false;
	});
	
	
	// mute on click on a nickname
	$('#list').on('click', 'a', function() {
	    var id = parseInt($(this).attr('id'));
	    mute(id);
	});
	
	
	// change the color on ESC pressed
	$(window).keyup(function(e){
		if(e.which == 27){
			$('form').toggle();
			$('#chat').toggle();
			$('body').css('background-color',(swit)?'black':'white');
			swit = !swit;
		}
	});
	
	
	setTimeout(function(){
		initialize_crypto();
		nkt_ready++;
	}, 0);
	
	setTimeout(function(){
		socket_connect();
		// Sockets events
		window.addEventListener('nktencryptedmessagereceived', (event) => {
			disp_msg(event.detail);
		});
		window.addEventListener('nktclearmessagereceived', (event) => {
			let data = event.detail;
			if(typeof data !== 'object' || !data.pubKeySrc || !data.nickSrc) return;
			if(!event.detail.ping) return;
			save_key(data.pubKeySrc, atob(data.nickSrc));
		});
		/*
		socket.on('new_msg2', disp_msg);
		socket.on('ping2', function(data) {
			if(typeof data !== 'object' || !data.pubKeySrc || !data.nickSrc) return;
			save_key(data.pubKeySrc, atob(data.nickSrc));
		});
		*/
		nkt_ready++;
	}, 0);
	
	setTimeout(function(){
		//var plugins = document.createElement('script');
		//plugins.src = '/PluginManager.js';
		//document.getElementsByTagName('body')[0].appendChild(plugins);
		$('<script src="/PluginManager.js" ></script>').appendTo($('body'));
		nkt_ready++;
	}, 0);
	
	nkt_checkReady = setInterval(function(){
		if(nkt_ready > 2){
			userList();
			$('#toggle').css('display','block');
			$('#crypto').css('display','none');
			$('.plugins').css('display','block');
			$('textarea').css('height',parseFloat($("body").css("font-size")));
			clearInterval(nkt_checkReady);
			$('textarea').focus();
			setInterval(function(){
				//if(myNick) socket.emit('ping2',{pubKeySrc:pubKey,nickSrc:btoa(myNick)});
				if(myNick) window.nkt.sendClearMessage({
					ping: true,
					nickSrc: btoa(myNick),
					pubKeySrc: pubKey
				});
			    ticks++;
		    },500);
		    setInterval(function(){
			    for(var i in pubKeys)
				    if(pubKeys[i] && Math.abs(userTicks2[i]-userTicks1[i])-Math.abs(userTicks2[i]-ticks)<4*(-2-Math.abs(userTicks2[i]-userTicks1[i]))){
						if (window.nkt.userList[pubKeys[i]]) window.nkt.userList[pubKeys[i]].isUnreachable = true;
						pubKeys[i]=null;
					    userList();
				    }
				//if(!socket.connected) socket_connect();
		    },2000);
		    setInterval(function(){
		    	if(Math.abs(lastaction - ticks) > 50) {
		    		pubKeys = [];
		    		userList();
		    	}
		    },30000);
		}
	}, 10);
	
	/*$('#chat').append(	
		'<br /><iframe sandbox="allow-same-origin allow-scripts allow-popups allow-forms" seamless src="https://rocky-depths-4612.herokuapp.com/" ></iframe>'		
	);
	$('iframe').css('border','none');
	$('iframe').css('height','300px');
	$('iframe').css('width','300px');
	$('iframe').css('overflow','hidden');
	$('iframe').toggle(); */
    
    
    // API
    this.subscribe = subscribe;
    
    this.login = login;
    this.send = send_msg;
    this.write = write_msg;
    this.mute = mute;
    this.isMuted = isMuted;
    this.sendPrivate = send_private;
    this.nicks = function() {
		var realNicks = [];
		for(var i in pubKeys)
			if(pubKeys[i] && pubKeys[i]!=pubKey) realNicks.push(nicks[i]);
		if(realNicks[0])
			return realNicks;
		else return [$('#list').text().split(': ')[1]];
    };
    this.myNick = function() {
        return myNick;
    };
	this.escape = escapeHTML;
}

jQuery.chat = new launch();
