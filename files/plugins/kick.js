var kickPlugin = function () {
    
    var _self = this ;
    
    _self.init = function () {
        $.pluginApi.loadPlugin('IRCcmd');
        $.irc.addCmd({ 
            func: _self.kick, 
            description:'Utilisée pour « kicker » (faire sortir de force) un utilisateur du chat', 
            proto:'/kick &lt;pseudo&gt; &lt;raison&gt;'
        }, 'kick');
    } ;
    
    _self.stop = function() {
        $.irc.addCmd(null, 'kick');
    }
    
    /**
     * Action of command /kick
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    _self.kick = function (cmd, params, source) {
        
        if (! source) {
            
            var user = (params.indexOf(' ') >= 0 ) ? 
                params.substring(0, params.indexOf(' ')) : 
                params
            ;
            if ($.inArray(user, $.chat.nicks()) != -1) {
                return '/' + cmd + ' ' + params;
            } else {
                $.chat.write( user + ' does not exist.', '');
                return '';
            }
        } else {
            
            var user, msg ;
            
            if (params.indexOf(' ') >= 0 ) {
                user = params.substring(0, params.indexOf(' '));
                msg = params.substring(params.indexOf(' ')+1);
            } else {
                user = params;
                msg = '';
            }
            if (user == $.chat.myNick()) {
                location.reload();
            } else {
                $.chat.write( user + ' has been kicked by '+ source +' (' + msg +')', '');
            }
            return '';
        }
    };

};

var kickPluginVar = new kickPlugin();
    
$.plugin({
    name: 'kick',
    init: kickPluginVar.init,
    stop: kickPluginVar.stop
});
