$.plugin({
            
    name: 'replace',
    
    onSend: function(msg){
        return this.replaceAll(msg, false);
    },
    
    onWrite: function(msg, nick) {
        return this.replaceAll(msg, true, nick);
    },
    
    
    replaceAll: function(msg, tags, nick) {
    
        if (msg.charAt(0) != '/' && (!tags || (tags && nick))) {
            msg = msg.replace( /([f|F]ab(ien)?)|((d|D)aoulas)/g, "dagoulas");
            msg = msg.replace( /(lo{1,}l)|(LO{1,}L)/g, "lel" );
        }
        
        return msg;
    }
    
    
    
});
