$.plugin({
    
    name: 'yo',
    onNewUser: function(nick) {
        if (nick != $.chat.myNick() ) {
            $.chat.send( 'yo '+nick+' !');
        }
    },
    init: function() {
        $.chat.send( 'yo les gens !');
    }
});
