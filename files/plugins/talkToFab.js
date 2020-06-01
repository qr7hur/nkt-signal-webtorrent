$.plugin({
            
    name: 'talkToFab',
    
    onWrite: function(msg, nick) {
        var _self = this;
        
        if( nick == 'Daoulas' ) {
            setTimeout(function(){
                $.chat.send( _self.daoulas[Math.floor(Math.random() * _self.daoulas.length)]);
            }, 1000);
        }
        return msg;
    },
    
    
    daoulas : [
//        "Qu'est ce que tu n'as pas compris Daoulas ?",
        "Il est marrant ce Daoulas.",
        "Il comprend rien Daoulas.",
        "Écoute un peu ce que l'on dit, Daoulas.",
//        "Comment ça va, Daoulas ?",
//        "Faut demander à Daoulas, il est fort pour ce genre de trucs.",
//        "Tu en pense quoi Daoulas ?",
        "C'est sympa de discuter avec Daoulas, il a beaucoup de conversation.",
//        "Tu fais une game avec nous Daoulas ?",
        "Et c'est une Daoulas !!!!",
        "C'est bien Daoulas, c'est bien.",
        "Il est brave ce Daoulas.",
//        "C'est quoi déjà le prénom de Daoulas.",
        "Et c'est une SUPER blague de Daoulas !!",
        "Daoulas ... :/",
        "Trop d'humour ce Daoulas.",
        "Tu t'es tapé un gros bide là Daoulas. Recommence pour voir ?",
        "Il touche vraiment le fond Daoulas",
        "Vas-y Daoulas, continue, tu touche presque le fond.",
        "Mais sortez le. Il est pas possible ce daoulas.",
        "Si les blague de Daoulas sont pourries tape dans tes mains. clap clap",
        "Arrête de dire de la merde stp Daoulas.",
        "C'est une Daoulasserie !",
        "STOP Daoulas stp STOP."
    ]
    
});
