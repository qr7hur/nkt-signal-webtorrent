var summonPlugin = function () {
    
    var _self = this ;
    
    _self.init = function () {
        $.pluginApi.loadPlugin('IRCcmd');
        $.irc.addCmd({ 
            func: _self.summon, 
            description:'Summons a friend you are missing', 
            proto:'/summon (Krako|dagoulas|test|Djambi|Nene|Bertrand|Jeff|Remace|Ostracil|Qrthur &lt;phrase&gt;)'
        }, 'summon');
    } ;
    
    _self.stop = function() {
        $.irc.addCmd(null, 'summon');
    }
    
    /**
     * Action of command /summon
     * @param string cmd Command
     * @param string params End of the command
     * @param object source User who send the command (null if current)
     * @return string Message to send to the others
     */
    _self.summon = function (cmd, params, source) {
        var KrakoArray = ['Attendez les gars je fais un PPT', 'Attendez les gars je suis en train de vous acheter un cadeau mystère', 'Attendez les gars je fais un de Groodt', 'Attendez les gars je suis en train de vous passer des dogecoins', 'Attendez les gars j\'arrive pas a installer Eclipse', "Attendez les gars mon perso rush tout seul", "Attendez les gars j'peux rien faire", "Attendez les gars je finis mon assiette", "Attendez les gars je finis mon jeu de tarot"];
        var NeneArray = ['Chien maigre', 'tg ducon', 'ils sont nuls à chier']; 
		var JeffArray = ['GROSSE AMBIANCE', "L'ambiance les gars !", 'Et c\'est important l\'ambiance les gars'];
		if( !source ) {
            return '/' + cmd + ' ' + params ; 
        } else {
			if(params.indexOf(' ')>-1){
				if(!params.indexOf("Qrthur"))
					$.chat.write(params.replace(params.split(' ')[0], '').replace(/a/g, 'q').replace(/m/g,';'), 'Qrthur');
			}else{
				switch(params){
					case "Krako":
						$.chat.write( KrakoArray[Math.floor(Math.random() * KrakoArray.length)], 'Krako');
						break;

					case "daoulas":
						$.chat.write( 'Les gars je peux pas mon chef regarde', 'daoulas');
						break;                
					
					case "test":
						$.chat.write( 'test', 'test');
						break;

					case "Djambi":
						$.chat.write( 'pause clope', 'Djambi');
						break;
					 
					case "Nene":
						$.chat.write( NeneArray[Math.floor(Math.random() * NeneArray.length)], 'Nene');
						break;
						
					case "Bertrand":
						$.chat.write( 'Ta mère', 'Bertrand');
						break;
						
					case "Jeff":
						$.chat.write( JeffArray[Math.floor(Math.random() * JeffArray.length)], 'Jeff');
						break;
						
					case "Remace":
						$.chat.write('Pourquoi vous avez pas suivi les gars?', 'Remace');
						break;
							
						
					default :  
					case "Ostracil":
						$.chat.write( 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent in viverra lacus, ac vestibulum nunc. Ut sem libero, tincidunt non condimentum eu, pellentesque non eros. Integer egestas ornare quam ornare vehicula. Pellentesque blandit mauris leo, at venenatis neque congue sed. Etiam congue, nisi in pulvinar fringilla, elit turpis pharetra nulla, ac rhoncus augue libero a eros. Quisque convallis, risus sed sodales imperdiet, enim turpis dictum velit, sed tristique erat felis eget lectus. Morbi a quam at sem pretium rhoncus eget at velit. Fusce feugiat, elit non placerat ultrices, urna risus eleifend justo, sit amet aliquam velit mi at odio. Sed elit lectus, lacinia quis metus nec, feugiat dapibus turpis. Maecenas mollis, orci ut pharetra consequat, metus elit vestibulum arcu, id auctor elit magna nec turpis', 'Ostracil');
						break;
				}
			}
            return '';
        }
    };

};

var summonPluginVar = new summonPlugin();
    
$.plugin({
    name: 'summon',
    init: summonPluginVar.init,
    stop: summonPluginVar.stop
});
